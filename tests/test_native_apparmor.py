"""Static, offline checks for the native AppArmor candidate."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "deploy/native/jev-audit-native.apparmor"
JOB_GLOB = "[0-9a-f]" * 32
RELEASE = "/opt/jev-audit-native/releases/0e7c53a36257c75d96aae7890f2103b9341c9e3b"
VENV = f"{RELEASE}/venv"
PACKAGE = f"{VENV}/lib/python3.12/site-packages/jevseo"
CAPABILITIES = {
    "sys_admin",
    "sys_chroot",
    "net_admin",
    "setuid",
    "setgid",
    "sys_ptrace",
}
EXECUTABLES = {
    f"{VENV}/bin/python",
    "/usr/bin/prlimit",
    "/usr/bin/bwrap",
    "/bin/true",
    "/usr/bin/true",
    "/usr/bin/fc-list",
    "/usr/sbin/ldconfig",
}


class NativeAppArmorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = PROFILE.read_text(encoding="utf-8")
        cls.lines = [line.strip() for line in cls.profile.splitlines() if line.strip()]

    def test_candidate_identity_and_bounded_syntax(self):
        self.assertIn("abi <abi/4.0>,", self.profile)
        self.assertIn('profile "jev-audit-native" flags=(attach_disconnected,mediate_deleted)', self.profile)
        self.assertEqual(len(re.findall(r"^profile\s+", self.profile, re.MULTILINE)), 1)
        self.assertIn("userns,", self.profile)
        self.assertNotIn("  file,", self.profile)
        self.assertNotIn("  capability,", self.profile)
        self.assertNotRegex(self.profile, r"\bux\b")
        self.assertNotRegex(self.profile, r'profile\s+"[^"]+//')
        self.assertNotRegex(self.profile, r"^\s*/oldroot/\*\*", re.MULTILINE)
        self.assertNotRegex(self.profile, r"^\s*/newroot/\*\*", re.MULTILINE)
        self.assertNotIn(f"{RELEASE}/** w", self.profile)
        self.assertIn("7370ec86d0cc2cd3fa761d5839c7fe9ae714c6ca66f752c969204d62f2e0c10c", self.profile)
        self.assertIn("6092022e955c98fb7b3e616cea3bd1902968113e9869615f8ad0818448e6ecd5", self.profile)

    def test_capabilities_and_network_are_exact(self):
        capabilities = {
            match.group(1)
            for match in re.finditer(r"^\s*capability\s+(\w+),$", self.profile, re.MULTILINE)
        }
        self.assertEqual(capabilities, CAPABILITIES)
        self.assertNotIn("capability setpcap,", self.profile)
        network = {
            match.group(1)
            for match in re.finditer(r"^\s*network\s+([^,]+),$", self.profile, re.MULTILINE)
        }
        self.assertEqual(
            network,
            {
                "inet stream",
                "inet dgram",
                "inet6 stream",
                "inet6 dgram",
                "unix stream",
                "unix dgram",
                "unix seqpacket",
            },
        )
        self.assertNotIn("  network,", self.profile)
        self.assertIn("deny network alg,", self.profile)
        self.assertIn("deny network vsock,", self.profile)

    def test_executable_set_and_directory_permissions_are_exact(self):
        file_rules = []
        for line in self.lines:
            if line.startswith("deny "):
                continue
            match = re.fullmatch(r"(/\S+) ([a-z]+),", line)
            if match:
                file_rules.append(match.groups())
        executable_rules = {path for path, permissions in file_rules if "x" in permissions}
        self.assertEqual(executable_rules, EXECUTABLES)
        self.assertTrue(all(permissions == "rix" for path, permissions in file_rules if "x" in permissions))
        directory_rules = [(path, permissions) for path, permissions in file_rules if path.endswith("/")]
        self.assertTrue(directory_rules)
        self.assertTrue(all("x" not in permissions for path, permissions in directory_rules))

    def test_job_paths_canaries_and_mount_sources_are_finite(self):
        prod = "/var/lib/jev-audit-native"
        acceptance = "/var/lib/jev-audit-native-acceptance"
        expected = (
            f"{prod}/jobs/{JOB_GLOB}/ rw,",
            f"{prod}/jobs/{JOB_GLOB}/** rwk,",
            f"{acceptance}/jobs/{JOB_GLOB}/ rw,",
            f"{acceptance}/jobs/{JOB_GLOB}/** rwk,",
            f"mount options=(rbind) /oldroot{prod}/jobs/{JOB_GLOB}/ -> /newroot/job/,",
            f"mount options=(rbind) /oldroot{acceptance}/jobs/{JOB_GLOB}/ -> /newroot/job/,",
        )
        for rule in expected:
            self.assertEqual(self.profile.count(rule), 1, rule)
        job_lines = [line for line in self.lines if "/jobs/" in line]
        for line in job_lines:
            if line.endswith("/jobs/ rw,"):
                continue
            self.assertIn(JOB_GLOB, line, line)
        self.assertIn(f"/runtime/jevseo/.jev-acceptance-ro-{JOB_GLOB} w,", self.profile)
        self.assertIn(f"{VENV}/.jev-acceptance-ro-{JOB_GLOB} w,", self.profile)
        self.assertNotIn("/runtime/jevseo/** rw", self.profile)

    def test_proc_and_ptrace_contract_is_complete(self):
        expected = (
            "/proc/ r,",
            "/proc/self/ r,",
            "/proc/[0-9]*/ r,",
            "/proc/self/ns/ r,",
            "/proc/[0-9]*/ns/ r,",
            "/proc/self/ns/{mnt,user,pid,ipc,uts,net,cgroup} r,",
            "/proc/[0-9]*/ns/{mnt,user,pid,ipc,uts,net,cgroup} r,",
            "/proc/self/status r,",
            "/proc/[0-9]*/status r,",
            "/proc/self/attr/ r,",
            "/proc/[0-9]*/attr/ r,",
            "/proc/self/attr/current r,",
            "/proc/[0-9]*/attr/current r,",
            "/proc/self/mountinfo r,",
            "/proc/[0-9]*/mountinfo r,",
            "/proc/self/fd/ r,",
            "/proc/[0-9]*/fd/ r,",
            "/proc/self/fd/[0-9]* r,",
            "/proc/[0-9]*/fd/[0-9]* r,",
            "/oldroot/proc/[0-9]*/fd/[0-9]* r,",
            "/proc/[0-9]*/uid_map rw,",
            "/proc/[0-9]*/gid_map rw,",
            "/proc/[0-9]*/setgroups rw,",
            'ptrace (read,readby) peer="jev-audit-native",',
        )
        for rule in expected:
            self.assertIn(rule, self.profile)
        self.assertNotRegex(self.profile, r"ptrace\s+\([^)]*(?:trace|tracedby)")
        self.assertNotIn("/proc/**", self.profile)

    def test_oldroot_source_permissions_are_finite(self):
        expected = (
            f"/oldroot/var/lib/jev-audit-native/jobs/{JOB_GLOB}/ r,",
            f"/oldroot/var/lib/jev-audit-native/jobs/{JOB_GLOB}/** r,",
            f"/oldroot/var/lib/jev-audit-native-acceptance/jobs/{JOB_GLOB}/ r,",
            f"/oldroot/var/lib/jev-audit-native-acceptance/jobs/{JOB_GLOB}/** r,",
            "/oldroot/usr/ r,",
            "/oldroot/usr/bin/ r,",
            "/oldroot/usr/lib/ r,",
            "/oldroot/usr/lib64/ r,",
            "/oldroot/usr/share/fonts/ r,",
            "/oldroot/usr/local/share/fonts/ r,",
            "/oldroot/etc/fonts/ r,",
            "/oldroot/etc/hosts r,",
            "/oldroot/etc/nsswitch.conf r,",
            "/oldroot/run/systemd/resolve/stub-resolv.conf r,",
            "/oldroot/etc/ssl/certs/ r,",
            f"/oldroot{VENV}/ r,",
            f"/oldroot{VENV}/bin/ r,",
            f"/oldroot{PACKAGE}/ r,",
            "/oldroot/dev/null r,",
            "/oldroot/dev/zero r,",
            "/oldroot/dev/full r,",
            "/oldroot/dev/random r,",
            "/oldroot/dev/urandom r,",
            "/oldroot/dev/tty r,",
        )
        for rule in expected:
            self.assertIn(rule, self.profile)
        self.assertNotIn("/oldroot/etc/resolv.conf", self.profile)

    def test_newroot_creation_permissions_are_finite(self):
        expected = (
            "/ r,",
            "/newroot/ r,",
            "/newroot/proc/ rw,",
            "/newroot/dev/ rw,",
            "/newroot/tmp/ rw,",
            "/newroot/etc/ rw,",
            "/newroot/runtime/ rw,",
            "/newroot/job/ rw,",
            "/newroot/usr/ rw,",
            "/newroot/bin/ rw,",
            "/newroot/lib/ rw,",
            "/newroot/lib64/ rw,",
            "/newroot/opt/ rw,",
            "/newroot/etc/fonts/ rw,",
            "/newroot/etc/ssl/ rw,",
            "/newroot/etc/ssl/certs/ rw,",
            "/newroot/etc/hosts rw,",
            "/newroot/etc/nsswitch.conf rw,",
            "/newroot/etc/resolv.conf rw,",
            "/newroot/runtime/jevseo/ rw,",
            "/newroot/usr/share/ rw,",
            "/newroot/usr/share/fonts/ rw,",
            "/newroot/usr/local/ rw,",
            "/newroot/usr/local/share/ rw,",
            "/newroot/usr/local/share/fonts/ rw,",
            "/newroot/proc/sys/ rw,",
            "/newroot/proc/sysrq-trigger rw,",
            "/newroot/proc/irq/ rw,",
            "/newroot/proc/bus/ rw,",
            "/newroot/dev/null rw,",
            "/newroot/dev/zero rw,",
            "/newroot/dev/full rw,",
            "/newroot/dev/random rw,",
            "/newroot/dev/urandom rw,",
            "/newroot/dev/tty rw,",
            "/newroot/dev/stdin rw,",
            "/newroot/dev/stdout rw,",
            "/newroot/dev/stderr rw,",
            "/newroot/dev/fd rw,",
            "/newroot/dev/core rw,",
            "/newroot/dev/ptmx rw,",
            "/newroot/dev/pts/ rw,",
            "/newroot/dev/shm/ rw,",
        )
        for rule in expected:
            self.assertIn(rule, self.lines)
        for path in (
            "/newroot/opt/jev-audit-native/ rw,",
            "/newroot/opt/jev-audit-native/releases/ rw,",
            f"/newroot{RELEASE}/ rw,",
            f"/newroot{VENV}/ rw,",
            f"/newroot{VENV}/bin/ rw,",
        ):
            self.assertIn(path, self.profile)

    def test_mount_contract_and_runtime_boundaries(self):
        mounts = {
            "/oldroot/usr/": "/newroot/usr/",
            "/oldroot/usr/bin/": "/newroot/bin/",
            "/oldroot/usr/lib/": "/newroot/lib/",
            "/oldroot/usr/lib64/": "/newroot/lib64/",
            "/oldroot/usr/share/fonts/": "/newroot/usr/share/fonts/",
            "/oldroot/usr/local/share/fonts/": "/newroot/usr/local/share/fonts/",
            "/oldroot/etc/fonts/": "/newroot/etc/fonts/",
            "/oldroot/etc/hosts": "/newroot/etc/hosts",
            "/oldroot/etc/nsswitch.conf": "/newroot/etc/nsswitch.conf",
            "/oldroot/run/systemd/resolve/stub-resolv.conf": "/newroot/etc/resolv.conf",
            "/oldroot/etc/ssl/certs/": "/newroot/etc/ssl/certs/",
            f"/oldroot{VENV}/": f"/newroot{VENV}/",
            f"/oldroot{VENV}/bin/": f"/newroot{VENV}/bin/",
            f"/oldroot{PACKAGE}/": "/newroot/runtime/jevseo/",
        }
        for source, target in mounts.items():
            self.assertIn(f"mount options=(rbind) {source} -> {target}", self.profile)
        self.assertIn("mount options=(rprivate,silent) -> /oldroot/", self.profile)
        self.assertIn("pivot_root oldroot=/tmp/oldroot/ /tmp/", self.profile)
        self.assertIn("pivot_root oldroot=/newroot/ /newroot/", self.profile)
        self.assertIn("umount /oldroot/", self.profile)
        self.assertIn("umount /,", self.profile)
        remounts = [line for line in self.lines if line.startswith("remount ")]
        self.assertTrue(remounts)
        for line in remounts:
            self.assertIn("options=(bind,remount,", line)
            self.assertIn("nosuid,nodev,silent)", line)
            self.assertIn("options in (noexec,noatime,nodiratime,relatime)", line)
            if line.endswith("/newroot/job/,"):
                self.assertNotIn(",ro,", line)
            else:
                self.assertIn(",ro,", line)

    def test_writes_secrets_tools_and_service_attachment_boundaries(self):
        for rule in (
            "/var/lib/jev-audit-native/jobs.sqlite3 rwk,",
            "/var/lib/jev-audit-native-acceptance/jobs.sqlite3 rwk,",
            "/tmp/** rwk,",
            f"{RELEASE}/tools/check_native_acceptance.py r,",
            f"{VENV}/bin/python rix,",
            "/job/ rw,",
            "/job/** rwk,",
        ):
            self.assertIn(rule, self.profile)
        for denied in (
            "/etc/jev-audit-native/** rwklx,",
            "/root/** rwklx,",
            "/home/** rwklx,",
            "/data/** rwklx,",
        ):
            self.assertIn(f"deny {denied}", self.profile)
        self.assertNotIn("/etc/jev-audit-native/api.env r", self.profile)
        self.assertNotRegex(self.profile, r"^\s*/etc/jev-audit-native/\*\* [rm]", re.MULTILINE)
        self.assertEqual(re.findall(r'^profile\s+"([^"]+)"', self.profile, re.MULTILINE), ["jev-audit-native"])
        self.assertNotRegex(self.profile, r'profile\s+"systemd')
        self.assertNotIn('profile "apparmor_parser', self.profile)


if __name__ == "__main__":
    unittest.main()
