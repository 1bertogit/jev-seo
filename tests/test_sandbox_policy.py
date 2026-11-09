"""Offline semantic checks for the unapproved Bubblewrap policy candidate."""

from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SECURITY_DIR = ROOT / "docker" / "security"
SECCOMP_PATH = SECURITY_DIR / "jev-bwrap-seccomp.json"
APPARMOR_PATH = SECURITY_DIR / "jev-bwrap.apparmor"
POLICY_DOC = ROOT / "docs" / "jev-sandbox-policy.md"

BASELINE_CANONICAL_SHA256 = "9da637d2ab0a204fcbd91bd88f1be9e004a3acab61c571a9f5b8870e588a17d2"
AMD64 = {"arches": ["amd64"]}
OPTIONAL_REMOUNT_FLAGS = 0x200C08
MANDATORY_RO_REMOUNT = 0x9027
MANDATORY_JOB_REMOUNT = 0x9026
ALLOWED_REMOUNT_FLAGS = MANDATORY_RO_REMOUNT | OPTIONAL_REMOUNT_FLAGS
REMOUNT_MASK = ((1 << 64) - 1) ^ OPTIONAL_REMOUNT_FLAGS
SELF_BIND_FLAGS = 0xC0EDD000
SECOND_USERNS_FLAGS = 0x10000000


def mount_rule(value: int) -> dict:
    return {
        "names": ["mount"],
        "action": "SCMP_ACT_ALLOW",
        "args": [{"index": 3, "value": value, "op": "SCMP_CMP_EQ"}],
        "includes": AMD64,
    }


CLONE_EXCEPTION = {
    "names": ["clone"],
    "action": "SCMP_ACT_ALLOW",
    "args": [
        {
            "index": 0,
            "value": 2114060288,
            "valueTwo": 1006764032,
            "op": "SCMP_CMP_MASKED_EQ",
        }
    ],
    "includes": AMD64,
}

RO_REMOUNT = {
    "names": ["mount"],
    "action": "SCMP_ACT_ALLOW",
    "args": [
        {
            "index": 3,
            "value": REMOUNT_MASK,
            "valueTwo": MANDATORY_RO_REMOUNT,
            "op": "SCMP_CMP_MASKED_EQ",
        },
    ],
    "includes": AMD64,
}

JOB_REMOUNT = {
    "names": ["mount"],
    "action": "SCMP_ACT_ALLOW",
    "args": [
        {
            "index": 3,
            "value": REMOUNT_MASK,
            "valueTwo": MANDATORY_JOB_REMOUNT,
            "op": "SCMP_CMP_MASKED_EQ",
        }
    ],
    "includes": AMD64,
}

EXTRA_RULES = [
    mount_rule(573440),  # MS_SILENT | MS_SLAVE | MS_REC
    mount_rule(6),  # MS_NOSUID | MS_NODEV, tmpfs
    mount_rule(53248),  # MS_SILENT | MS_BIND | MS_REC
    RO_REMOUNT,
    JOB_REMOUNT,
    mount_rule(14),  # MS_NOSUID | MS_NOEXEC | MS_NODEV, proc
    mount_rule(10),  # MS_NOSUID | MS_NOEXEC, devpts
    mount_rule(3236810752),  # MS_SILENT | MS_MGC_VAL | MS_BIND | MS_REC
    mount_rule(311296),  # MS_SILENT | MS_REC | MS_PRIVATE
    {"names": ["pivot_root"], "action": "SCMP_ACT_ALLOW", "includes": AMD64},
    {
        "names": ["umount2"],
        "action": "SCMP_ACT_ALLOW",
        "args": [{"index": 1, "value": 2, "op": "SCMP_CMP_EQ"}],
        "includes": AMD64,
    },
    {
        "names": ["unshare"],
        "action": "SCMP_ACT_ALLOW",
        "args": [{"index": 0, "value": SECOND_USERNS_FLAGS, "op": "SCMP_CMP_EQ"}],
        "includes": AMD64,
    },
    CLONE_EXCEPTION,
]


class SandboxPolicyStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.seccomp = json.loads(SECCOMP_PATH.read_text(encoding="utf-8")) if SECCOMP_PATH.is_file() else {}
        cls.apparmor = APPARMOR_PATH.read_text(encoding="utf-8") if APPARMOR_PATH.is_file() else ""
        cls.doc = POLICY_DOC.read_text(encoding="utf-8") if POLICY_DOC.is_file() else ""

    @staticmethod
    def _canonical_sha256(value: dict) -> str:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def test_candidate_files_and_provenance_exist(self) -> None:
        for path in (SECCOMP_PATH, APPARMOR_PATH, POLICY_DOC):
            self.assertTrue(path.is_file(), path)
        self.assertIn("536529b665dd0972c37bfb569f5d4ac8a53592e7b00752bc39ff063ca9864c74", self.doc)
        self.assertIn("9da637d2ab0a204fcbd91bd88f1be9e004a3acab61c571a9f5b8870e588a17d2", self.doc)
        self.assertIn("cce1c730656ad73cb04b19bf25caa2351732a00e04a06eeaf3010105e1ba6a57", self.doc)
        self.assertIn("38b25c808ac5fe87db27a3c3b1f9bf54b1b180ce", self.doc)
        self.assertIn("NOT APPROVED FOR DEPLOY", self.doc)

    def test_seccomp_is_pinned_baseline_plus_exact_amd64_delta(self) -> None:
        candidate = dict(self.seccomp)
        rules = candidate.get("syscalls", [])
        self.assertGreaterEqual(len(rules), len(EXTRA_RULES))
        self.assertEqual(rules[-len(EXTRA_RULES) :], EXTRA_RULES)
        candidate["syscalls"] = rules[: -len(EXTRA_RULES)]
        self.assertEqual(self._canonical_sha256(candidate), BASELINE_CANONICAL_SHA256)

    def test_seccomp_namespace_and_mount_bounds(self) -> None:
        added = self.seccomp.get("syscalls", [])[-len(EXTRA_RULES) :]
        names = {name for rule in added for name in rule.get("names", [])}
        self.assertNotIn("setns", names)
        for name in ("mount_setattr", "move_mount", "open_tree", "fsopen", "fsmount", "fsconfig", "fspick"):
            self.assertNotIn(name, names)
        self.assertEqual(
            [rule for rule in added if rule.get("names") == ["mount"]],
            EXTRA_RULES[:9],
        )
        self.assertEqual(
            [rule for rule in added if rule.get("names") == ["pivot_root"]],
            [EXTRA_RULES[9]],
        )
        self.assertEqual(
            [rule for rule in added if rule.get("names") == ["umount2"]],
            [EXTRA_RULES[10]],
        )
        self.assertTrue(all(rule.get("includes") == AMD64 for rule in added))

    def test_seccomp_remount_masks_are_single_arg_and_algebraically_bounded(self) -> None:
        added = self.seccomp.get("syscalls", [])[-len(EXTRA_RULES) :]
        remounts = [
            rule
            for rule in added
            if rule.get("names") == ["mount"]
            and rule.get("args", [{}])[0].get("op") == "SCMP_CMP_MASKED_EQ"
        ]
        self.assertEqual(remounts, [RO_REMOUNT, JOB_REMOUNT])
        self.assertEqual(ALLOWED_REMOUNT_FLAGS, 0x209C2F)
        self.assertEqual(REMOUNT_MASK, 0xFFFFFFFFFFDFF3F7)
        self.assertEqual(REMOUNT_MASK & OPTIONAL_REMOUNT_FLAGS, 0)
        self.assertEqual(REMOUNT_MASK | OPTIONAL_REMOUNT_FLAGS, (1 << 64) - 1)
        for rule, mandatory in ((RO_REMOUNT, MANDATORY_RO_REMOUNT), (JOB_REMOUNT, MANDATORY_JOB_REMOUNT)):
            self.assertEqual(len(rule["args"]), 1)
            self.assertEqual(rule["args"][0]["index"], 3)
            self.assertEqual(rule["args"][0]["value"], REMOUNT_MASK)
            self.assertEqual(rule["args"][0]["valueTwo"], mandatory)
            for subset in range(1 << 4):
                optional = sum(flag for bit, flag in enumerate((0x8, 0x400, 0x800, 0x200000)) if subset & (1 << bit))
                self.assertEqual((mandatory | optional) & REMOUNT_MASK, mandatory)
            for bit in (0x4000, 0x10000, 0x100000, 0x80000000):
                self.assertNotEqual((mandatory | bit) & REMOUNT_MASK, mandatory)
            for bit in (1, 2, 4, 0x20, 0x1000):
                self.assertNotEqual((mandatory ^ bit) & REMOUNT_MASK, mandatory)
        self.assertEqual(EXTRA_RULES[7]["args"][0]["value"], SELF_BIND_FLAGS)

    def test_seccomp_candidate_has_no_duplicate_argument_indexes(self) -> None:
        for rule in self.seccomp.get("syscalls", []):
            indexes = [argument["index"] for argument in rule.get("args", [])]
            self.assertEqual(len(indexes), len(set(indexes)), rule)

    def test_seccomp_allows_only_the_required_second_userns_unshare(self) -> None:
        added = self.seccomp.get("syscalls", [])[-len(EXTRA_RULES) :]
        unshare = [rule for rule in added if rule.get("names") == ["unshare"]]
        self.assertEqual(
            unshare,
            [
                {
                    "names": ["unshare"],
                    "action": "SCMP_ACT_ALLOW",
                    "args": [{"index": 0, "value": SECOND_USERNS_FLAGS, "op": "SCMP_CMP_EQ"}],
                    "includes": AMD64,
                }
            ],
        )
        self.assertNotIn("setns", {name for rule in added for name in rule.get("names", [])})

    def test_apparmor_retains_pinned_moby_default_inventory(self) -> None:
        self.assertIn("abi <abi/3.0>,", self.apparmor)
        self.assertRegex(self.apparmor, re.compile(r'^profile "jev-audit-bwrap" flags=\(attach_disconnected,mediate_deleted\) \{', re.MULTILINE))
        for line in (
            "  network,",
            "  deny network alg,",
            "  deny network vsock,",
            "  capability,",
            "  file,",
            "  signal (receive) peer=unconfined,",
            "  signal (receive) peer=runc,",
            "  signal (receive) peer=crun,",
            '  signal (receive) peer="unconfined",',
            '  signal (send,receive) peer="jev-audit-bwrap",',
            "  deny @{PROC}/* w,",
            "  deny @{PROC}/{[^1-9/],[^1-9/][^0-9/],[^1-9s/][^0-9y/][^0-9s/],[^1-9/][^0-9/][^0-9/][^0-9/]*}/** w,",
            "  deny @{PROC}/sys/[^k]** w,",
            "  deny @{PROC}/sys/kernel/{?,??,[^s][^h][^m]**} w,",
            "  deny @{PROC}/sysrq-trigger rwklx,",
            "  deny @{PROC}/kcore rwklx,",
            "  deny /sys/[^f]*/** wklx,",
            "  deny /sys/f[^s]*/** wklx,",
            "  deny /sys/fs/[^c]*/** wklx,",
            "  deny /sys/fs/c[^g]*/** wklx,",
            "  deny /sys/fs/cg[^r]*/** wklx,",
            "  deny /sys/firmware/** rwklx,",
            "  deny /sys/devices/virtual/powercap/** rwklx,",
            "  deny /sys/kernel/security/** rwklx,",
            '  ptrace (trace,tracedby,read,readby) peer="jev-audit-bwrap",',
        ):
            self.assertIn(line, self.apparmor, line)
        self.assertNotIn("  network alg,", self.apparmor)
        self.assertNotIn("  network vsock,", self.apparmor)

    def test_apparmor_mounts_are_fixed_and_umount_pivots_are_bounded(self) -> None:
        self.assertNotIn("  deny mount,", self.apparmor)
        self.assertNotRegex(self.apparmor, re.compile(r"^\s*umount,\s*$", re.MULTILINE))
        self.assertNotIn("/** -> /**", self.apparmor)
        self.assertNotIn("/data/**", self.apparmor)
        self.assertNotIn("/proc/self/fd", self.apparmor)
        self.assertNotIn("????????", self.apparmor)
        self.assertNotIn("CAP_SYS_ADMIN", self.apparmor)
        self.assertNotIn("options=(rbind,silent)", self.apparmor)
        job = "/oldroot/data/jobs/" + "[0-9a-f]" * 32 + "/ -> /newroot/job/,"
        self.assertIn(job, self.apparmor)
        self.assertIn("mount options=(rbind) /tmp/newroot/ -> /tmp/newroot/,", self.apparmor)
        self.assertIn("mount options=(rprivate,silent) -> /oldroot/,", self.apparmor)
        self.assertIn("mount options=(rbind) /oldroot/data/jobs/", self.apparmor)
        self.assertIn("remount options=(bind,remount,nosuid,nodev,silent) options in (noexec,noatime,nodiratime,relatime) /newroot/job/", self.apparmor)
        for path in ("sys", "irq", "bus"):
            self.assertIn(f"mount options=(rbind) /newroot/proc/{path}/ -> /newroot/proc/{path}/,", self.apparmor)
        self.assertIn("mount options=(rbind) /newroot/proc/sysrq-trigger -> /newroot/proc/sysrq-trigger,", self.apparmor)
        self.assertIn("/oldroot/usr/local/ -> /newroot/usr/local/", self.apparmor)
        self.assertIn("/newroot/usr/local/", self.apparmor)
        self.assertIn("pivot_root oldroot=/tmp/oldroot/ /tmp/,", self.apparmor)
        self.assertIn("pivot_root oldroot=/newroot/ /newroot/,", self.apparmor)
        self.assertIn("umount /oldroot/,", self.apparmor)
        self.assertIn("umount /,", self.apparmor)
        for target in ("/newroot/proc/", "/newroot/dev/", "/newroot/tmp/", "/newroot/dev/pts/"):
            self.assertIn(target, self.apparmor)
        for source in ("/oldroot/usr/bin/", "/oldroot/usr/lib/", "/oldroot/app/jevseo/"):
            self.assertIn(source, self.apparmor)

    def test_policy_manifest_maps_verified_sources_and_fixed_argv(self) -> None:
        for token in (
            "https://raw.githubusercontent.com/moby/profiles/61eaf32614c7/apparmor/template.go",
            "https://raw.githubusercontent.com/containers/bubblewrap/v0.8.0/bubblewrap.c",
            "Add-bind-fd-and-ro-bind-fd-to-let-you-bind-a-O_PATH-fd.patch",
            "bubblewrap.c:3052-3056",
            "bubblewrap.c:3143-3145",
            "bubblewrap.c:3147",
            "bubblewrap.c:3156-3172",
            "bubblewrap.c:1515-1555",
            "bubblewrap.c:1270-1285",
            "bind-mount.c:377-488",
            "root recursive slave",
            "read-only bind remount",
            "O_PATH",
            "--unshare-user",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "CLONE_NEWUSER",
            "0xc0edd000",
            "0x10000000",
            "/oldroot/usr/local/",
            "target-kernel",
            "sha256:654baccf4ddb0518ff84ca1b3a9d4243ea197058d198a4854c8daf6c0dbc15b6",
        ):
            self.assertIn(token, self.doc, token)
        self.assertNotIn("moby/moby/61eaf32614c7/profiles/apparmor/template.go", self.doc)
        self.assertNotIn("--unshare-net", self.doc)
        self.assertNotIn("--unshare-cgroup", self.doc)
        self.assertNotIn("Path.resolve() canonicalizes sources", self.doc)


if __name__ == "__main__":
    unittest.main()
