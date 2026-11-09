"""Focused semantic tests for the offline sandbox-acceptance orchestrator."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "docker" / "run_sandbox_acceptance.py"
SPEC = importlib.util.spec_from_file_location("sandbox_orchestration", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


BOOT = "0123456789abcdef0123456789abcdef"
SECCOMP = {"defaultAction": "SCMP_ACT_ERRNO", "syscalls": []}


def worker_output() -> dict:
    return {
        "ok": True,
        "worker": {
            "uid": 10001, "gid": 10001, "euid": 10001, "egid": 10001,
            "caps_eff": "0000000000000000", "caps_bnd": "0000000000000000",
            "no_new_privs": 1, "apparmor": "jev-audit-bwrap (enforce)",
            "namespace_ids": {name: f"{name}:[1]" for name in ("mnt", "user", "pid", "ipc", "uts", "net", "cgroup")},
            "assertions": {name: True for name in ("job_writable", "runtime_ro", "app_ro", "hidden_data", "hidden_env", "provider_fake")},
        },
        "artifacts": {name: {"size": 10, "sha256": "a" * 64} for name in ("pdf", "xlsx", "md")},
    }


def negative_output() -> dict:
    return {
        "denied_candidate": True,
        "audit_corroboration_required": True,
        "policy_proof": False,
        "expected_remount_target": "/usr/share/fonts",
        "source_options": ["relatime", "rw"],
        "missing_source_flags": ["nodev", "nosuid"],
        "child_pid": 7,
        "returncode": 1,
        "timed_out": False,
        "stderr_nonempty": True,
        "stderr_bytes": 4,
    }


def audit_event() -> dict:
    return {
        "serial": "99", "host_pid": 4321, "profile": MODULE.PROFILE_NAME,
        "comm": "bwrap", "operation": "mount", "target": "/newroot/usr/share/fonts",
        "flags": ["bind", "nodev", "nosuid", "relatime", "remount", "rw", "silent"],
    }


def audit_window(phase: str, event: dict | None = None) -> dict:
    return {"phase": phase, "boot": BOOT, "start_cursor": "s", "end_cursor": "e", "events": [] if event is None else [event]}


def inspect_fixture(run_root: Path, run_name: str, role: str) -> dict:
    helper = MODULE.WORKER_FILE if role == "positive" else MODULE.NEGATIVE_FILE
    bind_source = run_root / MODULE.DATA_DIR if role == "positive" else run_root / MODULE.FONTS_DIR
    destination = "/data" if role == "positive" else "/usr/share/fonts"
    return {
        "Image": MODULE.APP_IMAGE_ID,
        "Config": {
            "User": "10001:10001", "Tty": False, "OpenStdin": False,
            "Cmd": ["python", f"/app/{helper}"],
            "Env": [f"{name}={value}" for name, value in MODULE.STATIC_ENV.items()],
            "Labels": MODULE.required_labels(run_name),
        },
        "HostConfig": {
            "ReadonlyRootfs": True, "NetworkMode": "none", "CapDrop": ["ALL"], "CapAdd": [], "Devices": [],
            "SecurityOpt": ["no-new-privileges", f"apparmor={MODULE.PROFILE_NAME}", f"seccomp={json.dumps(SECCOMP, separators=(',', ':'))}"],
            "Privileged": False, "PidMode": "", "IpcMode": "", "UsernsMode": "", "CgroupnsMode": "private",
            "PortBindings": {}, "Memory": 1073741824, "NanoCpus": 1000000000, "PidsLimit": 256,
            "LogConfig": {"Type": "json-file", "Config": {"max-size": "1m", "max-file": "1", "compress": "false"}},
            "Tmpfs": {"/tmp": "rw,nosuid,nodev,noexec,size=128m"},
        },
        "NetworkSettings": {"Ports": {}},
        "Mounts": [
            {"Type": "bind", "Source": str(bind_source), "Destination": destination, "RW": True},
            {"Type": "bind", "Source": str(run_root / helper), "Destination": f"/app/{helper}", "RW": False},
        ],
    }


def inspect_stdout(data: dict) -> str:
    config = data["Config"]
    host = data["HostConfig"]
    fields = [
        data["Image"], config["User"], str(config["Tty"]).lower(), str(config["OpenStdin"]).lower(),
        json.dumps(config["Cmd"], separators=(",", ":")), json.dumps(config["Env"], separators=(",", ":")),
        json.dumps(config["Labels"], separators=(",", ":")), str(host["ReadonlyRootfs"]).lower(), host["NetworkMode"],
        json.dumps(host["CapDrop"], separators=(",", ":")), json.dumps(host["CapAdd"], separators=(",", ":")),
        json.dumps(host["Devices"], separators=(",", ":")), json.dumps(host["SecurityOpt"], separators=(",", ":")),
        str(host["Privileged"]).lower(), host["PidMode"], host["IpcMode"], host["UsernsMode"], host["CgroupnsMode"],
        json.dumps(host["PortBindings"], separators=(",", ":")), str(host["Memory"]), str(host["NanoCpus"]), str(host["PidsLimit"]),
        json.dumps(host["LogConfig"], separators=(",", ":")), json.dumps(host["Tmpfs"], separators=(",", ":")),
        json.dumps(data["NetworkSettings"]["Ports"], separators=(",", ":")), json.dumps(data["Mounts"], separators=(",", ":")),
    ]
    return "\t".join(fields)


class SandboxOrchestrationTests(unittest.TestCase):
    def test_run_root_requires_canonical_non_symlink_staging_child(self):
        with tempfile.TemporaryDirectory() as temp:
            staging = Path(temp) / "staging"
            staging.mkdir()
            run = staging / "run-unique"
            run.mkdir(mode=0o700)
            marker = run / MODULE.MARKER_NAME
            marker.write_text(MODULE.marker_text(run.name), encoding="ascii")
            marker.chmod(0o600)
            with mock.patch.object(MODULE, "STAGING_ROOT", staging), mock.patch.object(MODULE, "_owner_uid", return_value=0):
                self.assertEqual(MODULE.validate_run_root(run), run)
            with self.assertRaises(MODULE.OrchestrationError):
                MODULE.validate_run_root(staging / "../staging")

    def test_same_profile_complain_state_is_a_collision_not_absence(self):
        with mock.patch.object(MODULE.Path, "read_text", return_value="jev-audit-bwrap (complain)\n"):
            self.assertTrue(MODULE._profile_present())
            self.assertFalse(MODULE._profile_enforced())

    def test_all_fixed_hashes_are_required(self):
        hashes = [MODULE.EXPECTED_PREFLIGHT_SHA256, MODULE.EXPECTED_WORKER_SHA256, MODULE.EXPECTED_APPARMOR_SHA256, MODULE.EXPECTED_SECCOMP_SHA256, MODULE.EXPECTED_NEGATIVE_SHA256]
        with mock.patch.object(MODULE, "_sha256_file", side_effect=hashes):
            result = MODULE.validate_staged_files(Path("/owned/run"))
        self.assertEqual(len(result), 5)
        self.assertEqual(result[MODULE.NEGATIVE_FILE], MODULE.EXPECTED_NEGATIVE_SHA256)

    def test_preflight_has_owned_name_labels_and_correct_app_import_root(self):
        command = MODULE.build_preflight_command(Path("/owned/run"), "run-1")
        self.assertIn("--name", command)
        self.assertIn("run-1-preflight", command)
        self.assertIn("owner=jev-audit", command)
        self.assertIn("/app/acceptance_preflight.py", command)
        self.assertEqual(command[-2:], ["python", "/app/acceptance_preflight.py"])
        self.assertNotIn("--rm", command)

    def test_real_worker_contract_preserves_safe_facts_and_rejects_invented_contract(self):
        evidence = MODULE.validate_harness_output(json.dumps(worker_output()), MODULE._canaries())
        self.assertEqual(evidence["worker"]["uid"], 10001)
        self.assertEqual(set(evidence["artifacts"]), {"pdf", "xlsx", "md"})
        with self.assertRaises(MODULE.OrchestrationError):
            MODULE.validate_harness_output(json.dumps({"ok": True, "worker": worker_output()["worker"], "artifacts": {}}), MODULE._canaries())

    def test_negative_contract_requires_nonzero_child_and_no_timeout(self):
        candidate = MODULE.validate_negative_candidate(negative_output())
        self.assertEqual(candidate["child_pid"], 7)
        bad = negative_output()
        bad["returncode"] = 0
        with self.assertRaises(MODULE.OrchestrationError):
            MODULE.validate_negative_candidate(bad)
        bad = negative_output()
        bad["timed_out"] = True
        with self.assertRaises(MODULE.OrchestrationError):
            MODULE.validate_negative_candidate(bad)

    def test_audit_message_parses_message_pid_flags_and_rejects_drift(self):
        message = 'apparmor="DENIED" operation="mount" profile="jev-audit-bwrap" name="/newroot/usr/share/fonts" pid=4321 comm="bwrap" flags="rw,remount,bind,nosuid,nodev,silent,relatime" audit(1700000000.123:99)'
        event = MODULE._parse_audit_message(message)
        self.assertEqual(event["host_pid"], 4321)
        self.assertEqual(event["serial"], "99")
        bad = message.replace('flags="rw,remount,bind,nosuid,nodev,silent,relatime"', 'requested_mask="rw,remount,bind,nosuid,nodev,silent,relatime"')
        with self.assertRaises(MODULE.OrchestrationError):
            MODULE._parse_audit_message(bad)
        bad = message.replace("relatime", "ro")
        with self.assertRaises(MODULE.OrchestrationError):
            MODULE._parse_audit_message(bad)

    def test_cursor_record_boot_drift_is_inconclusive(self):
        result = MODULE.CommandResult(0, json.dumps({"_BOOT_ID": "other", "__CURSOR": "e"}) + "\n-- cursor: e\n", "")
        with mock.patch.object(MODULE, "run_command", return_value=result):
            with self.assertRaises(MODULE.OrchestrationError) as error:
                MODULE._journal_records({"boot": BOOT, "cursor": "s"}, {"boot": BOOT, "cursor": "e"})
        self.assertEqual(error.exception.code, "kernel_boot_drift")

    def test_rate_limit_metadata_is_a_hard_failure(self):
        with self.assertRaises(MODULE.OrchestrationError) as error:
            MODULE._journal_loss([{"MESSAGE": "audit messages dropped"}])
        self.assertEqual(error.exception.code, "kernel_audit_loss")
        MODULE._journal_loss([{"MESSAGE": "ordinary network rate update"}])

    def test_boundary_requires_lowercase_32_hex_boot_and_exact_cursor_footer(self):
        good = MODULE.CommandResult(0, json.dumps({"_BOOT_ID": BOOT, "__CURSOR": "cursor"}) + "\n-- cursor: cursor\n", "")
        with mock.patch.object(MODULE, "run_command", return_value=good):
            self.assertEqual(MODULE._journal_boundary(), {"boot": BOOT, "cursor": "cursor"})
        trailing = MODULE.CommandResult(0, json.dumps({"_BOOT_ID": BOOT, "__CURSOR": "cursor"}) + "\n-- cursor: cursor --\n", "")
        with mock.patch.object(MODULE, "run_command", return_value=trailing):
            with self.assertRaises(MODULE.OrchestrationError):
                MODULE._journal_boundary()
        empty = MODULE.CommandResult(0, "-- cursor: cursor\n", "")
        with mock.patch.object(MODULE, "run_command", return_value=empty), mock.patch.object(MODULE.Path, "read_text", return_value="invalid-boot-id"):
            with self.assertRaises(MODULE.OrchestrationError):
                MODULE._journal_boundary()

    def test_equal_cursors_short_circuit_without_journal_read(self):
        with mock.patch.object(MODULE, "run_command") as command:
            self.assertEqual(MODULE._journal_records({"boot": BOOT, "cursor": "same"}, {"boot": BOOT, "cursor": "same"}), [])
        command.assert_not_called()

    def test_forward_cursor_query_requires_end_footer_and_rejects_overflow(self):
        record = {"_BOOT_ID": BOOT, "__CURSOR": "e", "MESSAGE": "ordinary kernel message"}
        good = MODULE.CommandResult(0, json.dumps(record) + "\n-- cursor: e\n", "")
        with mock.patch.object(MODULE, "run_command", return_value=good) as command:
            self.assertEqual(len(MODULE._journal_records({"boot": BOOT, "cursor": "s"}, {"boot": BOOT, "cursor": "e"})), 1)
        self.assertIn("--after-cursor=s", command.call_args.args[0])
        self.assertNotIn("--reverse", command.call_args.args[0])
        self.assertFalse(any(str(item).startswith("--grep=") for item in command.call_args.args[0]))
        missing = MODULE.CommandResult(0, json.dumps(record) + "\n-- cursor: other\n", "")
        with mock.patch.object(MODULE, "run_command", return_value=missing):
            with self.assertRaises(MODULE.OrchestrationError):
                MODULE._journal_records({"boot": BOOT, "cursor": "s"}, {"boot": BOOT, "cursor": "e"})
        overflow = "\n".join(json.dumps({"_BOOT_ID": BOOT, "__CURSOR": f"c{i}", "MESSAGE": "x"}) for i in range(51)) + "\n-- cursor: e\n"
        with mock.patch.object(MODULE, "run_command", return_value=MODULE.CommandResult(0, overflow, "")):
            with self.assertRaises(MODULE.OrchestrationError):
                MODULE._journal_records({"boot": BOOT, "cursor": "s"}, {"boot": BOOT, "cursor": "e"})

    def test_phase_loss_uses_same_records_without_second_journal_query(self):
        record = {"_BOOT_ID": BOOT, "__CURSOR": "e", "MESSAGE": "audit_lost=2"}
        result = MODULE.CommandResult(0, json.dumps(record) + "\n-- cursor: e\n", "")
        with mock.patch.object(MODULE, "run_command", return_value=result) as command:
            with self.assertRaises(MODULE.OrchestrationError) as error:
                MODULE._phase_audit({"boot": BOOT, "cursor": "s"}, {"boot": BOOT, "cursor": "e"}, "negative")
        self.assertEqual(error.exception.code, "kernel_audit_loss")
        self.assertEqual(command.call_count, 1)

    def test_negative_audit_requires_exact_single_event_and_does_not_use_child_pid(self):
        evidence = MODULE.require_negative_corroboration(negative_output(), audit_window("negative", audit_event()))
        self.assertEqual(evidence["audit"]["events"][0]["host_pid"], 4321)
        drift = audit_window("negative", dict(audit_event(), flags=["bind", "nodev", "nosuid", "remount", "rw", "silent"]))
        with self.assertRaises(MODULE.OrchestrationError):
            MODULE.require_negative_corroboration(negative_output(), drift)
        bad_candidate = negative_output()
        bad_candidate["missing_source_flags"] = ["remount"]
        with self.assertRaises(MODULE.OrchestrationError):
            MODULE.require_negative_corroboration(bad_candidate, audit_window("negative", audit_event()))
        bad = audit_window("negative", audit_event())
        bad["events"].append(dict(audit_event(), serial="100"))
        with self.assertRaises(MODULE.OrchestrationError):
            MODULE.require_negative_corroboration(negative_output(), bad)

    def test_container_fixture_requires_exact_numeric_security_and_mount_manifest(self):
        root = Path("/opt/jev-audit-staging/run-1")
        with mock.patch.object(MODULE, "_load_seccomp_policy", return_value=SECCOMP):
            self.assertTrue(MODULE.validate_container_inspect(inspect_fixture(root, "run-1", "positive"), "run-1", "positive", root))
        bad = inspect_fixture(root, "run-1", "positive")
        bad["HostConfig"]["CapAdd"] = ["SYS_ADMIN"]
        with mock.patch.object(MODULE, "_load_seccomp_policy", return_value=SECCOMP):
            with self.assertRaises(MODULE.OrchestrationError):
                MODULE.validate_container_inspect(bad, "run-1", "positive", root)

    def test_container_security_options_are_exact_and_seccomp_is_compact_semantic_json(self):
        root = Path("/opt/jev-audit-staging/run-1")
        fixture = inspect_fixture(root, "run-1", "positive")
        with mock.patch.object(MODULE, "_load_seccomp_policy", return_value=SECCOMP):
            MODULE.validate_container_inspect(fixture, "run-1", "positive", root)
            fixture["HostConfig"]["SecurityOpt"].append("no-new-privileges")
            with self.assertRaises(MODULE.OrchestrationError):
                MODULE.validate_container_inspect(fixture, "run-1", "positive", root)
        fixture = inspect_fixture(root, "run-1", "positive")
        fixture["HostConfig"]["SecurityOpt"].append(f"seccomp={json.dumps(SECCOMP, separators=(',', ':'))}")
        with mock.patch.object(MODULE, "_load_seccomp_policy", return_value=SECCOMP):
            with self.assertRaises(MODULE.OrchestrationError):
                MODULE.validate_container_inspect(fixture, "run-1", "positive", root)
        fixture = inspect_fixture(root, "run-1", "positive")
        fixture["HostConfig"]["SecurityOpt"][2] = 'seccomp={"syscalls":[],"defaultAction":"SCMP_ACT_ERRNO"}'
        with mock.patch.object(MODULE, "_load_seccomp_policy", return_value=SECCOMP):
            self.assertTrue(MODULE.validate_container_inspect(fixture, "run-1", "positive", root))
        fixture = inspect_fixture(root, "run-1", "positive")
        fixture["Mounts"].append({"Type": "tmpfs", "Destination": "/tmp", "RW": True})
        with mock.patch.object(MODULE, "_load_seccomp_policy", return_value=SECCOMP):
            with self.assertRaises(MODULE.OrchestrationError):
                MODULE.validate_container_inspect(fixture, "run-1", "positive", root)

    def test_command_plan_has_network_none_no_ports_and_negative_font_bind(self):
        with mock.patch.object(MODULE, "_load_seccomp_policy", return_value=SECCOMP):
            positive, negative = MODULE.build_container_commands(Path("/opt/jev-audit-staging/run-1"), "run-1", MODULE._canaries())
        self.assertIn("none", positive)
        self.assertNotIn("--publish", positive)
        self.assertIn("dst=/usr/share/fonts", " ".join(negative))
        self.assertIn("compress=false", positive)
        seccomp = next(item for item in positive if item.startswith("seccomp="))
        self.assertEqual(seccomp, "seccomp=/opt/jev-audit-staging/run-1/jev-bwrap-seccomp.json")

    def test_successful_real_contract_transaction_is_sequential_and_unloads_owned_profile(self):
        root = Path("/opt/jev-audit-staging/run-1")
        calls: list[tuple[str, str]] = []
        boundaries = iter([{"boot": BOOT, "cursor": "p0"}, {"boot": BOOT, "cursor": "p1"}, {"boot": BOOT, "cursor": "n0"}, {"boot": BOOT, "cursor": "n1"}])

        def command(argv, **_kwargs):
            if argv[:3] == ["docker", "ps", "-a"]:
                return MODULE.CommandResult(0, "", "")
            if argv[:2] == ["apparmor_parser", "-a"]:
                calls.append(("load", "profile"))
                return MODULE.CommandResult(0, "", "")
            if argv[:2] == ["docker", "create"]:
                name = argv[argv.index("--name") + 1]
                calls.append(("create", name))
                return MODULE.CommandResult(0, name, "")
            if argv[:2] == ["docker", "inspect"]:
                name = argv[-1]
                role = "positive" if name.endswith("positive") else "negative"
                return MODULE.CommandResult(0, inspect_stdout(inspect_fixture(root, "run-1", role)), "")
            if argv[:3] == ["docker", "start", "-a"]:
                name = argv[3]
                calls.append(("start", name))
                return MODULE.CommandResult(0, json.dumps(worker_output() if name.endswith("positive") else negative_output()), "")
            if argv[:3] == ["docker", "rm", "-f"]:
                calls.append(("remove", argv[3]))
                return MODULE.CommandResult(0, "", "")
            if argv and argv[0] == "journalctl" and "--after-cursor=p0" in argv:
                record = {"_BOOT_ID": BOOT, "__CURSOR": "p1", "MESSAGE": "ordinary kernel message"}
                return MODULE.CommandResult(0, json.dumps(record) + "\n-- cursor: p1\n", "")
            if argv and argv[0] == "journalctl" and "--after-cursor=n0" in argv:
                message = 'apparmor="DENIED" operation="mount" profile="jev-audit-bwrap" name="/newroot/usr/share/fonts" pid=4321 comm="bwrap" flags="rw,remount,bind,nosuid,nodev,silent,relatime" audit(1700000000.123:99)'
                record = {"_BOOT_ID": BOOT, "__CURSOR": "n1", "MESSAGE": message}
                return MODULE.CommandResult(0, json.dumps(record) + "\n-- cursor: n1\n", "")
            return MODULE.CommandResult(0, "", "")

        with mock.patch.object(MODULE, "validate_run_root", return_value=root), mock.patch.object(MODULE, "validate_staged_files"), mock.patch.object(MODULE, "validate_host", return_value={}), mock.patch.object(MODULE, "validate_image", return_value={}), mock.patch.object(MODULE, "run_image_preflight", return_value={"ok": True}), mock.patch.object(MODULE, "_make_owned_dir"), mock.patch.object(MODULE, "_profile_present", return_value=False), mock.patch.object(MODULE, "_profile_enforced", return_value=True), mock.patch.object(MODULE, "_cleanup_profile", side_effect=lambda *_: calls.append(("unload", "profile"))), mock.patch.object(MODULE, "_journal_boundary", side_effect=lambda: next(boundaries)), mock.patch.object(MODULE, "_load_seccomp_policy", return_value=SECCOMP), mock.patch.object(MODULE, "run_command", side_effect=command):
            result = MODULE.run_acceptance(root)
        self.assertTrue(result["ok"])
        self.assertLess(calls.index(("remove", "run-1-positive")), calls.index(("create", "run-1-negative")))
        self.assertEqual(calls.count(("load", "profile")), 1)
        self.assertEqual(calls.count(("unload", "profile")), 1)

    def test_positive_failure_does_not_create_or_start_negative(self):
        root = Path("/opt/jev-audit-staging/run-1")
        calls: list[list[str]] = []

        def command(argv, **_kwargs):
            calls.append(argv)
            if argv[:2] == ["apparmor_parser", "-a"] or argv[:3] == ["docker", "ps", "-a"]:
                return MODULE.CommandResult(0, "", "")
            if argv[:2] == ["docker", "create"]:
                return MODULE.CommandResult(0, "", "")
            if argv[:3] == ["docker", "start", "-a"]:
                return MODULE.CommandResult(1, "", "")
            return MODULE.CommandResult(0, "", "")

        with mock.patch.object(MODULE, "validate_run_root", return_value=root), mock.patch.object(MODULE, "validate_staged_files"), mock.patch.object(MODULE, "validate_host", return_value={}), mock.patch.object(MODULE, "validate_image", return_value={}), mock.patch.object(MODULE, "run_image_preflight", return_value={"ok": True}), mock.patch.object(MODULE, "_make_owned_dir"), mock.patch.object(MODULE, "_profile_present", return_value=False), mock.patch.object(MODULE, "_profile_enforced", return_value=True), mock.patch.object(MODULE, "_cleanup_profile"), mock.patch.object(MODULE, "_journal_boundary", return_value={"boot": BOOT, "cursor": "x"}), mock.patch.object(MODULE, "_load_seccomp_policy", return_value=SECCOMP), mock.patch.object(MODULE, "_inspect"), mock.patch.object(MODULE, "_cleanup_container"), mock.patch.object(MODULE, "run_command", side_effect=command):
            with self.assertRaises(MODULE.OrchestrationError):
                MODULE.run_acceptance(root)
        self.assertFalse(any(argv[:3] == ["docker", "start", "-a"] and argv[3].endswith("negative") for argv in calls))

    def test_nonzero_profile_load_still_calls_cleanup_once_and_preserves_error(self):
        root = Path("/opt/jev-audit-staging/run-1")
        calls: list[list[str]] = []

        def command(argv, **_kwargs):
            calls.append(argv)
            if argv[:3] == ["docker", "ps", "-a"]:
                return MODULE.CommandResult(0, "", "")
            if argv[:2] == ["apparmor_parser", "-a"]:
                return MODULE.CommandResult(1, "", "load failed")
            return MODULE.CommandResult(0, "", "")

        with mock.patch.object(MODULE, "validate_run_root", return_value=root), mock.patch.object(MODULE, "validate_staged_files"), mock.patch.object(MODULE, "validate_host", return_value={}), mock.patch.object(MODULE, "validate_image", return_value={}), mock.patch.object(MODULE, "run_image_preflight", return_value={"ok": True}), mock.patch.object(MODULE, "_make_owned_dir"), mock.patch.object(MODULE, "_profile_present", return_value=False), mock.patch.object(MODULE, "_cleanup_profile") as cleanup, mock.patch.object(MODULE, "run_command", side_effect=command):
            with self.assertRaises(MODULE.OrchestrationError) as error:
                MODULE.run_acceptance(root)
        self.assertEqual(error.exception.code, "profile_load_failed")
        self.assertEqual(cleanup.call_count, 1)
        self.assertEqual(sum(argv[:2] == ["apparmor_parser", "-a"] for argv in calls), 1)

    def test_profile_load_timeout_still_calls_cleanup_once_without_retry(self):
        root = Path("/opt/jev-audit-staging/run-1")
        calls: list[list[str]] = []

        def command(argv, **_kwargs):
            calls.append(argv)
            if argv[:3] == ["docker", "ps", "-a"]:
                return MODULE.CommandResult(0, "", "")
            if argv[:2] == ["apparmor_parser", "-a"]:
                raise MODULE.OrchestrationError("command_timeout")
            return MODULE.CommandResult(0, "", "")

        with mock.patch.object(MODULE, "validate_run_root", return_value=root), mock.patch.object(MODULE, "validate_staged_files"), mock.patch.object(MODULE, "validate_host", return_value={}), mock.patch.object(MODULE, "validate_image", return_value={}), mock.patch.object(MODULE, "run_image_preflight", return_value={"ok": True}), mock.patch.object(MODULE, "_make_owned_dir"), mock.patch.object(MODULE, "_profile_present", return_value=False), mock.patch.object(MODULE, "_cleanup_profile") as cleanup, mock.patch.object(MODULE, "run_command", side_effect=command):
            with self.assertRaises(MODULE.OrchestrationError) as error:
                MODULE.run_acceptance(root)
        self.assertEqual(error.exception.code, "command_timeout")
        self.assertEqual(cleanup.call_count, 1)
        self.assertEqual(sum(argv[:2] == ["apparmor_parser", "-a"] for argv in calls), 1)

    def test_summary_is_bounded_and_has_only_sanitized_cleanup_warning(self):
        stream = io.StringIO()
        error = MODULE.OrchestrationError("positive_worker_failed")
        error.warnings.append("container_cleanup_uncertain")
        with contextlib.redirect_stdout(stream):
            MODULE.emit_summary({"ok": False, "error": error.code, "cleanup_warnings": error.warnings})
        output = stream.getvalue()
        self.assertLessEqual(len(output.encode()), MODULE.MAX_OUTPUT_BYTES)
        self.assertNotIn("docker create", output)

    def test_cleanup_preflight_rejects_unowned_container(self):
        result = MODULE.CommandResult(0, MODULE.APP_IMAGE_ID + "\t" + json.dumps({"owner": "other"}) + "\n", "")
        with mock.patch.object(MODULE, "run_command", return_value=result):
            with self.assertRaises(MODULE.OrchestrationError) as error:
                MODULE._cleanup_preflight("run-1-preflight", "run-1")
        self.assertEqual(error.exception.code, "preflight_cleanup_ownership")


if __name__ == "__main__":
    unittest.main()
