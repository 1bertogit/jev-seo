"""Focused semantic tests for the read-only image inventory preflight."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import stat
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "docker" / "acceptance_preflight.py"
SPEC = importlib.util.spec_from_file_location("acceptance_preflight", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def mount_line(number: int, mountpoint: str, options: str = "rw,nosuid") -> str:
    return f"{number} 1 0:1 / {mountpoint} {options} - tmpfs tmpfs {options}\n"


def complete_argv(python: str = "/usr/local/bin/python") -> list[str]:
    job = MODULE.SYNTHETIC_JOB_DIR
    argv = [
        "bwrap", "--die-with-parent", "--new-session", "--unshare-user", "--unshare-pid",
        "--unshare-ipc", "--unshare-uts", "--cap-drop", "ALL", "--proc", "/proc",
        "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/etc", "--dir", "/etc/fonts",
        "--dir", "/etc/ssl", "--dir", "/runtime", "--dir", "/job", "--bind", job, "/job",
    ]
    for source, (_, target, _optional) in MODULE.EXPECTED_BINDINGS.items():
        argv.extend(["--ro-bind", source, target])
    for name in sorted(MODULE.EXPECTED_ENV_NAMES):
        argv.extend(["--setenv", name, "sentinel-" + name])
    argv.extend(["--chdir", "/job", "--", python, "-m", "jevseo", "render", "/job", "--formats", "pdf"])
    return argv


def linux_canonical(value: str) -> str:
    if value == MODULE.SYNTHETIC_JOB_DIR:
        return value
    return MODULE.EXPECTED_BINDINGS.get(value, (value, "", False))[0]


def fixture_path_type(value: str) -> tuple[bool, str]:
    return (False, "missing") if value == MODULE.SYNTHETIC_JOB_DIR else (True, "directory")


class AcceptancePreflightTests(unittest.TestCase):
    def test_mountinfo_decodes_standard_escapes_and_rejects_bad_escape(self):
        self.assertEqual(
            MODULE._decode_mount_token(r"/dev/a\040b\011c\012d\134e"),
            "/dev/a b\tc\nd\\e",
        )
        with self.assertRaises(MODULE.PreflightError):
            MODULE._decode_mount_token(r"/dev/bad\08")
        with self.assertRaises(MODULE.PreflightError):
            MODULE._decode_mount_token("/dev/trailing\\")

    def test_mountinfo_rejects_malformed_duplicate_and_oversize_input(self):
        with self.assertRaises(MODULE.PreflightError):
            MODULE._parse_mountinfo("1 1 0:1 / /dev rw\n")
        duplicate = mount_line(1, "/dev") + mount_line(1, "/dev/pts")
        with self.assertRaises(MODULE.PreflightError):
            MODULE._parse_mountinfo(duplicate)
        overlimit = "".join(mount_line(index, f"/x{index}") for index in range(MODULE.MAX_MOUNT_RECORDS + 1))
        with self.assertRaises(MODULE.PreflightError):
            MODULE._parse_mountinfo(overlimit)

    def test_mount_inventory_checks_dev_flags_nodes_and_descendants(self):
        records = MODULE._parse_mountinfo(
            mount_line(1, "/dev")
            + mount_line(2, "/dev/mqueue")
            + mount_line(3, "/dev/pts")
            + mount_line(4, "/dev/shm")
            + mount_line(5, "/etc/hosts")
            + mount_line(6, "/usr/local/bin")
        )
        with mock.patch.object(MODULE, "_validate_dev_nodes", return_value=list(MODULE.EXPECTED_DEV_NODES)):
            result = MODULE._validate_mount_inventory(records, MODULE.EXPECTED_CANONICAL_SOURCES, MODULE.SYNTHETIC_JOB_DIR)
        self.assertEqual(result["dev_descendants"], ["/dev/mqueue", "/dev/pts", "/dev/shm"])
        self.assertIn("/etc/hosts", result["file_mounts"])
        bad_dev_flags = MODULE._parse_mountinfo(mount_line(1, "/dev", "ro,nosuid"))
        with self.assertRaises(MODULE.PreflightError):
            MODULE._validate_mount_inventory(bad_dev_flags, set(), MODULE.SYNTHETIC_JOB_DIR)
        bad_runtime = MODULE._parse_mountinfo(mount_line(1, "/dev") + mount_line(2, "/app/jevseo/private"))
        with mock.patch.object(MODULE, "_validate_dev_nodes", return_value=list(MODULE.EXPECTED_DEV_NODES)):
            with self.assertRaises(MODULE.PreflightError):
                MODULE._validate_mount_inventory(bad_runtime, MODULE.EXPECTED_CANONICAL_SOURCES, MODULE.SYNTHETIC_JOB_DIR)
        bad_job = MODULE._parse_mountinfo(mount_line(1, "/dev") + mount_line(2, MODULE.SYNTHETIC_JOB_DIR + "/nested"))
        with mock.patch.object(MODULE, "_validate_dev_nodes", return_value=list(MODULE.EXPECTED_DEV_NODES)):
            with self.assertRaises(MODULE.PreflightError):
                MODULE._validate_mount_inventory(bad_job, MODULE.EXPECTED_CANONICAL_SOURCES, MODULE.SYNTHETIC_JOB_DIR)

    def test_dev_nodes_are_char_devices_on_dev_mount_without_tty(self):
        dev = MODULE.MountRecord(1, "/", "/dev", ("nosuid", "rw"), "tmpfs")
        char_device = mock.Mock(st_mode=stat.S_IFCHR)
        with mock.patch.object(MODULE.os, "stat", return_value=char_device), \
             mock.patch.object(MODULE.os.path, "realpath", side_effect=lambda value: value), \
             mock.patch.object(MODULE.Path, "exists", return_value=False), \
             mock.patch.object(MODULE.os, "isatty", return_value=False):
            self.assertEqual(MODULE._validate_dev_nodes([dev], dev), list(MODULE.EXPECTED_DEV_NODES))
            with self.assertRaises(MODULE.PreflightError):
                MODULE._validate_dev_nodes([dev, MODULE.MountRecord(2, "/", "/dev/null", ("rw",), "devtmpfs")], dev)

    def test_complete_manifest_and_original_python_command_are_required(self):
        argv = complete_argv()
        with mock.patch.object(MODULE, "_path_type", side_effect=fixture_path_type), \
             mock.patch.object(MODULE, "_canonical", side_effect=linux_canonical):
            manifest = MODULE._extract_manifest(argv, MODULE.SYNTHETIC_JOB_DIR, "/usr/local/bin/python")
        self.assertEqual(len(manifest["bindings"]), len(MODULE.EXPECTED_BINDINGS))
        self.assertEqual(manifest["job_bind"]["target"], "/job")
        self.assertEqual(manifest["command_allowed"], True)
        with self.assertRaises(MODULE.PreflightError):
            MODULE._extract_manifest(argv, MODULE.SYNTHETIC_JOB_DIR, "/usr/local/bin/python3.12")

    def test_manifest_rejects_source_escape_unknown_flag_and_duplicate_entries(self):
        argv = complete_argv()
        source_index = argv.index("/usr")
        bad_source = list(argv)
        bad_source[source_index] = "/home/secret"
        with self.assertRaises(MODULE.PreflightError):
            MODULE._extract_manifest(bad_source, MODULE.SYNTHETIC_JOB_DIR, "/usr/local/bin/python")
        with mock.patch.object(MODULE, "_canonical", side_effect=lambda value: "/escape" if value == "/usr" else linux_canonical(value)):
            with self.assertRaises(MODULE.PreflightError):
                MODULE._extract_manifest(argv, MODULE.SYNTHETIC_JOB_DIR, "/usr/local/bin/python")
        unknown = list(argv)
        unknown.insert(unknown.index("--ro-bind"), "--unknown")
        with self.assertRaises(MODULE.PreflightError):
            MODULE._extract_manifest(unknown, MODULE.SYNTHETIC_JOB_DIR, "/usr/local/bin/python")
        duplicate_target = list(argv)
        env_index = duplicate_target.index("--setenv")
        duplicate_target[env_index:env_index] = ["--ro-bind", "/usr", "/usr"]
        with self.assertRaises(MODULE.PreflightError):
            MODULE._extract_manifest(duplicate_target, MODULE.SYNTHETIC_JOB_DIR, "/usr/local/bin/python")
        duplicate_env = list(argv)
        env_index = duplicate_env.index("--setenv")
        duplicate_env[env_index:env_index] = ["--setenv", "PATH", "sentinel-path"]
        with self.assertRaises(MODULE.PreflightError):
            MODULE._extract_manifest(duplicate_env, MODULE.SYNTHETIC_JOB_DIR, "/usr/local/bin/python")

    def test_fixed_probe_uses_argument_array_and_timeout(self):
        result = mock.Mock(returncode=0, stdout="bubblewrap 0.8.0\n")
        with mock.patch.object(MODULE.subprocess, "run", return_value=result) as run:
            self.assertEqual(MODULE._run_fixed(["bwrap", "--version"]), "bubblewrap 0.8.0\n")
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["bwrap", "--version"])
        self.assertEqual(kwargs["timeout"], 2)
        self.assertFalse(kwargs.get("shell", False))

    def test_real_manifest_output_is_bounded_and_redacted(self):
        argv = complete_argv()
        with mock.patch.object(MODULE, "_path_type", side_effect=fixture_path_type), \
             mock.patch.object(MODULE, "_canonical", side_effect=linux_canonical):
            manifest = MODULE._extract_manifest(argv, MODULE.SYNTHETIC_JOB_DIR, "/usr/local/bin/python")
        payload = {"ok": True, "bindings": manifest["bindings"], "environment_names": manifest["environment_names"]}
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            self.assertEqual(MODULE._emit(payload), 0)
        output = stream.getvalue()
        self.assertLessEqual(len(output.encode()), MODULE.MAX_OUTPUT_BYTES)
        self.assertNotIn("acceptance-secret-sentinel", output)
        self.assertNotIn("proxy-secret-sentinel", output)
        self.assertNotIn("sentinel-", output)


if __name__ == "__main__":
    unittest.main()
