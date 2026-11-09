"""Offline semantic tests for the future controlled remount-denial probe."""

from __future__ import annotations

import subprocess
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest import mock

from docker.check_remount_denial import (
    MAX_STDERR_BYTES,
    TARGET,
    _build_bwrap_argv,
    _parse_mountinfo,
    _run_candidate,
    _source_mount_ready,
    main,
)


MOUNTINFO = "36 25 0:32 / /usr/share/fonts rw,relatime - tmpfs fonts rw"


class RemountDenialHarnessTests(unittest.TestCase):
    def test_mountinfo_is_finite_and_exact_and_requires_missing_safety_flags(self) -> None:
        facts = _parse_mountinfo(MOUNTINFO)
        self.assertEqual(facts["mountpoint"], TARGET)
        self.assertEqual(facts["options"], {"rw", "relatime"})
        self.assertTrue(_source_mount_ready(facts))
        self.assertFalse(_source_mount_ready(_parse_mountinfo("36 25 0:32 / /usr/share/fonts rw,nosuid,nodev - tmpfs fonts rw")))
        with self.assertRaises(ValueError):
            _parse_mountinfo("36 25 0:32 / /other rw - tmpfs fonts rw")

    def test_bwrap_argv_has_only_fixed_runtime_ro_mounts_and_rw_target(self) -> None:
        argv = _build_bwrap_argv(("/usr", "/bin", "/lib", "/lib64"))
        self.assertEqual(argv[-2:], ["--", "/bin/true"])
        self.assertIn("--new-session", argv)
        self.assertEqual(argv.count("--unshare-user"), 1)
        self.assertEqual(argv.count("--unshare-pid"), 1)
        self.assertEqual(argv.count("--unshare-ipc"), 1)
        self.assertEqual(argv.count("--unshare-uts"), 1)
        self.assertNotIn("--unshare-net", argv)
        self.assertNotIn("--unshare-cgroup", argv)
        self.assertEqual(argv[argv.index("--bind") + 1 : argv.index("--bind") + 3], [TARGET, TARGET])
        self.assertEqual(argv.count("--ro-bind"), 4)
        self.assertNotIn("--bind-fd", argv)

    def test_candidate_runner_bounds_stderr_and_preserves_safe_status_only(self) -> None:
        class Process:
            pid = 4321
            returncode = 7

            def communicate(self, timeout=None):
                return b"discarded stdout", b"x" * (MAX_STDERR_BYTES + 100)

        with mock.patch("docker.check_remount_denial.subprocess.Popen", return_value=Process()) as popen:
            result = _run_candidate(["bwrap", "--", "/bin/true"])
        self.assertEqual(result["returncode"], 7)
        self.assertFalse(result["timed_out"])
        self.assertTrue(result["stderr_nonempty"])
        self.assertLessEqual(result["stderr_bytes"], MAX_STDERR_BYTES)
        self.assertNotIn("stdout", result)
        kwargs = popen.call_args.kwargs
        self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
        self.assertTrue(kwargs["start_new_session"])

    def test_candidate_runner_reports_success_nonzero_and_timeout_without_claiming_proof(self) -> None:
        class Process:
            pid = 4322
            returncode = 0

            def __init__(self, timeout=False, code=0):
                self.timeout = timeout
                self.returncode = code
                self.calls = 0

            def communicate(self, timeout=None):
                self.calls += 1
                if self.timeout and self.calls == 1:
                    raise subprocess.TimeoutExpired(["bwrap"], 15)
                return b"", b""

        success = Process()
        failure = Process(code=1)
        timed_out = Process(timeout=True)
        with mock.patch("docker.check_remount_denial.subprocess.Popen", side_effect=[success, failure, timed_out]), mock.patch("docker.check_remount_denial._kill_group"):
            self.assertEqual(_run_candidate(["bwrap"])["returncode"], 0)
            self.assertEqual(_run_candidate(["bwrap"])["returncode"], 1)
            result = _run_candidate(["bwrap"])
        self.assertTrue(result["timed_out"])
        self.assertIsNone(result["returncode"])
        self.assertNotIn("ok", result)

    def test_safe_source_gate_stops_before_bwrap(self) -> None:
        facts = {"mountpoint": TARGET, "options": {"rw", "nosuid", "nodev"}}
        output = StringIO()
        with (
            mock.patch("docker.check_remount_denial._source_mount_facts", return_value=facts),
            mock.patch("docker.check_remount_denial._run_candidate") as run_candidate,
            mock.patch("docker.check_remount_denial.sys.argv", ["check_remount_denial.py"]),
            redirect_stdout(output),
        ):
            self.assertEqual(main(), 2)
        run_candidate.assert_not_called()
        self.assertIn('"error_code":"source_mount_already_nosuid_nodev"', output.getvalue())


if __name__ == "__main__":
    unittest.main()
