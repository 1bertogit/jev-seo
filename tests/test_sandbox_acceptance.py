"""Focused offline tests for the future retained-image acceptance harness."""

from __future__ import annotations

import json
import errno
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from docker.check_sandbox_acceptance import (
    FORMATS,
    _artifact_summary,
    _artifacts_ok,
    _namespace_match,
    _prepare_job_dir,
    _probe_source,
    _run,
    _write_error_proves_readonly,
    _worker_result_ok,
    build_synthetic_audit,
    main,
)


class SandboxAcceptanceHarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_owned_job_directory_is_new_and_symlinks_are_rejected(self) -> None:
        job_id = "a" * 32
        job = _prepare_job_dir(self.root, job_id)
        self.assertEqual(job, self.root / "jobs" / job_id)
        self.assertTrue((job / ".acceptance-owner").is_file())

        with self.assertRaises(RuntimeError):
            _prepare_job_dir(self.root, job_id)

        linked_root = self.root / "linked"
        linked_root.symlink_to(self.root / "jobs", target_is_directory=True)
        with self.assertRaises(RuntimeError):
            _prepare_job_dir(linked_root, "b" * 32)

    def test_worker_namespace_comparison_requires_exact_topology(self) -> None:
        outer = {name: f"{name}-outer" for name in ("mnt", "user", "pid", "ipc", "uts", "net", "cgroup")}
        worker = dict(outer)
        for name in ("mnt", "user", "pid", "ipc", "uts"):
            worker[name] = f"{name}-worker"
        self.assertTrue(_namespace_match(worker, outer))
        worker["net"] = "net-worker"
        self.assertFalse(_namespace_match(worker, outer))

    def test_worker_result_rejects_caps_or_canary_failures(self) -> None:
        result = {
            "ok": True,
            "uid": 10001,
            "gid": 10001,
            "euid": 10001,
            "egid": 10001,
            "caps_eff": "0000000000000000",
            "caps_bnd": "0000000000000000",
            "no_new_privs": 1,
            "apparmor": "jev-audit-bwrap (enforce)",
            "assertions": {"job_writable": True, "runtime_ro": True, "app_ro": True, "hidden_data": True, "hidden_env": True, "provider_fake": True},
            "namespace_ids": {},
        }
        self.assertTrue(_worker_result_ok(result))
        result["caps_eff"] = "0000000000000001"
        self.assertFalse(_worker_result_ok(result))
        result["caps_eff"] = "0000000000000000"
        result["assertions"]["hidden_env"] = False
        self.assertFalse(_worker_result_ok(result))
        result["assertions"]["hidden_env"] = True
        result["apparmor"] = "jev-audit-bwrap-evil (enforce)"
        self.assertFalse(_worker_result_ok(result))
        result["apparmor"] = "jev-audit-bwrap (enforce)"
        result["gid"] = 10000
        self.assertFalse(_worker_result_ok(result))

    def test_only_erofs_proves_a_readonly_write_failure(self) -> None:
        self.assertTrue(_write_error_proves_readonly(OSError(errno.EROFS, "read-only")))
        self.assertFalse(_write_error_proves_readonly(OSError(errno.EACCES, "denied")))

    def test_generated_probe_contains_erofs_guard_and_compiles(self) -> None:
        source = _probe_source("a" * 32, Path("/data/outer"), Path("/data/db"), Path("/data/jobs/b/sentinel"))
        compile(source, "<generated-probe>", "exec")
        self.assertIn("errno.EROFS", source)

    def test_summary_does_not_echo_secret_canaries(self) -> None:
        result = {"ok": True, "worker": {"assertions": {"hidden_env": True}}}
        summary = json.dumps(result, sort_keys=True)
        for secret in ("service-secret", "task-secret", "outer-secret"):
            self.assertNotIn(secret, summary)
        output = StringIO()
        with mock.patch("docker.check_sandbox_acceptance._run", side_effect=RuntimeError("service-secret")), redirect_stdout(output):
            self.assertEqual(main(), 1)
        self.assertNotIn("service-secret", output.getvalue())

    def test_artifact_validation_is_fail_closed(self) -> None:
        for fmt in FORMATS:
            path = self.root / f"report.{fmt}"
            path.write_bytes(b"\xff" if fmt == "md" else b"not an artifact")
            self.assertIsNone(_artifact_summary(path, fmt))
        self.assertFalse(_artifacts_ok({fmt: None for fmt in FORMATS}))
        self.assertFalse(_worker_result_ok({"ok": True}, stopped=True))
        self.assertFalse(_worker_result_ok({"ok": True}, return_code=1))

    def test_synthetic_audit_is_partial_without_provider_sections(self) -> None:
        audit = build_synthetic_audit()
        self.assertEqual(len(audit["pages"]), 1)
        self.assertFalse(audit["jev"]["available"])
        self.assertIsNone(audit["performance"])
        self.assertIsNone(audit["dataforseo"])
        self.assertTrue(audit["scores"]["partial"])

    def test_mocked_lifecycle_runs_fixed_formats_and_returns_worker_facts(self) -> None:
        outer = {name: f"{name}-outer" for name in ("mnt", "user", "pid", "ipc", "uts", "net", "cgroup")}
        worker_ns = dict(outer)
        for name in ("mnt", "user", "pid", "ipc", "uts"):
            worker_ns[name] = f"{name}-worker"
        worker = {
            "ok": True, "uid": 10001, "gid": 10001, "euid": 10001, "egid": 10001,
            "caps_eff": "0000000000000000", "caps_bnd": "0000000000000000", "no_new_privs": 1,
            "apparmor": "jev-audit-bwrap (enforce)", "namespace_ids": worker_ns,
            "assertions": {name: True for name in ("job_writable", "runtime_ro", "app_ro", "hidden_data", "hidden_env", "provider_fake")},
        }
        commands = []
        deadlines = []

        def fake_run(job, config, command, deadline, stop_event, on_progress):
            commands.append(command)
            deadlines.append(deadline)
            if command == [sys.executable, "/job/probe.py"]:
                (job / "probe-result.json").write_text(json.dumps(worker), encoding="utf-8")
            return 0, False

        with (
            mock.patch("docker.check_sandbox_acceptance.DATA_ROOT", self.root),
            mock.patch("docker.check_sandbox_acceptance.sandbox_available", return_value=True),
            mock.patch("docker.check_sandbox_acceptance.secrets.token_hex", return_value="a" * 32),
            mock.patch("docker.check_sandbox_acceptance._namespace_ids", return_value=outer),
            mock.patch("docker.check_sandbox_acceptance._run_contained", side_effect=fake_run),
            mock.patch("docker.check_sandbox_acceptance._artifact_summary", return_value={"size": 1, "sha256": "a" * 64}),
            mock.patch("docker.check_sandbox_acceptance.sys.argv", ["check_sandbox_acceptance.py"]),
        ):
            result = _run()
        self.assertTrue(result["ok"])
        self.assertEqual(result["worker"]["gid"], 10001)
        self.assertEqual(
            set(result["worker"]),
            {"uid", "gid", "euid", "egid", "caps_eff", "caps_bnd", "no_new_privs", "apparmor", "namespace_ids", "assertions"},
        )
        self.assertEqual(commands[0], [sys.executable, "/job/probe.py"])
        self.assertEqual(commands[1:], [[sys.executable, "-m", "jevseo", "render", "/job", "--formats", fmt] for fmt in FORMATS])
        self.assertEqual(len(set(deadlines)), 1)

    def test_mocked_render_failure_stops_without_extra_formats(self) -> None:
        root = self.root / "failure"
        root.mkdir()
        outer = {name: f"{name}-outer" for name in ("mnt", "user", "pid", "ipc", "uts", "net", "cgroup")}
        worker_ns = dict(outer)
        for name in ("mnt", "user", "pid", "ipc", "uts"):
            worker_ns[name] = f"{name}-worker"
        worker = {
            "ok": True, "uid": 10001, "gid": 10001, "euid": 10001, "egid": 10001,
            "caps_eff": "0000000000000000", "caps_bnd": "0000000000000000", "no_new_privs": 1,
            "apparmor": "jev-audit-bwrap (enforce)", "namespace_ids": worker_ns,
            "assertions": {name: True for name in ("job_writable", "runtime_ro", "app_ro", "hidden_data", "hidden_env", "provider_fake")},
        }
        renders = []

        def fake_run(job, config, command, deadline, stop_event, on_progress):
            if command == [sys.executable, "/job/probe.py"]:
                (job / "probe-result.json").write_text(json.dumps(worker), encoding="utf-8")
                return 0, False
            renders.append(command[-1])
            return 1, False

        with (
            mock.patch("docker.check_sandbox_acceptance.DATA_ROOT", root),
            mock.patch("docker.check_sandbox_acceptance.sandbox_available", return_value=True),
            mock.patch("docker.check_sandbox_acceptance.secrets.token_hex", return_value="b" * 32),
            mock.patch("docker.check_sandbox_acceptance._namespace_ids", return_value=outer),
            mock.patch("docker.check_sandbox_acceptance._run_contained", side_effect=fake_run),
            mock.patch("docker.check_sandbox_acceptance.sys.argv", ["check_sandbox_acceptance.py"]),
        ):
            with self.assertRaises(RuntimeError):
                _run()
        self.assertEqual(renders, ["pdf"])


if __name__ == "__main__":
    unittest.main()
