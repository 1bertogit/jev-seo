"""Offline semantic tests for the bounded native acceptance operator."""

from __future__ import annotations

import json
import hashlib
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from deploy.native.check_native_acceptance import (
    AcceptanceError,
    EXPECTED_GID,
    EXPECTED_UID,
    EXPECTED_VENV,
    _network_probe_source,
    _network_evidence,
    _network_result_ok,
    _load_helper,
    main,
    run_acceptance,
)


def valid_network() -> dict:
    return {
        "ok": True,
        "public": {
            "http": {"url": "http://example.com/", "status": 200, "body_bytes": 648, "ok": True, "error_category": None},
            "https": {"url": "https://example.com/", "status": 200, "body_bytes": 648, "ok": True, "error_category": None},
        },
        "proxy_private": {
            "ipv4": {"url": "http://127.0.0.1:18080/", "status": 403, "blocked": True, "error_category": None},
            "ipv6": {"url": "http://[::1]:18080/", "status": 403, "blocked": True, "error_category": None},
        },
        "direct": {
            "ipv4": {"family": "AF_INET", "address": "127.0.0.1", "port": 18080, "blocked": True, "error_category": "timeout"},
            "ipv6": {"family": "AF_INET6", "address": "::1", "port": 18080, "blocked": True, "error_category": "permission"},
        },
    }


def valid_positive() -> dict:
    return {
        "ok": True,
        "worker": {
            "uid": 200,
            "gid": 200,
            "euid": 200,
            "egid": 200,
            "caps_eff": "0000000000000000",
            "caps_bnd": "0000000000000000",
            "no_new_privs": 1,
            "apparmor": "jev-audit-native (enforce)",
            "namespace_ids": {name: name for name in ("mnt", "user", "pid", "ipc", "uts", "net", "cgroup")},
            "assertions": {name: True for name in ("job_writable", "runtime_ro", "app_ro", "hidden_data", "hidden_env", "provider_fake")},
        },
        "artifacts": {fmt: {"size": 10, "sha256": "a" * 64} for fmt in ("pdf", "xlsx", "md")},
    }


class NativeAcceptanceTests(unittest.TestCase):
    def test_probe_source_has_only_fixed_targets_and_safe_requests_settings(self) -> None:
        source = _network_probe_source()
        compile(source, "<network-probe>", "exec")
        self.assertIn("http://example.com/", source)
        self.assertIn("https://example.com/", source)
        self.assertIn("http://127.0.0.1:18080/", source)
        self.assertIn("http://[::1]:18080/", source)
        self.assertIn("trust_env = False", source)
        self.assertIn("verify=True", source)
        self.assertIn("allow_redirects=False", source)
        self.assertIn("16 * 1024", source)
        self.assertNotIn("sys.argv", source)
        self.assertNotIn("TYPESAFE_API_KEY", source)

    def test_network_result_requires_public_2xx_proxy_403_and_both_direct_denials(self) -> None:
        self.assertTrue(_network_result_ok(valid_network()))
        for change in (
            ("public", "http", "status", 302),
            ("proxy_private", "ipv4", "status", 200),
            ("proxy_private", "ipv6", "error_category", "proxy_error"),
            ("direct", "ipv4", "error_category", "refused"),
            ("direct", "ipv6", "error_category", "unreachable"),
        ):
            result = valid_network()
            result[change[0]][change[1]][change[2]] = change[3]
            self.assertFalse(_network_result_ok(result))
        extra = valid_network()
        extra["unexpected"] = "not accepted"
        self.assertFalse(_network_result_ok(extra))

    def test_real_helper_load_registers_module_for_future_dataclass_annotations_and_guards(self) -> None:
        helper_path = Path(__file__).resolve().parents[1] / "docker" / "check_sandbox_acceptance.py"
        expected_hash = hashlib.sha256(helper_path.read_bytes()).hexdigest()
        real_lstat = Path.lstat

        def scoped_lstat(path):
            if path == helper_path:
                return SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0)
            return real_lstat(path)

        with (
            mock.patch("deploy.native.check_native_acceptance.EXPECTED_HELPER", helper_path),
            mock.patch("deploy.native.check_native_acceptance.EXPECTED_HELPER_SHA256", expected_hash),
            mock.patch.object(Path, "lstat", autospec=True, side_effect=scoped_lstat),
        ):
            helper = _load_helper()
        context = helper.AcceptanceContext(Path("/data"), 200, 200, "profile", "proxy", Path("/runtime"))
        self.assertEqual(context.uid, 200)
        self.assertEqual(helper.AcceptanceContext.__module__, "check_sandbox_acceptance")
        with (
            mock.patch("deploy.native.check_native_acceptance.EXPECTED_HELPER", helper_path),
            mock.patch("deploy.native.check_native_acceptance.EXPECTED_HELPER_SHA256", "0" * 64),
            mock.patch.object(Path, "lstat", autospec=True, side_effect=scoped_lstat),
        ):
            with self.assertRaisesRegex(AcceptanceError, "helper_hash_mismatch"):
                _load_helper()

        def wrong_owner(path):
            if path == helper_path:
                return SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=200)
            return real_lstat(path)

        with (
            mock.patch("deploy.native.check_native_acceptance.EXPECTED_HELPER", helper_path),
            mock.patch("deploy.native.check_native_acceptance.EXPECTED_HELPER_SHA256", expected_hash),
            mock.patch.object(Path, "lstat", autospec=True, side_effect=wrong_owner),
        ):
            with self.assertRaisesRegex(AcceptanceError, "helper_ownership_invalid"):
                _load_helper()

    def test_unknown_arguments_fail_before_identity_or_helper(self) -> None:
        output = SimpleNamespace(value="")
        with mock.patch("deploy.native.check_native_acceptance._verify_identity") as identity, mock.patch("deploy.native.check_native_acceptance._load_helper") as loader, mock.patch("builtins.print", side_effect=lambda value: setattr(output, "value", value)):
            self.assertEqual(main(["--url", "https://example.com"]), 2)
        identity.assert_not_called()
        loader.assert_not_called()
        self.assertEqual(json.loads(output.value)["error_code"], "arguments_not_allowed")

    def test_identity_failure_is_rejected_before_helper(self) -> None:
        output = SimpleNamespace(value="")
        with mock.patch("deploy.native.check_native_acceptance._verify_identity", side_effect=AcceptanceError("identity_mismatch")) as identity, mock.patch("deploy.native.check_native_acceptance._load_helper") as loader, mock.patch("builtins.print", side_effect=lambda value: setattr(output, "value", value)):
            self.assertEqual(main([]), 1)
        identity.assert_called_once()
        loader.assert_not_called()
        self.assertEqual(json.loads(output.value), {"error_code": "identity_mismatch", "ok": False})

    def test_network_evidence_drops_unknown_fields_and_does_not_override_validation(self) -> None:
        result = valid_network()
        result["secret"] = "must not be emitted"
        evidence = _network_evidence(result)
        self.assertNotIn("secret", json.dumps(evidence))
        self.assertFalse(_network_result_ok(result))

    def test_runner_uses_fresh_job_production_boundary_and_safe_aggregate(self) -> None:
        root = Path(tempfile.mkdtemp())
        context = SimpleNamespace(data_root=root, uid=EXPECTED_UID, gid=EXPECTED_GID, profile="jev-audit-native (enforce)", fake_proxy="http://127.0.0.1:4750", runtime_dir=EXPECTED_VENV)
        calls: list[tuple[Path, object, list[str]]] = []
        payload = valid_network()

        class Helper:
            WebConfig = lambda **kwargs: SimpleNamespace(**kwargs)

            @staticmethod
            def _native_context():
                return context

            @staticmethod
            def _run(*, context):
                return valid_positive()

            @staticmethod
            def _prepare_job_dir(data_root, job_id):
                job = data_root / "jobs" / job_id
                job.mkdir(parents=True)
                return job

            @staticmethod
            def _write_exclusive(path, data):
                path.write_bytes(data)

            @staticmethod
            def _run_contained(job, config, command, deadline, stop_event, on_progress):
                calls.append((job, config, command))
                (job / "network-result.json").write_text(json.dumps(payload), encoding="utf-8")
                return 0, False

            @staticmethod
            def _read_bounded_file(path, limit):
                data = path.read_bytes()
                return data if len(data) <= limit else None

        with mock.patch("deploy.native.check_native_acceptance._verify_identity"), mock.patch("deploy.native.check_native_acceptance.ACCEPTANCE_ROOT", root), mock.patch("deploy.native.check_native_acceptance.secrets.token_hex", side_effect=["b" * 32, "c" * 32]):
            result = run_acceptance(Helper)
            payload["ok"] = True
            payload["public"]["http"]["status"] = 302
            payload["public"]["http"]["ok"] = False
            payload["proxy_private"]["ipv4"]["status"] = 200
            payload["proxy_private"]["ipv4"]["blocked"] = False
            payload["proxy_private"]["ipv4"]["error_category"] = "unexpected_status"
            payload["direct"]["ipv4"]["error_category"] = "refused"
            payload["direct"]["ipv4"]["blocked"] = False
            failed = run_acceptance(Helper)
        self.assertTrue(result["ok"])
        self.assertEqual(result["positive"], valid_positive())
        self.assertTrue(result["network"]["ok"])
        self.assertEqual(calls[0][0], root / "jobs" / ("b" * 32))
        self.assertEqual(calls[0][2], [sys.executable, "/job/network_probe.py"])
        self.assertEqual(calls[0][1].egress_proxy, "http://127.0.0.1:4750")
        self.assertEqual(calls[0][1].data_dir, root)
        self.assertNotIn("native-network-service-secret", json.dumps(result))
        self.assertNotIn("fake-provider-key", json.dumps(result))
        self.assertNotIn("firewall_proof", result)
        self.assertTrue(result["firewall_corroboration_required"])
        self.assertFalse(failed["ok"])
        self.assertFalse(failed["network"]["ok"])

    def test_context_drift_fails_before_positive_runner(self) -> None:
        context = SimpleNamespace(data_root=Path("/wrong"), uid=EXPECTED_UID, gid=EXPECTED_GID, profile="jev-audit-native (enforce)", fake_proxy="http://127.0.0.1:4750", runtime_dir=EXPECTED_VENV)

        class Helper:
            @staticmethod
            def _native_context():
                return context

            @staticmethod
            def _run(**kwargs):
                raise AssertionError("positive runner must not start")

        with mock.patch("deploy.native.check_native_acceptance._verify_identity"):
            with self.assertRaisesRegex(AcceptanceError, "native_context_mismatch"):
                run_acceptance(Helper)


if __name__ == "__main__":
    unittest.main()
