import json
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jevseo.web.config import WebConfig
from jevseo.web.runner import (
    _build_bwrap_argv,
    _bounded_audit,
    _derive_task_token,
    _valid_artifact,
    JobService,
    run_job,
)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.job_dir = self.root / "jobs" / ("a" * 32)
        self.job_dir.mkdir(parents=True)
        self.config = WebConfig(
            data_dir=self.root,
            service_token="s" * 32,
            task_secret="t" * 32,
            typesafe_api_key="j" * 32,
            pagespeed_api_key=None,
            egress_proxy="http://proxy.example:8080",
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_bwrap_argv_contains_containment_and_does_not_mount_data_root(self):
        with mock.patch("jevseo.web.runner.platform.system", return_value="Linux"):
            argv = _build_bwrap_argv(self.job_dir, self.config, ["python", "-m", "jevseo"])
        self.assertIn("--unshare-pid", argv)
        self.assertIn("--unshare-user", argv)
        self.assertIn("--die-with-parent", argv)
        self.assertNotIn("--unshare-mnt", argv)
        self.assertIn("--ro-bind", argv)
        self.assertIn("--bind", argv)
        self.assertIn(str(self.job_dir), argv)
        self.assertNotIn(str(self.root), argv)
        self.assertNotIn(self.config.service_token, argv)
        self.assertNotIn(self.config.task_secret, argv)

    def test_sandbox_probe_uses_only_existing_runtime_directories(self):
        import jevseo.web.runner as runner

        with mock.patch.object(runner, "platform") as platform, mock.patch.object(runner.shutil, "which", return_value="/usr/bin/tool"), mock.patch.object(runner, "_runtime_dirs", return_value=(Path("/usr"), Path("/bin"), Path("/lib"))), mock.patch.object(runner.subprocess, "run", return_value=mock.Mock(returncode=0)) as run:
            platform.system.return_value = "Linux"
            runner.sandbox_available.cache_clear()
            self.assertTrue(runner.sandbox_available())
        argv = run.call_args.args[0]
        self.assertNotIn("/lib64", argv)

    def test_worker_proxy_environment_covers_crawler_and_providers(self):
        from jevseo.web.runner import _worker_environment

        env = _worker_environment(self.config)
        self.assertEqual(env["HTTP_PROXY"], self.config.egress_proxy)
        self.assertEqual(env["HTTPS_PROXY"], self.config.egress_proxy)
        self.assertNotIn("NO_PROXY", env)
        self.assertNotIn("ALL_PROXY", env)

    def test_non_html_and_unparsed_audit_is_not_usable(self):
        path = self.job_dir / "audit.json"
        path.write_text(json.dumps({"pages": [{"status": 200, "kind": "page", "content_type": "application/pdf"}]}))
        self.assertIsNone(_bounded_audit(path))
        path.write_text(json.dumps({"pages": [{"status": 200, "kind": "page", "content_type": "text/html"}]}))
        self.assertIsNone(_bounded_audit(path))

    def test_rendering_transition_and_final_page_count_are_persisted(self):
        from jevseo.web.store import Store

        store = Store(self.root / "jobs.sqlite3")
        job = store.accept("https://example.com/", "client", "key", 1_700_000_000)
        store.claim(1_700_000_000)
        service = JobService(self.config)
        service.store = store
        service._progress(job["job_id"], "rendering")
        service._progress(job["job_id"], "rendering", 2)
        current = store.get(job["job_id"])
        self.assertEqual(current["state"], "rendering")
        self.assertEqual(current["pages_crawled"], 2)

    def test_unexpected_runner_exception_fails_job_and_does_not_wedge_queue(self):
        class FakeStore:
            def __init__(self, owner):
                self.owner = owner
                self.claimed = False
                self.finished = []

            def expire(self, now):
                return []

            def claim(self, now):
                if self.claimed:
                    self.owner._stop.set()
                    return None
                self.claimed = True
                return {"job_id": "b" * 32, "url": "https://example.com/"}

            def finish(self, job_id, state, result):
                self.finished.append((job_id, state, result))
                self.owner._stop.set()

        service = JobService(self.config)
        fake = FakeStore(service)
        service.store = fake
        with mock.patch("jevseo.web.runner.run_job", side_effect=RuntimeError("boom")):
            service._loop()
        self.assertEqual(fake.finished[0][1], "failed")

    def test_task_token_is_domain_separated_hmac(self):
        first = _derive_task_token("t" * 32, "a" * 32)
        second = _derive_task_token("t" * 32, "b" * 32)
        self.assertEqual(len(first), 64)
        self.assertNotEqual(first, second)

    def test_artifact_signatures_and_size(self):
        pdf = self.job_dir / "report.pdf"
        pdf.write_bytes(b"%PDF-1.7\n")
        self.assertTrue(_valid_artifact(pdf, "pdf"))
        pdf.write_bytes(b"not pdf")
        self.assertFalse(_valid_artifact(pdf, "pdf"))

    def test_run_job_uses_fixed_audit_and_render_commands_and_keeps_other_formats(self):
        calls = []

        class Process:
            def __init__(self, code, output):
                self.code = code
                self.stdout = io.StringIO(output)

            def poll(self):
                return self.code

            def wait(self, timeout=None):
                return self.code

        def fake_launch(argv, **kwargs):
            calls.append((argv, kwargs))
            command = argv[-1] if argv else ""
            if "audit" in argv:
                (self.job_dir / "audit.json").write_text(json.dumps({
                    "pages": [{"url": "https://example.com/", "status": 200, "kind": "page", "content_type": "text/html", "word_count": 2, "text_hash": "a" * 40}],
                    "scores": {"overall": 91},
                    "site": {"limits": {}},
                }))
                return Process(0, "[jevseo 00:00] == 1/7 Crawl\n")
            fmt = argv[argv.index("--formats") + 1]
            if fmt == "pdf":
                return Process(1, "render failed")
            if fmt == "xlsx":
                import zipfile
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w") as zf:
                    zf.writestr("xl/workbook.xml", "<workbook/>")
                    zf.writestr("[Content_Types].xml", "<Types/>")
                (self.job_dir / "report.xlsx").write_bytes(buf.getvalue())
            else:
                (self.job_dir / "report.md").write_text("# report\n")
            return Process(0, "")

        with mock.patch("jevseo.web.runner.sandbox_available", return_value=True), mock.patch("jevseo.web.runner._launch_bwrap", side_effect=fake_launch):
            result = run_job(
                {"job_id": "a" * 32, "url": "https://example.com/"},
                self.config,
                lambda stage, pages=None: None,
            )
        self.assertEqual(result["state"], "partial")
        self.assertEqual(result["files"], ["xlsx", "md"])
        audit = calls[0][0]
        self.assertIn("--max-pages", audit)
        self.assertIn("60", audit)
        self.assertIn("--jev-budget", audit)
        self.assertNotIn("--full", audit)
        self.assertNotIn(self.config.service_token, calls[0][1]["env"].values())
        self.assertNotIn(self.config.task_secret, calls[0][1]["env"].values())


if __name__ == "__main__":
    unittest.main()
