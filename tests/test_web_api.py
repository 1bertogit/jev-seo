import asyncio
import json
import os
import sqlite3
import threading
import time
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient
import httpx

from jevseo.web.app import create_app, task_token
from jevseo.web.config import WebConfig


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.config = WebConfig(
            data_dir=Path(self.tmp.name),
            service_token="s" * 32,
            task_secret="t" * 32,
            typesafe_api_key="j" * 32,
            pagespeed_api_key=None,
            egress_proxy="http://proxy.example:8080",
        )
        self.fingerprint = "a" * 64
        self.headers = {
            "Authorization": "Bearer " + self.config.service_token,
            "X-Client-Fingerprint": self.fingerprint,
            "Idempotency-Key": str(uuid.uuid4()),
        }

    def tearDown(self):
        self.tmp.cleanup()

    def client(self):
        with mock.patch("jevseo.web.app.sandbox_available", return_value=True):
            return TestClient(create_app(self.config))

    def test_missing_auth_is_enveloped_and_admission_is_idempotent(self):
        with mock.patch("jevseo.web.app.sandbox_available", return_value=True), mock.patch("jevseo.web.runner.sandbox_available", return_value=True), mock.patch("jevseo.web.app.validate_public_url", side_effect=lambda value: value):
            with TestClient(create_app(self.config)) as client:
                response = client.post("/v1/jobs", json={"url": "https://example.com/"})
                self.assertEqual(response.status_code, 401)
                self.assertEqual(set(response.json()), {"error"})
                first = client.post("/v1/jobs", headers=self.headers, json={"url": "https://example.com/"})
                self.assertEqual(first.status_code, 202, first.text)
                self.assertIsInstance(first.json()["expiresAt"], str)
                replay = client.post("/v1/jobs", headers=self.headers, json={"url": "https://example.com/"})
                self.assertEqual(replay.status_code, 202)
                self.assertEqual(replay.json()["jobId"], first.json()["jobId"])

    def test_status_requires_task_token_and_download_has_fixed_name(self):
        def fake_run(job, config, on_progress, stop_event=None):
            folder = config.jobs_dir / job["job_id"]
            folder.mkdir(parents=True, exist_ok=True)
            (folder / "report.md").write_text("# report\n")
            return {"state": "partial", "pages_crawled": 1, "score": 1, "warnings": [], "files": ["md"]}

        with mock.patch("jevseo.web.app.sandbox_available", return_value=True), mock.patch("jevseo.web.runner.sandbox_available", return_value=True), mock.patch("jevseo.web.app.validate_public_url", side_effect=lambda value: value), mock.patch("jevseo.web.runner.run_job", side_effect=fake_run):
            with TestClient(create_app(self.config)) as client:
                response = client.post("/v1/jobs", headers=self.headers, json={"url": "https://example.com/"})
                job_id = response.json()["jobId"]
                for _ in range(20):
                    if "md" in client.get("/v1/jobs/" + job_id, headers={"Authorization": "Bearer " + self.config.service_token, "X-Job-Token": task_token(self.config.task_secret, job_id)}).json().get("files", []):
                        break
                    time.sleep(0.01)
                auth = {"Authorization": "Bearer " + self.config.service_token}
                self.assertEqual(client.get("/v1/jobs/" + job_id, headers=auth).status_code, 401)
                token = task_token(self.config.task_secret, job_id)
                status = client.get("/v1/jobs/" + job_id, headers={**auth, "X-Job-Token": token})
                self.assertEqual(status.status_code, 200)
                self.assertIsInstance(status.json()["expiresAt"], str)
                self.assertEqual(set(status.json()), {"jobId", "state", "stage", "pagesCrawled", "score", "warnings", "files", "expiresAt"})

                malformed = client.get("/v1/jobs/not-a-job-☃", headers={**auth, "X-Job-Token": "bad"})
                self.assertIn(malformed.status_code, (401, 404))

                folder = Path(self.tmp.name) / "jobs" / job_id
                folder.mkdir(parents=True, exist_ok=True)
                (folder / "report.md").write_text("# report\n")
                download = client.get(f"/v1/jobs/{job_id}/files/md", headers={**auth, "X-Job-Token": token})
                self.assertEqual(download.status_code, 200)
                self.assertIn('filename="report.md"', download.headers["content-disposition"])
                os.unlink(folder / "report.md")
                (folder / "outside.md").write_text("outside\n")
                (folder / "report.md").symlink_to(folder / "outside.md")
                self.assertEqual(client.get(f"/v1/jobs/{job_id}/files/md", headers={**auth, "X-Job-Token": token}).status_code, 404)
                os.unlink(folder / "report.md")
                (folder / "report.md").write_bytes(b"x" * (4 * 1024 * 1024 + 1))
                self.assertEqual(client.get(f"/v1/jobs/{job_id}/files/md", headers={**auth, "X-Job-Token": token}).status_code, 404)
                self.assertEqual(client.get(f"/v1/jobs/{job_id}/files/html", headers={**auth, "X-Job-Token": token}).status_code, 404)

    def test_body_is_strict_and_bounded(self):
        with mock.patch("jevseo.web.app.sandbox_available", return_value=True), mock.patch("jevseo.web.runner.sandbox_available", return_value=True), mock.patch("jevseo.web.app.validate_public_url", side_effect=lambda value: value):
            with TestClient(create_app(self.config)) as client:
                too_big = b"{" + b'"url":"https://example.com/","x":"' + b"a" * 8200 + b'"}'
                response = client.post("/v1/jobs", headers=self.headers, content=too_big)
                self.assertEqual(response.status_code, 400)
                response = client.post("/v1/jobs", headers=self.headers, json={"url": "https://example.com/", "extra": 1})
                self.assertEqual(response.status_code, 400)

    def test_missing_jev_key_is_not_admitted_and_expired_status_is_410(self):
        bad = WebConfig(data_dir=Path(self.tmp.name) / "bad", service_token="s" * 32, task_secret="t" * 32, typesafe_api_key=None, pagespeed_api_key=None, egress_proxy="http://proxy.example:8080")
        with mock.patch("jevseo.web.app.sandbox_available", return_value=True):
            with TestClient(create_app(bad)) as client:
                response = client.post("/v1/jobs", headers=self.headers, json={"url": "https://example.com/"})
                self.assertEqual(response.status_code, 503)

        with mock.patch("jevseo.web.app.sandbox_available", return_value=True), mock.patch("jevseo.web.runner.sandbox_available", return_value=True), mock.patch("jevseo.web.app.validate_public_url", side_effect=lambda value: value):
            with TestClient(create_app(self.config)) as client:
                response = client.post("/v1/jobs", headers=self.headers, json={"url": "https://example.com/"})
                job_id = response.json()["jobId"]
                with sqlite3.connect(Path(self.tmp.name) / "jobs.sqlite3") as connection:
                    connection.execute("UPDATE jobs SET expires_at = 0 WHERE job_id = ?", (job_id,))
                    connection.commit()
                token = task_token(self.config.task_secret, job_id)
                status = client.get("/v1/jobs/" + job_id, headers={"Authorization": "Bearer " + self.config.service_token, "X-Job-Token": token})
                self.assertEqual(status.status_code, 410)

    def test_dns_validation_gate_is_bounded_responsive_and_cancellation_safe(self):
        async def exercise():
            app = create_app(self.config)
            started = threading.Event()
            release = threading.Event()
            lock = threading.Lock()
            calls = 0

            def blocked(url):
                nonlocal calls
                with lock:
                    calls += 1
                    if calls >= 4:
                        started.set()
                release.wait(2)
                return url

            try:
                async with app.router.lifespan_context(app):
                    service = app.state.job_service
                    job = service.store.accept("https://example.com/", "status-client", str(uuid.uuid4()), time.time())
                    auth = {"Authorization": "Bearer " + self.config.service_token}
                    status_headers = {**auth, "X-Job-Token": task_token(self.config.task_secret, job["job_id"])}
                    transport = httpx.ASGITransport(app=app)
                    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                        with mock.patch("jevseo.web.app.validate_public_url", side_effect=blocked):
                            def post_headers(index):
                                return {**self.headers, "Idempotency-Key": str(uuid.UUID(int=index + 1))}

                            first = [asyncio.create_task(client.post("/v1/jobs", headers=post_headers(i), json={"url": "https://example.com/"})) for i in range(4)]
                            await asyncio.to_thread(started.wait, 1)
                            self.assertTrue(started.is_set())
                            fifth = await asyncio.wait_for(client.post("/v1/jobs", headers=post_headers(9), json={"url": "https://example.com/"}), 0.5)
                            self.assertEqual(fifth.status_code, 429)
                            status = await asyncio.wait_for(client.get("/v1/jobs/" + job["job_id"], headers=status_headers), 0.5)
                            self.assertEqual(status.status_code, 200)
                            release.set()
                            await asyncio.gather(*first)

                            started.clear()
                            release.clear()
                            with lock:
                                calls = 0
                            second = [asyncio.create_task(client.post("/v1/jobs", headers=post_headers(20 + i), json={"url": "https://example.com/"})) for i in range(4)]
                            await asyncio.to_thread(started.wait, 1)
                            second[0].cancel()
                            await asyncio.sleep(0.05)
                            fifth_after_cancel = await asyncio.wait_for(client.post("/v1/jobs", headers=post_headers(29), json={"url": "https://example.com/"}), 0.5)
                            self.assertEqual(fifth_after_cancel.status_code, 429)
                            release.set()
                            await asyncio.gather(*second, return_exceptions=True)
            finally:
                release.set()

        with mock.patch("jevseo.web.app.sandbox_available", return_value=True), mock.patch("jevseo.web.runner.sandbox_available", return_value=True):
            asyncio.run(exercise())


if __name__ == "__main__":
    unittest.main()
