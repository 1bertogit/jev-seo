import concurrent.futures
import datetime as dt
import sqlite3
import tempfile
import unittest
from pathlib import Path

from jevseo.web.store import AdmissionError, Store


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.database = Path(self.tmp.name) / "jobs.sqlite3"
        self.store = Store(self.database)

    def tearDown(self):
        self.tmp.cleanup()

    def accept(self, client="client", key=None, url="https://example.com/", now=1_700_000_000):
        return self.store.accept(url, client, key or f"key-{client}-{url}", now)

    def finish_accepted(self, client, now):
        job = self.accept(client=client, now=now)
        claimed = self.store.claim(now)
        self.assertEqual(claimed["job_id"], job["job_id"])
        self.store.finish(job["job_id"], "failed", {"warnings": ["test"]})

    def test_accept_has_stable_public_shape_and_reopens(self):
        job = self.accept(client="hmac-fingerprint")
        self.assertEqual(
            set(job),
            {
                "job_id",
                "url",
                "state",
                "stage",
                "created_at",
                "expires_at",
                "pages_crawled",
                "score",
                "warnings",
                "files",
            },
        )
        self.assertEqual(job["url"], "https://example.com/")
        self.assertEqual(job["state"], "queued")
        self.assertEqual(job["stage"], "queued")
        self.assertEqual(job["expires_at"], job["created_at"] + 86400)
        self.assertEqual(Store(self.database).get(job["job_id"]), job)

    def test_canonical_url_idempotency_and_conflict(self):
        first = self.store.accept(
            "https://Example.com#ignored", "client", "same-key", 1_000
        )
        replay = self.store.accept("https://example.com/", "client", "same-key", 1_001)
        self.assertEqual(replay["job_id"], first["job_id"])
        with self.assertRaises(AdmissionError) as raised:
            self.store.accept("https://example.com/other", "client", "same-key", 1_001)
        self.assertEqual(raised.exception.code, "idempotency_conflict")
        self.assertEqual(raised.exception.status_code, 409)

    def test_same_key_concurrent_retry_reserves_once(self):
        def retry(_):
            return Store(self.database).accept(
                "https://example.com/", "same-client", "same-key", 2_000
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(retry, range(8)))
        self.assertEqual({job["job_id"] for job in results}, {results[0]["job_id"]})
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0], 1)
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM admission_ledger").fetchone()[0], 1
            )

    def test_fingerprint_rolling_limit_and_boundary(self):
        for index in range(3):
            self.accept(client="fingerprint", key=f"key-{index}", now=10_000)
        with self.assertRaises(AdmissionError) as raised:
            self.accept(client="fingerprint", key="key-3", now=10_000 + 86_399)
        self.assertEqual(raised.exception.code, "rate_limit")
        fourth = self.accept(client="fingerprint", key="key-4", now=10_000 + 86_400)
        self.assertEqual(fourth["state"], "queued")

    def test_pending_queue_cap_is_independent_of_active_executor(self):
        active = self.accept(client="active", key="active-key")
        self.assertEqual(self.store.claim(active["created_at"])["state"], "auditing")
        for index in range(10):
            self.accept(client=f"queued-{index}", key=f"queued-key-{index}")
        with self.assertRaises(AdmissionError) as raised:
            self.accept(client="queued-10", key="queued-key-10")
        self.assertEqual(raised.exception.code, "queue_limit")
        self.assertEqual(raised.exception.status_code, 429)

    def test_idempotent_replay_bypasses_full_limits_but_conflict_does_not(self):
        original = self.accept(client="replay", key="replay-key")
        for index in range(9):
            self.accept(client=f"other-{index}", key=f"other-key-{index}")
        self.assertEqual(
            self.store.accept("https://example.com/", "replay", "replay-key", 1_700_000_001)["job_id"],
            original["job_id"],
        )
        with self.assertRaises(AdmissionError) as raised:
            self.store.accept("https://other.example/", "replay", "replay-key", 1_700_000_001)
        self.assertEqual(raised.exception.code, "idempotency_conflict")

    def test_daily_twenty_reservations_then_next_day(self):
        start = dt.datetime(2026, 1, 1, 23, 59, 0, tzinfo=dt.timezone.utc).timestamp()
        for index in range(20):
            self.finish_accepted(f"daily-{index}", start)
        with self.assertRaises(AdmissionError) as raised:
            self.accept(client="daily-21", key="daily-21-key", now=start)
        self.assertEqual(raised.exception.code, "daily_limit")
        next_day = start + 61
        self.finish_accepted("next-day", next_day)
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT SUM(reserved_microdollars) FROM admission_ledger WHERE accepted_date = ?",
                    ("2026-01-01",),
                ).fetchone()[0],
                1_000_000,
            )

    def test_expired_replay_cannot_silently_create_paid_job(self):
        job = self.accept(client="expire", key="expire-key", now=100_000)
        self.assertEqual(self.store.expire(100_000 + 86400), [job["job_id"]])
        self.assertIsNone(self.store.get(job["job_id"]))
        with self.assertRaises(AdmissionError) as raised:
            self.store.accept("https://example.com/", "expire", "expire-key", 100_000 + 86400)
        self.assertEqual(raised.exception.code, "idempotency_expired")
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM admission_ledger").fetchone()[0], 1)

    def test_expired_replay_survives_unrelated_admission_for_48_hours(self):
        start = 200_000
        original = self.accept(client="original", key="original-key", now=start)
        self.assertEqual(self.store.expire(start + 86400), [original["job_id"]])
        unrelated = self.accept(client="unrelated", key="unrelated-key", now=start + 86401)
        with self.assertRaises(AdmissionError) as raised:
            self.store.accept(
                "https://example.com/",
                "original",
                "original-key",
                start + 86402,
            )
        self.assertEqual(raised.exception.code, "idempotency_expired")
        self.assertEqual(raised.exception.status_code, 409)
        self.assertIsNone(self.store.get(original["job_id"]))
        self.assertIsNotNone(self.store.get(unrelated["job_id"]))
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0], 1)
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM admission_ledger WHERE idempotency_key = ?",
                    ("original-key",),
                ).fetchone()[0],
                1,
            )

    def test_expired_queued_history_is_cleaned_after_48_hours_and_key_can_reuse(self):
        start = 300_000
        original = self.accept(client="queued-old", key="queued-old-key", now=start)
        # Leave the queued row in jobs. Cleanup must not retain its ledger forever.
        self.accept(client="unrelated", key="unrelated-key", now=start + 86401)
        replacement = self.store.accept(
            "https://example.com/",
            "queued-old",
            "queued-old-key",
            start + 172801,
        )
        self.assertNotEqual(replacement["job_id"], original["job_id"])
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM admission_ledger WHERE idempotency_key = ?",
                    ("queued-old-key",),
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM jobs WHERE job_id = ?",
                    (original["job_id"],),
                ).fetchone()[0],
                1,
            )

    def test_simultaneous_claim_has_one_executor(self):
        for index in range(3):
            self.accept(client=f"claim-{index}", key=f"claim-key-{index}")

        def claim(_):
            return Store(self.database).claim(1_700_000_001)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            claimed = [job for job in pool.map(claim, range(8)) if job is not None]
        self.assertEqual(len(claimed), 1)
        self.assertEqual(claimed[0]["state"], "auditing")

    def test_legal_transitions_and_terminal_jobs_are_immutable(self):
        job = self.accept()
        with self.assertRaises(ValueError):
            self.store.progress(job["job_id"], "crawl", 1)
        self.store.claim(job["created_at"])
        self.store.progress(job["job_id"], "crawl", 3)
        self.store.begin_rendering(job["job_id"])
        self.store.progress(job["job_id"], "render", 3)
        self.store.finish(
            job["job_id"],
            "completed",
            {"score": 81, "warnings": ["partial provider data"], "files": ["report.pdf"]},
        )
        result = self.store.get(job["job_id"])
        self.assertEqual(result["state"], "completed")
        self.assertEqual(result["score"], 81)
        self.assertEqual(result["warnings"], ["partial provider data"])
        self.assertEqual(result["files"], ["report.pdf"])
        with self.assertRaises(ValueError):
            self.store.progress(job["job_id"], "late", 4)
        with self.assertRaises(ValueError):
            self.store.finish(job["job_id"], "failed", {})

    def test_restart_recovery_fails_active_jobs_without_releasing_admission(self):
        interrupted = self.accept(client="interrupted", key="interrupted-key")
        self.store.claim(interrupted["created_at"])
        queued = self.accept(client="queued", key="queued-key")
        recovered = Store(self.database).recover_interrupted(interrupted["created_at"] + 1)
        self.assertEqual(recovered, 1)
        recovered_job = self.store.get(interrupted["job_id"])
        self.assertEqual(recovered_job["state"], "failed")
        self.assertTrue(any("restart" in warning.lower() for warning in recovered_job["warnings"]))
        self.assertEqual(self.store.get(queued["job_id"])["state"], "queued")
        claimed = self.store.claim(interrupted["created_at"] + 1)
        self.assertEqual(claimed["job_id"], queued["job_id"])

    def test_expiration_removes_jobs_but_not_admission_history(self):
        first_jobs = [
            self.accept(client="first", key=f"first-key-{index}", now=50_000)
            for index in range(3)
        ]
        second = self.accept(client="second", key="second-key", now=50_000)
        first = first_jobs[0]
        self.assertEqual(
            self.store.expire(50_000 + 86_400),
            [job["job_id"] for job in first_jobs] + [second["job_id"]],
        )
        self.assertIsNone(self.store.get(first["job_id"]))
        replacement = self.accept(client="first", key="new-key", now=50_000 + 86_401)
        self.assertNotIn(replacement["job_id"], {job["job_id"] for job in first_jobs})


if __name__ == "__main__":
    unittest.main()
