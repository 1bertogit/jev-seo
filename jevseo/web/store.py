"""SQLite-backed admission, queue, and job state for web audits."""

from __future__ import annotations

import contextlib
import datetime as _datetime
import hashlib
import json
import math
import sqlite3
import uuid
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


RESERVATION_MICRODOLLARS = 50_000
DAILY_RESERVATION_MICRODOLLARS = 1_000_000
DAILY_ACCEPT_LIMIT = 20
ROLLING_WINDOW_SECONDS = 86_400
LEDGER_RETENTION_SECONDS = ROLLING_WINDOW_SECONDS * 2
QUEUE_LIMIT = 10
CLIENT_LIMIT = 3

_ACTIVE_STATES = ("auditing", "rendering")
_TERMINAL_STATES = ("completed", "partial", "failed")
_PUBLIC_KEYS = (
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
)


class AdmissionError(Exception):
    """A rejected admission with a stable public error code and HTTP status."""

    def __init__(self, code: str, status_code: int, message: str | None = None):
        self.code = code
        self.status_code = status_code
        super().__init__(message or code)


class Store:
    """Durable state store; every mutating operation uses one SQLite write lock."""

    def __init__(self, database: Path):
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state IN
                        ('queued', 'auditing', 'rendering', 'completed', 'partial', 'failed')),
                    stage TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    pages_crawled INTEGER,
                    score REAL,
                    warnings_json TEXT NOT NULL,
                    files_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS admission_ledger (
                    ledger_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL UNIQUE,
                    fingerprint TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    canonical_url TEXT NOT NULL,
                    accepted_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    accepted_date TEXT NOT NULL,
                    reserved_microdollars INTEGER NOT NULL
                        CHECK (reserved_microdollars = 50000)
                );

                CREATE UNIQUE INDEX IF NOT EXISTS one_active_executor
                    ON jobs ((1))
                    WHERE state IN ('auditing', 'rendering');
                CREATE UNIQUE INDEX IF NOT EXISTS one_idempotency_key_per_client
                    ON admission_ledger (fingerprint, idempotency_key);
                CREATE INDEX IF NOT EXISTS ledger_fingerprint_time
                    ON admission_ledger (fingerprint, accepted_at);
                CREATE INDEX IF NOT EXISTS ledger_date
                    ON admission_ledger (accepted_date);
                CREATE INDEX IF NOT EXISTS jobs_queue
                    ON jobs (state, created_at);
                """
            )

    def accept(self, url: str, client_key: str, idempotency_key: str, now: float) -> dict:
        """Atomically replay or admit one paid, queued job."""
        canonical_url = _canonical_url(url)
        now = _timestamp(now)
        if not isinstance(client_key, str) or not client_key:
            raise ValueError("client_key must be a non-empty string")
        if not isinstance(idempotency_key, str) or not idempotency_key:
            raise ValueError("idempotency_key must be a non-empty string")
        fingerprint = hashlib.sha256(client_key.encode("utf-8")).hexdigest()
        accepted_date = _utc_date(now)

        with self._write_transaction() as connection:
            existing = connection.execute(
                """
                SELECT l.*, j.job_id AS existing_job_id, j.state AS existing_state
                FROM admission_ledger AS l
                LEFT JOIN jobs AS j ON j.job_id = l.job_id
                WHERE l.fingerprint = ? AND l.idempotency_key = ?
                """,
                (fingerprint, idempotency_key),
            ).fetchone()
            if existing is not None:
                if (
                    now >= existing["accepted_at"] + LEDGER_RETENTION_SECONDS
                    and existing["existing_state"] not in _ACTIVE_STATES
                ):
                    connection.execute(
                        "DELETE FROM admission_ledger WHERE ledger_id = ?",
                        (existing["ledger_id"],),
                    )
                    existing = None
            if existing is not None:
                if existing["canonical_url"] != canonical_url:
                    raise AdmissionError("idempotency_conflict", 409)
                if now >= existing["expires_at"]:
                    raise AdmissionError("idempotency_expired", 409)
                if existing["existing_job_id"] is None:
                    raise AdmissionError("idempotency_unavailable", 409)
                return self._job_from_row(
                    connection.execute(
                        "SELECT * FROM jobs WHERE job_id = ?",
                        (existing["job_id"],),
                    ).fetchone()
                )

            self._cleanup_ledger(connection, now)

            client_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM admission_ledger
                WHERE fingerprint = ? AND accepted_at > ?
                """,
                (fingerprint, now - ROLLING_WINDOW_SECONDS),
            ).fetchone()[0]
            if client_count >= CLIENT_LIMIT:
                raise AdmissionError("rate_limit", 429)

            queued_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM jobs
                WHERE state = 'queued' AND expires_at > ?
                """,
                (now,),
            ).fetchone()[0]
            if queued_count >= QUEUE_LIMIT:
                raise AdmissionError("queue_limit", 429)

            daily = connection.execute(
                """
                SELECT COUNT(*), COALESCE(SUM(reserved_microdollars), 0)
                FROM admission_ledger
                WHERE accepted_date = ?
                """,
                (accepted_date,),
            ).fetchone()
            if daily[0] >= DAILY_ACCEPT_LIMIT:
                raise AdmissionError("daily_limit", 429)
            if daily[1] + RESERVATION_MICRODOLLARS > DAILY_RESERVATION_MICRODOLLARS:
                raise AdmissionError("daily_budget", 429)

            job_id = uuid.uuid4().hex
            expires_at = now + ROLLING_WINDOW_SECONDS
            connection.execute(
                """
                INSERT INTO jobs (
                    job_id, url, state, stage, created_at, expires_at,
                    pages_crawled, score, warnings_json, files_json
                ) VALUES (?, ?, 'queued', 'queued', ?, ?, NULL, NULL, '[]', '[]')
                """,
                (job_id, canonical_url, now, expires_at),
            )
            connection.execute(
                """
                INSERT INTO admission_ledger (
                    job_id, fingerprint, idempotency_key, canonical_url,
                    accepted_at, expires_at, accepted_date, reserved_microdollars
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    fingerprint,
                    idempotency_key,
                    canonical_url,
                    now,
                    expires_at,
                    accepted_date,
                    RESERVATION_MICRODOLLARS,
                ),
            )
            return self._job_from_row(
                connection.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            )

    def claim(self, now: float) -> dict | None:
        """Claim the oldest unexpired queued job, if the executor is idle."""
        now = _timestamp(now)
        with self._write_transaction() as connection:
            if connection.execute(
                "SELECT 1 FROM jobs WHERE state IN ('auditing', 'rendering') LIMIT 1"
            ).fetchone():
                return None
            row = connection.execute(
                """
                SELECT * FROM jobs
                WHERE state = 'queued' AND expires_at > ?
                ORDER BY created_at ASC, rowid ASC
                LIMIT 1
                """,
                (now,),
            ).fetchone()
            if row is None:
                return None
            connection.execute(
                "UPDATE jobs SET state = 'auditing', stage = 'auditing' WHERE job_id = ?",
                (row["job_id"],),
            )
            return self._job_from_row(
                connection.execute(
                    "SELECT * FROM jobs WHERE job_id = ?", (row["job_id"],)
                ).fetchone()
            )

    def progress(self, job_id: str, stage: str, pages_crawled: int | None = None) -> None:
        """Update an active job without allowing a terminal job to be resurrected."""
        if not isinstance(stage, str) or not stage:
            raise ValueError("stage must be a non-empty string")
        if pages_crawled is not None and (
            isinstance(pages_crawled, bool)
            or not isinstance(pages_crawled, int)
            or pages_crawled < 0
        ):
            raise ValueError("pages_crawled must be a non-negative integer")
        with self._write_transaction() as connection:
            row = self._active_job(connection, job_id)
            if pages_crawled is None:
                connection.execute(
                    "UPDATE jobs SET stage = ? WHERE job_id = ?",
                    (stage, row["job_id"]),
                )
            else:
                connection.execute(
                    "UPDATE jobs SET stage = ?, pages_crawled = ? WHERE job_id = ?",
                    (stage, pages_crawled, row["job_id"]),
                )

    def begin_rendering(self, job_id: str) -> None:
        """Move an auditing job into the report-rendering phase."""
        with self._write_transaction() as connection:
            row = self._job_or_raise(connection, job_id)
            if row["state"] != "auditing":
                raise ValueError("only auditing jobs can begin rendering")
            connection.execute(
                "UPDATE jobs SET state = 'rendering', stage = 'rendering' WHERE job_id = ?",
                (job_id,),
            )

    def finish(self, job_id: str, state: str, result: dict) -> None:
        """Store terminal result data for an active job."""
        if state not in _TERMINAL_STATES:
            raise ValueError("state must be completed, partial, or failed")
        if not isinstance(result, dict):
            raise ValueError("result must be a dictionary")
        warnings = result.get("warnings", [])
        files = result.get("files", [])
        score = result.get("score")
        warnings_json = json.dumps(warnings, ensure_ascii=False, separators=(",", ":"))
        files_json = json.dumps(files, ensure_ascii=False, separators=(",", ":"))
        with self._write_transaction() as connection:
            row = self._active_job(connection, job_id)
            connection.execute(
                """
                UPDATE jobs
                SET state = ?, stage = ?, score = ?, warnings_json = ?, files_json = ?
                WHERE job_id = ?
                """,
                (state, state, score, warnings_json, files_json, row["job_id"]),
            )

    def get(self, job_id: str) -> dict | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
            return None if row is None else self._job_from_row(row)

    def recover_interrupted(self, now: float) -> int:
        """Fail active jobs after restart; the caller must hold the startup lock."""
        _timestamp(now)  # The timestamp is part of the startup contract, not a lease.
        warning = "Audit interrupted by service restart."
        with self._write_transaction() as connection:
            rows = connection.execute(
                """
                SELECT * FROM jobs
                WHERE state IN ('auditing', 'rendering')
                ORDER BY rowid
                """
            ).fetchall()
            for row in rows:
                warnings = _json_value(row["warnings_json"], [])
                if warning not in warnings:
                    warnings.append(warning)
                connection.execute(
                    """
                    UPDATE jobs
                    SET state = 'failed', stage = 'failed', warnings_json = ?
                    WHERE job_id = ? AND state IN ('auditing', 'rendering')
                    """,
                    (json.dumps(warnings, ensure_ascii=False, separators=(",", ":")), row["job_id"]),
                )
            return len(rows)

    def expire(self, now: float) -> list[str]:
        """Remove expired job rows while leaving admission ledger reservations intact."""
        now = _timestamp(now)
        with self._write_transaction() as connection:
            rows = connection.execute(
                """
                SELECT job_id FROM jobs
                WHERE expires_at <= ?
                ORDER BY expires_at ASC, rowid ASC
                """,
                (now,),
            ).fetchall()
            job_ids = [row["job_id"] for row in rows]
            if job_ids:
                connection.execute("DELETE FROM jobs WHERE expires_at <= ?", (now,))
            return job_ids

    @contextlib.contextmanager
    def _connection(self):
        connection = sqlite3.connect(
            self.database,
            timeout=30,
            isolation_level=None,
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 30000")
        try:
            yield connection
        finally:
            connection.close()

    @contextlib.contextmanager
    def _write_transaction(self):
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                connection.rollback()
                raise
            else:
                connection.commit()

    @staticmethod
    def _job_or_raise(connection, job_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM jobs WHERE job_id = ?", (job_id,)
        ).fetchone()
        if row is None:
            raise KeyError(job_id)
        return row

    @classmethod
    def _active_job(cls, connection, job_id: str) -> sqlite3.Row:
        row = cls._job_or_raise(connection, job_id)
        if row["state"] not in _ACTIVE_STATES:
            raise ValueError("job is not active")
        return row

    @staticmethod
    def _job_from_row(row: sqlite3.Row) -> dict:
        if row is None:
            raise KeyError("job row disappeared")
        return {
            "job_id": row["job_id"],
            "url": row["url"],
            "state": row["state"],
            "stage": row["stage"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "pages_crawled": row["pages_crawled"],
            "score": row["score"],
            "warnings": _json_value(row["warnings_json"], []),
            "files": _json_value(row["files_json"], []),
        }

    @staticmethod
    def _cleanup_ledger(connection, now: float) -> None:
        cutoff = now - LEDGER_RETENTION_SECONDS
        connection.execute(
            """
            DELETE FROM admission_ledger
            WHERE accepted_at <= ?
              AND NOT EXISTS (
                  SELECT 1 FROM jobs
                  WHERE jobs.job_id = admission_ledger.job_id
                    AND jobs.state IN ('auditing', 'rendering')
              )
            """,
            (cutoff,),
        )


def _timestamp(value: float) -> float:
    try:
        timestamp = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("now must be a finite Unix timestamp") from exc
    if not math.isfinite(timestamp):
        raise ValueError("now must be a finite Unix timestamp")
    return timestamp


def _utc_date(timestamp: float) -> str:
    return _datetime.datetime.fromtimestamp(timestamp, tz=_datetime.timezone.utc).date().isoformat()


def _json_value(value: str, default):
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return default
    return parsed


def _canonical_url(url: str) -> str:
    if not isinstance(url, str) or not url or any(ord(char) < 32 for char in url):
        raise ValueError("url must be an HTTP(S) URL")
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("url must be an HTTP(S) URL") from exc
    if scheme not in {"http", "https"} or not hostname or parsed.username is not None:
        raise ValueError("url must be an HTTP(S) URL without credentials")
    try:
        hostname = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("url must contain a valid hostname") from exc
    if not hostname:
        raise ValueError("url must contain a valid hostname")
    if ":" in hostname:
        netloc = f"[{hostname}]"
    else:
        netloc = hostname
    if port is not None and port != (443 if scheme == "https" else 80):
        netloc = f"{netloc}:{port}"
    return urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, ""))
