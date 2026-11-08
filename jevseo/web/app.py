"""FastAPI surface for authenticated, asynchronous hosted audits."""
from __future__ import annotations

import asyncio
import hmac
import json
import os
import re
import stat
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from .config import WebConfig
from .runner import MAX_ARTIFACT_BYTES, JobService, sandbox_available, task_token, validate_artifact_bytes

try:
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import JSONResponse, Response
except ImportError as exc:  # pragma: no cover - the web extra supplies this module
    raise RuntimeError("install the optional 'web' extra to run jevseo.web") from exc


BODY_LIMIT = 8 * 1024
JOB_ID = re.compile(r"^[0-9a-f]{32}$")
FINGERPRINT = re.compile(r"^[0-9a-fA-F]{64}$")
IDEMPOTENCY = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
FORMAT_FILES = {"pdf": "report.pdf", "xlsx": "report.xlsx", "md": "report.md"}
FORMAT_MEDIA = {"pdf": "application/pdf", "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "md": "text/markdown; charset=utf-8"}
ERROR_MESSAGES = {
    "unauthorized": "Authentication required.",
    "invalid_request": "The request is invalid.",
    "not_found": "The requested job or file was not found.",
    "expired": "The job has expired.",
    "not_ready": "The audit service is not ready.",
    "idempotency_conflict": "That idempotency key was already used for another URL.",
    "rate_limit": "The client job limit was reached.",
    "queue_limit": "The service queue is full.",
    "daily_limit": "The service daily limit was reached.",
    "daily_budget": "The service daily budget was reached.",
    "idempotency_expired": "That idempotency key has expired.",
    "idempotency_unavailable": "That idempotency key is unavailable.",
}


def iso_time(value: float) -> str:
    return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def validate_public_url(url: str) -> str:
    """Resolve the shared crawler validator lazily so this module stays importable during setup."""
    from jevseo.crawl import validate_public_url as validator

    return validator(url)


def _error(code: str, status: int) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code, "message": ERROR_MESSAGES.get(code, ERROR_MESSAGES["invalid_request"])})


class _GateBusy(Exception):
    pass


class _BlockingGate:
    """Event-loop-owned slots; release is deferred until the worker future ends."""

    def __init__(self, limit: int):
        self.limit = limit
        self.available = limit

    def acquire(self) -> bool:
        if self.available <= 0:
            return False
        self.available -= 1
        return True

    def release(self) -> None:
        self.available = min(self.limit, self.available + 1)


def _ready_errors(config: WebConfig) -> list[str]:
    errors = config.errors(check_sandbox=False)
    if not sandbox_available():
        errors.append("hosted sandbox unavailable")
    return errors


def _authorized(request: Request, config: WebConfig) -> None:
    header = request.headers.get("authorization", "")
    expected = f"Bearer {config.service_token or ''}"
    try:
        matches = hmac.compare_digest(header.encode("ascii"), expected.encode("ascii"))
    except UnicodeEncodeError:
        matches = False
    if not config.service_token or not matches:
        raise _error("unauthorized", 401)


def _job_authorized(request: Request, config: WebConfig, job_id: str) -> None:
    _authorized(request, config)
    if not JOB_ID.fullmatch(job_id):
        raise _error("not_found", 404)
    supplied = request.headers.get("x-job-token", "")
    try:
        expected = task_token(config.task_secret or "", job_id)
        matches = hmac.compare_digest(supplied.encode("ascii"), expected.encode("ascii"))
    except (UnicodeEncodeError, ValueError):
        matches = False
    if not config.task_secret or not matches:
        raise _error("unauthorized", 401)


async def _strict_body(request: Request) -> dict[str, Any]:
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > BODY_LIMIT:
            raise _error("invalid_request", 400)
        chunks.append(chunk)
    try:
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError
                result[key] = value
            return result

        body = json.loads(b"".join(chunks), object_pairs_hook=pairs)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError, TypeError):
        raise _error("invalid_request", 400)
    if not isinstance(body, dict) or set(body) != {"url"} or not isinstance(body["url"], str):
        raise _error("invalid_request", 400)
    return body


def _status(job: dict) -> dict:
    warnings = [
        "A auditoria foi interrompida após o reinício do serviço."
        if warning == "Audit interrupted by service restart."
        else warning
        for warning in job["warnings"]
    ]
    return {
        "jobId": job["job_id"],
        "state": job["state"],
        "stage": job["stage"],
        "pagesCrawled": job["pages_crawled"],
        "score": job["score"],
        "warnings": warnings,
        "files": [fmt for fmt in job["files"] if fmt in FORMAT_FILES],
        "expiresAt": iso_time(job["expires_at"]),
    }


def _secure_artifact(config: WebConfig, job_id: str, fmt: str) -> bytes | None:
    if config.jobs_dir is None or not JOB_ID.fullmatch(job_id) or fmt not in FORMAT_FILES:
        return None
    jobs_fd = job_fd = file_fd = None
    try:
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        jobs_fd = os.open(config.jobs_dir, os.O_RDONLY | os.O_DIRECTORY | nofollow)
        job_fd = os.open(job_id, os.O_RDONLY | os.O_DIRECTORY | nofollow, dir_fd=jobs_fd)
        file_fd = os.open(FORMAT_FILES[fmt], os.O_RDONLY | nofollow, dir_fd=job_fd)
        file_stat = os.fstat(file_fd)
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size <= 0 or file_stat.st_size > MAX_ARTIFACT_BYTES:
            return None
        data = b""
        while len(data) <= MAX_ARTIFACT_BYTES:
            chunk = os.read(file_fd, min(128 * 1024, MAX_ARTIFACT_BYTES + 1 - len(data)))
            if not chunk:
                break
            data += chunk
        if len(data) > MAX_ARTIFACT_BYTES:
            return None
        return data if validate_artifact_bytes(data, fmt) else None
    except (OSError, UnicodeError, ValueError):
        return None
    finally:
        for fd in (file_fd, job_fd, jobs_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass


def create_app(config: WebConfig | None = None) -> FastAPI:
    config = config or WebConfig.from_env()
    service = JobService(config)
    dns_gate = _BlockingGate(4)
    dns_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="jevseo-dns")

    async def run_gated(func, *args):
        if not dns_gate.acquire():
            raise _GateBusy
        loop = asyncio.get_running_loop()
        try:
            future = loop.run_in_executor(dns_executor, func, *args)
        except BaseException:
            dns_gate.release()
            raise
        try:
            result = await asyncio.shield(future)
        except asyncio.CancelledError:
            future.add_done_callback(lambda _future: dns_gate.release())
            raise
        except BaseException:
            dns_gate.release()
            raise
        else:
            dns_gate.release()
            return result

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        try:
            if not _ready_errors(config):
                service.start()
            yield
        finally:
            try:
                service.stop()
            finally:
                dns_executor.shutdown(wait=True)

    app = FastAPI(title="jevseo hosted audit service", lifespan=lifespan)
    app.state.web_config = config
    app.state.job_service = service
    app.state.dns_gate = dns_gate

    @app.exception_handler(HTTPException)
    async def http_error(_request: Request, exc: HTTPException):
        detail = exc.detail if isinstance(exc.detail, dict) else {"code": "invalid_request", "message": str(exc.detail)}
        return JSONResponse(status_code=exc.status_code, content={"error": detail})

    @app.middleware("http")
    async def no_store_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Robots-Tag"] = "noindex, noarchive"
        return response

    @app.get("/readyz")
    async def ready():
        try:
            errors = await run_gated(_ready_errors, config)
        except _GateBusy:
            raise _error("rate_limit", 429)
        if errors:
            raise _error("not_ready", 503)
        return {"status": "ready"}

    @app.post("/v1/jobs", status_code=202)
    async def create_job(request: Request):
        _authorized(request, config)
        try:
            not_ready = await run_gated(_ready_errors, config)
        except _GateBusy:
            raise _error("rate_limit", 429)
        if not_ready or service.store is None:
            raise _error("not_ready", 503)
        fingerprint = request.headers.get("x-client-fingerprint", "")
        if not FINGERPRINT.fullmatch(fingerprint):
            raise _error("invalid_request", 400)
        raw_key = request.headers.get("idempotency-key", "")
        if not IDEMPOTENCY.fullmatch(raw_key):
            raise _error("invalid_request", 400)
        body = await _strict_body(request)
        try:
            canonical_url = await run_gated(validate_public_url, body["url"])
        except _GateBusy:
            raise _error("rate_limit", 429)
        except (ValueError, TypeError):
            raise _error("invalid_request", 400)
        from .store import AdmissionError
        try:
            job = await asyncio.to_thread(service.store.accept, canonical_url, fingerprint, str(uuid.UUID(raw_key)), time_now())
        except AdmissionError as exc:
            raise _error(exc.code, exc.status_code)
        except (ValueError, TypeError):
            raise _error("invalid_request", 400)
        return {"jobId": job["job_id"], "token": task_token(config.task_secret, job["job_id"]), "expiresAt": iso_time(job["expires_at"])}

    @app.get("/v1/jobs/{job_id}")
    async def get_job(request: Request, job_id: str):
        _job_authorized(request, config, job_id)
        if service.store is None:
            raise _error("not_ready", 503)
        job = await asyncio.to_thread(service.store.get, job_id)
        if job is None:
            raise _error("not_found", 404)
        if time_now() >= job["expires_at"]:
            raise _error("expired", 410)
        return _status(job)

    @app.get("/v1/jobs/{job_id}/files/{fmt}")
    async def get_file(request: Request, job_id: str, fmt: str):
        _job_authorized(request, config, job_id)
        if service.store is None:
            raise _error("not_ready", 503)
        if fmt not in FORMAT_FILES:
            raise _error("not_found", 404)
        job = await asyncio.to_thread(service.store.get, job_id)
        if job is None:
            raise _error("not_found", 404)
        if time_now() >= job["expires_at"]:
            raise _error("expired", 410)
        if fmt not in job["files"]:
            raise _error("not_found", 404)
        data = await asyncio.to_thread(_secure_artifact, config, job_id, fmt)
        if data is None:
            raise _error("not_found", 404)
        return Response(
            content=data,
            media_type=FORMAT_MEDIA[fmt],
            headers={"Content-Disposition": f'attachment; filename="{FORMAT_FILES[fmt]}"'},
        )

    return app


def time_now() -> float:
    import time

    return time.time()


app = create_app()
