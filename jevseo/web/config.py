"""Explicit configuration for the hosted audit service.

The web service deliberately has no dotenv or home-directory lookup.  The
process supervisor is the trust boundary for these values.
"""
from __future__ import annotations

import os
import platform
import shutil
from dataclasses import dataclass
from pathlib import Path


def _proxy_error(value: str | None) -> str | None:
    if not value:
        return "JEVSEO_EGRESS_PROXY is required"
    try:
        from jevseo.crawl import validate_proxy_url

        validate_proxy_url(value)
    except (ImportError, ValueError, TypeError):
        return "JEVSEO_EGRESS_PROXY must be an HTTP(S) proxy with host and port"
    return None


@dataclass(frozen=True)
class WebConfig:
    data_dir: Path | None
    service_token: str | None
    task_secret: str | None
    typesafe_api_key: str | None
    pagespeed_api_key: str | None
    egress_proxy: str | None

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> "WebConfig":
        env = os.environ if environ is None else environ
        raw_dir = env.get("JEV_AUDIT_DATA_DIR")
        return cls(
            data_dir=Path(raw_dir).expanduser() if raw_dir else None,
            service_token=env.get("JEV_AUDIT_SERVICE_TOKEN"),
            task_secret=env.get("JEV_AUDIT_TASK_SECRET"),
            typesafe_api_key=env.get("TYPESAFE_API_KEY"),
            pagespeed_api_key=env.get("PAGESPEED_API_KEY"),
            egress_proxy=env.get("JEVSEO_EGRESS_PROXY"),
        )

    @property
    def database(self) -> Path | None:
        return self.data_dir / "jobs.sqlite3" if self.data_dir is not None else None

    @property
    def jobs_dir(self) -> Path | None:
        return self.data_dir / "jobs" if self.data_dir is not None else None

    def errors(self, *, check_sandbox: bool = True) -> list[str]:
        errors: list[str] = []
        if self.data_dir is None:
            errors.append("JEV_AUDIT_DATA_DIR is required")
        elif not self.data_dir.is_absolute():
            errors.append("JEV_AUDIT_DATA_DIR must be an absolute path")
        if not self.service_token or len(self.service_token) < 32:
            errors.append("JEV_AUDIT_SERVICE_TOKEN must be at least 32 characters")
        if not self.task_secret or len(self.task_secret) < 32:
            errors.append("JEV_AUDIT_TASK_SECRET must be at least 32 characters")
        if not self.typesafe_api_key:
            errors.append("TYPESAFE_API_KEY is required")
        proxy_error = _proxy_error(self.egress_proxy)
        if proxy_error:
            errors.append(proxy_error)
        if check_sandbox:
            if platform.system() != "Linux":
                errors.append("hosted service requires Linux")
            if shutil.which("bwrap") is None:
                errors.append("Bubblewrap (bwrap) is unavailable")
            if shutil.which("prlimit") is None:
                errors.append("prlimit is unavailable")
        return errors

    def readiness_errors(self) -> list[str]:
        """Return safe operator-facing reasons, never secret values."""
        return self.errors()

    def configuration_errors(self) -> list[str]:
        return self.errors(check_sandbox=False)

    def is_ready(self) -> bool:
        return not self.errors()

    @property
    def ready(self) -> bool:
        return self.is_ready()
