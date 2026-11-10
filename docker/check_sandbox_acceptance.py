"""Small, fail-closed retained-image worker acceptance harness.

This is intentionally not a policy or namespace test runner.  It exercises the
existing production runner with one synthetic audit and records only bounded,
non-secret evidence for a future staged invocation.
"""

from __future__ import annotations

import hashlib
import errno
import json
import os
import pwd
import re
import secrets
import stat
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from jevseo.parse import parse_page
from jevseo import checks, score
from jevseo.web.config import WebConfig
from jevseo.web.runner import (
    FORMATS,
    MAX_ARTIFACT_BYTES,
    _read_bounded_file,
    _run_contained,
    _valid_artifact,
    sandbox_available,
)


DATA_ROOT = Path("/data")
DEADLINE_SECONDS = 180.0
EXPECTED_UID = 10001
EXPECTED_GID = 10001
EXPECTED_APPARMOR = "jev-audit-bwrap (enforce)"
NATIVE_DATA_ROOT = Path("/var/lib/jev-audit-native-acceptance")
NATIVE_ACCOUNT = "jev-audit-api"
NATIVE_APPARMOR = "jev-audit-native (enforce)"
NATIVE_PROXY = "http://127.0.0.1:4750"
NATIVE_RUNTIME_RE = re.compile(r"^/opt/jev-audit-native/releases/[0-9a-f]{40}/venv$")
JOB_ID_RE = re.compile(r"^[0-9a-f]{32}$")
NAMESPACE_NAMES = ("mnt", "user", "pid", "ipc", "uts", "net", "cgroup")
REQUIRED_ASSERTIONS = (
    "job_writable",
    "runtime_ro",
    "app_ro",
    "hidden_data",
    "hidden_env",
    "provider_fake",
)


@dataclass(frozen=True)
class AcceptanceContext:
    """Trusted, fixed worker expectations for one acceptance invocation."""

    data_root: Path
    uid: int
    gid: int
    profile: str
    fake_proxy: str
    runtime_dir: Path


def _docker_context() -> AcceptanceContext:
    return AcceptanceContext(
        data_root=DATA_ROOT,
        uid=EXPECTED_UID,
        gid=EXPECTED_GID,
        profile=EXPECTED_APPARMOR,
        fake_proxy="http://10.0.9.4:4750",
        runtime_dir=Path("/usr/local"),
    )


def _native_context() -> AcceptanceContext:
    uid = os.getuid()
    if uid == 0 or os.geteuid() != uid:
        raise RuntimeError("native acceptance must run as the dedicated account")
    try:
        account = pwd.getpwuid(uid)
    except (KeyError, OSError) as exc:
        raise RuntimeError("native acceptance account lookup failed") from exc
    if (
        account.pw_name != NATIVE_ACCOUNT
        or os.getgid() != account.pw_gid
        or os.getegid() != account.pw_gid
        or account.pw_gid == 0
    ):
        raise RuntimeError("native acceptance identity mismatch")
    runtime_dir = Path(sys.prefix)
    if NATIVE_RUNTIME_RE.fullmatch(runtime_dir.as_posix()) is None:
        raise RuntimeError("native acceptance venv path is not fixed")
    return AcceptanceContext(
        data_root=NATIVE_DATA_ROOT,
        uid=uid,
        gid=account.pw_gid,
        profile=NATIVE_APPARMOR,
        fake_proxy=NATIVE_PROXY,
        runtime_dir=runtime_dir,
    )


def _parse_mode() -> bool:
    """Accept only the operator-selected native switch, before any host work."""
    args = sys.argv[1:]
    if args not in ([], ["--native"]):
        raise RuntimeError("only --native is accepted")
    return args == ["--native"]


def _owned_directory(path: Path, *, empty: bool = False) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise RuntimeError("directory unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise RuntimeError("directory ownership check failed")
    if empty:
        try:
            if next(path.iterdir(), None) is not None:
                raise RuntimeError("job directory is not empty")
        except OSError as exc:
            raise RuntimeError("directory enumeration failed") from exc


def _write_exclusive(path: Path, data: bytes) -> None:
    fd = None
    try:
        fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise RuntimeError("exclusive write failed")
            view = view[written:]
        os.fsync(fd)
    except OSError as exc:
        raise RuntimeError("exclusive file creation failed") from exc
    finally:
        if fd is not None:
            os.close(fd)


def _write_exclusive_text(path: Path, value: str) -> None:
    _write_exclusive(path, value.encode("utf-8"))


def _prepare_job_dir(data_root: Path, job_id: str) -> Path:
    if not JOB_ID_RE.fullmatch(job_id):
        raise RuntimeError("invalid job id")
    _owned_directory(data_root)
    jobs = data_root / "jobs"
    if jobs.exists() or jobs.is_symlink():
        _owned_directory(jobs)
    else:
        try:
            jobs.mkdir(mode=0o700)
        except OSError as exc:
            raise RuntimeError("jobs directory creation failed") from exc
        _owned_directory(jobs)
    job = jobs / job_id
    try:
        job.mkdir(mode=0o700)
    except OSError as exc:
        raise RuntimeError("job directory already exists or cannot be created") from exc
    _owned_directory(job, empty=True)
    _write_exclusive_text(job / ".acceptance-owner", job_id)
    return job


def _namespace_ids() -> dict[str, str]:
    return {name: os.readlink(f"/proc/self/ns/{name}") for name in NAMESPACE_NAMES}


def _namespace_match(worker: dict, outer: dict) -> bool:
    if set(worker) != set(NAMESPACE_NAMES) or set(outer) != set(NAMESPACE_NAMES):
        return False
    return (
        all(worker[name] != outer[name] for name in ("mnt", "user", "pid", "ipc", "uts"))
        and all(worker[name] == outer[name] for name in ("net", "cgroup"))
    )


def _worker_result_ok(
    result: dict,
    uid: int = EXPECTED_UID,
    gid: int = EXPECTED_GID,
    *,
    context: AcceptanceContext | None = None,
    stopped: bool = False,
    return_code: int | None = 0,
) -> bool:
    if context is not None:
        uid = context.uid
        gid = context.gid
    expected_profile = EXPECTED_APPARMOR if context is None else context.profile
    if stopped or return_code != 0 or not isinstance(result, dict) or result.get("ok") is not True:
        return False
    if result.get("uid") != uid or result.get("euid") != uid:
        return False
    if result.get("caps_eff") != "0000000000000000" or result.get("caps_bnd") != "0000000000000000":
        return False
    if result.get("no_new_privs") != 1:
        return False
    if result.get("gid") != gid or result.get("egid") != gid:
        return False
    apparmor = result.get("apparmor")
    if apparmor != expected_profile:
        return False
    assertions = result.get("assertions")
    return isinstance(assertions, dict) and all(assertions.get(name) is True for name in REQUIRED_ASSERTIONS)


def _write_error_proves_readonly(error: OSError) -> bool:
    return error.errno == errno.EROFS


def _worker_facts(result: dict) -> dict:
    return {
        "uid": result["uid"],
        "gid": result["gid"],
        "euid": result["euid"],
        "egid": result["egid"],
        "caps_eff": result["caps_eff"],
        "caps_bnd": result["caps_bnd"],
        "no_new_privs": result["no_new_privs"],
        "apparmor": result["apparmor"],
        "namespace_ids": {name: result["namespace_ids"][name] for name in NAMESPACE_NAMES},
        "assertions": {name: result["assertions"][name] for name in REQUIRED_ASSERTIONS},
    }


def _artifact_summary(path: Path, fmt: str) -> dict | None:
    if not _valid_artifact(path, fmt):
        return None
    data = _read_bounded_file(path, MAX_ARTIFACT_BYTES)
    if data is None:
        return None
    try:
        info = path.lstat()
    except OSError:
        return None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        return None
    return {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _artifacts_ok(artifacts: dict[str, dict | None]) -> bool:
    if set(artifacts) != set(FORMATS):
        return False
    return all(
        isinstance(value, dict)
        and isinstance(value.get("size"), int)
        and 0 < value["size"] <= MAX_ARTIFACT_BYTES
        and isinstance(value.get("sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is not None
        for value in artifacts.values()
    )


def build_synthetic_audit() -> dict:
    """Build one valid, no-provider audit using production checks and scoring."""
    home = "https://example.org/"
    html = (
        "<!doctype html><html lang='en'><head><title>Example home</title>"
        "<meta name='description' content='A synthetic acceptance page.'>"
        "<meta name='viewport' content='width=device-width'>"
        f"<link rel='canonical' href='{home}'></head>"
        "<body><main><h1>Example home</h1>"
        "<p>This synthetic page exists only for offline report rendering.</p>"
        "</main></body></html>"
    )
    page = parse_page(home, html, "example.org")
    page.update(
        {
            "url": home,
            "final_url": home,
            "kind": "page",
            "status": 200,
            "depth": 0,
            "inlinks": 1,
            "in_sitemap": True,
            "ttfb_ms": 20,
            "bytes": len(html.encode()),
            "headers": {
                "strict-transport-security": "max-age=31536000",
                "x-content-type-options": "nosniff",
                "referrer-policy": "no-referrer",
                "x-frame-options": "DENY",
            },
            "rendered": False,
            "js_dependent": False,
        }
    )
    crawl = {
        "input_url": home,
        "start_url": home,
        "final_url": home,
        "origin": "https://example.org",
        "domain": "example.org",
        "https": True,
        "robots": {
            "url": "https://example.org/robots.txt",
            "status": 200,
            "present": True,
            "sitemaps": ["https://example.org/sitemap.xml"],
            "crawl_delay": None,
            "disallow_all": False,
            "search_bots": {"Googlebot": True, "Bingbot": True},
            "ai_bots": {"GPTBot": True, "ClaudeBot": True},
            "ai_bots_named": [],
        },
        "sitemaps": {
            "files": [{"url": "https://example.org/sitemap.xml", "status": 200, "urls": 1, "error": None}],
            "urls": [home],
            "total_urls": 1,
        },
        "probes": {
            "http_to_https": True,
            "http_redirect_status": 301,
            "host_variant": {"host": "www.example.org", "status": 301, "redirect_status": 301, "redirects_to_canonical_host": True},
            "not_found_status": 404,
            "llms_txt": True,
        },
        "pages": [page],
        "link_status": {},
        "external_status": {},
        "external_total": 0,
        "blocked_by_robots": [],
        "render": {"mode": "never", "browser_available": False, "homepage_rendered": False},
        "requests": 1,
        "limits": {"max_pages": 1, "max_depth": 1, "time_budget_s": 1, "hit_page_cap": False, "hit_time_budget": False},
    }
    findings = checks.run_checks(crawl)
    judged = {"available": False, "site": None, "pages": {}, "pairs": [], "ledger": {}, "questions": {}}
    return {
        "schema_version": "1.0",
        "tool": {"name": "jev-seo", "version": "acceptance"},
        "run": {"started_at": "2026-01-01T00:00:00+00:00", "finished_at": "2026-01-01T00:00:01+00:00", "timings_s": {}, "options": {}},
        "site": {key: value for key, value in crawl.items() if key != "pages"},
        "pages": crawl["pages"],
        "findings": findings,
        "passed_rules": checks.passed_rules(findings),
        "jev": judged,
        "performance": None,
        "dataforseo": None,
        "scores": score.score(crawl, findings, judged, None),
        "actions": score.actions(findings, judged, 1),
    }


def _probe_source(
    job_id: str,
    outer_secret: Path,
    database: Path,
    other_sentinel: Path,
    context: AcceptanceContext | None = None,
) -> str:
    context = _docker_context() if context is None else context
    output = f"/job/probe-result.json"
    owner = "/job/.acceptance-owner"
    worker_marker = f"/job/.worker-write-{job_id}"
    app_canary = f"/runtime/jevseo/.jev-acceptance-ro-{job_id}"
    return f'''import errno, json, os, stat
import sys
from pathlib import Path

OUTPUT = {output!r}
OWNER = {owner!r}
WORKER_MARKER = {worker_marker!r}
APP_CANARY = {app_canary!r}
EXPECTED_RUNTIME_DIR = {str(context.runtime_dir)!r}
EXPECTED_UID = {context.uid!r}
EXPECTED_GID = {context.gid!r}
EXPECTED_APPARMOR = {context.profile!r}
EXPECTED_PROXY = {context.fake_proxy!r}
NATIVE_RUNTIME = {context.profile == NATIVE_APPARMOR!r}
OUTER_SECRET = {str(outer_secret)!r}
DATABASE = {str(database)!r}
OTHER_SENTINEL = {str(other_sentinel)!r}
JOB_ID = {job_id!r}

def ns_ids():
    return {{name: os.readlink("/proc/self/ns/" + name) for name in ("mnt", "user", "pid", "ipc", "uts", "net", "cgroup")}}

def status_values():
    values = {{}}
    for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
        key, _, value = line.partition(":")
        if key in ("CapEff", "CapBnd", "NoNewPrivs"):
            values[key] = value.strip()
    return values

def exclusive_marker(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, JOB_ID.encode("ascii"))
    finally:
        os.close(fd)

def write_fails(path):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        return False
    except OSError as exc:
        return exc.errno == errno.EROFS
    else:
        os.close(fd)
        try:
            os.unlink(path)
        except OSError:
            pass
        return False

def unreadable(path):
    try:
        Path(path).read_bytes()
    except OSError:
        return True
    return False

def write_result(result):
    fd = os.open(OUTPUT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        data = json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
        os.write(fd, data)
    finally:
        os.close(fd)

def main():
    values = status_values()
    apparmor = Path("/proc/self/attr/current").read_text(encoding="utf-8").strip()
    runtime_base = Path(sys.prefix) if NATIVE_RUNTIME else Path(EXPECTED_RUNTIME_DIR)
    runtime_canary = str(runtime_base / (".jev-acceptance-ro-" + JOB_ID))
    owner_ok = (not Path(OWNER).is_symlink() and Path(OWNER).read_text(encoding="ascii") == JOB_ID)
    exclusive_marker(WORKER_MARKER)
    assertions = {{
        "job_writable": owner_ok and Path(WORKER_MARKER).is_file(),
        "runtime_ro": (sys.prefix == EXPECTED_RUNTIME_DIR if NATIVE_RUNTIME else True) and runtime_base.is_dir() and write_fails(runtime_canary),
        "app_ro": Path("/runtime/jevseo/web/runner.py").is_file() and write_fails(APP_CANARY),
        "hidden_data": all(unreadable(path) for path in (OUTER_SECRET, DATABASE, OTHER_SENTINEL)),
        "hidden_env": all(os.environ.get(name) is None for name in ("JEV_AUDIT_SERVICE_TOKEN", "JEV_AUDIT_TASK_SECRET", "JEV_ACCEPTANCE_OUTER_SECRET")),
        "provider_fake": os.environ.get("TYPESAFE_API_KEY") == "fake-provider-key" and os.environ.get("JEVSEO_EGRESS_PROXY") == EXPECTED_PROXY,
    }}
    result = {{
        "ok": all(assertions.values()) and os.getuid() == EXPECTED_UID and os.geteuid() == EXPECTED_UID and os.getgid() == EXPECTED_GID and os.getegid() == EXPECTED_GID and int(values.get("NoNewPrivs", "0")) == 1 and int(values.get("CapEff", "-1"), 16) == 0 and int(values.get("CapBnd", "-1"), 16) == 0 and apparmor == EXPECTED_APPARMOR,
        "uid": os.getuid(), "gid": os.getgid(), "euid": os.geteuid(), "egid": os.getegid(),
        "caps_eff": values.get("CapEff", ""), "caps_bnd": values.get("CapBnd", ""),
        "no_new_privs": int(values.get("NoNewPrivs", "0")), "apparmor": apparmor,
        "namespace_ids": ns_ids(), "assertions": assertions,
    }}
    write_result(result)
    return 0 if result["ok"] else 1

try:
    result_code = main()
except Exception:
    try:
        write_result({{"ok": False, "assertions": {{name: False for name in ("job_writable", "runtime_ro", "app_ro", "hidden_data", "hidden_env", "provider_fake")}}}})
    except Exception:
        pass
    raise SystemExit(1)
raise SystemExit(result_code)
'''


def _read_json(path: Path, limit: int = 64 * 1024) -> dict | None:
    data = _read_bounded_file(path, limit)
    if data is None:
        return None
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _run(context: AcceptanceContext | None = None) -> dict:
    if context is None:
        context = _native_context() if _parse_mode() else _docker_context()
    if not sandbox_available():
        raise RuntimeError("sandbox unavailable")
    job_id = secrets.token_hex(16)
    job = _prepare_job_dir(context.data_root, job_id)
    other_id = hashlib.sha256((job_id + "-other").encode("ascii")).hexdigest()[:32]
    other_job = context.data_root / "jobs" / other_id
    other_job.mkdir(mode=0o700)
    _owned_directory(other_job, empty=True)
    outer_secret = context.data_root / ".acceptance-outer-secret"
    database = context.data_root / "jobs.sqlite3"
    other_sentinel = other_job / "sentinel"
    _write_exclusive_text(outer_secret, "outer-secret-canary")
    _write_exclusive_text(database, "database-canary")
    _write_exclusive_text(other_sentinel, "other-job-canary")
    _write_exclusive(
        job / "probe.py",
        _probe_source(job_id, outer_secret, database, other_sentinel, context=context).encode("utf-8"),
    )
    outer_ns = _namespace_ids()
    config = WebConfig(
        data_dir=context.data_root,
        service_token="service-secret-canary-" + job_id,
        task_secret="task-secret-canary-" + job_id,
        typesafe_api_key="fake-provider-key",
        pagespeed_api_key=None,
        egress_proxy=context.fake_proxy,
    )
    sentinel_env = {"JEV_ACCEPTANCE_OUTER_SECRET": "outer-env-secret-canary", "JEV_AUDIT_SERVICE_TOKEN": config.service_token, "JEV_AUDIT_TASK_SECRET": config.task_secret}
    previous_env = {name: os.environ.get(name) for name in sentinel_env}
    os.environ.update(sentinel_env)
    deadline = time.monotonic() + DEADLINE_SECONDS
    try:
        code, stopped = _run_contained(job, config, [sys.executable, "/job/probe.py"], deadline, threading.Event(), lambda *_: None)
    finally:
        for name, value in previous_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    result = _read_json(job / "probe-result.json")
    if result is None or not _worker_result_ok(result, context=context, stopped=stopped, return_code=code):
        raise RuntimeError("worker probe failed")
    worker_ns = result.get("namespace_ids")
    if not isinstance(worker_ns, dict) or not _namespace_match(worker_ns, outer_ns):
        raise RuntimeError("namespace comparison failed")
    _write_exclusive_text(job / "audit.json", json.dumps(build_synthetic_audit(), separators=(",", ":")))
    artifacts: dict[str, dict | None] = {}
    for fmt in FORMATS:
        if time.monotonic() >= deadline:
            raise RuntimeError("acceptance deadline reached")
        code, stopped = _run_contained(
            job,
            config,
            [sys.executable, "-m", "jevseo", "render", "/job", "--formats", fmt],
            deadline,
            threading.Event(),
            lambda *_: None,
        )
        if code != 0 or stopped:
            raise RuntimeError("render failed")
        artifacts[fmt] = _artifact_summary(job / f"report.{fmt}", fmt)
    if not _artifacts_ok(artifacts):
        raise RuntimeError("artifact validation failed")
    return {"ok": True, "worker": _worker_facts(result), "artifacts": artifacts}


def main() -> int:
    try:
        summary = _run()
    except Exception:
        summary = {"ok": False}
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0 if summary.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
