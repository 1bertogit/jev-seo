"""Fail-closed Bubblewrap runner for one hosted audit job."""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import logging
import os
import platform
import queue
import re
import shutil
import signal
import stat
import subprocess
import threading
import time
import zipfile
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from .config import WebConfig


LOG = logging.getLogger(__name__)
PACKAGE_DIR = Path(__file__).resolve().parents[1]
PACKAGE_PARENT = "/runtime"


DEADLINE_SECONDS = 900.0
MAX_OUTPUT_BYTES = 256 * 1024
MAX_AUDIT_BYTES = 8 * 1024 * 1024
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
FORMATS = ("pdf", "xlsx", "md")
_STAGES = {
    "1/7 Crawl": "crawling",
    "2/7 Rule checks": "checking",
    "3/7 DataForSEO": "dataforseo",
    "4/7 Jev judgments": "judging",
    "5/7 PageSpeed": "pagespeed",
    "6/7 Scoring": "scoring",
    "7/7 Render": "rendering",
}
_JOB_ID = re.compile(r"^[0-9a-f]{32}$")


def _runtime_dirs() -> tuple[Path, ...]:
    return tuple(path for path in (Path("/usr"), Path("/bin"), Path("/lib"), Path("/lib64")) if path.exists())


@lru_cache(maxsize=1)
def sandbox_available() -> bool:
    """Probe the actual namespace boundary once; a binary on PATH is insufficient."""
    if platform.system() != "Linux" or shutil.which("bwrap") is None or shutil.which("prlimit") is None:
        return False
    try:
        argv = [
            "bwrap", "--die-with-parent", "--unshare-user", "--unshare-pid",
            "--unshare-ipc", "--unshare-uts", "--cap-drop", "ALL",
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
        ]
        for path in _runtime_dirs():
            argv.extend(["--ro-bind", str(path), str(path)])
        argv.extend(["--", "/bin/true"])
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def task_token(task_secret: str, job_id: str) -> str:
    if not _JOB_ID.fullmatch(job_id):
        raise ValueError("invalid job id")
    return hmac.new(
        task_secret.encode("utf-8"),
        b"jevseo-job-task-token\x00" + job_id.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def _derive_task_token(task_secret: str, job_id: str) -> str:
    return task_token(task_secret, job_id)


def _worker_environment(config: WebConfig) -> dict[str, str]:
    """The only environment values that cross the worker boundary."""
    if not config.egress_proxy or not config.typesafe_api_key:
        raise RuntimeError("worker configuration is incomplete")
    from jevseo.crawl import validate_proxy_url

    proxy = validate_proxy_url(config.egress_proxy)
    return {
        "JEVSEO_HOSTED": "1",
        "JEVSEO_EGRESS_PROXY": proxy,
        "HTTP_PROXY": proxy,
        "HTTPS_PROXY": proxy,
        "TYPESAFE_API_KEY": config.typesafe_api_key,
        **({"PAGESPEED_API_KEY": config.pagespeed_api_key} if config.pagespeed_api_key else {}),
        "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "PYTHONPATH": PACKAGE_PARENT,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "MKL_NUM_THREADS": "1",
        "HOME": "/tmp",
    }


def _ro_mounts() -> list[tuple[Path, Path]]:
    """Return fixed runtime mounts without ever mounting the service data root."""
    paths = [
        *_runtime_dirs(),
        Path("/usr/share/fonts"), Path("/usr/local/share/fonts"),
        Path("/etc/fonts"), Path("/etc/hosts"), Path("/etc/nsswitch.conf"),
        Path("/etc/resolv.conf"), Path("/etc/ssl/certs"),
    ]
    executable = Path(os.path.realpath(os.sys.executable))
    paths.extend([Path(os.sys.prefix), executable.parent])
    result: list[tuple[Path, Path]] = []
    seen: set[str] = set()
    for path in paths:
        if not path.exists():
            continue
        key = str(path)
        if key not in seen:
            result.append((path, path))
            seen.add(key)
    return result


def _build_bwrap_argv(job_dir: Path, config: WebConfig, command: list[str]) -> list[str]:
    """Build a fresh namespace with only the current job writable."""
    argv = [
        "bwrap",
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--cap-drop", "ALL",
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
        "--dir", "/etc",
        "--dir", "/etc/fonts",
        "--dir", "/etc/ssl",
        "--dir", PACKAGE_PARENT,
        "--dir", "/job",
        "--bind", str(job_dir), "/job",
    ]
    forbidden = [Path.home().resolve()]
    if config.data_dir is not None:
        forbidden.append(config.data_dir.resolve())
    for source, target in _ro_mounts():
        resolved = source.resolve()
        if any(resolved == root or root in resolved.parents for root in forbidden):
            continue
        argv.extend(["--ro-bind", str(source), str(target)])
    package = PACKAGE_DIR.resolve()
    if not any(package == root or root in package.parents for root in forbidden):
        argv.extend(["--ro-bind", str(package), f"{PACKAGE_PARENT}/jevseo"])
    for key, value in _worker_environment(config).items():
        argv.extend(["--setenv", key, value])
    argv.extend(["--chdir", "/job", "--"])
    argv.extend(command)
    return argv


def _bounded_audit(path: Path) -> dict | None:
    try:
        raw = _read_bounded_file(path, MAX_AUDIT_BYTES)
        if raw is None:
            return None
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, RecursionError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("pages"), list) or len(data["pages"]) > 120:
        return None
    usable = [
        page for page in data["pages"]
        if isinstance(page, dict)
        and page.get("status") == 200
        and page.get("kind", "page") == "page"
        and "html" in str(page.get("content_type", "")).lower()
        and isinstance(page.get("word_count"), int)
        and isinstance(page.get("text_hash"), str)
        and re.fullmatch(r"[0-9a-f]{40}", page["text_hash"])
    ]
    if len(usable) > 60:
        return None
    return data if usable else None


def _read_bounded_file(path: Path, limit: int) -> bytes | None:
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > limit:
            return None
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(128 * 1024, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        return None if len(data) > limit else bytes(data)
    except OSError:
        return None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def validate_artifact_bytes(data: bytes, fmt: str) -> bool:
    if not data or len(data) > MAX_ARTIFACT_BYTES:
        return False
    try:
        if fmt == "pdf":
            return data.startswith(b"%PDF-")
        if fmt == "xlsx":
            if not data.startswith(b"PK"):
                return False
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                infos = archive.infolist()
                if len(infos) > 256 or sum(info.file_size for info in infos) > MAX_ARTIFACT_BYTES:
                    return False
                names = {info.filename for info in infos}
                return "[Content_Types].xml" in names and "xl/workbook.xml" in names
        if fmt == "md":
            data.decode("utf-8")
            return True
    except (UnicodeError, ValueError, zipfile.BadZipFile):
        return False
    return False


def _valid_artifact(path: Path, fmt: str) -> bool:
    return (data := _read_bounded_file(path, MAX_ARTIFACT_BYTES)) is not None and validate_artifact_bytes(data, fmt)


def _terminate_group(process: subprocess.Popen, grace: float = 2.0) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        try:
            process.terminate()
        except OSError:
            return
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            try:
                process.kill()
            except OSError:
                pass
        try:
            process.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            pass


def _launch_bwrap(argv: list[str], **kwargs):
    """Launch one contained process; kept separate so tests can fake the boundary."""
    return subprocess.Popen(argv, **kwargs)


def _run_contained(
    job_dir: Path,
    config: WebConfig,
    command: list[str],
    deadline: float,
    stop_event: threading.Event | None,
    on_progress,
) -> tuple[int | None, bool]:
    if not sandbox_available():
        raise RuntimeError("hosted sandbox unavailable")
    argv = _build_bwrap_argv(job_dir, config, command)
    # prlimit is an executable wrapper, not a Python preexec hook.
    argv = [
        "prlimit", "--cpu=900", "--as=2147483648", "--fsize=8388608", "--nproc=128", "--",
        *argv,
    ]
    env = _worker_environment(config)
    process = _launch_bwrap(
        argv,
        cwd=str(job_dir),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        text=True,
        bufsize=1,
    )
    output: queue.Queue[str] = queue.Queue(maxsize=256)

    def drain() -> None:
        stream = process.stdout
        if stream is None:
            return
        consumed = 0
        try:
            while True:
                line = stream.read(4096)
                if not line:
                    break
                if consumed < MAX_OUTPUT_BYTES:
                    consumed += len(line.encode("utf-8", "replace"))
                    try:
                        output.put_nowait(line)
                    except queue.Full:
                        pass
        finally:
            stream.close()

    reader = threading.Thread(target=drain, name="jevseo-job-output", daemon=True)
    reader.start()
    stopped = False

    carry = ""

    def handle_output(chunk: str) -> None:
        nonlocal carry
        if len(chunk) > 4096:
            chunk = chunk[:4096]
        text = carry + chunk
        lines = text.splitlines(keepends=True)
        carry = "" if not lines or lines[-1].endswith(("\n", "\r")) else lines.pop()[-1024:]
        for line in lines:
            count = re.search(r"\bcrawled\s+(\d{1,3})/60\s+URLs\b", line)
            if count:
                try:
                    on_progress("crawling", min(int(count.group(1)), 60))
                except Exception:
                    pass
            for marker, stage in _STAGES.items():
                if marker in line:
                    try:
                        on_progress(stage, None)
                    except Exception:  # callback is persistence, never worker control
                        pass
                    break

    try:
        while process.poll() is None:
            if time.monotonic() >= deadline or (stop_event is not None and stop_event.is_set()):
                stopped = True
                _terminate_group(process)
                break
            try:
                line = output.get(timeout=0.05)
            except queue.Empty:
                continue
            handle_output(line)
        return_code = process.wait()
    except BaseException:
        _terminate_group(process)
        raise
    reader.join(timeout=1)
    while True:
        try:
            line = output.get_nowait()
        except queue.Empty:
            break
        handle_output(line)
    if carry:
        handle_output("\n")
    return return_code, stopped


def _partial_reason(value: str) -> str:
    text = value.lower()
    if "not judged" in text:
        return "Some pages did not receive a Jev judgment."
    if "jev judgments unavailable" in text:
        return "Jev judgments were unavailable for this audit."
    if "pagespeed insights failed" in text:
        return "A PageSpeed run failed."
    if "pagespeed insights unavailable" in text:
        return "PageSpeed data was unavailable."
    if "page cap" in text:
        return "The crawl reached its page limit."
    if "time budget" in text:
        return "The crawl reached its time limit."
    if "javascript rendering unavailable" in text:
        return "JavaScript rendering was unavailable for some pages."
    return "A processing limit affected part of the audit."


def _augment_partial(audit: dict) -> list[str]:
    scores = audit.setdefault("scores", {})
    existing = scores.get("partial")
    partial = list(existing) if isinstance(existing, list) else ([] if not existing else [str(existing)])
    site = audit.get("site") or {}
    limits = site.get("limits") or {}
    if limits.get("hit_page_cap"):
        partial.append("Crawl page cap reached.")
    if limits.get("hit_time_budget"):
        partial.append("Crawl time budget reached.")
    if limits.get("hit_request_cap") or limits.get("hit_body_cap") or limits.get("hit_total_bytes_cap") or limits.get("hit_sitemap_cap"):
        partial.append("Hosted crawl byte/request limits reduced coverage.")
    if limits.get("reasons"):
        partial.append("Hosted crawl limits reduced coverage.")
    ledger = (audit.get("jev") or {}).get("ledger") or {}
    if ledger.get("failed") or ledger.get("skipped_budget"):
        partial.append("Some Jev judgments failed or were skipped by budget.")
    clean = []
    for reason in partial:
        if isinstance(reason, str) and reason:
            clean.append(reason[:300] if reason.startswith(("Crawl ", "Hosted ", "Some Jev ")) else _partial_reason(reason))
    scores["partial"] = list(dict.fromkeys(clean))
    return scores["partial"]


def _audit_warnings(audit: dict) -> list[str]:
    warnings: list[str] = []
    for reason in (audit.get("scores") or {}).get("partial") or []:
        if isinstance(reason, str):
            warnings.append(_partial_reason(reason))
    for warning in audit.get("warnings") or []:
        if isinstance(warning, str) and warning:
            warnings.append(_partial_reason(warning))
    return list(dict.fromkeys(warnings))


def run_job(job: dict, config: WebConfig, on_progress, stop_event: threading.Event | None = None) -> dict:
    """Run the audit and each report in one bounded, fail-closed worker lifecycle."""
    job_id = str(job.get("job_id", ""))
    url = job.get("url")
    if not _JOB_ID.fullmatch(job_id) or not isinstance(url, str) or config.configuration_errors() or not sandbox_available():
        return {"state": "failed", "pages_crawled": None, "score": None, "warnings": ["O trabalhador hospedado não está pronto."], "files": []}
    job_dir = config.jobs_dir / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + DEADLINE_SECONDS
    warnings: list[str] = []
    try:
        return_code, stopped = _run_contained(
            job_dir,
            config,
            [
                os.sys.executable,
                "-m", "jevseo", "audit", url,
                "--out", "/job",
                "--max-pages", "60",
                "--jev-pages", "60",
                "--jev-budget", "0.05",
                "--render", "never",
            ],
            deadline,
            stop_event,
            on_progress,
        )
    except (OSError, RuntimeError) as exc:
        return {"state": "failed", "pages_crawled": None, "score": None, "warnings": ["O trabalhador hospedado não pôde iniciar com segurança."], "files": []}
    if stopped:
        warnings.append("A auditoria foi interrompida pelo prazo do serviço.")
    audit = _bounded_audit(job_dir / "audit.json")
    if return_code != 0:
        warnings.append("O processo de auditoria reportou uma falha.")
    if audit is None:
        return {"state": "failed", "pages_crawled": None, "score": None, "warnings": warnings or ["A auditoria não produziu evidências HTTP utilizáveis."], "files": []}
    _augment_partial(audit)
    try:
        (job_dir / "audit.json").write_text(json.dumps(audit, indent=1, ensure_ascii=False), encoding="utf-8")
    except OSError:
        warnings.append("A cobertura parcial não pôde ser salva no relatório.")
    pages = [
        p for p in audit["pages"]
        if isinstance(p, dict)
        and p.get("status") == 200
        and p.get("kind", "page") == "page"
        and "html" in str(p.get("content_type", "")).lower()
        and isinstance(p.get("word_count"), int)
        and isinstance(p.get("text_hash"), str)
        and re.fullmatch(r"[0-9a-f]{40}", p["text_hash"])
    ]
    pages_crawled = len(pages)
    score = (audit.get("scores") or {}).get("overall")
    warnings.extend(_audit_warnings(audit))
    try:
        on_progress("rendering", pages_crawled)
    except TypeError:
        try:
            on_progress("rendering")
        except Exception:
            pass
    except Exception:
        pass
    for fmt in FORMATS:
        if stop_event is not None and stop_event.is_set():
            warnings.append("A renderização foi interrompida durante o encerramento do serviço.")
            break
        if time.monotonic() >= deadline:
            warnings.append("A renderização atingiu o prazo do serviço.")
            break
        try:
            code, render_stopped = _run_contained(
                job_dir,
                config,
                [os.sys.executable, "-m", "jevseo", "render", "/job", "--formats", fmt],
                deadline,
                stop_event,
                on_progress,
            )
        except (OSError, RuntimeError):
            code, render_stopped = None, False
        if render_stopped:
            warnings.append(f"A renderização {fmt.upper()} foi interrompida antes de terminar.")
        if code == 0 and _valid_artifact(job_dir / f"report.{fmt}", fmt):
            continue
        warnings.append(f"O relatório {fmt.upper()} não pôde ser gerado.")
    files = [fmt for fmt in FORMATS if _valid_artifact(job_dir / f"report.{fmt}", fmt)]
    warnings = list(dict.fromkeys(warnings))
    limits = audit.get("site", {}).get("limits", {}) or {}
    material_limit = bool(limits.get("hit_page_cap") or limits.get("hit_time_budget"))
    state = "completed" if files == list(FORMATS) and not material_limit and not warnings else "partial"
    return {"state": state, "pages_crawled": pages_crawled, "score": score, "warnings": warnings, "files": files}


class JobService:
    """One locked SQLite worker and its shutdown lifecycle."""

    def __init__(self, config: WebConfig):
        self.config = config
        self.store = None
        self._lock_file = None
        self._executor = None
        self._future = None
        self._stop = threading.Event()
        self._active_stop = None

    def start(self) -> None:
        if self.config.configuration_errors():
            return
        import fcntl
        from concurrent.futures import ThreadPoolExecutor
        from .store import Store

        self.config.data_dir.mkdir(parents=True, exist_ok=True)
        self.config.jobs_dir.mkdir(parents=True, exist_ok=True)
        self._lock_file = open(self.config.data_dir / "worker.lock", "a+")
        try:
            fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError) as exc:
            self._lock_file.close()
            self._lock_file = None
            raise RuntimeError("another hosted worker already owns the data directory") from exc
        self.store = Store(self.config.database)
        self.store.recover_interrupted(time.time())
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="jevseo-worker")
        self._future = self._executor.submit(self._loop)

    def _loop(self) -> None:
        while not self._stop.is_set():
            job = None
            stage = "idle"
            try:
                expired = self.store.expire(time.time())
                for job_id in expired:
                    if _JOB_ID.fullmatch(job_id):
                        shutil.rmtree(self.config.jobs_dir / job_id, ignore_errors=True)
                job = self.store.claim(time.time())
                if job is None:
                    self._stop.wait(0.25)
                    continue
                self._active_stop = threading.Event()
                try:
                    stage = "auditing"
                    result = run_job(job, self.config, lambda stage, pages=None: self._progress(job["job_id"], stage, pages), self._active_stop)
                    stage = "rendering" if result.get("files") else "auditing"
                    if result.get("pages_crawled") is not None:
                        current = self.store.get(job["job_id"])
                        if current and current["state"] in ("auditing", "rendering"):
                            self.store.progress(job["job_id"], current["stage"], result["pages_crawled"])
                    self.store.finish(job["job_id"], result["state"], result)
                except Exception as exc:  # never leave a claimed job wedging the queue
                    stage = stage or "auditing"
                    LOG.warning("job worker failure stage=%s error=%s", stage, type(exc).__name__)
                    self._fail_job(job["job_id"])
                finally:
                    self._active_stop = None
            except Exception as exc:
                LOG.warning("job worker failure stage=%s error=%s", stage, type(exc).__name__)
                if job is not None:
                    self._fail_job(job["job_id"])
                self._stop.wait(0.25)

    def _progress(self, job_id: str, stage: str, pages: int | None = None) -> None:
        try:
            if stage == "rendering":
                try:
                    self.store.begin_rendering(job_id)
                except ValueError:
                    if (self.store.get(job_id) or {}).get("state") != "rendering":
                        return
            self.store.progress(job_id, stage, pages)
        except (KeyError, ValueError):
            pass

    def _fail_job(self, job_id: str) -> None:
        try:
            self.store.finish(
                job_id,
                "failed",
                {"warnings": ["A auditoria falhou no serviço; tente novamente."], "files": []},
            )
        except (KeyError, ValueError):
            pass

    def stop(self) -> None:
        self._stop.set()
        if self._active_stop is not None:
            self._active_stop.set()
        if self._future is not None:
            self._future.result(timeout=DEADLINE_SECONDS + 10)
        if self._executor is not None:
            self._executor.shutdown(wait=True)
        if self._lock_file is not None:
            import fcntl
            fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_UN)
            self._lock_file.close()
            self._lock_file = None
