"""Bounded, operator-only native acceptance using the installed worker helper."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pwd
import re
import secrets
import stat
import sys
import threading
import time
from pathlib import Path


RELEASE_ROOT = Path("/opt/jev-audit-native/releases/0e7c53a36257c75d96aae7890f2103b9341c9e3b")
EXPECTED_VENV = RELEASE_ROOT / "venv"
EXPECTED_PYTHON = EXPECTED_VENV / "bin/python"
EXPECTED_HELPER = RELEASE_ROOT / "tools/check_sandbox_acceptance.py"
EXPECTED_HELPER_SHA256 = "8ca4a97edf4cced600ff51248a1ef6eb587c71fa8ec913f9619c299cb9aaf287"
EXPECTED_UID = 200
EXPECTED_GID = 200
EXPECTED_ACCOUNT = "jev-audit-api"
EXPECTED_PROFILE = "jev-audit-native (enforce)"
EXPECTED_PROXY = "http://127.0.0.1:4750"
ACCEPTANCE_ROOT = Path("/var/lib/jev-audit-native-acceptance")
NETWORK_DEADLINE_SECONDS = 60.0
MAX_NETWORK_RESULT_BYTES = 16 * 1024
MAX_BODY_BYTES = 16 * 1024
NETWORK_PORT = 18080
JOB_ID_RE = re.compile(r"^[0-9a-f]{32}$")


class AcceptanceError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _verify_identity() -> None:
    if os.getuid() != EXPECTED_UID or os.geteuid() != EXPECTED_UID or os.getgid() != EXPECTED_GID or os.getegid() != EXPECTED_GID:
        raise AcceptanceError("identity_mismatch")
    try:
        account = pwd.getpwuid(EXPECTED_UID)
    except (KeyError, OSError) as exc:
        raise AcceptanceError("identity_lookup_failed") from exc
    if account.pw_name != EXPECTED_ACCOUNT or account.pw_gid != EXPECTED_GID:
        raise AcceptanceError("identity_mismatch")
    if Path(sys.prefix) != EXPECTED_VENV or Path(sys.executable) != EXPECTED_PYTHON:
        raise AcceptanceError("venv_identity_mismatch")


def _load_helper():
    path = EXPECTED_HELPER
    try:
        info = path.lstat()
        data = path.read_bytes()
    except OSError as exc:
        raise AcceptanceError("helper_unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise AcceptanceError("helper_ownership_invalid")
    if hashlib.sha256(data).hexdigest() != EXPECTED_HELPER_SHA256:
        raise AcceptanceError("helper_hash_mismatch")
    spec = importlib.util.spec_from_file_location("check_sandbox_acceptance", path)
    if spec is None or spec.loader is None:
        raise AcceptanceError("helper_import_failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        sys.modules.pop(spec.name, None)
        raise AcceptanceError("helper_import_failed") from exc
    return module


def _network_probe_source() -> str:
    return r'''import errno, json, os, socket
import requests

OUT = "/job/network-result.json"
PROXY = "http://127.0.0.1:4750"
MAX_BODY = 16 * 1024
PORT = 18080
PROXIES = {"http": PROXY, "https": PROXY}

def public(url):
    response = None
    try:
        with requests.Session() as session:
            session.trust_env = False
            response = session.get(url, proxies=PROXIES, verify=True, timeout=(5, 10), allow_redirects=False, stream=True)
            body = response.raw.read(MAX_BODY + 1)
            status = int(response.status_code)
            return {"url": url, "status": status, "body_bytes": len(body), "ok": 200 <= status <= 299 and len(body) <= MAX_BODY, "error_category": None}
    except (requests.RequestException, OSError):
        return {"url": url, "status": None, "body_bytes": 0, "ok": False, "error_category": "public_request_error"}
    finally:
        if response is not None:
            response.close()

def private(url):
    response = None
    try:
        with requests.Session() as session:
            session.trust_env = False
            response = session.get(url, proxies=PROXIES, verify=True, timeout=(5, 10), allow_redirects=False, stream=True)
            status = int(response.status_code)
            return {"url": url, "status": status, "blocked": status == 403, "error_category": None if status == 403 else "unexpected_status"}
    except (requests.RequestException, OSError):
        return {"url": url, "status": None, "blocked": False, "error_category": "proxy_error"}
    finally:
        if response is not None:
            response.close()

def direct(family, address):
    try:
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.settimeout(1.0)
            peer = (address, PORT, 0, 0) if family == socket.AF_INET6 else (address, PORT)
            connection.connect(peer)
        return {"family": "AF_INET6" if family == socket.AF_INET6 else "AF_INET", "address": address, "port": PORT, "blocked": False, "error_category": "connected"}
    except socket.timeout:
        return {"family": "AF_INET6" if family == socket.AF_INET6 else "AF_INET", "address": address, "port": PORT, "blocked": True, "error_category": "timeout"}
    except OSError as error:
        category = "permission" if error.errno in (errno.EPERM, errno.EACCES) else "refused" if error.errno == errno.ECONNREFUSED else "unreachable" if error.errno == errno.ENETUNREACH else "socket_error"
        return {"family": "AF_INET6" if family == socket.AF_INET6 else "AF_INET", "address": address, "port": PORT, "blocked": category in ("timeout", "permission"), "error_category": category}

result = {
    "public": {"http": public("http://example.com/"), "https": public("https://example.com/")},
    "proxy_private": {"ipv4": private("http://127.0.0.1:18080/"), "ipv6": private("http://[::1]:18080/")},
    "direct": {"ipv4": direct(socket.AF_INET, "127.0.0.1"), "ipv6": direct(socket.AF_INET6, "::1")},
}
result["ok"] = all(item["ok"] for item in result["public"].values()) and all(item["blocked"] and item["status"] == 403 for item in result["proxy_private"].values()) and all(item["blocked"] and item["error_category"] in ("timeout", "permission") for item in result["direct"].values())
data = json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
fd = os.open("/job/network-result.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
try:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("result write failed")
        view = view[written:]
finally:
    os.close(fd)
 '''


def _network_result_ok(result: object) -> bool:
    if not isinstance(result, dict) or set(result) != {"ok", "public", "proxy_private", "direct"} or result.get("ok") is not True:
        return False
    public = result.get("public")
    if not isinstance(public, dict) or set(public) != {"http", "https"}:
        return False
    for name, url in (("http", "http://example.com/"), ("https", "https://example.com/")):
        item = public.get(name)
        if not isinstance(item, dict) or set(item) != {"url", "status", "body_bytes", "ok", "error_category"}:
            return False
        if item.get("url") != url or item.get("ok") is not True or item.get("error_category") is not None:
            return False
        if isinstance(item.get("status"), bool) or not isinstance(item.get("status"), int) or not 200 <= item["status"] <= 299:
            return False
        if isinstance(item.get("body_bytes"), bool) or not isinstance(item.get("body_bytes"), int) or not 0 <= item["body_bytes"] <= MAX_BODY_BYTES:
            return False
    private = result.get("proxy_private")
    if not isinstance(private, dict) or set(private) != {"ipv4", "ipv6"}:
        return False
    for name, url in (("ipv4", "http://127.0.0.1:18080/"), ("ipv6", "http://[::1]:18080/")):
        item = private.get(name)
        if not isinstance(item, dict) or set(item) != {"url", "status", "blocked", "error_category"}:
            return False
        if item != {"url": url, "status": 403, "blocked": True, "error_category": None}:
            return False
    direct = result.get("direct")
    if not isinstance(direct, dict) or set(direct) != {"ipv4", "ipv6"}:
        return False
    expected = {"ipv4": ("AF_INET", "127.0.0.1"), "ipv6": ("AF_INET6", "::1")}
    for name, (family, address) in expected.items():
        item = direct.get(name)
        if not isinstance(item, dict) or set(item) != {"family", "address", "port", "blocked", "error_category"}:
            return False
        if item.get("family") != family or item.get("address") != address or item.get("port") != NETWORK_PORT or item.get("blocked") is not True or item.get("error_category") not in ("timeout", "permission"):
            return False
    return True


def _positive_facts(summary: object) -> dict:
    if not isinstance(summary, dict) or summary.get("ok") is not True:
        raise AcceptanceError("positive_acceptance_failed")
    worker = summary.get("worker")
    artifacts = summary.get("artifacts")
    worker_keys = {"uid", "gid", "euid", "egid", "caps_eff", "caps_bnd", "no_new_privs", "apparmor", "namespace_ids", "assertions"}
    if not isinstance(worker, dict) or set(worker) != worker_keys or worker.get("uid") != EXPECTED_UID or worker.get("gid") != EXPECTED_GID:
        raise AcceptanceError("positive_facts_invalid")
    if not isinstance(artifacts, dict) or set(artifacts) != {"pdf", "xlsx", "md"}:
        raise AcceptanceError("positive_artifacts_invalid")
    for value in artifacts.values():
        if not isinstance(value, dict) or set(value) != {"size", "sha256"} or not isinstance(value["size"], int) or not 0 < value["size"] or re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is None:
            raise AcceptanceError("positive_artifacts_invalid")
    return {"ok": True, "worker": worker, "artifacts": artifacts}


def _network_evidence(result: object) -> dict:
    if not isinstance(result, dict):
        return {"ok": False, "error_code": "network_result_invalid"}
    evidence: dict[str, object] = {"ok": result.get("ok") is True}
    for group, names in (("public", ("http", "https")), ("proxy_private", ("ipv4", "ipv6")), ("direct", ("ipv4", "ipv6"))):
        source = result.get(group)
        if not isinstance(source, dict):
            return {"ok": False, "error_code": "network_result_invalid"}
        evidence[group] = {}
        for name in names:
            item = source.get(name)
            evidence[group][name] = {key: item.get(key) for key in ("url", "status", "body_bytes", "ok", "blocked", "family", "address", "port", "error_category") if isinstance(item, dict) and key in item}
    return evidence


def _check_context(context: object) -> None:
    if any((getattr(context, "data_root", None) != ACCEPTANCE_ROOT, getattr(context, "uid", None) != EXPECTED_UID, getattr(context, "gid", None) != EXPECTED_GID, getattr(context, "profile", None) != EXPECTED_PROFILE, getattr(context, "fake_proxy", None) != EXPECTED_PROXY, getattr(context, "runtime_dir", None) != EXPECTED_VENV)):
        raise AcceptanceError("native_context_mismatch")


def run_acceptance(helper=None) -> dict:
    _verify_identity()
    helper = _load_helper() if helper is None else helper
    try:
        context = helper._native_context()
        _check_context(context)
        positive = _positive_facts(helper._run(context=context))
    except AcceptanceError:
        raise
    except Exception as exc:
        raise AcceptanceError("positive_acceptance_failed") from exc
    job_id = secrets.token_hex(16)
    if not JOB_ID_RE.fullmatch(job_id):
        raise AcceptanceError("job_id_invalid")
    try:
        job = helper._prepare_job_dir(context.data_root, job_id)
        helper._write_exclusive(job / "network_probe.py", _network_probe_source().encode("utf-8"))
        config = helper.WebConfig(
            data_dir=context.data_root,
            service_token="native-network-service-secret-" + job_id,
            task_secret="native-network-task-secret-" + job_id,
            typesafe_api_key="fake-provider-key",
            pagespeed_api_key=None,
            egress_proxy=EXPECTED_PROXY,
        )
        code, stopped = helper._run_contained(job, config, [sys.executable, "/job/network_probe.py"], time.monotonic() + NETWORK_DEADLINE_SECONDS, threading.Event(), lambda *_: None)
        if code != 0 or stopped:
            network = {"ok": False, "error_code": "network_worker_failed"}
        else:
            raw = helper._read_bounded_file(job / "network-result.json", MAX_NETWORK_RESULT_BYTES)
            try:
                network_result = json.loads(raw.decode("utf-8")) if raw is not None else None
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                network_result = None
            network = _network_evidence(network_result)
            network["ok"] = network_result is not None and _network_result_ok(network_result)
    except AcceptanceError:
        raise
    except Exception as exc:
        raise AcceptanceError("network_acceptance_failed") from exc
    return {"ok": positive["ok"] and network.get("ok") is True, "positive": positive, "network": network, "firewall_corroboration_required": True}


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        print(json.dumps({"error_code": "arguments_not_allowed", "ok": False}, separators=(",", ":")))
        return 2
    try:
        summary = run_acceptance()
    except AcceptanceError as exc:
        summary = {"error_code": exc.code, "ok": False}
    except Exception:
        summary = {"error_code": "acceptance_failed", "ok": False}
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0 if summary.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
