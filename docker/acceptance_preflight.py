"""Bounded, read-only inventory for the retained hosted-worker image."""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


MAX_OUTPUT_BYTES = 64 * 1024
MAX_MOUNTINFO_BYTES = 256 * 1024
MAX_MOUNT_RECORDS = 256
MAX_TOKEN_LENGTH = 4096
SYNTHETIC_JOB_ID = "a" * 32
SYNTHETIC_JOB_DIR = f"/data/jobs/{SYNTHETIC_JOB_ID}"
FAKE_PROXY = "http://proxy.invalid:4750"
FAKE_TOKEN = "acceptance-secret-sentinel"
FAKE_TASK = "task-secret-sentinel"

EXPECTED_ENV_NAMES = {
    "JEVSEO_HOSTED",
    "JEVSEO_EGRESS_PROXY",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "TYPESAFE_API_KEY",
    "PATH",
    "PYTHONPATH",
    "LANG",
    "LC_ALL",
    "OMP_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "MKL_NUM_THREADS",
    "HOME",
}
EXPECTED_DIRS = {"/etc", "/etc/fonts", "/etc/ssl", "/runtime", "/job"}
EXPECTED_DEV_DESCENDANTS = {"/dev/mqueue", "/dev/pts", "/dev/shm"}
EXPECTED_FILE_MOUNTS = {"/etc/hostname", "/etc/hosts", "/etc/resolv.conf"}
EXPECTED_RUNTIME_DIRS = {
    "/usr": "/usr",
    "/bin": "/usr/bin",
    "/lib": "/usr/lib",
    "/lib64": "/usr/lib64",
}
EXPECTED_BINDINGS = {
    "/usr": ("/usr", "/usr", False),
    "/bin": ("/usr/bin", "/bin", False),
    "/lib": ("/usr/lib", "/lib", False),
    "/lib64": ("/usr/lib64", "/lib64", False),
    "/usr/share/fonts": ("/usr/share/fonts", "/usr/share/fonts", True),
    "/usr/local/share/fonts": ("/usr/local/share/fonts", "/usr/local/share/fonts", True),
    "/etc/fonts": ("/etc/fonts", "/etc/fonts", False),
    "/etc/hosts": ("/etc/hosts", "/etc/hosts", False),
    "/etc/nsswitch.conf": ("/etc/nsswitch.conf", "/etc/nsswitch.conf", False),
    "/etc/resolv.conf": ("/etc/resolv.conf", "/etc/resolv.conf", False),
    "/etc/ssl/certs": ("/etc/ssl/certs", "/etc/ssl/certs", False),
    "/usr/local": ("/usr/local", "/usr/local", False),
    "/usr/local/bin": ("/usr/local/bin", "/usr/local/bin", False),
    "/app/jevseo": ("/app/jevseo", "/runtime/jevseo", False),
}
EXPECTED_CANONICAL_SOURCES = {item[0] for item in EXPECTED_BINDINGS.values()}
EXPECTED_BIND_TARGETS = {item[1] for item in EXPECTED_BINDINGS.values()} | {"/job"}
EXPECTED_DEV_NODES = ("/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/tty")


class PreflightError(RuntimeError):
    """A safe, non-sensitive failure code."""

    pass


@dataclass(frozen=True)
class MountRecord:
    mount_id: int
    root: str
    mountpoint: str
    options: tuple[str, ...]
    filesystem: str


def _fail(code: str) -> None:
    raise PreflightError(code)


def _decode_mount_token(token: str) -> str:
    if len(token) > MAX_TOKEN_LENGTH:
        _fail("mount_token_oversize")
    result: list[str] = []
    index = 0
    while index < len(token):
        char = token[index]
        if char != "\\":
            if ord(char) < 0x20:
                _fail("mount_token_control")
            result.append(char)
            index += 1
            continue
        escaped = token[index + 1 : index + 4]
        if len(escaped) != 3 or any(item not in "01234567" for item in escaped):
            _fail("mount_escape_invalid")
        result.append(chr(int(escaped, 8)))
        index += 4
    value = "".join(result)
    if "\x00" in value or len(value) > MAX_TOKEN_LENGTH:
        _fail("mount_token_invalid")
    return value


def _parse_mountinfo(text: str) -> list[MountRecord]:
    if len(text.encode("utf-8")) > MAX_MOUNTINFO_BYTES:
        _fail("mountinfo_oversize")
    lines = text.splitlines()
    if not lines or len(lines) > MAX_MOUNT_RECORDS:
        _fail("mountinfo_count")
    records: list[MountRecord] = []
    seen_ids: set[int] = set()
    seen_mountpoints: set[str] = set()
    for line in lines:
        halves = line.split(" - ")
        if len(halves) != 2:
            _fail("mountinfo_separator")
        left, right = halves
        left_fields = left.split()
        right_fields = right.split()
        if len(left_fields) < 6 or len(right_fields) < 3:
            _fail("mountinfo_fields")
        try:
            mount_id = int(left_fields[0])
        except ValueError:
            _fail("mountinfo_id")
        if mount_id in seen_ids:
            _fail("mountinfo_duplicate_id")
        root = _decode_mount_token(left_fields[3])
        mountpoint = _decode_mount_token(left_fields[4])
        if mountpoint in seen_mountpoints:
            _fail("mountinfo_duplicate_path")
        seen_ids.add(mount_id)
        seen_mountpoints.add(mountpoint)
        filesystem = _decode_mount_token(right_fields[0])
        options = tuple(sorted(set(left_fields[5].split(","))))
        records.append(MountRecord(mount_id, root, mountpoint, options, filesystem))
    return records


def _is_descendant(path: str, parent: str) -> bool:
    return path.startswith(parent.rstrip("/") + "/")


def _validate_dev_nodes(records: list[MountRecord], dev_mount: MountRecord) -> list[str]:
    if Path("/dev/console").exists() or any(os.isatty(fd) for fd in (0, 1, 2)):
        _fail("console_or_tty_present")
    mountpoints = {record.mountpoint: record for record in records}
    for path in EXPECTED_DEV_NODES:
        try:
            info = os.stat(path)
        except OSError:
            _fail("dev_node_missing")
        if not stat.S_ISCHR(info.st_mode) or not _is_descendant(os.path.realpath(path), "/dev"):
            _fail("dev_node_invalid")
        if path in mountpoints or mountpoints.get("/dev") is not dev_mount:
            _fail("dev_node_separate_mount")
    return list(EXPECTED_DEV_NODES)


def _validate_mount_inventory(records: list[MountRecord], canonical_sources: set[str], job_dir: str) -> dict:
    dev = [record for record in records if record.mountpoint == "/dev"]
    if len(dev) != 1:
        _fail("dev_mount_missing_or_duplicate")
    if dev[0].filesystem != "tmpfs" or not {"rw", "nosuid"}.issubset(dev[0].options):
        _fail("dev_mount_flags")
    dev_descendants = sorted(
        record.mountpoint for record in records if _is_descendant(record.mountpoint, "/dev")
    )
    if not set(dev_descendants).issubset(EXPECTED_DEV_DESCENDANTS):
        _fail("unexpected_dev_submount")
    if any(
        _is_descendant(record.mountpoint, descendant)
        for record in records
        for descendant in EXPECTED_DEV_DESCENDANTS
    ):
        _fail("recursive_dev_submount")
    file_mounts = sorted(record.mountpoint for record in records if record.mountpoint in EXPECTED_FILE_MOUNTS)
    parents = set(canonical_sources) | {_canonical(job_dir)}
    runtime_descendants: list[dict[str, object]] = []
    for record in records:
        if any(_is_descendant(record.mountpoint, parent) for parent in parents):
            if record.mountpoint not in EXPECTED_CANONICAL_SOURCES:
                _fail("unexpected_runtime_submount")
            runtime_descendants.append(
                {
                    "mountpoint": record.mountpoint,
                    "root": record.root,
                    "filesystem": record.filesystem,
                    "options": list(record.options),
                }
            )
        elif record.mountpoint.startswith("/etc/") and record.mountpoint not in EXPECTED_FILE_MOUNTS:
            _fail("unexpected_etc_mount")
    return {
        "dev": {"mountpoint": "/dev", "options": list(dev[0].options), "filesystem": dev[0].filesystem},
        "dev_descendants": dev_descendants,
        "dev_nodes": _validate_dev_nodes(records, dev[0]),
        "file_mounts": file_mounts,
        "runtime_descendants": sorted(runtime_descendants, key=lambda item: str(item["mountpoint"])),
    }


def _canonical(path: str) -> str:
    return os.path.realpath(path)


def _path_type(path: str) -> tuple[bool, str]:
    try:
        info = os.lstat(path)
    except OSError:
        return False, "missing"
    if stat.S_ISLNK(info.st_mode):
        return True, "symlink"
    if stat.S_ISDIR(info.st_mode):
        return True, "directory"
    if stat.S_ISREG(info.st_mode):
        return True, "file"
    return True, "other"


def _binding_record(source: str, target: str, job_dir: str) -> dict[str, object]:
    canonical = _canonical(source)
    exists, path_type = _path_type(source)
    if source == job_dir:
        if canonical != source:
            _fail("synthetic_job_not_canonical")
        if exists:
            _fail("synthetic_job_exists")
    else:
        expected = EXPECTED_BINDINGS.get(source)
        if expected is None or expected[0] != canonical or expected[1] != target:
            _fail("unexpected_bind_mapping")
    return {
        "source": source,
        "canonical_source": canonical,
        "target": target,
        "exists": exists,
        "type": path_type,
    }


def _validate_bindings(bindings: list[tuple[str, str]], job_dir: str) -> list[dict[str, object]]:
    if len(set(bindings)) != len(bindings):
        _fail("duplicate_bind_mapping")
    records = [_binding_record(source, target, job_dir) for source, target in bindings]
    actual = {(source, target) for source, target in bindings}
    mandatory = {
        (source, target)
        for source, (_, target, optional) in EXPECTED_BINDINGS.items()
        if not optional
    }
    if not mandatory.issubset(actual):
        _fail("required_bind_missing")
    if any(source not in EXPECTED_BINDINGS for source, _ in bindings):
        _fail("unexpected_bind_source")
    for record in records:
        source = str(record["source"])
        if not record["exists"] and not EXPECTED_BINDINGS[source][2]:
            _fail("required_bind_missing_path")
    return records


def _extract_manifest(argv: list[str], job_dir: str, python_executable: str) -> dict[str, object]:
    prefix = [
        "bwrap", "--die-with-parent", "--new-session", "--unshare-user", "--unshare-pid",
        "--unshare-ipc", "--unshare-uts", "--cap-drop", "ALL", "--proc", "/proc",
        "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/etc", "--dir", "/etc/fonts",
        "--dir", "/etc/ssl", "--dir", "/runtime", "--dir", "/job", "--bind", job_dir, "/job",
    ]
    if argv[: len(prefix)] != prefix:
        _fail("bwrap_prefix_mismatch")
    index = len(prefix)
    bindings: list[tuple[str, str]] = []
    while index < len(argv) and argv[index] == "--ro-bind":
        if index + 2 >= len(argv):
            _fail("bind_arity")
        bindings.append((argv[index + 1], argv[index + 2]))
        index += 3
    env_names: list[str] = []
    while index < len(argv) and argv[index] == "--setenv":
        if index + 2 >= len(argv):
            _fail("setenv_arity")
        name, value = argv[index + 1], argv[index + 2]
        if name not in EXPECTED_ENV_NAMES or not value:
            _fail("unexpected_environment_name")
        env_names.append(name)
        index += 3
    suffix = ["--chdir", "/job", "--", python_executable, "-m", "jevseo", "render", "/job", "--formats", "pdf"]
    if argv[index:] != suffix:
        _fail("unexpected_worker_command")
    if len(set(env_names)) != len(env_names) or set(env_names) != EXPECTED_ENV_NAMES:
        _fail("worker_environment_names")
    records = _validate_bindings(bindings, job_dir)
    if len(records) != len(bindings):
        _fail("bind_record_mismatch")
    return {
        "bindings": records,
        "job_bind": _binding_record(job_dir, "/job", job_dir),
        "directories": sorted(EXPECTED_DIRS),
        "environment_names": sorted(env_names),
        "command_allowed": True,
    }


def _read_mountinfo() -> str:
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as handle:
            text = handle.read(MAX_MOUNTINFO_BYTES + 1)
    except OSError:
        _fail("mountinfo_unreadable")
    if len(text.encode("utf-8")) > MAX_MOUNTINFO_BYTES:
        _fail("mountinfo_oversize")
    return text


def _status_facts() -> dict[str, object]:
    values: dict[str, str] = {}
    try:
        for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
            key, separator, value = line.partition(":")
            if separator and key in {"CapEff", "CapBnd", "NoNewPrivs"}:
                values[key] = value.strip()
    except (OSError, UnicodeError):
        _fail("status_unreadable")
    if values.get("CapEff") is None or values.get("CapBnd") is None or values.get("NoNewPrivs") is None:
        _fail("status_fields_missing")
    try:
        cap_eff_zero = int(values["CapEff"], 16) == 0
        cap_bnd_zero = int(values["CapBnd"], 16) == 0
    except ValueError:
        _fail("capability_format")
    if os.getuid() != 10001 or os.getgid() != 10001 or not cap_eff_zero or not cap_bnd_zero or values["NoNewPrivs"] != "1":
        _fail("identity_mismatch")
    return {"uid": 10001, "gid": 10001, "cap_eff_zero": True, "cap_bnd_zero": True, "no_new_privs": True}


def _run_fixed(argv: list[str]) -> str:
    try:
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        _fail("fixed_command_failed")
    if result.returncode != 0:
        _fail("fixed_command_failed")
    return result.stdout


def _tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        _fail("required_tool_missing")
    return str(Path(path).resolve())


def _safe_version(text: str) -> str:
    lines = text.strip().splitlines()
    if len(lines) != 1 or len(lines[0]) > 128 or not re.fullmatch(r"[A-Za-z0-9 .()+:/_-]+", lines[0]):
        _fail("version_output_invalid")
    return lines[0]


def _collect_report() -> dict[str, object]:
    if platform.system() != "Linux":
        _fail("linux_required")
    identity = _status_facts()
    bwrap = _tool("bwrap")
    prlimit = _tool("prlimit")
    dpkg_query = _tool("dpkg-query")
    bwrap_version = _safe_version(_run_fixed([bwrap, "--version"]))
    package_version = _run_fixed([dpkg_query, "-W", "-f=${Package}=${Version}\n", "bubblewrap"]).strip()
    if package_version != "bubblewrap=0.8.0-2+deb12u1":
        _fail("bubblewrap_package_mismatch")
    from jevseo.web.config import WebConfig
    from jevseo.web import runner

    runtime_dirs = tuple(runner._runtime_dirs())
    ro_mounts = list(runner._ro_mounts())
    runtime_records = [
        {
            "source": str(path),
            "canonical_source": _canonical(str(path)),
            "exists": _path_type(str(path))[0],
            "type": _path_type(str(path))[1],
        }
        for path in runtime_dirs
    ]
    if {
        (item["source"], item["canonical_source"])
        for item in runtime_records
    } != set(EXPECTED_RUNTIME_DIRS.items()):
        _fail("unexpected_runtime_directory")
    config = WebConfig(
        data_dir=Path("/data"),
        service_token=FAKE_TASK,
        task_secret=FAKE_TOKEN,
        typesafe_api_key=FAKE_TOKEN,
        pagespeed_api_key=None,
        egress_proxy=FAKE_PROXY,
    )
    command = [sys.executable, "-m", "jevseo", "render", "/job", "--formats", "pdf"]
    argv = runner._build_bwrap_argv(Path(SYNTHETIC_JOB_DIR), config, command)
    manifest = _extract_manifest(argv, SYNTHETIC_JOB_DIR, sys.executable)
    manifest_pairs = {(item["source"], item["target"]) for item in manifest["bindings"]}
    if not {(str(source), str(target)) for source, target in ro_mounts}.issubset(manifest_pairs):
        _fail("runner_mount_inventory_mismatch")
    bindings = list(manifest["bindings"])
    inventory = _validate_mount_inventory(
        _parse_mountinfo(_read_mountinfo()),
        EXPECTED_CANONICAL_SOURCES,
        SYNTHETIC_JOB_DIR,
    )
    resolved_python = str(Path(sys.executable).resolve())
    source_records = sorted(bindings, key=lambda item: (str(item["target"]), str(item["source"])))
    report = {
        "ok": True,
        "platform": {"system": "Linux", "machine": platform.machine()},
        "identity": identity,
        "tools": {"bwrap": bwrap, "bwrap_version": bwrap_version, "prlimit": prlimit, "dpkg_query": dpkg_query, "bubblewrap_package": package_version},
        "python": {"executable": sys.executable, "canonical_executable": resolved_python, "prefix": str(Path(sys.prefix).resolve())},
        "runtime_dirs": runtime_records,
        "bindings": source_records,
        "directories": manifest["directories"],
        "environment_names": manifest["environment_names"],
        "mounts": inventory,
        "assertions": {"bwrap_invoked": False, "environment_values_emitted": False, "synthetic_job_only_writable": True},
    }
    return report


def _emit(payload: dict[str, object]) -> int:
    text = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    if len(text.encode("utf-8")) + 1 > MAX_OUTPUT_BYTES:
        text = json.dumps({"ok": False, "error": "output_oversize"}, separators=(",", ":"))
        return_code = 1
    else:
        return_code = 0 if payload.get("ok") else 1
    print(text)
    return return_code


def main(argv: list[str] | None = None) -> int:
    try:
        if list(sys.argv[1:] if argv is None else argv):
            _fail("arguments_not_allowed")
        report = _collect_report()
        report["ok"] = True
        return _emit(report)
    except PreflightError as error:
        return _emit({"ok": False, "error": str(error)[:64] or "preflight_failed"})
    except Exception:
        return _emit({"ok": False, "error": "preflight_failed"})


if __name__ == "__main__":
    raise SystemExit(main())
