"""Bounded future-host sandbox acceptance; never SSHs or creates networks."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


STAGING_ROOT = Path("/opt/jev-audit-staging")
MARKER_NAME = ".jev-audit-run"
MARKER_PURPOSE = "sandbox-acceptance"
PROFILE_NAME = "jev-audit-bwrap"
PROFILE_FILE = "jev-bwrap.apparmor"
SECCOMP_FILE = "jev-bwrap-seccomp.json"
PREFLIGHT_FILE = "acceptance_preflight.py"
WORKER_FILE = "check_sandbox_acceptance.py"
NEGATIVE_FILE = "check_remount_denial.py"
DATA_DIR = "data"
FONTS_DIR = "fonts"
APP_IMAGE_ID = "sha256:654baccf4ddb0518ff84ca1b3a9d4243ea197058d198a4854c8daf6c0dbc15b6"
EXPECTED_PREFLIGHT_SHA256 = "dabc8dd04f9dfd75ff88db8332837f136bbc7cf5fad6003d7058667d9a2978d0"
EXPECTED_WORKER_SHA256 = "cecef1c4282c6d217f11f60486d64f658b2ef4344750f5e49bfd6155fd4329b0"
EXPECTED_SECCOMP_SHA256 = "1285dce068672733cf16929dfae98d8142375f78f4df34e4fe62f368c3153c98"
EXPECTED_APPARMOR_SHA256 = "5ab7d8551d97cf15624c91ca8170b32c07026aa33eae503da5965a1f9ebfd211"
EXPECTED_NEGATIVE_SHA256 = "5425cab3962191ccb3b78cdc8d02c341620bc9dd6795b28feabdb7b3b48f966f"
EXPECTED_HOST = {
    "arch": "x86_64",
    "ubuntu": "24.04",
    "docker": "29.8.1",
    "docker_git": "464cd50",
    "runc": "1.5.1",
    "libseccomp": "2.5.5",
    "apparmor": "4.0.1",
}
MAX_OUTPUT_BYTES = 64 * 1024
MAX_COMMAND_OUTPUT = 256 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
RUN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
EXPECTED_DEV_SUBMOUNTS = ["/dev/mqueue", "/dev/pts", "/dev/shm"]
PRECHECK_SENTINELS = ("acceptance-secret-sentinel", "proxy-secret-sentinel", "task-secret-sentinel")
REQUIRED_REMOUNT_FLAGS = {"rw", "remount", "bind", "nosuid", "nodev", "silent"}
OPTIONAL_REMOUNT_FLAGS = {"noexec", "noatime", "nodiratime", "relatime"}
APPARMOR_SECURITY = "name=apparmor,profile=default"
SECCOMP_SECURITY_PREFIX = "name=seccomp,profile=builtin"
EXPECTED_PROFILE_DENIAL_TARGETS = {"/newroot/usr/share/fonts", "/newroot/usr/share/fonts/"}
AUDIT_MAX_RECORDS = 50
AUDIT_LOSS_SIGNATURES = ("audit_lost=", "rate limit exceeded", "backlog limit exceeded", "messages dropped", "audit messages lost")
STATIC_ENV = {
    "JEVSEO_HOSTED": "1",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "HOME": "/tmp",
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "PYTHONDONTWRITEBYTECODE": "1",
    "OMP_NUM_THREADS": "1",
    "OPENBLAS_NUM_THREADS": "1",
    "MKL_NUM_THREADS": "1",
}
CANARY_ENV_NAMES = {"JEVSEO_EGRESS_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "TYPESAFE_API_KEY"}
IMAGE_SAFE_ENV_NAMES = {"GPG_KEY", "PYTHON_VERSION", "PYTHON_SHA256", "PYTHON_PIP_VERSION", "PYTHON_SETUPTOOLS_VERSION", "PYTHON_GET_PIP_URL", "PYTHON_GET_PIP_SHA256"}


class OrchestrationError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        self.warnings: list[str] = []
        super().__init__(code)


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def fail(code: str) -> None:
    raise OrchestrationError(code)


def marker_text(run_name: str) -> str:
    return f"owner=jev-audit\npurpose={MARKER_PURPOSE}\nrun={run_name}\n"


def _owner_uid(path: Path) -> int:
    return os.lstat(path).st_uid


def validate_run_root(path: Path) -> Path:
    if not path.is_absolute() or path.parent != STAGING_ROOT or not RUN_NAME_RE.fullmatch(path.name):
        fail("run_root_not_unique_child")
    try:
        parent_info = os.lstat(STAGING_ROOT.parent)
        staging_info = os.lstat(STAGING_ROOT)
        staging_real = Path(os.path.realpath(STAGING_ROOT))
        path_real = Path(os.path.realpath(path))
    except OSError:
        fail("staging_root_unreadable")
    if stat.S_ISLNK(parent_info.st_mode) or stat.S_ISLNK(staging_info.st_mode) or not stat.S_ISDIR(staging_info.st_mode) or path_real.parent != staging_real:
        fail("run_root_not_unique_child")
    try:
        info = os.lstat(path)
    except OSError:
        fail("run_root_unreadable")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        fail("run_root_not_directory")
    if _owner_uid(path) != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        fail("run_root_ownership")
    marker = path / MARKER_NAME
    try:
        marker_info = os.lstat(marker)
    except OSError:
        fail("run_marker_unreadable")
    if stat.S_ISLNK(marker_info.st_mode) or not stat.S_ISREG(marker_info.st_mode) or marker_info.st_size > 1024:
        fail("run_marker_not_regular")
    try:
        content = marker.read_text(encoding="ascii")
    except (OSError, UnicodeError):
        fail("run_marker_unreadable")
    if _owner_uid(marker) != 0 or stat.S_IMODE(marker_info.st_mode) != 0o600 or content != marker_text(path.name):
        fail("run_marker_invalid")
    return path


def _owned_regular(path: Path) -> None:
    try:
        info = os.lstat(path)
    except OSError:
        fail("staged_file_missing")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        fail("staged_file_not_regular")
    if info.st_uid != 0 or info.st_size > MAX_FILE_BYTES:
        fail("staged_file_ownership")


def _sha256_file(path: Path) -> str:
    _owned_regular(path)
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    except OSError:
        fail("staged_file_unreadable")
    return digest.hexdigest()


def validate_staged_files(run_root: Path) -> dict[str, str]:
    expected = {
        PREFLIGHT_FILE: EXPECTED_PREFLIGHT_SHA256,
        WORKER_FILE: EXPECTED_WORKER_SHA256,
        PROFILE_FILE: EXPECTED_APPARMOR_SHA256,
        SECCOMP_FILE: EXPECTED_SECCOMP_SHA256,
        NEGATIVE_FILE: EXPECTED_NEGATIVE_SHA256,
    }
    result: dict[str, str] = {}
    for filename, wanted in expected.items():
        if not wanted or not re.fullmatch(r"[0-9a-f]{64}", wanted):
            fail("negative_helper_hash_unset" if filename == NEGATIVE_FILE else "artifact_hash_unset")
        actual = _sha256_file(run_root / filename)
        if actual != wanted:
            fail("staged_hash_mismatch")
        result[filename] = actual
    return result


def run_command(argv: list[str], *, timeout: float = 15.0) -> CommandResult:
    if not argv or any(not isinstance(item, str) for item in argv) or argv[0] in {"ssh", "scp", "rsync"}:
        fail("command_not_allowed")
    try:
        result = subprocess.run(
            argv,
            text=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        fail("command_timeout")
    except OSError:
        fail("command_unavailable")
    if len(result.stdout.encode()) > MAX_COMMAND_OUTPUT or len(result.stderr.encode()) > MAX_COMMAND_OUTPUT:
        fail("command_output_oversize")
    return CommandResult(result.returncode, result.stdout, result.stderr)


def _require(result: CommandResult, code: str) -> str:
    if result.returncode != 0:
        fail(code)
    return result.stdout.strip()


def _read_os_release() -> tuple[str, str]:
    try:
        data = Path("/etc/os-release").read_text(encoding="ascii")
    except (OSError, UnicodeError):
        fail("os_release_unreadable")
    values = dict(line.split("=", 1) for line in data.splitlines() if "=" in line and len(line) < 256)
    return values.get("ID", "").strip('"'), values.get("VERSION_ID", "").strip('"')


def _dockerd_label() -> str:
    matches: list[Path] = []
    try:
        entries = list(Path("/proc").iterdir())
        if len(entries) > 4096:
            fail("dockerd_inventory_truncated")
        for entry in entries:
            if not entry.name.isdigit():
                continue
            try:
                if (entry / "comm").read_text(encoding="ascii")[:32].strip() == "dockerd":
                    matches.append(entry)
            except FileNotFoundError:
                continue
            except OSError:
                fail("dockerd_process_unreadable")
    except OSError:
        fail("dockerd_inventory_unreadable")
    if len(matches) != 1:
        fail("dockerd_pid_count")
    try:
        return (matches[0] / "attr/current").read_text(encoding="ascii")[:128].strip()
    except OSError:
        fail("dockerd_label_unreadable")


def _profile_states() -> list[str]:
    try:
        data = Path("/sys/kernel/security/apparmor/profiles").read_text(encoding="ascii")
    except (OSError, UnicodeError):
        fail("apparmor_inventory_unreadable")
    if len(data.encode()) > MAX_COMMAND_OUTPUT:
        fail("apparmor_inventory_oversize")
    return [line for line in data.splitlines() if line == PROFILE_NAME or line.startswith(PROFILE_NAME + " ")]


def _profile_present() -> bool:
    return bool(_profile_states())


def _profile_enforced() -> bool:
    return PROFILE_NAME + " (enforce)" in _profile_states()


def validate_host() -> dict[str, str]:
    arch = _require(run_command(["uname", "-m"]), "host_arch_probe_failed")
    os_id, os_version = _read_os_release()
    docker = _require(run_command(["docker", "version", "--format", "{{.Server.Version}}\n{{.Server.GitCommit}}"]), "docker_version_probe_failed").splitlines()
    runc = _require(run_command(["runc", "--version"]), "runc_probe_failed")
    libseccomp = _require(run_command(["dpkg-query", "-W", "-f=${Version}\n", "libseccomp2"]), "libseccomp_probe_failed")
    apparmor = _require(run_command(["apparmor_parser", "--version"]), "apparmor_probe_failed")
    security_text = _require(run_command(["docker", "info", "--format", "{{json .SecurityOptions}}"]), "docker_security_probe_failed")
    try:
        security = json.loads(security_text)
    except json.JSONDecodeError:
        fail("docker_security_format")
    facts = {
        "arch": arch,
        "ubuntu": os_version if os_id == "ubuntu" else os_id,
        "docker": docker[0] if docker else "",
        "docker_git": docker[1] if len(docker) > 1 else "",
        "runc": runc.splitlines()[0] if runc else "",
        "libseccomp": libseccomp,
        "apparmor": apparmor.splitlines()[0] if apparmor else "",
    }
    if arch != EXPECTED_HOST["arch"] or os_id != "ubuntu" or os_version != EXPECTED_HOST["ubuntu"]:
        fail("host_os_drift")
    if facts["docker"] != EXPECTED_HOST["docker"] or facts["docker_git"] != EXPECTED_HOST["docker_git"]:
        fail("docker_version_drift")
    if not re.search(r"\brunc version 1\.5\.1\b", runc) or not libseccomp.startswith(EXPECTED_HOST["libseccomp"]) or not re.search(r"\b4\.0\.1\b", apparmor):
        fail("runtime_version_drift")
    if not isinstance(security, list) or set(security) != {APPARMOR_SECURITY, SECCOMP_SECURITY_PREFIX, "name=cgroupns"}:
        fail("docker_apparmor_security_missing")
    if not any(str(item) == SECCOMP_SECURITY_PREFIX for item in security):
        fail("docker_seccomp_security_missing")
    if _dockerd_label() != "unconfined":
        fail("dockerd_label_drift")
    if _profile_present():
        fail("profile_name_conflict")
    return facts


def validate_image() -> dict[str, str]:
    template = "{{.Id}}\n{{.Os}}\n{{.Architecture}}\n{{.Config.User}}"
    fields = _require(run_command(["docker", "image", "inspect", APP_IMAGE_ID, "--format", template]), "image_inspect_failed").splitlines()
    image = {"id": fields[0] if len(fields) > 0 else "", "os": fields[1] if len(fields) > 1 else "", "arch": fields[2] if len(fields) > 2 else "", "user": fields[3] if len(fields) > 3 else ""}
    if image != {"id": APP_IMAGE_ID, "os": "linux", "arch": "amd64", "user": "10001:10001"}:
        fail("image_metadata_drift")
    return {"id": APP_IMAGE_ID, "os": "linux", "arch": "amd64", "user": "10001:10001"}


def _assert_resource_absent(name: str) -> None:
    result = run_command(["docker", "ps", "-a", "--filter", f"name=^{name}$", "--format", "{{.Names}}"])
    if result.returncode != 0:
        fail("resource_collision_probe_failed")
    if result.stdout.strip():
        fail("resource_name_collision")


def build_preflight_command(run_root: Path, run_name: str) -> list[str]:
    name = f"{run_name}-preflight"
    labels = [part for key, value in required_labels(run_name).items() for part in ("--label", f"{key}={value}")]
    return [
        "docker", "run", "--name", name, *labels, "--platform", "linux/amd64", "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "10001:10001",
        "--memory", "512m", "--cpus", "1", "--pids-limit", "128",
        "--mount", f"type=bind,src={run_root / PREFLIGHT_FILE},dst=/app/acceptance_preflight.py,readonly",
        APP_IMAGE_ID, "python", "/app/acceptance_preflight.py",
    ]


def _cleanup_preflight(name: str, run_name: str) -> None:
    result = run_command(["docker", "inspect", "--format", "{{.Image}}\t{{json .Config.Labels}}", name])
    if result.returncode != 0:
        fail("preflight_cleanup_uncertain")
    fields = result.stdout.strip().split("\t")
    try:
        labels = json.loads(fields[1])
    except (IndexError, json.JSONDecodeError):
        fail("preflight_cleanup_uncertain")
    if fields[0] != APP_IMAGE_ID or labels != required_labels(run_name):
        fail("preflight_cleanup_ownership")
    if run_command(["docker", "rm", "-f", name]).returncode != 0:
        fail("preflight_cleanup_uncertain")


def run_image_preflight(run_root: Path, run_name: str) -> dict:
    name = f"{run_name}-preflight"
    _assert_resource_absent(name)
    original: OrchestrationError | None = None
    payload: dict | None = None
    try:
        result = run_command(build_preflight_command(run_root, run_name), timeout=30)
        if result.returncode != 0:
            fail("image_preflight_failed")
        if any(sentinel in result.stdout or sentinel in result.stderr for sentinel in PRECHECK_SENTINELS):
            fail("image_preflight_secret_leak")
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            fail("image_preflight_format")
    except OrchestrationError as error:
        original = error
    try:
        _cleanup_preflight(name, run_name)
    except OrchestrationError as error:
        if original is None:
            raise
        original.warnings.append(error.code)
    if original is not None:
        raise original
    mounts = payload.get("mounts", {})
    if payload.get("ok") is not True or len(payload.get("bindings", [])) != 14:
        fail("image_preflight_facts")
    if mounts.get("dev", {}).get("options") is None or not {"rw", "nosuid"}.issubset(mounts["dev"]["options"]):
        fail("image_preflight_dev")
    if len(mounts.get("dev_nodes", [])) != 6 or mounts.get("dev_descendants") != EXPECTED_DEV_SUBMOUNTS:
        fail("image_preflight_devices")
    if mounts.get("runtime_descendants"):
        fail("image_preflight_submounts")
    return {"ok": True, "bindings": 14, "dev_nodes": 6, "dev_descendants": EXPECTED_DEV_SUBMOUNTS}


def required_labels(run_name: str) -> dict[str, str]:
    return {"owner": "jev-audit", "environment": "staging", "purpose": "sandbox-acceptance", "run": run_name}


def _env(canaries: dict[str, str] | None) -> list[str]:
    values = dict(STATIC_ENV)
    if canaries:
        values.update(canaries)
    return [item for name, value in values.items() for item in ("--env", f"{name}={value}")]


def build_container_commands(run_root: Path, run_name: str, canaries: dict[str, str] | None = None) -> list[list[str]]:
    labels = [part for key, value in required_labels(run_name).items() for part in ("--label", f"{key}={value}")]
    common = [
        "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--security-opt", f"apparmor={PROFILE_NAME}", "--security-opt", f"seccomp={run_root / SECCOMP_FILE}",
        "--user", "10001:10001", "--memory", "1g", "--cpus", "1", "--pids-limit", "256",
        "--log-driver", "json-file", "--log-opt", "max-size=1m", "--log-opt", "max-file=1", "--log-opt", "compress=false",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=128m",
    ]
    positive = ["docker", "create", "--name", f"{run_name}-positive", *labels, *common, *_env(canaries),
                "--mount", f"type=bind,src={run_root / DATA_DIR},dst=/data", "--mount",
                f"type=bind,src={run_root / WORKER_FILE},dst=/app/{WORKER_FILE},readonly", APP_IMAGE_ID,
                "python", f"/app/{WORKER_FILE}"]
    negative = ["docker", "create", "--name", f"{run_name}-negative", *labels, *common, *_env(canaries),
                "--mount", f"type=bind,src={run_root / FONTS_DIR},dst=/usr/share/fonts", "--mount",
                f"type=bind,src={run_root / NEGATIVE_FILE},dst=/app/{NEGATIVE_FILE},readonly", APP_IMAGE_ID,
                "python", f"/app/{NEGATIVE_FILE}"]
    return [positive, negative]


def _security_options(options: object) -> set[str]:
    return {str(item) for item in options} if isinstance(options, list) else set()


def _load_seccomp_policy(run_root: Path) -> object:
    path = run_root / SECCOMP_FILE
    _owned_regular(path)
    try:
        raw = path.read_bytes()
    except OSError:
        fail("seccomp_unreadable")
    if len(raw) > MAX_FILE_BYTES:
        fail("seccomp_oversize")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("seccomp_format")


def validate_container_inspect(data: dict, run_name: str, role: str, run_root: Path | None = None) -> bool:
    host = data.get("HostConfig", {})
    config = data.get("Config", {})
    if data.get("Image") != APP_IMAGE_ID or config.get("User") != "10001:10001":
        fail("container_image_or_user_drift")
    if config.get("Labels") != required_labels(run_name) or config.get("Tty") is not False or config.get("OpenStdin") is not False or config.get("Cmd") != ["python", f"/app/{WORKER_FILE if role == 'positive' else NEGATIVE_FILE}"]:
        fail("container_label_or_tty_drift")
    if host.get("NetworkMode") != "none":
        fail("container_network_drift")
    if host.get("ReadonlyRootfs") is not True:
        fail("container_isolation_drift")
    if set(host.get("CapDrop") or []) != {"ALL"} or host.get("CapAdd") not in (None, []) or host.get("Devices") not in (None, []):
        fail("container_capability_drift")
    options = _security_options(host.get("SecurityOpt"))
    if not isinstance(host.get("SecurityOpt"), list) or len(host["SecurityOpt"]) != 3 or len(options) != 3 or "no-new-privileges" not in options or f"apparmor={PROFILE_NAME}" not in options:
        fail("container_security_option_drift")
    seccomp_entries = [item for item in host["SecurityOpt"] if isinstance(item, str) and item.startswith("seccomp=")]
    if run_root is None or len(seccomp_entries) != 1:
        fail("container_seccomp_drift")
    try:
        inspected_seccomp = json.loads(seccomp_entries[0][len("seccomp="):])
    except json.JSONDecodeError:
        fail("container_seccomp_drift")
    if inspected_seccomp != _load_seccomp_policy(run_root):
        fail("container_seccomp_drift")
    if host.get("Privileged") is not False or host.get("PidMode") not in ("", None) or host.get("IpcMode") not in ("", "private", None) or host.get("UsernsMode") not in ("", None) or host.get("CgroupnsMode") not in ("private", "", None):
        fail("container_namespace_drift")
    if host.get("PortBindings") not in (None, {}) or data.get("NetworkSettings", {}).get("Ports") not in (None, {}):
        fail("container_port_drift")
    if host.get("Memory") != 1073741824 or host.get("NanoCpus") != 1000000000 or host.get("PidsLimit") != 256:
        fail("container_resource_drift")
    log = host.get("LogConfig")
    if not isinstance(log, dict) or log.get("Type") != "json-file" or log.get("Config", {}).get("max-size") != "1m" or log.get("Config", {}).get("max-file") != "1" or log.get("Config", {}).get("compress", "false") != "false":
        fail("container_log_drift")
    if host.get("Tmpfs") != {"/tmp": "rw,nosuid,nodev,noexec,size=128m"}:
        fail("container_tmpfs_drift")
    allowed_env = set(STATIC_ENV) | set(CANARY_ENV_NAMES) | IMAGE_SAFE_ENV_NAMES
    allowed_env |= {"JEV_AUDIT_DATA_DIR", "PYTHONUNBUFFERED"}
    env = config.get("Env")
    if not isinstance(env, list) or any(str(item).split("=", 1)[0] not in allowed_env for item in env):
        fail("container_environment_drift")
    if run_root is not None:
        mounts = data.get("Mounts")
        expected = {
            "/data": (str(run_root / DATA_DIR), True),
            f"/app/{WORKER_FILE}": (str(run_root / WORKER_FILE), False),
        }
        if role == "negative":
            expected = {
                "/usr/share/fonts": (str(run_root / FONTS_DIR), True),
                f"/app/{NEGATIVE_FILE}": (str(run_root / NEGATIVE_FILE), False),
            }
        if not isinstance(mounts, list) or len(mounts) != len(expected):
            fail("container_mount_drift")
        for destination, (source, writable) in expected.items():
            found = [item for item in mounts if item.get("Destination") == destination]
            if len(found) != 1 or found[0].get("RW") is not writable:
                fail("container_mount_drift")
            if found[0].get("Type") != "bind" or found[0].get("Source") != source:
                fail("container_mount_drift")
    return True


def _inspect(name: str, run_name: str, role: str, run_root: Path | None = None) -> dict:
    template = (
        "{{.Image}}\t{{.Config.User}}\t{{.Config.Tty}}\t{{.Config.OpenStdin}}\t"
        "{{json .Config.Cmd}}\t{{json .Config.Env}}\t{{json .Config.Labels}}\t"
        "{{.HostConfig.ReadonlyRootfs}}\t{{.HostConfig.NetworkMode}}\t{{json .HostConfig.CapDrop}}\t"
        "{{json .HostConfig.CapAdd}}\t{{json .HostConfig.Devices}}\t{{json .HostConfig.SecurityOpt}}\t"
        "{{.HostConfig.Privileged}}\t{{.HostConfig.PidMode}}\t{{.HostConfig.IpcMode}}\t"
        "{{.HostConfig.UsernsMode}}\t{{.HostConfig.CgroupnsMode}}\t{{json .HostConfig.PortBindings}}\t"
        "{{.HostConfig.Memory}}\t{{.HostConfig.NanoCpus}}\t{{.HostConfig.PidsLimit}}\t"
        "{{json .HostConfig.LogConfig}}\t{{json .HostConfig.Tmpfs}}\t{{json .NetworkSettings.Ports}}\t{{json .Mounts}}"
    )
    fields = _require(run_command(["docker", "inspect", "--format", template, name]), "container_inspect_failed").split("\t")
    if len(fields) != 26:
        fail("container_inspect_format")
    try:
        data = {
            "Image": fields[0],
            "Config": {"User": fields[1], "Tty": fields[2] == "true", "OpenStdin": fields[3] == "true", "Cmd": json.loads(fields[4]), "Env": json.loads(fields[5]), "Labels": json.loads(fields[6])},
            "HostConfig": {"ReadonlyRootfs": fields[7] == "true", "NetworkMode": fields[8], "CapDrop": json.loads(fields[9]), "CapAdd": json.loads(fields[10]), "Devices": json.loads(fields[11]), "SecurityOpt": json.loads(fields[12]), "Privileged": fields[13] == "true", "PidMode": fields[14], "IpcMode": fields[15], "UsernsMode": fields[16], "CgroupnsMode": fields[17], "PortBindings": json.loads(fields[18]), "Memory": int(fields[19]), "NanoCpus": int(fields[20]), "PidsLimit": int(fields[21]), "LogConfig": json.loads(fields[22]), "Tmpfs": json.loads(fields[23])},
            "NetworkSettings": {"Ports": json.loads(fields[24])},
            "Mounts": json.loads(fields[25]),
        }
    except (ValueError, TypeError, json.JSONDecodeError):
        fail("container_inspect_format")
    validate_container_inspect(data, run_name, role, run_root)
    return data


def validate_harness_output(output: str, canaries: dict[str, str]) -> dict[str, object]:
    if len(output.encode()) > MAX_COMMAND_OUTPUT or any(value and value in output for value in canaries.values()):
        fail("harness_secret_leak")
    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        fail("harness_output_format")
    worker = payload.get("worker")
    artifacts = payload.get("artifacts")
    required_assertions = {"job_writable", "runtime_ro", "app_ro", "hidden_data", "hidden_env", "provider_fake"}
    required_worker = {"uid", "gid", "euid", "egid", "caps_eff", "caps_bnd", "no_new_privs", "apparmor", "namespace_ids", "assertions"}
    if set(payload) != {"ok", "worker", "artifacts"} or payload.get("ok") is not True or not isinstance(worker, dict) or not isinstance(artifacts, dict) or set(worker) != required_worker:
        fail("harness_facts_missing")
    if worker.get("uid") != 10001 or worker.get("gid") != 10001 or worker.get("euid") != 10001 or worker.get("egid") != 10001:
        fail("worker_identity_facts")
    if worker.get("caps_eff") != "0000000000000000" or worker.get("caps_bnd") != "0000000000000000" or worker.get("no_new_privs") != 1 or worker.get("apparmor") != PROFILE_NAME + " (enforce)":
        fail("worker_confinement_facts")
    namespaces = worker.get("namespace_ids")
    assertions = worker.get("assertions")
    if not isinstance(namespaces, dict) or set(namespaces) != {"mnt", "user", "pid", "ipc", "uts", "net", "cgroup"} or not all(isinstance(value, str) and 0 < len(value) <= 128 for value in namespaces.values()):
        fail("worker_namespace_facts")
    if not isinstance(assertions, dict) or set(assertions) != required_assertions or not all(assertions.get(name) is True for name in required_assertions):
        fail("worker_assertion_facts")
    if set(artifacts) != {"pdf", "xlsx", "md"}:
        fail("worker_artifact_facts")
    for artifact in artifacts.values():
        if not isinstance(artifact, dict) or not isinstance(artifact.get("size"), int) or not 0 < artifact["size"] <= 4 * 1024 * 1024 or not isinstance(artifact.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"]):
            fail("worker_artifact_facts")
    return {"ok": True, "worker": worker, "artifacts": artifacts, "log_canary_scope": "outer_known_values_only"}


def _journal_boundary() -> dict[str, str]:
    result = run_command(["journalctl", "-k", "--boot=0", "-n", "1", "--show-cursor", "--no-pager", "-o", "json"], timeout=10)
    if result.returncode not in (0, 1):
        fail("kernel_boundary_failed")
    cursor_matches = re.findall(r"^-- cursor: (\S+)$", result.stdout, re.MULTILINE)
    if len(cursor_matches) != 1:
        fail("kernel_cursor_missing")
    records = []
    for line in result.stdout.splitlines():
        if line.startswith("{"):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                fail("kernel_boundary_format")
            if isinstance(record, dict):
                records.append(record)
    boot = records[-1].get("_BOOT_ID") if records else ""
    if records and (not isinstance(boot, str) or not re.fullmatch(r"[0-9a-f]{32}", boot)):
        fail("kernel_boot_missing")
    if not records:
        try:
            boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        except (OSError, UnicodeError):
            fail("kernel_boot_missing")
        if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", boot):
            fail("kernel_boot_missing")
    normalized_boot = boot.replace("-", "") if isinstance(boot, str) else ""
    if not re.fullmatch(r"[0-9a-f]{32}", normalized_boot):
        fail("kernel_boot_missing")
    return {"boot": normalized_boot, "cursor": cursor_matches[0]}


def _journal_records(start: dict[str, str], end: dict[str, str]) -> list[dict]:
    if start.get("boot") != end.get("boot") or not re.fullmatch(r"[0-9a-f]{32}", start.get("boot", "")):
        fail("kernel_boot_drift")
    if start["cursor"] == end["cursor"]:
        return []
    command = ["journalctl", "-k", "--boot=0", f"--after-cursor={start['cursor']}", "--no-pager", "--show-cursor", "-n", str(AUDIT_MAX_RECORDS + 1), "-o", "json"]
    result = run_command(command, timeout=10)
    if result.returncode not in (0, 1):
        fail("kernel_evidence_failed")
    cursor_matches = re.findall(r"^-- cursor: (\S+)$", result.stdout, re.MULTILINE)
    if len(cursor_matches) != 1 or cursor_matches[0] != end["cursor"]:
        fail("kernel_cursor_incomplete")
    records: list[dict] = []
    for line in result.stdout.splitlines():
        if not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            fail("kernel_evidence_format")
        if not isinstance(record, dict) or not isinstance(record.get("_BOOT_ID"), str) or not re.fullmatch(r"[0-9a-f]{32}", record["_BOOT_ID"]) or record["_BOOT_ID"] != start["boot"]:
            fail("kernel_boot_drift")
        records.append(record)
        if record.get("__CURSOR") == end["cursor"]:
            break
    if len(records) > AUDIT_MAX_RECORDS:
        fail("kernel_evidence_truncated")
    if start["cursor"] != end["cursor"] and not any(record.get("__CURSOR") == end["cursor"] for record in records):
        fail("kernel_cursor_incomplete")
    return records


def _journal_loss(records: list[dict]) -> None:
    for record in records:
        text = " ".join(str(record.get(key, "")).lower() for key in ("MESSAGE", "MESSAGE_ID"))
        if any(signature in text for signature in AUDIT_LOSS_SIGNATURES):
            fail("kernel_audit_loss")


def _parse_audit_message(message: str) -> dict[str, object] | None:
    if "DENIED" not in message or PROFILE_NAME not in message:
        return None
    try:
        tokens = shlex.split(message)
    except ValueError:
        fail("audit_message_malformed")
    fields: dict[str, str] = {}
    for token in tokens:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        if key in fields:
            fail("audit_message_duplicate")
        fields[key] = value
    serials = re.findall(r"audit\(\d+(?:\.\d+)?:([0-9]+)\)", message)
    if len(serials) != 1 or fields.get("apparmor") != "DENIED" or fields.get("profile") != PROFILE_NAME or fields.get("comm") != "bwrap" or fields.get("operation") != "mount":
        fail("audit_event_mismatch")
    target = fields.get("name", "")
    if target not in EXPECTED_PROFILE_DENIAL_TARGETS:
        fail("audit_target_mismatch")
    try:
        pid = int(fields["pid"])
    except (KeyError, ValueError):
        fail("audit_pid_missing")
    if pid <= 0:
        fail("audit_pid_missing")
    raw_flags = fields.get("flags")
    if not raw_flags:
        fail("audit_flags_missing")
    flag_parts = [flag for flag in re.split(r"[,\s]+", raw_flags) if flag]
    flags = set(flag_parts)
    if len(flag_parts) != len(flags):
        fail("audit_flags_mismatch")
    if not REQUIRED_REMOUNT_FLAGS.issubset(flags) or "ro" in flags or not flags.issubset(REQUIRED_REMOUNT_FLAGS | OPTIONAL_REMOUNT_FLAGS):
        fail("audit_flags_mismatch")
    return {"serial": serials[0], "host_pid": pid, "profile": PROFILE_NAME, "comm": "bwrap", "operation": "mount", "target": target, "flags": sorted(flags)}


def _phase_audit(start: dict[str, str], end: dict[str, str], phase: str) -> dict[str, object]:
    records = _journal_records(start, end)
    _journal_loss(records)
    events: list[dict[str, object]] = []
    for record in records:
        message = record.get("MESSAGE")
        if isinstance(message, str):
            event = _parse_audit_message(message)
            if event is not None:
                events.append(event)
    serials = [event["serial"] for event in events]
    if len(serials) != len(set(serials)):
        fail("audit_event_duplicate")
    if phase == "positive":
        if events:
            fail("positive_apparmor_denial")
    elif len(events) != 1:
        fail("negative_audit_inconclusive")
    if phase == "negative":
        pid = events[0]["host_pid"]
        pid_events = []
        for record in records:
            message = record.get("MESSAGE")
            if isinstance(message, str):
                event = _parse_audit_message(message)
                if event is not None and event["host_pid"] == pid:
                    pid_events.append(event)
        if len(pid_events) != 1:
            fail("negative_audit_inconclusive")
    return {"phase": phase, "boot": start["boot"], "start_cursor": start["cursor"], "end_cursor": end["cursor"], "events": events}


def validate_negative_candidate(candidate: dict) -> dict[str, object]:
    required = {"denied_candidate", "audit_corroboration_required", "policy_proof", "expected_remount_target", "source_options", "missing_source_flags", "child_pid", "returncode", "timed_out", "stderr_nonempty", "stderr_bytes"}
    if set(candidate) != required or candidate["denied_candidate"] is not True or candidate["audit_corroboration_required"] is not True or candidate["policy_proof"] is not False:
        fail("negative_candidate_contract")
    if candidate["expected_remount_target"] != "/usr/share/fonts" or not isinstance(candidate["source_options"], list) or not isinstance(candidate["missing_source_flags"], list) or len(candidate["source_options"]) > 32 or len(candidate["missing_source_flags"]) > 32 or not all(isinstance(item, str) and len(item) <= 32 for item in candidate["source_options"] + candidate["missing_source_flags"]):
        fail("negative_candidate_contract")
    if type(candidate["child_pid"]) is not int or candidate["child_pid"] <= 0 or type(candidate["returncode"]) is not int or candidate["returncode"] == 0 or candidate["timed_out"] is not False or type(candidate["stderr_nonempty"]) is not bool or type(candidate["stderr_bytes"]) is not int or candidate["stderr_bytes"] < 0:
        fail("negative_candidate_contract")
    source_options = set(candidate["source_options"])
    missing_source_flags = set(candidate["missing_source_flags"])
    if not source_options or "rw" not in source_options or not missing_source_flags or missing_source_flags != ({"nosuid", "nodev"} - source_options):
        fail("negative_candidate_contract")
    return {key: candidate[key] for key in required}


def require_negative_corroboration(candidate: dict, audit: dict[str, object]) -> dict[str, object]:
    candidate = validate_negative_candidate(candidate)
    source_options = set(candidate["source_options"])
    missing_source_flags = set(candidate["missing_source_flags"])
    if len(source_options) != len(candidate["source_options"]) or len(missing_source_flags) != len(candidate["missing_source_flags"]) or "rw" not in source_options:
        fail("negative_candidate_contract")
    expected_missing = {"nosuid", "nodev"} - source_options
    if not missing_source_flags or missing_source_flags != expected_missing:
        fail("negative_candidate_contract")
    events = audit.get("events", [])
    if not isinstance(events, list) or len(events) != 1:
        fail("negative_audit_inconclusive")
    event = events[0]
    expected_flags = REQUIRED_REMOUNT_FLAGS | (source_options & OPTIONAL_REMOUNT_FLAGS)
    if not isinstance(event, dict) or type(event.get("host_pid")) is not int or event.get("host_pid") <= 0 or event.get("profile") != PROFILE_NAME or event.get("comm") != "bwrap" or event.get("operation") != "mount" or event.get("target") not in EXPECTED_PROFILE_DENIAL_TARGETS or set(event.get("flags", [])) != expected_flags:
        fail("negative_audit_inconclusive")
    if len([item for item in events if isinstance(item, dict) and item.get("host_pid") == event["host_pid"]]) != 1:
        fail("negative_audit_inconclusive")
    return {"candidate": candidate, "audit": audit}


def _canaries() -> dict[str, str]:
    proxy = "http://10.0.9.4:4750"
    return {"JEVSEO_EGRESS_PROXY": proxy, "HTTP_PROXY": proxy, "HTTPS_PROXY": proxy, "TYPESAFE_API_KEY": "fake-provider-key"}


def _make_owned_dir(path: Path) -> None:
    if path.exists() or path.is_symlink():
        fail("owned_data_collision")
    path.mkdir(mode=0o700)
    os.chown(path, 10001, 10001)


def _cleanup_container(name: str, run_name: str, role: str, run_root: Path) -> None:
    _inspect(name, run_name, role, run_root)
    result = run_command(["docker", "rm", "-f", name], timeout=15)
    if result.returncode != 0:
        fail("container_cleanup_failed")


def _profile_users() -> bool:
    try:
        entries = list(Path("/proc").iterdir())
        if len(entries) > 4096:
            fail("profile_user_inventory_truncated")
        for entry in entries:
            if not entry.name.isdigit():
                continue
            try:
                if (entry / "attr/current").read_text(encoding="ascii")[:128].strip().startswith(PROFILE_NAME + " "):
                    return True
            except FileNotFoundError:
                continue
            except OSError:
                fail("profile_user_label_unreadable")
    except OSError:
        fail("profile_user_inventory_failed")
    return False


def _cleanup_profile(profile_path: Path) -> None:
    if not _profile_present():
        return
    if _profile_users():
        fail("profile_cleanup_uncertain")
    result = run_command(["apparmor_parser", "-R", str(profile_path)], timeout=15)
    if result.returncode != 0 or _profile_present():
        fail("profile_cleanup_uncertain")


def run_acceptance(run_root: Path) -> dict[str, object]:
    run_root = validate_run_root(run_root)
    validate_staged_files(run_root)
    host = validate_host()
    image = validate_image()
    preflight = run_image_preflight(run_root, run_root.name)
    data_path = run_root / DATA_DIR
    fonts_path = run_root / FONTS_DIR
    _make_owned_dir(data_path)
    _make_owned_dir(fonts_path)
    profile_attempted = False
    created: dict[str, str] = {}
    removed: set[str] = set()
    canaries = _canaries()
    original: OrchestrationError | None = None
    outcome: dict[str, object] | None = None
    try:
        positive_name, negative_name = f"{run_root.name}-positive", f"{run_root.name}-negative"
        _assert_resource_absent(positive_name)
        _assert_resource_absent(negative_name)
        if _profile_present():
            fail("profile_name_conflict")
        profile_attempted = True
        loaded_result = run_command(["apparmor_parser", "-a", str(run_root / PROFILE_FILE)], timeout=15)
        if loaded_result.returncode != 0:
            fail("profile_load_failed")
        if not _profile_enforced():
            fail("profile_load_failed")
        positive_command, negative_command = build_container_commands(run_root, run_root.name, canaries)
        positive = run_command(positive_command, timeout=30)
        if positive.returncode != 0:
            fail("positive_container_create_failed")
        created[positive_name] = "positive"
        _inspect(positive_name, run_root.name, "positive", run_root)
        positive_start = _journal_boundary()
        positive_result = run_command(["docker", "start", "-a", positive_name], timeout=240)
        positive_end = _journal_boundary()
        if positive_result.returncode != 0:
            fail("positive_worker_failed")
        if any(value in positive_result.stderr for value in canaries.values()):
            fail("harness_secret_leak")
        worker_evidence = validate_harness_output(positive_result.stdout, canaries)
        positive_audit = _phase_audit(positive_start, positive_end, "positive")
        _cleanup_container(positive_name, run_root.name, "positive", run_root)
        removed.add(positive_name)
        negative = run_command(negative_command, timeout=30)
        if negative.returncode != 0:
            fail("negative_container_create_failed")
        created[negative_name] = "negative"
        _inspect(negative_name, run_root.name, "negative", run_root)
        negative_start = _journal_boundary()
        negative_result = run_command(["docker", "start", "-a", negative_name], timeout=240)
        negative_end = _journal_boundary()
        if any(value in negative_result.stdout or value in negative_result.stderr for value in canaries.values()):
            fail("harness_secret_leak")
        try:
            candidate = json.loads(negative_result.stdout)
        except json.JSONDecodeError:
            fail("negative_candidate_format")
        negative_audit = _phase_audit(negative_start, negative_end, "negative")
        negative_evidence = require_negative_corroboration(candidate, negative_audit)
        _cleanup_container(negative_name, run_root.name, "negative", run_root)
        removed.add(negative_name)
        outcome = {"ok": True, "host": host, "image": image, "preflight": preflight, "positive": worker_evidence, "positive_audit": positive_audit, "negative": negative_evidence}
    except OrchestrationError as error:
        original = error
    except Exception:
        original = OrchestrationError("orchestration_failed")
    warnings: list[str] = []
    for name, role in reversed(list(created.items())):
        if name in removed:
            continue
        try:
            _cleanup_container(name, run_root.name, role, run_root)
        except OrchestrationError as error:
            warnings.append(error.code)
    if profile_attempted:
        if warnings:
            warnings.append("profile_cleanup_skipped")
        else:
            try:
                _cleanup_profile(run_root / PROFILE_FILE)
            except OrchestrationError as error:
                warnings.append(error.code)
    if original is not None:
        original.warnings.extend(warnings)
        raise original
    if warnings:
        error = OrchestrationError("cleanup_uncertain")
        error.warnings.extend(warnings)
        raise error
    return outcome or {"ok": False, "error": "orchestration_failed"}


def emit_summary(payload: dict[str, object]) -> int:
    text = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    if len(text.encode()) > MAX_OUTPUT_BYTES:
        text = '{"error":"output_oversize","ok":false}'
        code = 1
    else:
        code = 0 if payload.get("ok") is True else 1
    print(text)
    return code


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if len(args) != 1:
            fail("one_run_root_required")
        return emit_summary(run_acceptance(Path(args[0])))
    except OrchestrationError as error:
        return emit_summary({"ok": False, "error": error.code[:64], "cleanup_warnings": error.warnings})
    except Exception:
        return emit_summary({"ok": False, "error": "orchestration_failed"})


if __name__ == "__main__":
    raise SystemExit(main())
