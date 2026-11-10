"""Offline-first staging for the native fallback.

Only identities, owned directories, a verified release and its offline venv are
handled here.  Units, AppArmor, nftables, routes, services and existing apps
are intentionally outside this slice.
"""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import tarfile
from pathlib import Path, PurePosixPath


NATIVE_ROOT = Path("/opt/jev-audit-native")
RELEASES_ROOT = NATIVE_ROOT / "releases"
DATA_ROOT = Path("/var/lib/jev-audit-native")
ACCEPTANCE_ROOT = Path("/var/lib/jev-audit-native-acceptance")
CONFIG_ROOT = Path("/etc/jev-audit-native")
RESOLVER_PATH = Path("/run/systemd/resolve/stub-resolv.conf")
RESOLVER_ADDRESS = "127.0.0.53"
APP_SOURCE_SHA = "0e7c53a36257c75d96aae7890f2103b9341c9e3b"
ROLES = ("jev-audit-api", "jev-audit-egress", "jev-audit-relay")
EXPECTED_VERSIONS = {"python": "3.12.3", "bwrap": "0.9.0-1ubuntu0.3", "systemd": "255", "nft": "1.0.9", "apparmor": "4.0.1"}
DEFAULT_UID_RANGE = (200, 999)  # finite documented fallback when login.defs is unavailable
MIN_FREE_BYTES = 512 * 1024 * 1024
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_BUNDLE_BYTES = 1024 * 1024 * 1024
MAX_BUNDLE_MEMBERS = 4096
MAX_UNPACKED_BYTES = 512 * 1024 * 1024
MAX_HEADROOM_BYTES = 512 * 1024 * 1024
DISK_ANCHORS = (Path("/opt"), Path("/var/lib"), Path("/etc"))
OWNER_MARKER_PREFIX = "jev-audit-native-owner-v1"
REQUIRED_PAYLOADS = {"native/smokescreen", "native/smokescreen.json", "native/tools/check_sandbox_acceptance.py", "native-inputs/manifest.json", "requirements.lock"}
FIXED_NATIVE_PAYLOADS = {"native/smokescreen", "native/smokescreen.json", "native/tools/check_sandbox_acceptance.py"}


class StageError(RuntimeError):
    pass


def _fail(code: str) -> None:
    raise StageError(code)


def _safe_name(name: str) -> str:
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts or str(path) != name:
        _fail("unsafe_bundle_member")
    return name


def _read_member(tar: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    if not member.isreg() or member.issym() or member.islnk() or member.size > MAX_MEMBER_BYTES:
        _fail("bundle_member_not_regular")
    stream = tar.extractfile(member)
    if stream is None:
        _fail("bundle_member_unreadable")
    data = stream.read(MAX_MEMBER_BYTES + 1)
    if len(data) != member.size or len(data) > MAX_MEMBER_BYTES:
        _fail("bundle_member_oversize")
    return data


def verify_bundle(archive: Path) -> tuple[str, dict[str, bytes]]:
    """Verify every archive member and hash before any destination is created."""
    try:
        archive_info = archive.lstat()
    except OSError as exc:
        raise StageError("bundle_not_regular") from exc
    if stat.S_ISLNK(archive_info.st_mode) or not stat.S_ISREG(archive_info.st_mode) or archive_info.st_nlink != 1 or archive_info.st_size > MAX_BUNDLE_BYTES:
        _fail("bundle_not_regular")
    try:
        with tarfile.open(archive, "r:gz") as tar:
            members = tar.getmembers()
            if len(members) > MAX_BUNDLE_MEMBERS or sum(max(0, member.size) for member in members) > MAX_UNPACKED_BYTES:
                _fail("bundle_size_bound")
            names = [_safe_name(member.name) for member in members]
            if len(names) != len(set(names)):
                _fail("bundle_duplicate_member")
            by_name = dict(zip(names, members))
            if {"bundle.marker", "manifest.sha256"} - set(by_name):
                _fail("bundle_marker_missing")
            marker_data = _read_member(tar, by_name["bundle.marker"])
            manifest_data = _read_member(tar, by_name["manifest.sha256"])
            try:
                marker = json.loads(marker_data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                _fail("bundle_marker_invalid")
            if set(marker) != {"format", "manifest_sha256", "source_sha"} or marker.get("format") != 1:
                _fail("bundle_marker_invalid")
            source_sha = marker.get("source_sha", "")
            if source_sha != APP_SOURCE_SHA:
                _fail("bundle_source_sha_invalid")
            if marker.get("manifest_sha256") != hashlib.sha256(manifest_data).hexdigest():
                _fail("bundle_manifest_hash")
            expected: dict[str, str] = {}
            for line in manifest_data.decode("ascii").splitlines():
                match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
                if not match:
                    _fail("bundle_manifest_invalid")
                name = _safe_name(match.group(2))
                if name in expected or name in {"bundle.marker", "manifest.sha256"}:
                    _fail("bundle_manifest_invalid")
                expected[name] = match.group(1)
            actual = set(names) - {"bundle.marker", "manifest.sha256"}
            if actual != set(expected):
                _fail("bundle_members_unexpected")
            payload: dict[str, bytes] = {}
            for name, digest in expected.items():
                data = _read_member(tar, by_name[name])
                if hashlib.sha256(data).hexdigest() != digest:
                    _fail("bundle_member_hash")
                payload[name] = data
            _validate_payload(payload)
            return source_sha, payload
    except (OSError, tarfile.TarError, UnicodeDecodeError) as exc:
        raise StageError("bundle_invalid") from exc


def _command(argv: list[str], *, cwd: Path | None = None, timeout: int = 120) -> str:
    if not argv or any(not isinstance(part, str) for part in argv):
        _fail("invalid_command")
    executable = Path(argv[0]).name
    if executable in {"systemctl", "service", "apparmor_parser", "nft", "ip", "ufw", "docker", "ssh", "scp", "rsync", "curl", "wget", "git", "sh", "bash"}:
        if not (executable in {"apparmor_parser", "nft"} and len(argv) == 2 and argv[1] in {"--version", "-v"}):
            _fail("activation_command_forbidden")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/root", "PIP_CONFIG_FILE": os.devnull, "PIP_NO_INPUT": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1"}
    try:
        result = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StageError("command_failed") from exc
    if result.returncode != 0:
        raise StageError("command_failed")
    if len(result.stdout.encode()) > 256 * 1024 or len(result.stderr.encode()) > 256 * 1024:
        _fail("command_output_oversize")
    return result.stdout.strip()


def _validate_payload(payload: dict[str, bytes]) -> None:
    if not REQUIRED_PAYLOADS.issubset(payload):
        _fail("bundle_required_member_missing")
    for name in payload:
        if name == "requirements.lock" or name in FIXED_NATIVE_PAYLOADS or name == "native-inputs/manifest.json":
            continue
        if name.startswith("source/"):
            relative = name.removeprefix("source/")
            if not (relative.startswith("jevseo/") or relative in {"pyproject.toml", "README.md", "LICENSE"}) or any(part in {".git", ".env", "__pycache__"} or part.endswith(".pyc") for part in PurePosixPath(relative).parts):
                _fail("bundle_source_prefix_unexpected")
            continue
        if name.startswith("native-inputs/"):
            if name.endswith("/"):
                _fail("bundle_prefix_unexpected")
            continue
        if name.startswith("wheelhouse/"):
            if PurePosixPath(name).parent != PurePosixPath("wheelhouse"):
                _fail("bundle_wheelhouse_invalid")
            continue
        _fail("bundle_prefix_unexpected")
    if not payload["native/smokescreen"].startswith(b"\x7fELF"):
        _fail("bundle_smokescreen_invalid")
    try:
        lock_lines = payload["requirements.lock"].decode("ascii").splitlines()
    except UnicodeDecodeError:
        _fail("requirements_lock_invalid")
    lock_names: set[str] = set()
    for line in lock_lines:
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([^\s]+) --hash=sha256:([0-9a-f]{64})", line)
        if not match:
            _fail("requirements_lock_invalid")
        normalized = re.sub(r"[-_.]+", "-", match.group(1)).lower()
        if normalized in lock_names:
            _fail("requirements_lock_invalid")
        lock_names.add(normalized)
    if "jev-seo" not in lock_names:
        _fail("requirements_lock_invalid")
    try:
        native_manifest = json.loads(payload["native-inputs/manifest.json"].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("native_input_manifest_invalid")
    if set(native_manifest) != {"format", "inputs"} or native_manifest["format"] != 1 or not isinstance(native_manifest["inputs"], list) or not native_manifest["inputs"]:
        _fail("native_input_manifest_invalid")
    native_members = {name for name in payload if name.startswith("native-inputs/") and name != "native-inputs/manifest.json"}
    manifest_members: set[str] = set()
    for item in native_manifest["inputs"]:
        if not isinstance(item, dict) or set(item) != {"member", "source", "sha256"} or not isinstance(item["member"], str) or not isinstance(item["source"], str) or not isinstance(item["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]):
            _fail("native_input_manifest_invalid")
        member = item["member"]
        if not member.startswith("native-inputs/") or member == "native-inputs/manifest.json" or member in manifest_members or not re.fullmatch(r"native-inputs/deploy/native/.+", member):
            _fail("native_input_manifest_invalid")
        if item["source"] != member.removeprefix("native-inputs/") or member not in payload or hashlib.sha256(payload[member]).hexdigest() != item["sha256"]:
            _fail("native_input_manifest_invalid")
        manifest_members.add(member)
    if manifest_members != native_members:
        _fail("native_input_manifest_invalid")
    wheels = [name for name in payload if name.startswith("wheelhouse/")]
    if not wheels or any(not name.endswith(".whl") for name in wheels):
        _fail("bundle_wheelhouse_invalid")
    projects = [name for name in wheels if re.fullmatch(r"wheelhouse/jev[_-]seo-0\.1\.1-.+\.whl", name)]
    if len(projects) != 1:
        _fail("bundle_project_wheel_missing")


def host_versions() -> dict[str, str]:
    facts = {
        "python": _command(["python3", "--version"]),
        "bwrap": _command(["dpkg-query", "-W", "-f=${Version}\n", "bubblewrap"]),
        "bwrap_binary": _command(["bwrap", "--version"]),
        "systemd": _command(["systemd", "--version"]),
        "nft": _command(["nft", "--version"]),
        "apparmor": _command(["apparmor_parser", "--version"]),
    }
    patterns = {
        "python": rf"Python\s+{re.escape(EXPECTED_VERSIONS['python'])}\b",
        "bwrap": rf"^{re.escape(EXPECTED_VERSIONS['bwrap'])}$",
        "bwrap_binary": r"\b0\.9\.0\b",
        "systemd": rf"\bsystemd\s+{re.escape(EXPECTED_VERSIONS['systemd'])}\b",
        "nft": rf"\bnftables v{re.escape(EXPECTED_VERSIONS['nft'])}\b",
        "apparmor": rf"\b{re.escape(EXPECTED_VERSIONS['apparmor'])}\b",
    }
    if any(re.search(patterns[key], facts[key]) is None for key in facts):
        _fail("host_version_drift")
    return facts


def validate_prerequisites() -> None:
    for executable in ("python3", "useradd", "groupadd", "chown", "passwd"):
        if shutil.which(executable) is None:
            _fail("prerequisite_missing")
    _command(["python3", "-c", "import ensurepip,venv; assert hasattr(venv, 'EnvBuilder')"])


def uid_range(login_defs: Path = Path("/etc/login.defs")) -> tuple[int, int]:
    values: dict[str, int] = {}
    try:
        for line in login_defs.read_text(encoding="ascii").splitlines():
            match = re.match(r"^\s*(SYS_UID_MIN|SYS_UID_MAX)\s+(\d+)\s*$", line)
            if match:
                values[match.group(1)] = int(match.group(2))
    except OSError:
        values = {}
    result = (values.get("SYS_UID_MIN"), values.get("SYS_UID_MAX"))
    if result[0] is None or result[1] is None or result[0] < 1 or result[1] < result[0] or result[1] - result[0] > 100_000:
        return DEFAULT_UID_RANGE
    return result  # type: ignore[return-value]


def process_uids(proc_root: Path = Path("/proc")) -> set[int]:
    occupied: set[int] = set()
    try:
        entries = list(proc_root.iterdir())
    except OSError as exc:
        raise StageError("process_uid_inventory_failed") from exc
    if len(entries) > 20_000:
        _fail("process_uid_inventory_truncated")
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            status = (entry / "status").read_text(encoding="ascii")
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise StageError("process_uid_inventory_failed") from exc
        for line in status.splitlines():
            if line.startswith(("Uid:", "Gid:", "Groups:")):
                for value in line.split()[1:]:
                    if value.isdigit():
                        occupied.add(int(value))
    return occupied


def occupied_uids() -> set[int]:
    result = {value for entry in pwd.getpwall() for value in (entry.pw_uid, entry.pw_gid)}
    result.update(group.gr_gid for group in grp.getgrall())
    return result | process_uids()


def allocate_uids(occupied: set[int], count: int, bounds: tuple[int, int] | None = None) -> list[int]:
    if count < 1:
        _fail("uid_count_invalid")
    low, high = bounds or uid_range()
    result: list[int] = []
    for candidate in range(low, high + 1):
        if candidate in occupied or candidate in {10001, 65534}:
            continue
        result.append(candidate)
        occupied = occupied | {candidate}
        if len(result) == count:
            return result
    _fail("uid_pool_exhausted")


def _marker(path: Path) -> Path:
    return path / ".jev-audit-native-owner"


def _marker_text(path: Path) -> str:
    return f"{OWNER_MARKER_PREFIX}\npath={path}\n"


def _owned_or_absent(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink() or not path.is_dir():
        _fail("owned_path_collision")
    marker = _marker(path)
    try:
        if marker.is_symlink() or marker.stat().st_uid != 0 or stat.S_IMODE(marker.stat().st_mode) != 0o600 or marker.read_text(encoding="ascii") != _marker_text(path):
            _fail("unverified_existing_path")
    except OSError as exc:
        raise StageError("unverified_existing_path") from exc


def validate_paths(release_root: Path) -> None:
    targets = (NATIVE_ROOT, DATA_ROOT, ACCEPTANCE_ROOT, CONFIG_ROOT, release_root)
    for target in targets:
        target_absolute = target.absolute()
        for anchor in DISK_ANCHORS:
            try:
                target_absolute.relative_to(anchor.absolute())
            except ValueError:
                continue
            current = target_absolute.parent
            while current != anchor.absolute().parent:
                try:
                    info = current.lstat()
                except FileNotFoundError:
                    current = current.parent
                    continue
                except OSError as exc:
                    raise StageError("path_ancestor_unreadable") from exc
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                    _fail("path_ancestor_unsafe")
                current = current.parent
            break
    for path in (NATIVE_ROOT, DATA_ROOT, ACCEPTANCE_ROOT, CONFIG_ROOT):
        _owned_or_absent(path)
    _owned_or_absent(RELEASES_ROOT)
    if release_root.exists() or release_root.is_symlink():
        _fail("release_exists")


def validate_accounts() -> None:
    for name in ROLES:
        try:
            pwd.getpwnam(name)
        except KeyError:
            pass
        else:
            _fail("service_account_exists")
        try:
            grp.getgrnam(name)
        except KeyError:
            continue
        _fail("service_group_exists")


def validate_resolver() -> None:
    if RESOLVER_PATH.is_symlink() or not RESOLVER_PATH.is_file():
        _fail("resolver_path_invalid")
    try:
        content = RESOLVER_PATH.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise StageError("resolver_path_invalid") from exc
    if f"nameserver {RESOLVER_ADDRESS}" not in content:
        _fail("resolver_address_invalid")


def disk_anchor(path: Path) -> Path:
    for anchor in DISK_ANCHORS:
        try:
            path.absolute().relative_to(anchor.absolute())
        except ValueError:
            continue
        try:
            info = anchor.lstat()
        except OSError as exc:
            raise StageError("disk_anchor_missing") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            _fail("disk_anchor_unsafe")
        return anchor
    _fail("disk_anchor_unallowlisted")


def _write_bytes(path: Path, data: bytes, mode: int) -> None:
    if path.exists() or path.is_symlink():
        _fail("write_destination_exists")
    path.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
    except OSError as exc:
        raise StageError("write_failed") from exc


def _extract_payload(release_root: Path, payload: dict[str, bytes]) -> None:
    for name, data in sorted(payload.items()):
        if name.startswith("source/"):
            target_name = name.replace("source/", "code/", 1)
        elif name == "native/smokescreen":
            target_name = "bin/smokescreen"
        elif name == "native/smokescreen.json":
            target_name = "smokescreen.json"
        elif name.startswith("native/tools/"):
            target_name = name.replace("native/", "", 1)
        else:
            target_name = name
        _safe_name(target_name)
        _write_bytes(release_root / target_name, data, 0o755 if target_name == "bin/smokescreen" else 0o644)


def _write_owner_marker(path: Path, mode: int = 0o700) -> None:
    path.mkdir(parents=True, mode=mode, exist_ok=True)
    os.chown(path, 0, 0)
    os.chmod(path, mode)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != mode:
        _fail("owned_path_update_failed")
    if not _marker(path).exists():
        _write_bytes(_marker(path), _marker_text(path).encode(), 0o600)
    marker = _marker(path).lstat()
    if stat.S_ISLNK(marker.st_mode) or not stat.S_ISREG(marker.st_mode) or marker.st_uid != 0 or stat.S_IMODE(marker.st_mode) != 0o600 or _marker(path).read_text(encoding="ascii") != _marker_text(path):
        _fail("owner_marker_invalid")


def _state(path: Path, data: dict[str, object]) -> None:
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if path.exists() or path.is_symlink():
        try:
            info = path.lstat()
        except OSError as exc:
            raise StageError("state_unreadable") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            _fail("state_unowned")
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    if temporary.exists() or temporary.is_symlink():
        _fail("state_temp_exists")
    _write_bytes(temporary, encoded, 0o600)
    os.chown(temporary, 0, 0)
    os.replace(temporary, path)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
        _fail("state_update_failed")


def _create_group(name: str, gid: int) -> dict[str, object]:
    current = occupied_uids()
    if gid in current:
        _fail("gid_race_detected")
    try:
        grp.getgrnam(name)
    except KeyError:
        pass
    else:
        _fail("service_group_exists")
    _command(["groupadd", "--system", "--gid", str(gid), name])
    try:
        entry = grp.getgrnam(name)
    except KeyError as exc:
        raise StageError("groupadd_verification_failed") from exc
    if entry.gr_gid != gid:
        _fail("groupadd_gid_drift")
    return {"name": name, "gid": entry.gr_gid}


def _create_account(name: str, uid: int, gid: int) -> dict[str, object]:
    if any(entry.pw_uid == uid for entry in pwd.getpwall()):
        _fail("uid_race_detected")
    if any(group.gr_gid == uid and group.gr_name != name for group in grp.getgrall()):
        _fail("uid_race_detected")
    if uid in process_uids():
        _fail("uid_race_detected")
    _command(["useradd", "--system", "--uid", str(uid), "--gid", name, "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "--password", "!", name])
    try:
        entry = pwd.getpwnam(name)
    except KeyError as exc:
        raise StageError("useradd_verification_failed") from exc
    if entry.pw_uid != uid or entry.pw_gid != gid or entry.pw_dir != "/nonexistent" or entry.pw_shell != "/usr/sbin/nologin":
        _fail("useradd_id_drift")
    lock_status = _command(["passwd", "--status", name]).split()
    if len(lock_status) < 2 or lock_status[0] != name or lock_status[1] != "L":
        _fail("useradd_lock_status_invalid")
    try:
        groups = set(os.getgrouplist(name, gid))
    except OSError as exc:
        raise StageError("useradd_group_lookup_failed") from exc
    if groups != {gid}:
        _fail("useradd_supplementary_group_drift")
    try:
        group_name = grp.getgrgid(gid).gr_name
    except KeyError as exc:
        raise StageError("useradd_group_verification_failed") from exc
    return {"name": name, "uid": entry.pw_uid, "gid": entry.pw_gid, "group": group_name}


def offline_install_command(python: Path, release_root: Path) -> list[str]:
    return [str(python), "-m", "pip", "install", "--no-index", "--find-links", str(release_root / "wheelhouse"), "--require-hashes", "--only-binary=:all:", "--disable-pip-version-check", "-r", str(release_root / "requirements.lock")]


def _chmod_tree(root: Path) -> None:
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            if root.name != "venv" or path.relative_to(root) != Path("lib64") or not (root / "lib").is_dir() or path.resolve() != (root / "lib").resolve():
                _fail("release_symlink")
            if info.st_uid != 0:
                _fail("release_symlink_owner")
            continue
        os.chown(path, 0, 0)
        os.chmod(path, 0o555 if stat.S_ISDIR(info.st_mode) else 0o555 if path.name == "smokescreen" or path.parent.name == "bin" else 0o444)
    os.chown(root, 0, 0)
    os.chmod(root, 0o555)


def _native_facts(python: Path, release_root: Path) -> dict[str, str]:
    code = "import importlib.util,json,sys; from pathlib import Path; p=next(iter(importlib.util.find_spec('jevseo').submodule_search_locations or ('' ,))); assert importlib.util.find_spec('jevseo.web') and importlib.util.find_spec('jevseo.cli') and (Path(sys.executable).parent / 'jevseo').is_file(); print(json.dumps({'venv_python':str(Path(sys.executable).resolve()),'sys_prefix':str(Path(sys.prefix).resolve()),'package_dir':str(Path(p).resolve()),'api_runner':'python -m jevseo.web','cli_runner':'jevseo'}))"
    raw = _command([str(python), "-c", code], cwd=release_root)
    try:
        facts = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise StageError("native_facts_invalid") from exc
    if set(facts) != {"venv_python", "sys_prefix", "package_dir", "api_runner", "cli_runner"}:
        _fail("native_facts_invalid")
    if any(not isinstance(value, str) for value in facts.values()):
        _fail("native_facts_invalid")
    if facts["api_runner"] != "python -m jevseo.web" or facts["cli_runner"] != "jevseo":
        _fail("native_facts_invalid")
    expected_python = (release_root / "venv/bin/python").resolve()
    expected_prefix = (release_root / "venv").resolve()
    expected_site = expected_prefix / "lib/python3.12/site-packages"
    if Path(facts["venv_python"]) != expected_python or Path(facts["sys_prefix"]) != expected_prefix or not Path(facts["package_dir"]).is_relative_to(expected_site):
        _fail("native_facts_outside_release")
    return facts


def stage_bundle(bundle: Path, apply: bool = False) -> dict[str, object]:
    source_sha, payload = verify_bundle(bundle)
    release_root = RELEASES_ROOT / source_sha
    facts = host_versions()
    validate_prerequisites()
    validate_resolver()
    unpacked = sum(len(data) for data in payload.values())
    required_free = MIN_FREE_BYTES + min(unpacked * 2, MAX_HEADROOM_BYTES)
    if shutil.disk_usage(disk_anchor(RELEASES_ROOT)).free < required_free:
        _fail("disk_space_low")
    validate_accounts()
    validate_paths(release_root)
    planned = allocate_uids(occupied_uids(), len(ROLES))
    roles = [{"name": name, "uid": uid, "gid": uid} for name, uid in zip(ROLES, planned)]
    result: dict[str, object] = {
        "apply": apply,
        "source_sha": source_sha,
        "release_root": str(release_root),
        "venv_python": str(release_root / "venv/bin/python"),
        "package_dir": str(release_root / "venv/lib/python3.12/site-packages/jevseo"),
        "sys_prefix": str(release_root / "venv"),
        "canonical_exe": str(release_root / "venv/bin/python"),
        "roles": roles,
        "data_root": str(DATA_ROOT),
        "acceptance_root": str(ACCEPTANCE_ROOT),
        "hostresolverpath": str(RESOLVER_PATH),
        "hostresolveraddr": RESOLVER_ADDRESS,
        "versionfacts": facts,
    }
    if not apply:
        return result
    if os.geteuid() != 0:
        _fail("apply_requires_root")
    _write_owner_marker(NATIVE_ROOT, 0o755)
    _write_owner_marker(RELEASES_ROOT, 0o755)
    _write_owner_marker(DATA_ROOT)
    _write_owner_marker(ACCEPTANCE_ROOT)
    _write_owner_marker(CONFIG_ROOT)
    state_path = CONFIG_ROOT / "native-stage-state.json"
    created_groups: list[dict[str, object]] = []
    created_users: list[dict[str, object]] = []
    intent = [{"name": name, "uid": uid, "gid": uid, "group": name} for name, uid in zip(ROLES, planned)]
    _state(state_path, {"format": 1, "source_sha": source_sha, "resource_intent": intent, "created_groups": [], "created_users": []})
    for role, uid in zip(ROLES, planned):
        group = _create_group(role, uid)
        created_groups.append(group)
        _state(state_path, {"format": 1, "source_sha": source_sha, "resource_intent": intent, "created_groups": created_groups, "created_users": created_users})
        account = _create_account(role, uid, uid)
        created_users.append(account)
        result["roles"] = created_users
        _state(state_path, {"format": 1, "source_sha": source_sha, "resource_intent": intent, "created_groups": created_groups, "created_users": created_users})
    release_root.mkdir(parents=True, mode=0o755)
    _extract_payload(release_root, payload)
    code_root = release_root / "code"
    venv_root = release_root / "venv"
    _command(["python3", "-m", "venv", "--copies", str(venv_root)])
    python = venv_root / "bin" / "python"
    _command(offline_install_command(python, release_root), cwd=release_root)
    native = _native_facts(python, release_root)
    _chmod_tree(code_root)
    _chmod_tree(venv_root)
    api = created_users[0]
    os.chown(DATA_ROOT, api["uid"], api["gid"])
    os.chown(ACCEPTANCE_ROOT, api["uid"], api["gid"])
    result.update(native)
    result["canonical_exe"] = str(Path(native["venv_python"]).resolve())
    result["stage_state"] = str(state_path)
    manifest_path = CONFIG_ROOT / "native-stage-manifest.json"
    result["manifest"] = str(manifest_path)
    _state(manifest_path, result)
    _state(state_path, {"format": 1, "source_sha": source_sha, "resource_intent": intent, "created_groups": created_groups, "created_users": created_users, "release_root": str(release_root), "manifest": str(manifest_path)})
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(stage_bundle(args.bundle, args.apply), sort_keys=True, separators=(",", ":")))
    except StageError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, separators=(",", ":")))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
