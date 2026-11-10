"""Build a provenance-checked, offline native fallback bundle.

This module deliberately knows only the files needed by the native runtime.  It
does not discover the repository, execute downloaded bytes, or deploy anything.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath


APP_SOURCE_SHA = "0e7c53a36257c75d96aae7890f2103b9341c9e3b"
APP_PACKAGE = "jevseo"
RUNTIME_PINS = Path("deploy/native/runtime-pins.txt")
OFFICIAL_PYPI = "https://pypi.org/simple"
WHEEL_PLATFORMS = ("manylinux_2_17_x86_64", "manylinux2014_x86_64", "manylinux_2_28_x86_64")
SMOKESCREEN_URL = "https://github.com/stripe/smokescreen/releases/download/v0.1.0/smokescreen_v0.1.0_linux_amd64.tar.gz"
SMOKESCREEN_COMMIT = "609eb8931420453daf5893509be0b25b21bd9edb"
SMOKESCREEN_SIZE = 5_313_984
SMOKESCREEN_SHA256 = "4e1e447449e3cc653dae956208588722b5c8fe8ce894f633adc756a851d1ec46"
SMOKESCREEN_ELF_SHA256 = "ff564742b3631616553b60c561a84930b881d327c80da8be8a9206513044ee2e"
SMOKESCREEN_MEMBER = "smokescreen_v0.1.0_linux_amd64/smokescreen"
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_WHEEL_MEMBERS = 8192
MAX_WHEEL_UNPACKED_BYTES = 512 * 1024 * 1024
FIXED_INPUTS = {
    "native/smokescreen.json": Path("docker/smokescreen.json"),
    "native/tools/check_sandbox_acceptance.py": Path("docker/check_sandbox_acceptance.py"),
}
PIN_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;]+)$")


class BundleError(RuntimeError):
    pass


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _safe_relative(value: str) -> str:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or str(path) != value:
        raise BundleError("unsafe_archive_member")
    return value


def _safe_zip_name(value: str, directory: bool = False) -> str:
    return _safe_relative(value[:-1] if directory and value.endswith("/") else value)


def _regular_bytes(path: Path) -> bytes:
    try:
        info = path.lstat()
    except OSError as exc:
        raise BundleError(f"input_unreadable:{path}") from exc
    if not path.is_file() or path.is_symlink() or info.st_nlink != 1:
        raise BundleError(f"input_not_regular:{path}")
    if info.st_size > MAX_MEMBER_BYTES:
        raise BundleError(f"input_oversize:{path}")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise BundleError(f"input_unreadable:{path}") from exc


def _git_source_paths(root: Path) -> set[str]:
    command = ["git", "-C", str(root), "diff", "--quiet", APP_SOURCE_SHA, "--", "jevseo", "pyproject.toml", "README.md", "LICENSE"]
    try:
        result = subprocess.run(command, cwd=root, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(root), "GIT_CONFIG_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0"}, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BundleError("source_git_probe_failed") from exc
    if result.returncode != 0:
        raise BundleError("application_source_changed")
    command = ["git", "-C", str(root), "ls-files", "--others", "--exclude-standard", "--", "jevseo", "pyproject.toml", "README.md", "LICENSE"]
    try:
        result = subprocess.run(command, cwd=root, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(root), "GIT_CONFIG_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0"}, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BundleError("source_git_probe_failed") from exc
    if result.returncode != 0 or result.stdout.strip():
        raise BundleError("application_untracked_file")
    command = ["git", "-C", str(root), "ls-tree", "-r", "--name-only", APP_SOURCE_SHA, "--", "jevseo", "pyproject.toml", "README.md", "LICENSE"]
    try:
        result = subprocess.run(command, cwd=root, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(root), "GIT_CONFIG_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0"}, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BundleError("source_git_probe_failed") from exc
    if result.returncode != 0:
        raise BundleError("source_git_probe_failed")
    return {line for line in result.stdout.splitlines() if line}


def _package_files(root: Path, tracked: set[str] | None = None) -> list[Path]:
    package = root / APP_PACKAGE
    if not package.is_dir() or package.is_symlink():
        raise BundleError("application_package_missing")
    files: list[Path] = []
    paths = [root / name for name in sorted(tracked or {path.relative_to(root).as_posix() for path in package.rglob("*") if path.is_file()})]
    for path in paths:
        if "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        if path.is_dir():
            if path.is_symlink():
                raise BundleError("application_symlink")
            continue
        _regular_bytes(path)
        files.append(path)
    if not files:
        raise BundleError("application_package_empty")
    return files


def collect_source(root: Path, native_inputs: list[Path], verify_git: bool = True) -> dict[str, bytes]:
    """Collect only the explicit application and native input allowlists."""
    payload: dict[str, bytes] = {}
    tracked = _git_source_paths(root) if verify_git else None
    if tracked is not None and (not all(name == "jevseo" or name.startswith("jevseo/") or name in {"pyproject.toml", "README.md", "LICENSE"} for name in tracked)):
        raise BundleError("application_allowlist_drift")
    for path in _package_files(root, {name for name in tracked or set() if name.startswith("jevseo/")} if tracked is not None else None):
        payload[f"source/{path.relative_to(root).as_posix()}"] = _regular_bytes(path)
    for name in ("pyproject.toml", "README.md", "LICENSE"):
        path = root / name
        payload[f"source/{name}"] = _regular_bytes(path)
    for destination, source in FIXED_INPUTS.items():
        payload[destination] = _regular_bytes(root / source)
    if not native_inputs:
        raise BundleError("native_inputs_required")
    native_manifest: list[dict[str, str]] = []
    native_members: set[str] = set()
    for path in native_inputs:
        path = path if path.is_absolute() else root / path
        try:
            relative = Path(os.path.normpath(str(path.absolute().relative_to(root.absolute()))))
        except ValueError as exc:
            raise BundleError("native_input_outside_project") from exc
        if relative.parts[:2] != ("deploy", "native"):
            raise BundleError("native_input_not_declared")
        member = f"native-inputs/{relative.as_posix()}"
        if member in native_members:
            raise BundleError("native_input_duplicate")
        data = _regular_bytes(path)
        native_members.add(member)
        payload[member] = data
        native_manifest.append({"member": member, "source": relative.as_posix(), "sha256": _sha256(data)})
    payload["native-inputs/manifest.json"] = (json.dumps({"format": 1, "inputs": sorted(native_manifest, key=lambda item: item["member"])}, sort_keys=True, separators=(",", ":")) + "\n").encode()
    return payload


def parse_runtime_pins(path: Path) -> list[tuple[str, str]]:
    pins: list[tuple[str, str]] = []
    for raw in path.read_text(encoding="ascii").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = PIN_RE.fullmatch(line)
        if not match:
            raise BundleError("runtime_pin_not_exact")
        pins.append((match.group(1), match.group(2)))
    if not pins or len({_pep503(name) for name, _ in pins}) != len(pins):
        raise BundleError("runtime_pins_invalid")
    return pins


def _metadata(wheel: Path) -> tuple[str, str]:
    try:
        with zipfile.ZipFile(wheel) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_WHEEL_MEMBERS or sum(max(0, info.file_size) for info in infos) > MAX_WHEEL_UNPACKED_BYTES:
                raise BundleError("wheel_member_bound")
            names = []
            for info in infos:
                name = _safe_zip_name(info.filename, info.is_dir())
                mode = (info.external_attr >> 16) & 0o170000
                if mode not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise BundleError("wheel_member_unsafe")
                names.append(name)
            if len(names) != len(set(names)):
                raise BundleError("wheel_member_duplicate")
            metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
            if len(metadata_names) != 1:
                raise BundleError("wheel_metadata_missing")
            values: dict[str, str] = {}
            for line in archive.read(metadata_names[0]).decode("utf-8").splitlines():
                if ": " in line:
                    key, value = line.split(": ", 1)
                    if key in {"Name", "Version"}:
                        values[key] = value
    except (OSError, zipfile.BadZipFile, UnicodeDecodeError) as exc:
        raise BundleError("wheel_invalid") from exc
    if set(values) != {"Name", "Version"}:
        raise BundleError("wheel_metadata_missing")
    return values["Name"], values["Version"]


def make_lock(wheelhouse: Path, pins: list[tuple[str, str]], project_wheel: Path) -> str:
    candidates = list(dict.fromkeys([project_wheel, *sorted(wheelhouse.glob("*.whl"))]))
    found: dict[tuple[str, str], list[Path]] = {}
    for wheel in candidates:
        name, version = _metadata(wheel)
        found.setdefault((_pep503(name), version), []).append(wheel)
    required = [("jev-seo", "0.1.1"), *pins]
    lines: list[str] = []
    for name, version in required:
        key = (_pep503(name), version)
        matches = found.get(key, [])
        if len(matches) != 1:
            raise BundleError(f"wheel_missing_or_ambiguous:{name}=={version}")
        digest = _sha256(_regular_bytes(matches[0]))
        lines.append(f"{name}=={version} --hash=sha256:{digest}")
    return "\n".join(lines) + "\n"


def verify_project_assets(wheel: Path, source_payload: dict[str, bytes]) -> None:
    expected = {name.removeprefix("source/") for name in source_payload if name.startswith("source/jevseo/")}
    try:
        with zipfile.ZipFile(wheel) as archive:
            members = set(archive.namelist())
    except (OSError, zipfile.BadZipFile) as exc:
        raise BundleError("application_wheel_invalid") from exc
    if not expected.issubset(members):
        raise BundleError("application_wheel_assets_missing")


def materialize_source(payload: dict[str, bytes], destination: Path) -> Path:
    if destination.exists() or destination.is_symlink():
        raise BundleError("source_temp_exists")
    destination.mkdir(parents=True)
    for name, data in payload.items():
        if not name.startswith("source/"):
            continue
        relative = _safe_relative(name.removeprefix("source/"))
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        os.chmod(target, 0o644)
    return destination


def _run(argv: list[str], cwd: Path, timeout: int = 900) -> None:
    if not argv or any(not isinstance(item, str) for item in argv):
        raise BundleError("invalid_tool_command")
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(cwd),
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INPUT": "1",
        "PIP_NO_CACHE_DIR": "1",
        "UV_NO_CONFIG": "1",
    }
    try:
        result = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BundleError("tool_failed") from exc
    if result.returncode != 0:
        raise BundleError("tool_failed")


def smokescreen_bytes(archive: Path) -> bytes:
    data = _regular_bytes(archive)
    if len(data) != SMOKESCREEN_SIZE or _sha256(data) != SMOKESCREEN_SHA256:
        raise BundleError("smokescreen_archive_hash")
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            members = tar.getmembers()
            for member in members:
                _safe_relative(member.name.rstrip("/") if member.isdir() else member.name)
                if (not member.isreg() and not member.isdir()) or member.issym() or member.islnk():
                    raise BundleError("smokescreen_member_not_regular")
            matches = [member for member in members if member.name == SMOKESCREEN_MEMBER]
            if len(matches) != 1:
                raise BundleError("smokescreen_member_missing")
            binary = tar.extractfile(matches[0])
            result = binary.read() if binary else b""
    except (OSError, tarfile.TarError) as exc:
        raise BundleError("smokescreen_archive_invalid") from exc
    if result[:4] != b"\x7fELF" or _sha256(result) != SMOKESCREEN_ELF_SHA256:
        raise BundleError("smokescreen_elf_hash")
    return result


def download_smokescreen(destination: Path, opener=None) -> Path:
    if destination.exists() or destination.is_symlink():
        raise BundleError("smokescreen_destination_exists")
    try:
        with (opener or urllib.request.urlopen)(SMOKESCREEN_URL, timeout=60) as response:
            chunks: list[bytes] = []
            total = 0
            while total <= SMOKESCREEN_SIZE:
                chunk = response.read(min(1024 * 1024, SMOKESCREEN_SIZE + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            data = b"".join(chunks)
    except OSError as exc:
        raise BundleError("smokescreen_download_failed") from exc
    if len(data) != SMOKESCREEN_SIZE or _sha256(data) != SMOKESCREEN_SHA256:
        raise BundleError("smokescreen_archive_hash")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    os.chmod(destination, 0o600)
    return destination


def make_archive(output: Path, payload: dict[str, bytes], source_sha: str) -> dict[str, object]:
    if output.exists() or output.is_symlink():
        raise BundleError("bundle_destination_exists")
    if any(name in {"bundle.marker", "manifest.sha256"} or _safe_relative(name) != name for name in payload):
        raise BundleError("bundle_payload_invalid")
    manifest = "".join(f"{_sha256(data)}  {name}\n" for name, data in sorted(payload.items()))
    marker = json.dumps({"format": 1, "source_sha": source_sha, "manifest_sha256": _sha256(manifest.encode())}, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    files = {**payload, "manifest.sha256": manifest.encode(), "bundle.marker": marker}
    if output.parent.exists() and (output.parent.is_symlink() or not output.parent.is_dir()):
        raise BundleError("bundle_parent_invalid")
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("wb") as raw, __import__("gzip").GzipFile(fileobj=raw, mode="wb", mtime=0) as compressed, tarfile.open(fileobj=compressed, mode="w|") as tar:
            for name, data in sorted(files.items()):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o755 if name == "native/smokescreen" else 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mtime = 0
                tar.addfile(info, io.BytesIO(data))
    except OSError as exc:
        raise BundleError("bundle_write_failed") from exc
    return {"bundle": str(output), "source_sha": source_sha, "manifest_sha256": _sha256(manifest.encode()), "members": sorted(files)}


def build_bundle(project_root: Path, output: Path, source_sha: str, native_inputs: list[Path], smokescreen_archive: Path | None = None, python: str = sys.executable) -> dict[str, object]:
    if source_sha != APP_SOURCE_SHA:
        raise BundleError("source_sha_unknown")
    pins = parse_runtime_pins(project_root / RUNTIME_PINS)
    payload = collect_source(project_root, native_inputs)
    if smokescreen_archive is None:
        raise BundleError("smokescreen_archive_required")
    payload["native/smokescreen"] = smokescreen_bytes(smokescreen_archive)
    with tempfile.TemporaryDirectory(prefix="jev-native-", dir="/Volumes/SSD_Samsung/.dev-cache/tmp/opencode" if Path("/Volumes/SSD_Samsung/.dev-cache/tmp/opencode").is_dir() else None) as temp:
        wheelhouse = Path(temp) / "wheelhouse"
        wheelhouse.mkdir()
        source_tree = materialize_source(payload, Path(temp) / "source")
        _run([python, "-m", "pip", "wheel", "--no-index", "--no-deps", "--no-build-isolation", "--wheel-dir", str(wheelhouse), str(source_tree)], source_tree)
        project_wheels = sorted(wheelhouse.glob("jev_seo-*.whl"))
        if len(project_wheels) != 1:
            raise BundleError("application_wheel_missing")
        verify_project_assets(project_wheels[0], payload)
        download = [python, "-m", "pip", "download", "--requirement", str(project_root / RUNTIME_PINS), "--dest", str(wheelhouse), "--only-binary=:all:", "--no-deps", "--index-url", OFFICIAL_PYPI, "--implementation", "cp", "--python-version", "3.12", "--abi", "cp312"]
        for platform in WHEEL_PLATFORMS:
            download.extend(["--platform", platform])
        _run(download, project_root)
        lock = make_lock(wheelhouse, pins, project_wheels[0])
        payload["requirements.lock"] = lock.encode()
        for wheel in sorted(wheelhouse.glob("*.whl")):
            payload[f"wheelhouse/{wheel.name}"] = _regular_bytes(wheel)
    return make_archive(output, payload, source_sha)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--native-input", action="append", type=Path, required=True)
    parser.add_argument("--smokescreen-archive", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = build_bundle(args.project_root.resolve(), args.output, args.source_sha, args.native_input, args.smokescreen_archive)
    except BundleError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, separators=(",", ":")))
        return 1
    print(json.dumps({"ok": True, **result}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
