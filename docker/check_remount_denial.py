"""Future staged probe for the narrow writable-bind remount denial."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from pathlib import Path


TARGET = "/usr/share/fonts"
RUNTIME_DIRS = ("/usr", "/bin", "/lib", "/lib64")
MAX_MOUNTINFO_BYTES = 256 * 1024
MAX_STDERR_BYTES = 16 * 1024
TIMEOUT_SECONDS = 15


def _parse_mountinfo(line: str) -> dict:
    if not line or "\n" in line or len(line) > 8192:
        raise ValueError("malformed_mountinfo")
    halves = line.split(" - ", 1)
    left = halves[0].split() if len(halves) == 2 else []
    if len(left) < 6 or left[4] != TARGET:
        raise ValueError("unexpected_mountpoint")
    options = set(left[5].split(","))
    return {"mountpoint": left[4], "options": options}


def _source_mount_facts() -> dict:
    source = Path(TARGET)
    if source.is_symlink() or not source.is_dir():
        raise RuntimeError("source_directory_unavailable")
    try:
        if next(source.iterdir(), None) is not None:
            raise RuntimeError("source_directory_not_empty")
    except OSError as exc:
        raise RuntimeError("source_directory_unreadable") from exc
    try:
        raw = Path("/proc/self/mountinfo").read_bytes()
    except OSError as exc:
        raise RuntimeError("mountinfo_unavailable") from exc
    if not raw or len(raw) > MAX_MOUNTINFO_BYTES:
        raise RuntimeError("mountinfo_too_large")
    matches = []
    for line in raw.decode("utf-8", "replace").splitlines():
        try:
            matches.append(_parse_mountinfo(line))
        except ValueError:
            continue
    if len(matches) != 1:
        raise RuntimeError("source_mount_not_unique")
    facts = matches[0]
    if "rw" not in facts["options"]:
        raise RuntimeError("source_mount_not_rw")
    return facts


def _source_mount_ready(facts: dict) -> bool:
    options = facts.get("options", set())
    return "rw" in options and not {"nosuid", "nodev"}.issubset(options)


def _build_bwrap_argv(runtime_dirs: tuple[str, ...] = RUNTIME_DIRS) -> list[str]:
    argv = ["bwrap", "--die-with-parent", "--new-session", "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--cap-drop", "ALL", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    for path in runtime_dirs:
        argv.extend(["--ro-bind", path, path])
    argv.extend(["--bind", TARGET, TARGET, "--", "/bin/true"])
    return argv


def _kill_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        try:
            process.terminate()
        except OSError:
            pass
    try:
        process.wait(timeout=1)
    except (OSError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            try:
                process.kill()
            except OSError:
                pass
        try:
            process.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _run_candidate(argv: list[str]) -> dict:
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        raise RuntimeError("bwrap_spawn_failed") from exc
    try:
        _, stderr = process.communicate(timeout=TIMEOUT_SECONDS)
    except (subprocess.TimeoutExpired, TimeoutError):
        _kill_group(process)
        try:
            _, stderr = process.communicate(timeout=1)
        except (OSError, subprocess.TimeoutExpired, TimeoutError):
            stderr = b""
        return {
            "child_pid": process.pid,
            "returncode": None,
            "timed_out": True,
            "stderr_nonempty": bool(stderr),
            "stderr_bytes": min(len(stderr), MAX_STDERR_BYTES),
        }
    return {
        "child_pid": process.pid,
        "returncode": process.returncode,
        "timed_out": False,
        "stderr_nonempty": bool(stderr),
        "stderr_bytes": min(len(stderr), MAX_STDERR_BYTES),
    }


def main() -> int:
    if len(sys.argv) != 1:
        print(json.dumps({"error_code": "arguments_not_allowed", "audit_corroboration_required": True}, separators=(",", ":")))
        return 2
    try:
        facts = _source_mount_facts()
        if not _source_mount_ready(facts):
            raise RuntimeError("source_mount_already_nosuid_nodev")
        result = _run_candidate(_build_bwrap_argv())
    except RuntimeError as exc:
        print(json.dumps({"error_code": str(exc), "audit_corroboration_required": True}, separators=(",", ":")))
        return 2
    print(json.dumps({"denied_candidate": True, "audit_corroboration_required": True, "policy_proof": False, "expected_remount_target": TARGET, "source_options": sorted(facts["options"]), "missing_source_flags": sorted({"nosuid", "nodev"} - facts["options"]), **result}, sort_keys=True, separators=(",", ":")))
    return 1 if result["timed_out"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
