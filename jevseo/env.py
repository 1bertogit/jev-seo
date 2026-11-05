"""Secret lookup. Values are returned to callers, never printed or written.

Normal mode checks the process environment, then the first env file that defines the
name, among $JEVSEO_ENV_FILE, ./.env in the working directory, .env in this
repository, and ~/Desktop/Keys/.env. Hosted mode checks only the process environment.
"""
from __future__ import annotations

import os
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def hosted_mode() -> bool:
    """Whether the process was explicitly launched in the restricted worker mode."""
    return os.environ.get("JEVSEO_HOSTED") == "1"


def key_files() -> list[Path]:
    files = []
    if os.environ.get("JEVSEO_ENV_FILE"):
        files.append(Path(os.environ["JEVSEO_ENV_FILE"]).expanduser())
    files += [Path.cwd() / ".env", REPO / ".env", Path.home() / "Desktop" / "Keys" / ".env"]
    return files


def secret(name: str) -> str | None:
    if os.environ.get(name):
        return os.environ[name]
    if hosted_mode():
        return None
    for path in key_files():
        if not path.is_file():
            continue
        for line in path.read_text(errors="ignore").splitlines():
            line = line.strip()
            if line.startswith("export "):
                line = line[7:]
            if line.startswith(f"{name}="):
                return line.split("=", 1)[1].strip().strip("'\"") or None
    return None
