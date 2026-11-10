"""Render the finite, offline native fallback deployment artifacts."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Mapping
from pathlib import Path


API_UID = "jev-audit-api"
HOST_IPV4 = "45.132.246.207"
HOST_IPV6 = "2a03:4000:48:ed8:3814:5bff:fef6:565"
TRAEFIK_IP = "10.0.1.7"
RELAY_IP = "10.0.1.1"
TRAEFIK_HOST = "jev-audit.humberto.ai"
TRAEFIK_RESOLVER = "letsencrypt"
TRAEFIK_ENTRYPOINT = "https"
SMOKESCREEN_SHA256 = "c51fdce3072397c2a97552f6cc49b7ef73c8a60447de26718ca5616414c02906"

ROLE_NAMES = ("jev-audit-api", "jev-audit-egress", "jev-audit-relay")
MANIFEST_KEYS = {
    "release_sha",
    "uids",
    "gids",
    "self_ips",
    "traefik_resolver",
    "traefik_entrypoint",
    "traefik_resolver_validated",
}
RELEASE_BASE = "/opt/jev-audit-native/releases"
DATA_ROOT = "/var/lib/jev-audit-native"
ACCEPTANCE_ROOT = "/var/lib/jev-audit-native-acceptance"
SECRETS_ROOT = "/etc/jev-audit-native"
TEMPLATE_ROOT = Path(__file__).with_name("templates")
REPO_ROOT = Path(__file__).resolve().parents[2]


def _error(message: str) -> ValueError:
    return ValueError(f"invalid native manifest: {message}")


def _validate_ids(value: object, field: str) -> dict[str, int]:
    if not isinstance(value, Mapping) or set(value) != set(ROLE_NAMES):
        raise _error(f"{field} roles")
    result: dict[str, int] = {}
    for role in ROLE_NAMES:
        number = value[role]
        if isinstance(number, bool) or not isinstance(number, int) or not 0 < number <= 65535:
            raise _error(f"{field} value")
        result[role] = number
    if len(set(result.values())) != len(ROLE_NAMES):
        raise _error(f"{field} roles must be distinct")
    return result


def validate_manifest(manifest: Mapping[str, object]) -> dict[str, object]:
    """Validate the only supported manifest shape and derive fixed paths."""

    if not isinstance(manifest, Mapping) or set(manifest) != MANIFEST_KEYS:
        raise _error("unsupported fields")
    release_sha = manifest["release_sha"]
    if not isinstance(release_sha, str) or re.fullmatch(r"[0-9a-f]{40}", release_sha) is None:
        raise _error("release_sha must be 40 lowercase hexadecimal characters")
    uids = _validate_ids(manifest["uids"], "uids")
    gids = _validate_ids(manifest["gids"], "gids")

    self_ips = manifest["self_ips"]
    if (
        not isinstance(self_ips, list)
        or len(self_ips) != 2
        or not all(isinstance(address, str) for address in self_ips)
        or set(self_ips) != {HOST_IPV4, HOST_IPV6}
    ):
        raise _error("self_ips must contain the two verified host addresses")
    for address in self_ips:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as exc:
            raise _error("self_ips contains an invalid address") from exc
        if not parsed.is_global:
            raise _error("self_ips must be global addresses")

    if manifest["traefik_resolver"] != TRAEFIK_RESOLVER:
        raise _error("resolver must be the validated host resolver")
    if manifest["traefik_entrypoint"] != TRAEFIK_ENTRYPOINT:
        raise _error("entrypoint must be the validated HTTPS entrypoint")
    if manifest["traefik_resolver_validated"] is not True:
        raise _error("resolver validation is required")

    release_root = f"{RELEASE_BASE}/{release_sha}"
    return {
        "release_sha": release_sha,
        "uids": uids,
        "gids": gids,
        "self_ips": [HOST_IPV4, HOST_IPV6],
        "traefik_resolver": TRAEFIK_RESOLVER,
        "traefik_entrypoint": TRAEFIK_ENTRYPOINT,
        "traefik_resolver_validated": True,
        "release_root": release_root,
        "venv_root": f"{release_root}/venv",
        "tools_root": f"{release_root}/tools",
        "smokescreen_bin": f"{release_root}/bin/smokescreen",
        "data_root": DATA_ROOT,
        "acceptance_root": ACCEPTANCE_ROOT,
        "secrets_root": SECRETS_ROOT,
        "runtime_root": "/run/jev-audit-native",
        "relay_ip": RELAY_IP,
        "traefik_ip": TRAEFIK_IP,
    }


def _template(relative: str) -> str:
    path = TEMPLATE_ROOT / relative
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"native template unavailable: {relative}")
    return path.read_text(encoding="utf-8")


def _replace(template: str, replacements: Mapping[str, object]) -> str:
    rendered = template
    for token, value in replacements.items():
        rendered = rendered.replace(token, str(value))
    if re.search(r"@[A-Z0-9_]+@", rendered):
        raise RuntimeError("unreplaced native template token")
    return rendered


def _smokescreen() -> str:
    source_path = REPO_ROOT / "docker" / "smokescreen.json"
    source = source_path.read_text(encoding="utf-8")
    template = _template("smokescreen.json")
    if source != template:
        raise RuntimeError("native Smokescreen template diverges from the reviewed source")
    if hashlib.sha256(source.encode()).hexdigest() != SMOKESCREEN_SHA256:
        raise RuntimeError("reviewed Smokescreen source hash changed")
    config = json.loads(source)
    if HOST_IPV4 + "/32" not in config.get("deny_ranges", []):
        raise RuntimeError("reviewed Smokescreen deny set lost the host address")
    return source


def render(manifest: Mapping[str, object]) -> dict[str, str]:
    """Return deterministic artifact contents without writing to the host."""

    normalized = validate_manifest(manifest)
    release_root = normalized["release_root"]
    ids = normalized["uids"]
    replacements = {
        "@RELEASE_ROOT@": release_root,
        "@API_UID@": ids["jev-audit-api"],
        "@EGRESS_UID@": ids["jev-audit-egress"],
        "@RELAY_UID@": ids["jev-audit-relay"],
        "@HOST_IPV6_DENIES@": HOST_IPV6 + "/128",
        "@TRAEFIK_ENTRYPOINT@": normalized["traefik_entrypoint"],
        "@TRAEFIK_RESOLVER@": normalized["traefik_resolver"],
    }
    nft_content = _replace(_template("nftables/jev-audit-native.nft"), replacements)
    artifacts = {
        "systemd/jev-audit-api.service": _replace(_template("systemd/jev-audit-api.service"), replacements),
        "systemd/jev-audit-egress.service": _replace(_template("systemd/jev-audit-egress.service"), replacements),
        "systemd/jev-audit-relay.socket": _template("systemd/jev-audit-relay.socket"),
        "systemd/jev-audit-relay.service": _template("systemd/jev-audit-relay.service"),
        "systemd/jev-audit-firewall.service": _template("systemd/jev-audit-firewall.service"),
        "nftables/jev-audit-native.nft": nft_content,
        "etc/jev-audit-native/egress.nft": nft_content,
        "traefik/jev-audit-native.yml": _replace(_template("traefik/jev-audit-native.yml"), replacements),
        "smokescreen.json": _smokescreen(),
        "etc/jev-audit-native/api.env": _template("etc-api.env"),
    }
    artifact_manifest = {
        "schema": "jev-audit-native/v1",
        "release_sha": normalized["release_sha"],
        "accounts": {
            role: {
                "uid": ids[role],
                "gid": normalized["gids"][role],
                "expected_locked": True,
                "expected_administrative": False,
                "expected_shell": "/usr/sbin/nologin",
            }
            for role in ROLE_NAMES
        },
        "paths": {
            "release": release_root,
            "venv": normalized["venv_root"],
            "tools": normalized["tools_root"],
            "smokescreen": normalized["smokescreen_bin"],
            "data": DATA_ROOT,
            "acceptance_data": ACCEPTANCE_ROOT,
            "secrets": SECRETS_ROOT,
            "api_env": f"{SECRETS_ROOT}/api.env",
        },
        "network": {"relay": RELAY_IP, "traefik": TRAEFIK_IP, "self_ips": normalized["self_ips"]},
        "traefik": {
            "host": TRAEFIK_HOST,
            "entrypoint": normalized["traefik_entrypoint"],
            "resolver": normalized["traefik_resolver"],
            "resolver_validated": True,
        },
        "firewall": {
            "unit": "systemd/jev-audit-firewall.service",
            "config": "/etc/jev-audit-native/egress.nft",
            "artifact": "etc/jev-audit-native/egress.nft",
            "config_mode": "0600",
            "table": "inet jev_audit_native",
        },
        "smokescreen_sha256": SMOKESCREEN_SHA256,
        "api_env_mode": "0600",
    }
    artifacts["manifest.json"] = json.dumps(artifact_manifest, indent=2, sort_keys=True) + "\n"
    return artifacts
