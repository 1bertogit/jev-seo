"""Offline invariants for the pinned Smokescreen packaging dependency."""

from __future__ import annotations

import json
import ipaddress
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "docker" / "smokescreen.Dockerfile"
CONFIG_PATH = ROOT / "docker" / "smokescreen.json"
PROVENANCE = ROOT / "docs" / "jev-egress-proxy.md"

ASSET_SHA256 = "4e1e447449e3cc653dae956208588722b5c8fe8ce894f633adc756a851d1ec46"
ASSET_SIZE = 5313984
BASE_SHA256 = "935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df"
DENY_RANGES = {
    "0.0.0.0/8",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "240.0.0.0/4",
    "64:ff9b:1::/48",
    "100::/64",
    "2001::/23",
    "2001:db8::/32",
    "3fff::/20",
    "5f00::/16",
    "45.132.246.207/32",
}


class ProxyConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dockerfile = DOCKERFILE.read_text(encoding="utf-8")
        cls.config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        cls.provenance = PROVENANCE.read_text(encoding="utf-8")

    def test_pinned_release_provenance(self) -> None:
        self.assertIn("609eb8931420453daf5893509be0b25b21bd9edb", self.provenance)
        self.assertIn(ASSET_SHA256, self.provenance)
        self.assertIn(str(ASSET_SIZE), self.dockerfile)
        self.assertIn(ASSET_SHA256, self.dockerfile)
        self.assertIn("smokescreen_v0.1.0_linux_amd64.tar.gz", self.dockerfile)

    def test_archive_verification_is_before_safe_binary_extraction(self) -> None:
        self.assertLess(self.dockerfile.index("archive.stat().st_size"), self.dockerfile.index("tarfile.open"))
        self.assertLess(self.dockerfile.index("hashlib.sha256(archive.read_bytes())"), self.dockerfile.index("tarfile.open"))
        for token in (
            "posixpath.isabs(member.name)",
            '".." not in member.name.split("/")',
            "posixpath.normpath(member.name) == member.name",
            "not member.issym() and not member.islnk()",
            "matches[0].isreg()",
            'assert data[:4] == b"\\x7fELF"',
        ):
            self.assertIn(token, self.dockerfile, token)
        self.assertIn("target = \"smokescreen_v0.1.0_linux_amd64/smokescreen\"", self.dockerfile)

    def test_runtime_image_is_nonroot_stock_binary_only(self) -> None:
        self.assertEqual(self.dockerfile.count("FROM --platform=linux/amd64 python:3.12-slim-bookworm@sha256:" + BASE_SHA256), 2)
        self.assertIn("COPY --from=fetch /tmp/smokescreen /usr/local/bin/smokescreen", self.dockerfile)
        self.assertIn("COPY docker/smokescreen.json /etc/smokescreen/smokescreen.json", self.dockerfile)
        self.assertIn("USER 10001:10001", self.dockerfile)
        self.assertIn('ENTRYPOINT ["/usr/local/bin/smokescreen"]', self.dockerfile)
        self.assertIn('CMD ["--config-file", "/etc/smokescreen/smokescreen.json", "--listen-ip", "127.0.0.1", "--listen-port", "4750"]', self.dockerfile)
        for forbidden in ("CAP_NET_BIND_SERVICE", "CAP_SYS_ADMIN", "setcap", "0.0.0.0", "--privileged", "HTTP_PROXY", ".env"):
            self.assertNotIn(forbidden, self.dockerfile)

    def test_config_is_fail_closed_and_has_only_reviewed_denies(self) -> None:
        self.assertEqual(self.config["connect_timeout"], "10s")
        self.assertEqual(self.config["dns_timeout"], "5s")
        self.assertEqual(self.config["max_concurrent_requests"], 32)
        self.assertEqual(self.config["max_concurrent_connect_tunnels"], 16)
        self.assertEqual(self.config["max_request_rate"], 10)
        self.assertEqual(self.config["max_request_burst"], 20)
        self.assertEqual(set(self.config["deny_ranges"]), DENY_RANGES)
        for cidr in self.config["deny_ranges"]:
            ipaddress.ip_network(cidr)
        for forbidden in ("allow-range", "allow_ranges", "unsafe_allow_private_ranges", "acl", "dns", "proxy", "mitm", "tls"):
            self.assertNotIn(forbidden, self.config)
        self.assertNotIn("listen-ip", self.config)

    def test_no_unreviewed_network_or_logging_bypass_is_packaged(self) -> None:
        for forbidden in (
            "--allow-range",
            "unsafe_allow_private_ranges",
            "--debug",
            "--mitm",
            "--listen-ip 0.0.0.0",
            "--network host",
            "--publish",
            "--dns",
            '"listen-ip"',
            '"listen-port"',
        ):
            self.assertNotIn(forbidden, self.dockerfile + CONFIG_PATH.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
