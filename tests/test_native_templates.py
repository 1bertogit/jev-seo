"""Focused offline semantic checks for native fallback artifacts."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import unittest

from deploy.native.render import (
    API_UID,
    HOST_IPV4,
    HOST_IPV6,
    RELAY_IP,
    TRAEFIK_IP,
    validate_manifest,
    render,
)


MANIFEST = {
    "release_sha": "a" * 40,
    "uids": {
        "jev-audit-api": 21001,
        "jev-audit-egress": 21002,
        "jev-audit-relay": 21003,
    },
    "gids": {
        "jev-audit-api": 22001,
        "jev-audit-egress": 22002,
        "jev-audit-relay": 22003,
    },
    "self_ips": [HOST_IPV4, HOST_IPV6],
    "traefik_resolver": "letsencrypt",
    "traefik_entrypoint": "https",
    "traefik_resolver_validated": True,
}


class NativeTemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.artifacts = render(MANIFEST)
        cls.nft = cls.artifacts["nftables/jev-audit-native.nft"]
        cls.api = cls.artifacts["systemd/jev-audit-api.service"]
        cls.proxy = cls.artifacts["systemd/jev-audit-egress.service"]
        cls.relay = cls.artifacts["systemd/jev-audit-relay.service"]
        cls.socket = cls.artifacts["systemd/jev-audit-relay.socket"]
        cls.firewall = cls.artifacts["systemd/jev-audit-firewall.service"]
        cls.firewall_nft = cls.artifacts["etc/jev-audit-native/egress.nft"]
        cls.traefik = cls.artifacts["traefik/jev-audit-native.yml"]

    def test_manifest_requires_exact_accounts_paths_and_readonly_resolver_fact(self) -> None:
        normalized = validate_manifest(MANIFEST)
        self.assertEqual(normalized["release_root"], "/opt/jev-audit-native/releases/" + "a" * 40)
        self.assertEqual(normalized["data_root"], "/var/lib/jev-audit-native")
        self.assertEqual(normalized["acceptance_root"], "/var/lib/jev-audit-native-acceptance")
        generated_manifest = json.loads(self.artifacts["manifest.json"])
        recorded = generated_manifest["accounts"]
        self.assertEqual(set(recorded), set(MANIFEST["uids"]))
        self.assertTrue(all(account["expected_locked"] and not account["expected_administrative"] for account in recorded.values()))
        self.assertEqual(generated_manifest["firewall"], {
            "artifact": "etc/jev-audit-native/egress.nft",
            "config": "/etc/jev-audit-native/egress.nft",
            "config_mode": "0600",
            "table": "inet jev_audit_native",
            "unit": "systemd/jev-audit-firewall.service",
        })
        for bad in (
            {**MANIFEST, "traefik_resolver_validated": False},
            {**MANIFEST, "traefik_resolver": "letsencrypt;bad"},
            {**MANIFEST, "self_ips": [HOST_IPV4]},
            {**MANIFEST, "extra": "not-a-supported-option"},
        ):
            with self.assertRaises(ValueError):
                validate_manifest(bad)

    def test_fixed_roles_and_systemd_hardening(self) -> None:
        self.assertIn("User=jev-audit-api", self.api)
        self.assertIn("Group=jev-audit-api", self.api)
        self.assertIn("--host 127.0.0.1 --port 18080", self.api)
        self.assertIn("CapabilityBoundingSet=", self.api)
        self.assertIn("NoNewPrivileges=true", self.api)
        self.assertIn("ProtectSystem=strict", self.api)
        self.assertIn("ProtectHome=true", self.api)
        self.assertIn("PrivateTmp=true", self.api)
        self.assertIn("ReadWritePaths=/var/lib/jev-audit-native /run/jev-audit-native", self.api)
        self.assertIn("MemoryMax=1G", self.api)
        self.assertIn("CPUQuota=100%", self.api)
        self.assertIn("TasksMax=128", self.api)
        self.assertIn("RestrictNamespaces=user pid ipc uts mnt", self.api)
        self.assertNotIn("PrivateUsers", self.api)
        self.assertIn("AppArmorProfile=jev-audit-native", self.api)
        self.assertIn("User=jev-audit-egress", self.proxy)
        self.assertIn("--listen-ip 127.0.0.1 --listen-port 4750", self.proxy)
        self.assertIn("AF_NETLINK", self.proxy)
        self.assertIn("MemoryMax=128M", self.proxy)
        self.assertIn("CPUQuota=20%", self.proxy)
        self.assertNotIn("ReadWritePaths=", self.proxy)
        self.assertIn("RestrictNamespaces=true", self.proxy)
        self.assertIn("RestrictNamespaces=true", self.relay)

    def test_firewall_loader_is_root_only_and_worker_units_bind_to_it(self) -> None:
        for unit in (self.api, self.proxy, self.relay, self.socket):
            self.assertIn("BindsTo=jev-audit-firewall.service", unit)
            self.assertIn("After=jev-audit-firewall.service", unit)
        self.assertIn("Before=jev-audit-api.service jev-audit-egress.service jev-audit-relay.socket jev-audit-relay.service", self.firewall)
        self.assertIn("User=root", self.firewall)
        self.assertIn("Group=root", self.firewall)
        self.assertIn("CapabilityBoundingSet=CAP_NET_ADMIN", self.firewall)
        self.assertIn("AmbientCapabilities=CAP_NET_ADMIN", self.firewall)
        self.assertIn("NoNewPrivileges=true", self.firewall)
        self.assertIn("ProtectSystem=strict", self.firewall)
        self.assertIn("ProtectHome=true", self.firewall)
        self.assertIn("RestrictNamespaces=true", self.firewall)
        self.assertIn("/usr/sbin/nft --check --file /etc/jev-audit-native/egress.nft", self.firewall)
        self.assertIn("ExecStart=/usr/sbin/nft --file /etc/jev-audit-native/egress.nft", self.firewall)
        self.assertNotIn("ExecStop=", self.firewall)
        self.assertNotRegex(self.firewall, r"(?i)(flush|delete table|rm -|/bin/sh)")

    def test_nft_create_is_first_and_existing_owned_table_fails_closed(self) -> None:
        self.assertEqual(self.nft.splitlines()[0], "create table inet jev_audit_native")
        self.assertEqual(self.nft.count("table inet jev_audit_native"), 2)
        self.assertEqual(self.nft, self.firewall_nft)
        self.assertIn("RemainAfterExit=yes", self.firewall)

    def test_nft_role_reply_and_endpoint_gate_order_is_fail_closed(self) -> None:
        output_body = self.nft.split("chain output {", 1)[1].split("\n    }", 1)[0]
        self.assertNotIn("ct state established,related accept", output_body)
        for role_uid in MANIFEST["uids"].values():
            self.assertIn(f"meta skuid {role_uid} jump", self.nft)
        for chain_name in ("api_output", "egress_output", "relay_output"):
            body = self.nft.split(f"chain {chain_name} {{", 1)[1].split("\n    }", 1)[0]
            self.assertIn("ct state established,related ct direction reply accept", body)
            self.assertNotIn("ct state established,related accept", body)
        input_body = self.nft.split("chain input {", 1)[1].split("\n    }", 1)[0]
        source_allow = input_body.index("ip daddr 10.0.1.1 tcp dport 18081 ip saddr 10.0.1.7 accept")
        endpoint_drop = input_body.index("ip daddr 10.0.1.1 tcp dport 18081 drop")
        established = input_body.index("ct state established,related accept")
        self.assertLess(source_allow, established)
        self.assertLess(endpoint_drop, established)

    def test_api_denial_counters_are_family_specific_before_fallback_drop(self) -> None:
        api_body = self.nft.split("chain api_output {", 1)[1].split("\n    }", 1)[0]
        ipv4 = api_body.index('meta nfproto ipv4 counter drop comment "jev-api-deny-ipv4"')
        ipv6 = api_body.index('meta nfproto ipv6 counter drop comment "jev-api-deny-ipv6"')
        fallback = api_body.rindex("\n        drop")
        self.assertLess(ipv4, ipv6)
        self.assertLess(ipv6, fallback)
        self.assertEqual(self.nft.count('comment "jev-api-deny-ipv4"'), 1)
        self.assertEqual(self.nft.count('comment "jev-api-deny-ipv6"'), 1)

    def test_nft_ipv6_public_allow_is_limited_and_reserved_prefixes_are_denied(self) -> None:
        self.assertIn("64:ff9b::/96", self.nft)
        self.assertIn("2002::/16", self.nft)
        self.assertIn("fec0::/10", self.nft)
        self.assertIn("ff00::/8", self.nft)
        self.assertIn("ip daddr 0.0.0.0/0 tcp dport { 80, 443 } accept", self.nft)
        self.assertIn("ip6 daddr 2000::/3 tcp dport { 80, 443 } accept", self.nft)
        self.assertNotIn("\n        tcp dport { 80, 443 } accept", self.nft)
        self.assertLess(self.nft.index("64:ff9b::/96"), self.nft.index("ip6 daddr 2000::/3 tcp dport"))

    def test_relay_socket_and_service_are_private_and_use_stock_binary(self) -> None:
        self.assertIn("ListenStream=10.0.1.1:18081", self.socket)
        self.assertIn("Service=jev-audit-relay.service", self.socket)
        self.assertIn("User=jev-audit-relay", self.relay)
        self.assertIn("/usr/lib/systemd/systemd-socket-proxyd 127.0.0.1:18080", self.relay)
        self.assertNotIn("18081", self.relay.split("[Service]", 1)[1])

    def test_nft_is_owned_table_only_with_role_limits_and_no_flush(self) -> None:
        self.assertIn("table inet jev_audit_native", self.nft)
        self.assertNotIn("flush", self.nft.lower())
        self.assertNotIn("delete table", self.nft.lower())
        self.assertIn(f"meta skuid {MANIFEST['uids']['jev-audit-api']}", self.nft)
        self.assertIn(f"meta skuid {MANIFEST['uids']['jev-audit-egress']}", self.nft)
        self.assertIn(f"meta skuid {MANIFEST['uids']['jev-audit-relay']}", self.nft)
        self.assertIn("127.0.0.1 tcp dport 4750", self.nft)
        self.assertIn("127.0.0.53 udp dport 53", self.nft)
        self.assertIn("127.0.0.53 tcp dport 53", self.nft)
        self.assertIn("10.0.1.1 tcp dport 18081 ip saddr 10.0.1.7 accept", self.nft)
        self.assertIn("10.0.1.1 tcp dport 18081 drop", self.nft)
        self.assertIn("10.0.1.1/32", self.nft)
        self.assertIn("2a03:4000:48:ed8:3814:5bff:fef6:565/128", self.nft)
        self.assertIn("tcp dport { 80, 443 } accept", self.nft)
        self.assertGreaterEqual(self.nft.count("drop"), 6)

    def test_traefik_has_one_https_route_and_validated_resolver(self) -> None:
        self.assertIn("Host(`jev-audit.humberto.ai`)", self.traefik)
        self.assertIn("- https", self.traefik)
        self.assertNotIn("websecure", self.traefik)
        self.assertIn("certResolver: letsencrypt", self.traefik)
        self.assertIn("url: http://10.0.1.1:18081", self.traefik)
        self.assertEqual(self.traefik.count("jev-audit-native:"), 2)

    def test_smokescreen_is_unchanged_and_api_env_has_no_secret_values(self) -> None:
        proxy = json.loads(self.artifacts["smokescreen.json"])
        self.assertIn("45.132.246.207/32", proxy["deny_ranges"])
        source_hash = hashlib.sha256(self.artifacts["smokescreen.json"].encode()).hexdigest()
        self.assertEqual(source_hash, "c51fdce3072397c2a97552f6cc49b7ef73c8a60447de26718ca5616414c02906")
        env = self.artifacts["etc/jev-audit-native/api.env"]
        self.assertIn("JEV_AUDIT_DATA_DIR=/var/lib/jev-audit-native", env)
        self.assertIn("JEVSEO_EGRESS_PROXY=http://127.0.0.1:4750", env)
        self.assertRegex(env, r"(?m)^(JEV_AUDIT_SERVICE_TOKEN|JEV_AUDIT_TASK_SECRET|TYPESAFE_API_KEY|PAGESPEED_API_KEY)=$")
        self.assertNotRegex(env, r"(?m)^[A-Z_]+=.{32,}$")

    def test_paths_are_fixed_and_templates_have_no_unreplaced_tokens(self) -> None:
        for path, content in self.artifacts.items():
            self.assertFalse(re.search(r"@[A-Z0-9_]+@", content), path)
            self.assertNotIn("/tmp/", content)
        self.assertIn("/opt/jev-audit-native/releases/" + "a" * 40 + "/venv/bin/python", self.api)
        self.assertIn("/opt/jev-audit-native/releases/" + "a" * 40 + "/bin/smokescreen", self.proxy)
        self.assertIn("/etc/jev-audit-native/api.env", self.api)


if __name__ == "__main__":
    unittest.main()
