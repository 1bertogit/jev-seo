"""Bounded DNS-positive, direct-egress-negative diagnostic."""
from __future__ import annotations

import ipaddress
import json
import socket
import subprocess
import sys
from pathlib import Path


CHILD = (
    "import json,socket\n"
    "rows=socket.getaddrinfo('example.com',443,type=socket.SOCK_STREAM)\n"
    "print(json.dumps(sorted({row[4][0] for row in rows})))\n"
)

def _ipv4(value: str) -> ipaddress.IPv4Address:
    address = ipaddress.ip_address(value)
    assert address.version == 4, "IPv4 argument required"
    return address

def _tcp_must_fail(label: str, address: ipaddress._BaseAddress) -> None:
    try:
        with socket.create_connection((str(address), 443), timeout=3):
            raise AssertionError(f"unexpected_tcp_success={label}")
    except OSError as exc:  # A blocked connect is the expected result.
        print(f"tcp_{label}=blocked:{type(exc).__name__}")

def main(argv: list[str]) -> int:
    assert len(argv) == 3, "expected DNS IPv4 and server IPv4 arguments"
    dns_ip = _ipv4(argv[1])
    server_ip = _ipv4(argv[2])
    assert dns_ip.is_private and not dns_ip.is_loopback
    assert server_ip.is_global and not server_ip.is_multicast

    expected_resolv = f"nameserver {dns_ip}\noptions timeout:2 attempts:2\n"
    actual_resolv = Path("/etc/resolv.conf").read_text()
    assert actual_resolv == expected_resolv
    print(f"resolv_exact=true nameserver={dns_ip}")

    try:
        result = subprocess.run(
            [sys.executable, "-c", CHILD],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        print("dns_error=timeout dns_child_timeout=10")
        return 1
    if result.returncode != 0:
        print(f"dns_error=child_exit_{result.returncode}")
        return 1
    try:
        addresses = json.loads(result.stdout.strip())
    except json.JSONDecodeError as exc:
        raise AssertionError("DNS child did not return JSON") from exc
    assert isinstance(addresses, list) and addresses
    global_unicast = [
        address for address in map(ipaddress.ip_address, addresses)
        if address.is_global
        and not address.is_multicast
        and not address.is_loopback
        and not address.is_link_local
    ]
    assert len(global_unicast) == len(addresses), "DNS returned a non-public address"
    selected = next((a for a in global_unicast if a.version == 4), global_unicast[0])
    print(f"dns_child_returncode=0 addresses={len(addresses)} global_unicast={len(global_unicast)}")
    print(f"dns_selected_public={selected}")

    _tcp_must_fail("selected_public", selected)
    _tcp_must_fail("server_public", server_ip)
    _tcp_must_fail("dns_internal", dns_ip)
    print("tcp_all_blocked=true")
    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
