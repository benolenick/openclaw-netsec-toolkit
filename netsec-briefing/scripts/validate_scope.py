#!/usr/bin/env python3
"""Validate that scan targets are RFC1918 private subnets only.

Importable module + standalone CLI test.
Usage:
    python3 validate_scope.py 192.168.1.0/24        # exits 0 if private
    python3 validate_scope.py 8.8.8.0/24             # exits 1 (public)
"""

import ipaddress
import sys
from typing import List, Tuple

# RFC1918 + link-local ranges that are safe to scan
ALLOWED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
]


def is_private_subnet(subnet_str: str) -> bool:
    """Return True if the given CIDR subnet falls entirely within RFC1918 or link-local space."""
    try:
        network = ipaddress.ip_network(subnet_str, strict=False)
    except ValueError:
        return False

    # IPv6 is out of scope
    if network.version != 4:
        return False

    for allowed in ALLOWED_NETWORKS:
        if network.subnet_of(allowed):
            return True
    return False


def validate_targets(ip_list: List[str]) -> Tuple[List[str], List[str]]:
    """Partition a list of IP strings into (valid_private, rejected_public).

    Any IP that does not fall within an allowed private range is rejected.
    """
    valid = []
    rejected = []
    for ip_str in ip_list:
        try:
            addr = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            rejected.append(ip_str)
            continue

        if addr.version != 4:
            rejected.append(ip_str)
            continue

        is_allowed = any(addr in net for net in ALLOWED_NETWORKS)
        if is_allowed:
            valid.append(str(addr))
        else:
            rejected.append(str(addr))

    return valid, rejected


def abort_if_public(subnet_str: str) -> None:
    """Hard abort if the subnet is not private. Called before any scanning."""
    if not is_private_subnet(subnet_str):
        print(f"ABORT: '{subnet_str}' is not a private (RFC1918/link-local) subnet.", file=sys.stderr)
        print("This tool only scans private networks for safety.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: validate_scope.py <subnet-cidr>", file=sys.stderr)
        sys.exit(2)

    subnet = sys.argv[1]
    if is_private_subnet(subnet):
        print(f"OK: {subnet} is a private subnet.")
        sys.exit(0)
    else:
        print(f"REJECTED: {subnet} is NOT a private subnet.", file=sys.stderr)
        sys.exit(1)
