#!/usr/bin/env python3
"""Firewall auditor: parse and audit iptables/ufw rules -> structured findings.

Usage:
    sudo python3 firewall_audit.py --output /tmp/firewall-audit-latest
    python3 firewall_audit.py --output /tmp/firewall-audit-latest --rules-file /path/to/iptables-save.txt
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# Dangerous ports that should generally not be exposed
DANGEROUS_PORTS = {
    23:  ("telnet",  "Telnet transmits credentials in cleartext"),
    513: ("rlogin",  "rlogin is an insecure remote login protocol"),
    514: ("rsh",     "Remote shell has no encryption"),
    69:  ("tftp",    "TFTP has no authentication"),
    111: ("rpcbind", "RPCbind can leak service information"),
    135: ("msrpc",   "Microsoft RPC often targeted by exploits"),
    445: ("smb",     "SMB has a long history of critical vulnerabilities"),
    139: ("netbios", "NetBIOS session service often unnecessary"),
    1433: ("mssql",  "Microsoft SQL Server exposed"),
    1521: ("oracle",  "Oracle database listener exposed"),
    3306: ("mysql",   "MySQL database exposed"),
    5432: ("postgres", "PostgreSQL database exposed"),
    6379: ("redis",   "Redis often runs without authentication"),
    27017: ("mongodb", "MongoDB often runs without authentication"),
}


def is_root() -> bool:
    """Check if running as root."""
    return os.geteuid() == 0


def run_command(cmd: List[str], description: str, allow_fail: bool = False) -> Optional[str]:
    """Run a system command and return stdout, or None on failure."""
    print(f"[*] {description}")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            if not allow_fail:
                print(f"WARNING: {' '.join(cmd)} exited with code {result.returncode}", file=sys.stderr)
                if result.stderr.strip():
                    print(f"    stderr: {result.stderr.strip()}", file=sys.stderr)
            return result.stdout if result.stdout.strip() else None
        return result.stdout
    except FileNotFoundError:
        print(f"WARNING: {cmd[0]} not found on this system", file=sys.stderr)
        return None
    except subprocess.TimeoutExpired:
        print(f"WARNING: {' '.join(cmd)} timed out after 30s", file=sys.stderr)
        return None


def capture_iptables_save() -> Optional[str]:
    """Capture raw iptables rules via iptables-save."""
    return run_command(["iptables-save"], "Capturing iptables-save output")


def capture_iptables_listing() -> Optional[str]:
    """Capture formatted iptables listing with counters."""
    return run_command(
        ["iptables", "-L", "-n", "-v", "--line-numbers"],
        "Capturing iptables listing with counters"
    )


def capture_ufw_status() -> Optional[str]:
    """Capture ufw status if available and active."""
    output = run_command(["ufw", "status", "verbose"], "Checking ufw status", allow_fail=True)
    if output and "Status: active" in output:
        return output
    if output and "Status: inactive" in output:
        print("[*] ufw is installed but inactive")
        return output
    return None


def parse_iptables_save(raw_rules: str) -> Dict[str, Any]:
    """Parse iptables-save output into structured data.

    Returns dict with:
        tables: {table_name: {chains: {chain_name: {policy, rules: [...]}}}}
    """
    tables: Dict[str, Dict] = {}
    current_table = None

    for line in raw_rules.splitlines():
        line = line.strip()

        # Skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        # Table declaration: *filter, *nat, *mangle, etc.
        if line.startswith("*"):
            current_table = line[1:]
            tables[current_table] = {"chains": {}}
            continue

        # Chain policy: :INPUT ACCEPT [0:0]
        if line.startswith(":") and current_table:
            match = re.match(r"^:(\S+)\s+(\S+)\s+\[(\d+):(\d+)\]", line)
            if match:
                chain_name = match.group(1)
                policy = match.group(2)
                packets = int(match.group(3))
                bytecnt = int(match.group(4))
                tables[current_table]["chains"][chain_name] = {
                    "policy": policy,
                    "packets": packets,
                    "bytes": bytecnt,
                    "rules": [],
                }
            continue

        # Rule: -A INPUT -s 10.0.0.0/8 -j ACCEPT
        if line.startswith("-A") and current_table:
            parts = line.split()
            if len(parts) >= 2:
                chain_name = parts[1]
                rule_text = line
                parsed_rule = parse_single_rule(rule_text)
                if chain_name in tables[current_table]["chains"]:
                    tables[current_table]["chains"][chain_name]["rules"].append(parsed_rule)
            continue

        # COMMIT line
        if line == "COMMIT":
            current_table = None
            continue

    return {"tables": tables}


def parse_single_rule(rule_text: str) -> Dict[str, Any]:
    """Parse a single iptables rule line into a structured dict."""
    rule: Dict[str, Any] = {
        "raw": rule_text,
        "chain": "",
        "source": "0.0.0.0/0",
        "destination": "0.0.0.0/0",
        "protocol": "all",
        "target": "",
        "in_interface": "",
        "out_interface": "",
        "dport": "",
        "sport": "",
        "match_modules": [],
        "extra": "",
    }

    parts = rule_text.split()
    i = 0
    while i < len(parts):
        flag = parts[i]

        if flag == "-A" and i + 1 < len(parts):
            rule["chain"] = parts[i + 1]
            i += 2
        elif flag == "-s" and i + 1 < len(parts):
            rule["source"] = parts[i + 1]
            i += 2
        elif flag == "-d" and i + 1 < len(parts):
            rule["destination"] = parts[i + 1]
            i += 2
        elif flag == "-p" and i + 1 < len(parts):
            rule["protocol"] = parts[i + 1]
            i += 2
        elif flag == "-j" and i + 1 < len(parts):
            rule["target"] = parts[i + 1]
            i += 2
        elif flag == "-i" and i + 1 < len(parts):
            rule["in_interface"] = parts[i + 1]
            i += 2
        elif flag == "-o" and i + 1 < len(parts):
            rule["out_interface"] = parts[i + 1]
            i += 2
        elif flag == "--dport" and i + 1 < len(parts):
            rule["dport"] = parts[i + 1]
            i += 2
        elif flag == "--sport" and i + 1 < len(parts):
            rule["sport"] = parts[i + 1]
            i += 2
        elif flag == "-m" and i + 1 < len(parts):
            rule["match_modules"].append(parts[i + 1])
            i += 2
        else:
            i += 1

    return rule


def parse_iptables_listing(listing: str) -> Dict[str, Dict]:
    """Parse iptables -L -n -v --line-numbers output for counter data.

    Returns dict of chain_name -> {rules_with_counters: [{num, pkts, bytes, ...}]}
    """
    chains: Dict[str, Dict] = {}
    current_chain = None
    current_policy = None

    for line in listing.splitlines():
        line = line.strip()

        # Chain header: "Chain INPUT (policy ACCEPT 123 packets, 456 bytes)"
        chain_match = re.match(
            r"^Chain\s+(\S+)\s+\(policy\s+(\S+)\s+(\d+)\s+packets,\s+(\d+)\s+bytes\)",
            line,
        )
        if chain_match:
            current_chain = chain_match.group(1)
            chains[current_chain] = {
                "policy": chain_match.group(2),
                "policy_packets": int(chain_match.group(3)),
                "policy_bytes": int(chain_match.group(4)),
                "rules_with_counters": [],
            }
            continue

        # Also match user-defined chains: "Chain ufw-... (1 references)"
        user_chain_match = re.match(r"^Chain\s+(\S+)\s+\(", line)
        if user_chain_match and current_chain is None or (user_chain_match and user_chain_match.group(1) != current_chain):
            current_chain = user_chain_match.group(1)
            if current_chain not in chains:
                chains[current_chain] = {
                    "policy": "-",
                    "policy_packets": 0,
                    "policy_bytes": 0,
                    "rules_with_counters": [],
                }
            continue

        # Skip header line
        if line.startswith("num") or not line or line.startswith("Chain"):
            continue

        # Rule line: "1  123  456  tcp  --  *  *  0.0.0.0/0  0.0.0.0/0  tcp dpt:22"
        rule_match = re.match(
            r"^(\d+)\s+(\d+[KMG]?)\s+(\d+[KMG]?)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)",
            line,
        )
        if rule_match and current_chain:
            rule_entry = {
                "num": int(rule_match.group(1)),
                "packets": parse_counter(rule_match.group(2)),
                "bytes": parse_counter(rule_match.group(3)),
                "protocol": rule_match.group(4),
                "opt": rule_match.group(5),
                "in_iface": rule_match.group(6),
                "out_iface": rule_match.group(7),
                "source": rule_match.group(8),
                "destination": rule_match.group(9),
                "extra": rule_match.group(10).strip() if rule_match.group(10) else "",
            }
            chains[current_chain]["rules_with_counters"].append(rule_entry)

    return chains


def parse_counter(value: str) -> int:
    """Parse a counter value like '123', '1K', '2M', '3G' into an integer."""
    value = value.strip()
    multipliers = {"K": 1000, "M": 1000000, "G": 1000000000}
    if value and value[-1] in multipliers:
        try:
            return int(float(value[:-1]) * multipliers[value[-1]])
        except ValueError:
            return 0
    try:
        return int(value)
    except ValueError:
        return 0


def parse_ufw_status(ufw_output: str) -> Dict[str, Any]:
    """Parse ufw status verbose output."""
    result: Dict[str, Any] = {
        "active": False,
        "default_incoming": "",
        "default_outgoing": "",
        "default_routed": "",
        "logging": "",
        "rules": [],
    }

    for line in ufw_output.splitlines():
        line = line.strip()

        if "Status: active" in line:
            result["active"] = True
        elif line.startswith("Default:"):
            defaults = line.replace("Default:", "").strip()
            # Parse "deny (incoming), allow (outgoing), disabled (routed)"
            for part in defaults.split(","):
                part = part.strip()
                if "(incoming)" in part:
                    result["default_incoming"] = part.split()[0]
                elif "(outgoing)" in part:
                    result["default_outgoing"] = part.split()[0]
                elif "(routed)" in part:
                    result["default_routed"] = part.split()[0]
        elif line.startswith("Logging:"):
            result["logging"] = line.replace("Logging:", "").strip()
        elif re.match(r"^\d+", line) or re.match(r"^Anywhere", line):
            # ufw rule line
            result["rules"].append(line)

    return result


def analyze_rules(
    parsed_save: Dict[str, Any],
    listing_data: Optional[Dict[str, Dict]],
    ufw_data: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Analyze parsed firewall rules and generate findings."""
    findings: List[Dict[str, Any]] = []
    finding_id = 0

    def add_finding(
        severity: str,
        title: str,
        description: str,
        evidence: str,
        recommendation: str,
        chain: str = "",
        rule_num: str = "",
    ) -> None:
        nonlocal finding_id
        finding_id += 1
        findings.append({
            "finding_id": f"F-{finding_id:03d}",
            "severity": severity,
            "title": title,
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation,
            "chain": chain,
            "rule_num": rule_num,
        })

    tables = parsed_save.get("tables", {})
    filter_table = tables.get("filter", {})
    chains = filter_table.get("chains", {})

    # ---------------------------------------------------------------
    # CHECK 1: Default chain policies
    # ---------------------------------------------------------------
    for chain_name in ("INPUT", "FORWARD", "OUTPUT"):
        chain_data = chains.get(chain_name, {})
        policy = chain_data.get("policy", "UNKNOWN")

        if chain_name == "INPUT" and policy == "ACCEPT":
            add_finding(
                severity="CRITICAL",
                title=f"Default INPUT policy is ACCEPT",
                description=(
                    "The INPUT chain has a default policy of ACCEPT, meaning all "
                    "incoming traffic that does not match an explicit rule is allowed. "
                    "This is the most common firewall misconfiguration."
                ),
                evidence=f"Chain {chain_name} policy: {policy}",
                recommendation=(
                    "Set the default INPUT policy to DROP: "
                    "`iptables -P INPUT DROP` (ensure SSH access rules exist first)"
                ),
                chain=chain_name,
            )
        elif chain_name == "FORWARD" and policy == "ACCEPT":
            add_finding(
                severity="HIGH",
                title=f"Default FORWARD policy is ACCEPT",
                description=(
                    "The FORWARD chain has a default policy of ACCEPT. Unless this "
                    "system is intentionally configured as a router, this allows "
                    "traffic to pass through the system between interfaces."
                ),
                evidence=f"Chain {chain_name} policy: {policy}",
                recommendation=(
                    "Set the default FORWARD policy to DROP unless this system "
                    "is a router: `iptables -P FORWARD DROP`"
                ),
                chain=chain_name,
            )
        elif chain_name == "OUTPUT" and policy == "ACCEPT":
            add_finding(
                severity="MEDIUM",
                title=f"Default OUTPUT policy is ACCEPT",
                description=(
                    "The OUTPUT chain allows all outgoing traffic by default. "
                    "While common, this means compromised software can freely "
                    "exfiltrate data or establish reverse shells."
                ),
                evidence=f"Chain {chain_name} policy: {policy}",
                recommendation=(
                    "Consider restricting OUTPUT to known-required destinations "
                    "and protocols for high-security environments"
                ),
                chain=chain_name,
            )

    # ---------------------------------------------------------------
    # CHECK 2: Overly permissive rules (0.0.0.0/0 -> 0.0.0.0/0 ACCEPT)
    # ---------------------------------------------------------------
    for chain_name, chain_data in chains.items():
        for idx, rule in enumerate(chain_data.get("rules", []), start=1):
            src = rule.get("source", "0.0.0.0/0")
            dst = rule.get("destination", "0.0.0.0/0")
            target = rule.get("target", "")
            protocol = rule.get("protocol", "all")

            # Any/any ACCEPT on INPUT is critical
            is_any_src = src in ("0.0.0.0/0", "anywhere")
            is_any_dst = dst in ("0.0.0.0/0", "anywhere")
            is_all_proto = protocol == "all"

            if (
                is_any_src
                and is_any_dst
                and is_all_proto
                and target == "ACCEPT"
                and chain_name == "INPUT"
            ):
                add_finding(
                    severity="CRITICAL",
                    title=f"Any/any ACCEPT rule on INPUT chain",
                    description=(
                        "A rule accepts ALL protocols from ANY source to ANY "
                        "destination on the INPUT chain. This effectively "
                        "disables the firewall for this rule position."
                    ),
                    evidence=f"Rule {idx} in {chain_name}: {rule['raw']}",
                    recommendation="Remove this rule or restrict source, destination, and protocol",
                    chain=chain_name,
                    rule_num=str(idx),
                )
            elif (
                is_any_src
                and is_any_dst
                and is_all_proto
                and target == "ACCEPT"
                and chain_name == "FORWARD"
            ):
                add_finding(
                    severity="HIGH",
                    title=f"Any/any ACCEPT rule on FORWARD chain",
                    description=(
                        "A rule in the FORWARD chain accepts all traffic from "
                        "any source to any destination. Unless this is an "
                        "intentional router configuration, this is dangerous."
                    ),
                    evidence=f"Rule {idx} in {chain_name}: {rule['raw']}",
                    recommendation="Restrict FORWARD rules to specific interfaces and subnets",
                    chain=chain_name,
                    rule_num=str(idx),
                )
            elif is_any_src and is_any_dst and target == "ACCEPT" and chain_name == "INPUT":
                # Single-protocol any/any on INPUT
                add_finding(
                    severity="HIGH",
                    title=f"Wide-open {protocol} ACCEPT on INPUT",
                    description=(
                        f"A rule accepts {protocol} from any source to any "
                        f"destination on INPUT without port restriction."
                    ),
                    evidence=f"Rule {idx} in {chain_name}: {rule['raw']}",
                    recommendation=f"Restrict the source IP range or add port-specific rules for {protocol}",
                    chain=chain_name,
                    rule_num=str(idx),
                )

    # ---------------------------------------------------------------
    # CHECK 3: SSH without rate limiting
    # ---------------------------------------------------------------
    ssh_rules_found = False
    ssh_rate_limited = False

    for chain_name, chain_data in chains.items():
        for rule in chain_data.get("rules", []):
            dport = rule.get("dport", "")
            if dport == "22" or dport == "ssh":
                ssh_rules_found = True
                modules = rule.get("match_modules", [])
                if "limit" in modules or "hashlimit" in modules or "recent" in modules:
                    ssh_rate_limited = True

    if ssh_rules_found and not ssh_rate_limited:
        add_finding(
            severity="HIGH",
            title="SSH (port 22) allowed without rate limiting",
            description=(
                "SSH access is permitted but no rate limiting module (limit, "
                "hashlimit, or recent) is applied. This leaves SSH vulnerable "
                "to brute-force attacks."
            ),
            evidence="SSH rules found without -m limit, -m hashlimit, or -m recent modules",
            recommendation=(
                "Add rate limiting to SSH rules: "
                "`iptables -A INPUT -p tcp --dport 22 -m limit --limit 3/min "
                "--limit-burst 3 -j ACCEPT`"
            ),
            chain="INPUT",
        )

    # ---------------------------------------------------------------
    # CHECK 4: Dangerous ports open
    # ---------------------------------------------------------------
    for chain_name, chain_data in chains.items():
        if chain_name != "INPUT":
            continue
        for idx, rule in enumerate(chain_data.get("rules", []), start=1):
            target = rule.get("target", "")
            if target not in ("ACCEPT", ""):
                continue

            dport = rule.get("dport", "")
            if not dport:
                continue

            # Handle port ranges like "1000:2000"
            try:
                port_num = int(dport)
            except ValueError:
                continue

            if port_num in DANGEROUS_PORTS:
                svc_name, svc_desc = DANGEROUS_PORTS[port_num]
                severity = "CRITICAL" if port_num in (23, 513, 514) else "HIGH"
                add_finding(
                    severity=severity,
                    title=f"Dangerous port {port_num} ({svc_name}) open on INPUT",
                    description=f"{svc_desc}. Allowing inbound access to this port is a security risk.",
                    evidence=f"Rule {idx} in {chain_name}: {rule['raw']}",
                    recommendation=f"Close port {port_num} or replace {svc_name} with a secure alternative",
                    chain=chain_name,
                    rule_num=str(idx),
                )

    # ---------------------------------------------------------------
    # CHECK 5: Missing logging rules
    # ---------------------------------------------------------------
    has_log_rule = False
    for chain_name, chain_data in chains.items():
        for rule in chain_data.get("rules", []):
            if rule.get("target", "") == "LOG":
                has_log_rule = True
                break
        if has_log_rule:
            break

    if not has_log_rule:
        add_finding(
            severity="MEDIUM",
            title="No LOG rules found in any chain",
            description=(
                "There are no logging rules in the firewall configuration. "
                "Without logging, dropped or rejected packets leave no audit "
                "trail, making incident investigation difficult."
            ),
            evidence="No rules with -j LOG target found in iptables-save output",
            recommendation=(
                "Add LOG rules before final DROP/REJECT rules: "
                "`iptables -A INPUT -j LOG --log-prefix 'IPT-DROP: ' --log-level 4`"
            ),
        )

    # ---------------------------------------------------------------
    # CHECK 6: Rules with zero packet/byte counters (potentially unused)
    # ---------------------------------------------------------------
    if listing_data:
        unused_count = 0
        for chain_name, chain_info in listing_data.items():
            for rule_entry in chain_info.get("rules_with_counters", []):
                pkts = rule_entry.get("packets", 0)
                bytecnt = rule_entry.get("bytes", 0)
                if pkts == 0 and bytecnt == 0:
                    unused_count += 1

        if unused_count > 0:
            add_finding(
                severity="MEDIUM",
                title=f"{unused_count} rule(s) with zero packet counters (potentially unused)",
                description=(
                    f"Found {unused_count} rule(s) that have never matched any traffic "
                    f"(zero packets and zero bytes). These may be unused, redundant, "
                    f"or the counters were recently reset."
                ),
                evidence=f"{unused_count} rules across all chains with 0 packets and 0 bytes",
                recommendation=(
                    "Review zero-counter rules to determine if they are needed. "
                    "Remove unused rules to simplify the firewall and reduce attack surface."
                ),
            )

    # ---------------------------------------------------------------
    # CHECK 7: FORWARD chain allowing all (non-router check)
    # ---------------------------------------------------------------
    forward_chain = chains.get("FORWARD", {})
    forward_rules = forward_chain.get("rules", [])
    for idx, rule in enumerate(forward_rules, start=1):
        target = rule.get("target", "")
        src = rule.get("source", "0.0.0.0/0")
        dst = rule.get("destination", "0.0.0.0/0")
        protocol = rule.get("protocol", "all")

        if (
            target == "ACCEPT"
            and src in ("0.0.0.0/0", "anywhere")
            and dst in ("0.0.0.0/0", "anywhere")
            and protocol == "all"
            and not rule.get("in_interface")
            and not rule.get("out_interface")
        ):
            # Already covered by CHECK 2 for FORWARD, but add interface note
            pass

    # ---------------------------------------------------------------
    # CHECK 8: Rule ordering issues
    # ---------------------------------------------------------------
    for chain_name in ("INPUT", "FORWARD", "OUTPUT"):
        chain_data = chains.get(chain_name, {})
        rules = chain_data.get("rules", [])
        drop_seen = False
        for idx, rule in enumerate(rules, start=1):
            target = rule.get("target", "")
            if target in ("DROP", "REJECT"):
                drop_seen = True
            elif target == "ACCEPT" and drop_seen:
                add_finding(
                    severity="LOW",
                    title=f"ACCEPT rule after DROP/REJECT in {chain_name} chain",
                    description=(
                        f"Rule {idx} in {chain_name} is an ACCEPT rule that appears "
                        f"after a DROP/REJECT rule. Depending on specificity, this "
                        f"rule may never match or indicate a rule ordering problem."
                    ),
                    evidence=f"Rule {idx} in {chain_name}: {rule['raw']}",
                    recommendation=f"Review rule ordering in {chain_name} chain; ensure ACCEPT rules precede DROP/REJECT for the same traffic",
                    chain=chain_name,
                    rule_num=str(idx),
                )
                break  # Only flag once per chain

    # ---------------------------------------------------------------
    # CHECK 9: Redundant rules (simple duplicate detection)
    # ---------------------------------------------------------------
    for chain_name, chain_data in chains.items():
        rules = chain_data.get("rules", [])
        seen_rules = set()
        for idx, rule in enumerate(rules, start=1):
            # Normalize for comparison
            key = (
                rule.get("source"),
                rule.get("destination"),
                rule.get("protocol"),
                rule.get("target"),
                rule.get("dport"),
                rule.get("sport"),
                rule.get("in_interface"),
                rule.get("out_interface"),
            )
            if key in seen_rules:
                add_finding(
                    severity="LOW",
                    title=f"Potentially redundant rule in {chain_name} chain",
                    description=(
                        f"Rule {idx} in {chain_name} appears to be a duplicate of "
                        f"an earlier rule with the same source, destination, "
                        f"protocol, target, and ports."
                    ),
                    evidence=f"Rule {idx} in {chain_name}: {rule['raw']}",
                    recommendation=f"Remove the duplicate rule from {chain_name} chain",
                    chain=chain_name,
                    rule_num=str(idx),
                )
            seen_rules.add(key)

    # ---------------------------------------------------------------
    # CHECK 10: UFW-specific checks
    # ---------------------------------------------------------------
    if ufw_data and ufw_data.get("active"):
        if ufw_data.get("default_incoming", "").lower() == "allow":
            add_finding(
                severity="CRITICAL",
                title="ufw default incoming policy is ALLOW",
                description=(
                    "ufw is configured to allow all incoming traffic by default. "
                    "This defeats the purpose of the firewall."
                ),
                evidence=f"ufw default incoming: {ufw_data['default_incoming']}",
                recommendation="Set default incoming to deny: `ufw default deny incoming`",
            )
        if ufw_data.get("logging", "").lower().startswith("off"):
            add_finding(
                severity="MEDIUM",
                title="ufw logging is disabled",
                description=(
                    "ufw logging is turned off. Without logging, there is no "
                    "audit trail for blocked connections."
                ),
                evidence=f"ufw logging: {ufw_data['logging']}",
                recommendation="Enable ufw logging: `ufw logging on`",
            )

    # ---------------------------------------------------------------
    # INFO: General firewall statistics
    # ---------------------------------------------------------------
    total_rules = 0
    for chain_name, chain_data in chains.items():
        total_rules += len(chain_data.get("rules", []))

    table_names = list(tables.keys())
    chain_names = []
    for t in tables.values():
        chain_names.extend(t.get("chains", {}).keys())

    add_finding(
        severity="INFO",
        title="Firewall statistics",
        description=(
            f"Tables: {', '.join(table_names) if table_names else 'none detected'}. "
            f"Chains: {len(chain_names)}. "
            f"Total rules (filter table): {total_rules}."
        ),
        evidence=(
            f"iptables tables: {table_names}, "
            f"chains: {chain_names}, "
            f"filter table rule count: {total_rules}"
        ),
        recommendation="Review this report and address findings in priority order",
    )

    if total_rules == 0:
        add_finding(
            severity="CRITICAL",
            title="No firewall rules configured",
            description=(
                "The filter table contains zero rules. The system is relying "
                "entirely on default chain policies, which may be ACCEPT."
            ),
            evidence="0 rules found in the filter table",
            recommendation="Configure firewall rules immediately. At minimum, set INPUT/FORWARD policies to DROP and allow only required services.",
        )

    return findings


def generate_json_report(
    findings: List[Dict[str, Any]],
    parsed_save: Dict[str, Any],
    ufw_data: Optional[Dict[str, Any]],
    listing_data: Optional[Dict[str, Dict]],
    is_offline: bool,
    rules_file: Optional[str],
) -> Dict[str, Any]:
    """Build the full structured audit result."""
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Calculate total rules
    total_rules = 0
    tables = parsed_save.get("tables", {})
    for table_data in tables.values():
        for chain_data in table_data.get("chains", {}).values():
            total_rules += len(chain_data.get("rules", []))

    # Determine overall posture
    if severity_counts["CRITICAL"] > 0:
        posture = "CRITICAL - Immediate action required"
    elif severity_counts["HIGH"] > 0:
        posture = "POOR - Significant issues need attention"
    elif severity_counts["MEDIUM"] > 0:
        posture = "FAIR - Improvements recommended"
    elif severity_counts["LOW"] > 0:
        posture = "GOOD - Minor improvements possible"
    else:
        posture = "STRONG - No significant issues found"

    return {
        "audit_timestamp": datetime.now(timezone.utc).isoformat(),
        "audit_mode": "offline" if is_offline else "live",
        "rules_source": rules_file if is_offline else "iptables-save (live)",
        "is_root": is_root(),
        "posture": posture,
        "severity_counts": severity_counts,
        "total_rules": total_rules,
        "tables": list(tables.keys()),
        "findings": findings,
        "parsed_rules": parsed_save,
        "ufw_status": ufw_data,
    }


def generate_summary(
    findings: List[Dict[str, Any]],
    parsed_save: Dict[str, Any],
    ufw_data: Optional[Dict[str, Any]],
    is_offline: bool,
) -> str:
    """Generate a human-readable summary for the audit."""
    lines: List[str] = []

    # Header
    lines.append("=" * 60)
    lines.append("FIREWALL AUDIT SUMMARY")
    lines.append(f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append(f"Mode: {'Offline analysis' if is_offline else 'Live system audit'}")
    if not is_root() and not is_offline:
        lines.append("NOTE: Running without root - some data may be incomplete")
    lines.append("=" * 60)
    lines.append("")

    # Chain policies
    tables = parsed_save.get("tables", {})
    filter_table = tables.get("filter", {})
    chains = filter_table.get("chains", {})

    lines.append("DEFAULT CHAIN POLICIES (filter table):")
    for chain_name in ("INPUT", "FORWARD", "OUTPUT"):
        chain_data = chains.get(chain_name, {})
        policy = chain_data.get("policy", "UNKNOWN")
        flag = " <<< DANGER" if (chain_name in ("INPUT", "FORWARD") and policy == "ACCEPT") else ""
        lines.append(f"  {chain_name:12s} -> {policy}{flag}")
    lines.append("")

    # Rule counts per table
    lines.append("RULE COUNTS:")
    for table_name, table_data in tables.items():
        rule_count = sum(
            len(cd.get("rules", []))
            for cd in table_data.get("chains", {}).values()
        )
        chain_list = ", ".join(table_data.get("chains", {}).keys())
        lines.append(f"  {table_name:12s} -> {rule_count} rules ({chain_list})")
    lines.append("")

    # UFW status
    if ufw_data:
        lines.append("UFW STATUS:")
        if ufw_data.get("active"):
            lines.append(f"  Active:     Yes")
            lines.append(f"  Incoming:   {ufw_data.get('default_incoming', 'unknown')}")
            lines.append(f"  Outgoing:   {ufw_data.get('default_outgoing', 'unknown')}")
            lines.append(f"  Routed:     {ufw_data.get('default_routed', 'unknown')}")
            lines.append(f"  Logging:    {ufw_data.get('logging', 'unknown')}")
        else:
            lines.append("  Active:     No (ufw is inactive)")
        lines.append("")

    # Severity counts
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        if sev in severity_counts:
            severity_counts[sev] += 1

    lines.append("FINDING SUMMARY:")
    lines.append(
        f"  CRITICAL: {severity_counts['CRITICAL']}  |  "
        f"HIGH: {severity_counts['HIGH']}  |  "
        f"MEDIUM: {severity_counts['MEDIUM']}  |  "
        f"LOW: {severity_counts['LOW']}  |  "
        f"INFO: {severity_counts['INFO']}"
    )
    lines.append("")

    # Posture
    if severity_counts["CRITICAL"] > 0:
        posture = "CRITICAL - Immediate action required"
    elif severity_counts["HIGH"] > 0:
        posture = "POOR - Significant issues need attention"
    elif severity_counts["MEDIUM"] > 0:
        posture = "FAIR - Improvements recommended"
    elif severity_counts["LOW"] > 0:
        posture = "GOOD - Minor improvements possible"
    else:
        posture = "STRONG - No significant issues found"
    lines.append(f"OVERALL POSTURE: {posture}")
    lines.append("")

    # Findings detail
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(findings, key=lambda f: sev_order.get(f["severity"], 5))

    lines.append("-" * 60)
    lines.append("FINDINGS DETAIL:")
    lines.append("-" * 60)

    for f in sorted_findings:
        lines.append("")
        lines.append(f"[{f['severity']}] {f['finding_id']}: {f['title']}")
        lines.append(f"  Description:    {f['description']}")
        lines.append(f"  Evidence:       {f['evidence']}")
        lines.append(f"  Recommendation: {f['recommendation']}")
        if f.get("chain"):
            lines.append(f"  Chain:          {f['chain']}")
        if f.get("rule_num"):
            lines.append(f"  Rule #:         {f['rule_num']}")

    lines.append("")
    lines.append("=" * 60)
    lines.append("END OF AUDIT SUMMARY")
    lines.append("=" * 60)

    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(
        description="Firewall auditor: parse and audit iptables/ufw rules"
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output directory for audit results",
    )
    parser.add_argument(
        "--rules-file",
        default=None,
        help="Path to saved iptables-save output for offline analysis",
    )
    args = parser.parse_args()

    # Prepare output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    is_offline = args.rules_file is not None

    print("[*] Firewall Audit starting")
    print(f"[*] Output directory: {output_dir}")
    print(f"[*] Mode: {'Offline analysis' if is_offline else 'Live system audit'}")

    # Root check for live mode
    if not is_offline and not is_root():
        print(
            "WARNING: Not running as root. Some iptables data may be unavailable. "
            "Run with sudo for complete results.",
            file=sys.stderr,
        )

    # ---------------------------------------------------------------
    # Capture / Load rules
    # ---------------------------------------------------------------
    raw_rules = None
    listing_output = None
    ufw_output = None

    if is_offline:
        # Offline mode: read from file
        rules_path = Path(args.rules_file)
        if not rules_path.exists():
            print(f"ERROR: Rules file not found: {args.rules_file}", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Reading rules from: {args.rules_file}")
        raw_rules = rules_path.read_text()
        if not raw_rules.strip():
            print(f"ERROR: Rules file is empty: {args.rules_file}", file=sys.stderr)
            sys.exit(1)
    else:
        # Live mode: capture from system
        raw_rules = capture_iptables_save()
        listing_output = capture_iptables_listing()
        ufw_output = capture_ufw_status()

    if raw_rules is None:
        if not is_offline:
            print(
                "ERROR: Could not capture iptables rules. "
                "Ensure iptables is installed and you have permission (try sudo).",
                file=sys.stderr,
            )
            # Try to still provide useful info
            if ufw_output:
                print("[*] ufw data was captured; proceeding with limited analysis")
                raw_rules = ""  # Empty but non-None so we can continue
            else:
                sys.exit(1)
        else:
            print("ERROR: Failed to read rules file", file=sys.stderr)
            sys.exit(1)

    # Save raw rules
    raw_path = output_dir / "raw-iptables.txt"
    raw_path.write_text(raw_rules)
    print(f"[*] Raw rules saved to: {raw_path}")

    if listing_output:
        listing_path = output_dir / "iptables-listing.txt"
        listing_path.write_text(listing_output)
        print(f"[*] Formatted listing saved to: {listing_path}")

    if ufw_output:
        ufw_path = output_dir / "ufw-status.txt"
        ufw_path.write_text(ufw_output)
        print(f"[*] ufw status saved to: {ufw_path}")

    # ---------------------------------------------------------------
    # Parse
    # ---------------------------------------------------------------
    print("[*] Parsing iptables rules")
    parsed_save = parse_iptables_save(raw_rules)

    listing_data = None
    if listing_output:
        print("[*] Parsing iptables listing with counters")
        listing_data = parse_iptables_listing(listing_output)

    ufw_data = None
    if ufw_output:
        print("[*] Parsing ufw status")
        ufw_data = parse_ufw_status(ufw_output)

    # ---------------------------------------------------------------
    # Analyze
    # ---------------------------------------------------------------
    print("[*] Analyzing firewall rules")
    findings = analyze_rules(parsed_save, listing_data, ufw_data)

    # ---------------------------------------------------------------
    # Generate outputs
    # ---------------------------------------------------------------
    print("[*] Generating audit reports")

    # JSON report
    json_report = generate_json_report(
        findings, parsed_save, ufw_data, listing_data, is_offline, args.rules_file
    )
    json_path = output_dir / "audit-results.json"
    json_path.write_text(json.dumps(json_report, indent=2))
    print(f"[*] JSON report saved to: {json_path}")

    # Human-readable summary
    summary = generate_summary(findings, parsed_save, ufw_data, is_offline)
    summary_path = output_dir / "audit-summary.txt"
    summary_path.write_text(summary)
    print(f"[*] Summary saved to: {summary_path}")

    # ---------------------------------------------------------------
    # Final output
    # ---------------------------------------------------------------
    severity_counts = json_report["severity_counts"]
    print(f"\n[*] Audit complete:")
    print(f"    Findings: {len(findings)} total")
    print(f"      CRITICAL: {severity_counts['CRITICAL']}")
    print(f"      HIGH:     {severity_counts['HIGH']}")
    print(f"      MEDIUM:   {severity_counts['MEDIUM']}")
    print(f"      LOW:      {severity_counts['LOW']}")
    print(f"      INFO:     {severity_counts['INFO']}")
    print(f"    Posture:  {json_report['posture']}")
    print(f"    Reports:  {json_path}")
    print(f"              {summary_path}")
    print(f"              {raw_path}")

    # Print summary to stdout so LLM can see it directly
    print(f"\n{'=' * 60}")
    print(summary)
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
