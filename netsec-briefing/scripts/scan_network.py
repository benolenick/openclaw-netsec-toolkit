#!/usr/bin/env python3
"""Network scanner: nmap discovery + service scan -> structured JSON.

Usage:
    python3 scan_network.py --subnet 192.168.1.0/24 --output-dir /tmp/netsec-scan
    python3 scan_network.py --subnet 10.0.0.0/24 --output-dir /tmp/scan --skip-service-scan
"""

import argparse
import json
import os
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Allow importing validate_scope from same directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from validate_scope import abort_if_public, validate_targets

MAX_HOSTS = 50  # context budget cap

# Services that get deterministic findings pre-flagged
RISKY_SERVICES = {
    "telnet":   ("CRITICAL", "Telnet transmits credentials in cleartext"),
    "ftp":      ("HIGH",     "FTP transmits credentials in cleartext"),
    "smb":      ("HIGH",     "SMB may expose shares or be vulnerable to relay attacks"),
    "ms-wbt-server": ("MEDIUM", "RDP exposed — brute-force and CVE risk"),
    "rdp":      ("MEDIUM",   "RDP exposed — brute-force and CVE risk"),
    "vnc":      ("MEDIUM",   "VNC remote desktop exposed"),
    "mysql":    ("MEDIUM",   "MySQL database port exposed to network"),
    "postgresql": ("MEDIUM", "PostgreSQL database port exposed to network"),
    "mongod":   ("MEDIUM",   "MongoDB exposed — check authentication"),
    "redis":    ("MEDIUM",   "Redis exposed — often unauthenticated by default"),
    "snmp":     ("MEDIUM",   "SNMP may leak device info with default communities"),
}

RISKY_PORTS = {
    23:   ("CRITICAL", "telnet", "Telnet transmits credentials in cleartext"),
    21:   ("HIGH",     "ftp",    "FTP transmits credentials in cleartext"),
    445:  ("HIGH",     "smb",    "SMB may expose shares or be vulnerable to relay attacks"),
    139:  ("HIGH",     "netbios-ssn", "NetBIOS session service exposed"),
    3389: ("MEDIUM",   "rdp",    "RDP exposed — brute-force and CVE risk"),
    5900: ("MEDIUM",   "vnc",    "VNC remote desktop exposed"),
    3306: ("MEDIUM",   "mysql",  "MySQL database port exposed to network"),
    5432: ("MEDIUM",   "postgresql", "PostgreSQL database port exposed to network"),
    27017:("MEDIUM",   "mongodb","MongoDB exposed — check authentication"),
    6379: ("MEDIUM",   "redis",  "Redis exposed — often unauthenticated by default"),
    161:  ("MEDIUM",   "snmp",   "SNMP may leak device info with default communities"),
    8080: ("LOW",      "http-proxy", "HTTP proxy/alt port — verify if intentional"),
    8443: ("LOW",      "https-alt",  "HTTPS alt port — verify if intentional"),
}


def run_nmap(args: List[str], description: str) -> subprocess.CompletedProcess:
    """Run nmap with the given arguments. Abort on failure."""
    cmd = ["nmap"] + args
    print(f"[*] {description}")
    print(f"    Command: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        print("ERROR: nmap not found. Install with: apt install -y nmap", file=sys.stderr)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("ERROR: nmap timed out after 300s", file=sys.stderr)
        sys.exit(1)

    if result.returncode != 0 and "0 hosts up" not in result.stdout:
        print(f"WARNING: nmap exited with code {result.returncode}", file=sys.stderr)
        if result.stderr:
            print(f"    stderr: {result.stderr.strip()}", file=sys.stderr)
    return result


def discover_hosts(subnet: str, output_dir: Path) -> List[str]:
    """Phase 1: nmap -sn ping sweep to discover live hosts."""
    xml_path = output_dir / "discovery.xml"
    txt_path = output_dir / "discovery.txt"

    result = run_nmap(
        ["-sn", subnet, "-oX", str(xml_path), "-oN", str(txt_path)],
        f"Host discovery on {subnet}"
    )

    # Parse XML for live hosts
    live_hosts = []
    try:
        tree = ET.parse(str(xml_path))
        root = tree.getroot()
        for host_elem in root.findall("host"):
            status = host_elem.find("status")
            if status is not None and status.get("state") == "up":
                addr = host_elem.find("address")
                if addr is not None and addr.get("addrtype") == "ipv4":
                    live_hosts.append(addr.get("addr"))
    except ET.ParseError as e:
        print(f"WARNING: Could not parse discovery XML: {e}", file=sys.stderr)
        # Fallback: grep from text output
        for line in result.stdout.splitlines():
            if "Nmap scan report for" in line:
                parts = line.split()
                ip = parts[-1].strip("()")
                live_hosts.append(ip)

    # Validate all discovered hosts are private
    valid, rejected = validate_targets(live_hosts)
    if rejected:
        print(f"WARNING: Filtered {len(rejected)} non-private IPs: {rejected}", file=sys.stderr)

    print(f"[*] Discovered {len(valid)} live hosts")
    return valid


def service_scan(hosts: List[str], output_dir: Path) -> str:
    """Phase 2: nmap -sV service detection on discovered hosts."""
    if not hosts:
        return ""

    xml_path = output_dir / "services.xml"
    txt_path = output_dir / "services.txt"

    target_str = " ".join(hosts)
    run_nmap(
        ["-sV", "--top-ports", "1000", "-T4",
         "-oX", str(xml_path), "-oN", str(txt_path)] + hosts,
        f"Service detection on {len(hosts)} hosts"
    )

    return str(xml_path)


def parse_service_xml(xml_path: str) -> List[Dict[str, Any]]:
    """Parse nmap service scan XML into asset dicts."""
    assets = []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except (ET.ParseError, FileNotFoundError) as e:
        print(f"WARNING: Could not parse service XML: {e}", file=sys.stderr)
        return assets

    for host_elem in root.findall("host"):
        asset: Dict[str, Any] = {
            "ip": "",
            "mac": "",
            "hostname": "",
            "vendor": "",
            "os_guess": "",
            "open_ports": [],
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Addresses
        for addr in host_elem.findall("address"):
            if addr.get("addrtype") == "ipv4":
                asset["ip"] = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                asset["mac"] = addr.get("addr", "")
                asset["vendor"] = addr.get("vendor", "")

        # Hostname
        hostnames = host_elem.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                asset["hostname"] = hn.get("name", "")

        # OS guess (from service scan heuristics)
        os_elem = host_elem.find("os")
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            if osmatch is not None:
                asset["os_guess"] = osmatch.get("name", "")

        # Open ports
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    service = port.find("service")
                    port_info = {
                        "port": int(port.get("portid", 0)),
                        "protocol": port.get("protocol", "tcp"),
                        "service": service.get("name", "unknown") if service is not None else "unknown",
                        "product": service.get("product", "") if service is not None else "",
                        "version": service.get("version", "") if service is not None else "",
                        "extrainfo": service.get("extrainfo", "") if service is not None else "",
                    }
                    asset["open_ports"].append(port_info)

        if asset["ip"]:
            assets.append(asset)

    return assets


def generate_findings(assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deterministic finding engine: flag obvious risks before LLM analysis."""
    findings = []
    finding_counter = 0

    for asset in assets:
        for port_info in asset.get("open_ports", []):
            port_num = port_info["port"]
            service_name = port_info["service"].lower()
            product = port_info.get("product", "")
            version = port_info.get("version", "")

            severity = None
            title = None
            evidence = None
            recommendation = None

            # Check by service name
            if service_name in RISKY_SERVICES:
                severity, description = RISKY_SERVICES[service_name]
                title = f"{service_name.upper()} service detected on port {port_num}"
                evidence = f"nmap identified {service_name} on {asset['ip']}:{port_num}"
                if product:
                    evidence += f" ({product} {version})".rstrip()
                recommendation = f"Disable {service_name} or replace with encrypted alternative"

            # Check by port number (catches misidentified services)
            elif port_num in RISKY_PORTS:
                severity, svc, description = RISKY_PORTS[port_num]
                title = f"{svc.upper()} (port {port_num}) detected"
                evidence = f"nmap found open port {port_num} on {asset['ip']}"
                if product:
                    evidence += f" running {product} {version}".rstrip()
                recommendation = f"Review necessity of {svc} on this host"

            # Flag HTTP (not HTTPS) on standard web ports
            elif service_name == "http" and port_num in (80, 8080, 8000):
                severity = "LOW"
                title = f"Unencrypted HTTP on port {port_num}"
                evidence = f"nmap identified HTTP (not HTTPS) on {asset['ip']}:{port_num}"
                if product:
                    evidence += f" ({product} {version})".rstrip()
                recommendation = "Redirect HTTP to HTTPS or add TLS termination"

            if severity:
                finding_counter += 1
                findings.append({
                    "finding_id": f"F-{finding_counter:03d}",
                    "asset_ip": asset["ip"],
                    "severity": severity,
                    "title": title,
                    "evidence": evidence,
                    "port": port_num,
                    "service": service_name,
                    "recommendation": recommendation,
                })

    return findings


def build_scan_result(
    subnet: str,
    assets: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    output_dir: Path,
    truncated: bool,
    discovery_only: bool,
) -> Dict[str, Any]:
    """Assemble the final ScanResult JSON."""
    raw_artifacts = []
    for f in output_dir.iterdir():
        if f.is_file() and f.name != "scan-results.json":
            raw_artifacts.append(str(f))

    return {
        "scan_id": str(uuid.uuid4())[:8],
        "subnet": subnet,
        "scan_start": datetime.now(timezone.utc).isoformat(),
        "scan_end": datetime.now(timezone.utc).isoformat(),
        "host_count": len(assets),
        "assets": assets,
        "findings": findings,
        "raw_artifacts": sorted(raw_artifacts),
        "truncated": truncated,
        "discovery_only": discovery_only,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Network security scanner: nmap discovery + service scan -> structured JSON"
    )
    parser.add_argument("--subnet", required=True, help="Target subnet in CIDR notation (e.g. 192.168.1.0/24)")
    parser.add_argument("--output-dir", required=True, help="Directory to write scan artifacts")
    parser.add_argument("--skip-service-scan", action="store_true", help="Only do host discovery, skip service detection")
    args = parser.parse_args()

    # Safety check: hard abort if not a private subnet
    abort_if_public(args.subnet)

    # Prepare output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Phase 1: Host discovery
    live_hosts = discover_hosts(args.subnet, output_dir)

    if not live_hosts:
        print("[!] No live hosts found on this subnet.")
        result = build_scan_result(args.subnet, [], [], output_dir, False, True)
        result_path = output_dir / "scan-results.json"
        result_path.write_text(json.dumps(result, indent=2))
        print(f"[*] Results saved to {result_path}")
        return

    # Context budget: truncate if too many hosts
    truncated = False
    if len(live_hosts) > MAX_HOSTS:
        print(f"[!] {len(live_hosts)} hosts found — truncating to {MAX_HOSTS} for context budget")
        live_hosts = live_hosts[:MAX_HOSTS]
        truncated = True

    # Phase 2: Service detection
    assets = []
    discovery_only = args.skip_service_scan

    if not args.skip_service_scan:
        xml_path = service_scan(live_hosts, output_dir)
        if xml_path:
            assets = parse_service_xml(xml_path)

    # If no assets from service scan, build minimal assets from discovery
    if not assets:
        assets = [
            {
                "ip": ip,
                "mac": "",
                "hostname": "",
                "vendor": "",
                "os_guess": "",
                "open_ports": [],
                "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            }
            for ip in live_hosts
        ]

    # Deterministic finding engine
    findings = generate_findings(assets)

    # Build and save result
    result = build_scan_result(args.subnet, assets, findings, output_dir, truncated, discovery_only)
    result_path = output_dir / "scan-results.json"
    result_path.write_text(json.dumps(result, indent=2))

    # Write compact text summary (~500 tokens) for LLM consumption
    summary_path = output_dir / "scan-summary.txt"
    summary_lines = []
    summary_lines.append(f"NETWORK SCAN SUMMARY — {args.subnet}")
    summary_lines.append(f"Hosts: {len(assets)} | Findings: {len(findings)}")
    if truncated:
        summary_lines.append(f"WARNING: Truncated to {MAX_HOSTS} hosts")
    summary_lines.append("")

    # Findings sorted by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(findings, key=lambda f: sev_order.get(f["severity"], 5))
    if sorted_findings:
        summary_lines.append("FINDINGS:")
        for f in sorted_findings:
            summary_lines.append(f"  [{f['severity']}] {f['finding_id']}: {f['title']} — {f['asset_ip']}:{f['port']} ({f['evidence']})")
            summary_lines.append(f"    → {f['recommendation']}")
    else:
        summary_lines.append("FINDINGS: None — no risky services detected.")

    summary_lines.append("")
    summary_lines.append("HOST INVENTORY:")
    for a in assets:
        ports = ", ".join(f"{p['port']}/{p['service']}" for p in a.get("open_ports", []))
        hostname = f" ({a['hostname']})" if a.get("hostname") else ""
        vendor = f" [{a['vendor']}]" if a.get("vendor") else ""
        summary_lines.append(f"  {a['ip']}{hostname}{vendor}: {ports or 'no open ports'}")

    summary_text = "\n".join(summary_lines) + "\n"
    summary_path.write_text(summary_text)

    print(f"\n[*] Scan complete:")
    print(f"    Hosts: {len(assets)}")
    print(f"    Findings: {len(findings)}")
    print(f"    Results: {result_path}")
    print(f"    Summary: {summary_path}")
    if truncated:
        print(f"    WARNING: Results truncated to {MAX_HOSTS} hosts")

    # Print summary to stdout so LLM can see it directly
    print(f"\n{'='*60}")
    print(summary_text)
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
