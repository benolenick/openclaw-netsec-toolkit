#!/usr/bin/env python3
"""SSL/TLS certificate auditor: openssl s_client probes -> structured JSON.

Usage:
    python3 ssl_audit.py --targets "example.com,example.org" --output /tmp/ssl-audit-latest
    python3 ssl_audit.py --targets "192.168.1.1" --output /tmp/ssl-audit-latest
"""

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

MAX_TARGETS = 5
CONNECT_TIMEOUT = 10  # seconds for openssl/curl connections

# Weak cipher substrings to test for
WEAK_CIPHER_PATTERNS = [
    "RC4",
    "DES-CBC3",
    "NULL",
    "EXPORT",
    "anon",
    "MD5",
]

# Protocol versions to test, from weakest to strongest
PROTOCOL_TESTS = [
    ("TLSv1",   "-tls1"),
    ("TLSv1.1", "-tls1_1"),
    ("TLSv1.2", "-tls1_2"),
    ("TLSv1.3", "-tls1_3"),
]

# Deprecated protocols that should be disabled
DEPRECATED_PROTOCOLS = {"SSLv3", "TLSv1", "TLSv1.1"}


def log_progress(msg: str) -> None:
    """Print progress message to stdout."""
    print(f"[*] {msg}")


def log_error(msg: str) -> None:
    """Print error to stderr."""
    print(f"ERROR: {msg}", file=sys.stderr)


def log_warning(msg: str) -> None:
    """Print warning to stderr."""
    print(f"WARNING: {msg}", file=sys.stderr)


def log_abort(msg: str) -> None:
    """Print abort message to stderr and exit."""
    print(f"ABORT: {msg}", file=sys.stderr)
    sys.exit(1)


def validate_target(target: str) -> str:
    """Validate and normalize a target string. Returns host:port or raises ValueError."""
    target = target.strip()
    if not target:
        raise ValueError("Empty target")

    # Strip protocol prefix if present
    for prefix in ("https://", "http://"):
        if target.lower().startswith(prefix):
            target = target[len(prefix):]

    # Strip trailing path
    target = target.split("/")[0]

    # Split host and port
    if ":" in target and not target.startswith("["):
        parts = target.rsplit(":", 1)
        host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            raise ValueError(f"Invalid port in target: {target}")
    elif target.startswith("[") and "]:" in target:
        # IPv6 with port: [::1]:443
        bracket_end = target.index("]:")
        host = target[1:bracket_end]
        try:
            port = int(target[bracket_end + 2:])
        except ValueError:
            raise ValueError(f"Invalid port in target: {target}")
    else:
        host = target
        port = 443

    if not host:
        raise ValueError("Empty hostname")

    # Basic hostname validation
    if not re.match(r'^[a-zA-Z0-9._:[\]-]+$', host):
        raise ValueError(f"Invalid characters in hostname: {host}")

    return f"{host}:{port}"


def parse_targets(targets_str: str) -> List[str]:
    """Parse comma-separated target string into validated host:port list."""
    raw_targets = [t.strip() for t in targets_str.split(",") if t.strip()]

    if not raw_targets:
        log_error("No targets provided.")
        sys.exit(2)

    if len(raw_targets) > MAX_TARGETS:
        log_abort(f"Too many targets ({len(raw_targets)}). Maximum is {MAX_TARGETS}.")

    validated = []
    for t in raw_targets:
        try:
            validated.append(validate_target(t))
        except ValueError as e:
            log_warning(f"Skipping invalid target '{t}': {e}")

    if not validated:
        log_error("No valid targets after validation.")
        sys.exit(2)

    return validated


def run_openssl(args: List[str], stdin_data: str = "",
                timeout: int = CONNECT_TIMEOUT) -> Tuple[int, str, str]:
    """Run openssl with given arguments. Returns (returncode, stdout, stderr)."""
    cmd = ["openssl"] + args
    try:
        result = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        log_error("openssl not found. Install with: apt install -y openssl")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        return 1, "", f"Connection timed out after {timeout}s"


def run_curl(args: List[str], timeout: int = CONNECT_TIMEOUT) -> Tuple[int, str, str]:
    """Run curl with given arguments. Returns (returncode, stdout, stderr)."""
    cmd = ["curl"] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        log_warning("curl not found — HSTS check will be skipped.")
        return 1, "", "curl not found"
    except subprocess.TimeoutExpired:
        return 1, "", f"curl timed out after {timeout}s"


def check_dns_resolution(host: str) -> bool:
    """Check if a hostname resolves to an IP address."""
    # Strip port if present
    hostname = host.split(":")[0]
    try:
        socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return True
    except socket.gaierror:
        return False


def get_certificate_info(host: str, port: int) -> Dict[str, Any]:
    """Connect via openssl s_client and extract certificate details."""
    connect_str = f"{host}:{port}"
    log_progress(f"Fetching certificate from {connect_str}")

    # Use -servername for SNI
    rc, stdout, stderr = run_openssl(
        ["s_client", "-connect", connect_str, "-servername", host,
         "-showcerts", "-brief"],
        stdin_data="",
        timeout=CONNECT_TIMEOUT,
    )

    cert_info: Dict[str, Any] = {
        "connected": False,
        "subject": "",
        "issuer": "",
        "not_before": "",
        "not_after": "",
        "serial": "",
        "signature_algorithm": "",
        "san": [],
        "chain_depth": 0,
        "chain_issues": [],
        "protocol_negotiated": "",
        "cipher_negotiated": "",
        "raw_brief": "",
        "error": "",
    }

    combined = stdout + "\n" + stderr

    # Check for connection failure
    if "connect:errno=" in combined or "Connection refused" in combined:
        cert_info["error"] = "Connection refused or failed"
        return cert_info

    if "Name or service not known" in combined or "resolve" in combined.lower():
        cert_info["error"] = "DNS resolution failed"
        return cert_info

    if "timed out" in combined.lower():
        cert_info["error"] = f"Connection timed out after {CONNECT_TIMEOUT}s"
        return cert_info

    cert_info["connected"] = True
    cert_info["raw_brief"] = combined[:2000]  # Truncate for safety

    # Parse brief output for protocol and cipher
    for line in combined.splitlines():
        line_stripped = line.strip()
        if line_stripped.startswith("Protocol version:"):
            cert_info["protocol_negotiated"] = line_stripped.split(":", 1)[1].strip()
        elif line_stripped.startswith("Ciphersuite:") or line_stripped.startswith("Cipher:"):
            cert_info["cipher_negotiated"] = line_stripped.split(":", 1)[1].strip()

    # Now get detailed certificate text
    rc2, stdout2, stderr2 = run_openssl(
        ["s_client", "-connect", connect_str, "-servername", host],
        stdin_data="",
        timeout=CONNECT_TIMEOUT,
    )

    full_output = stdout2 + "\n" + stderr2

    # Extract the PEM certificate
    pem_match = re.search(
        r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
        full_output,
        re.DOTALL,
    )

    if pem_match:
        pem_cert = pem_match.group(1)

        # Parse with openssl x509
        rc3, x509_out, x509_err = run_openssl(
            ["x509", "-noout", "-subject", "-issuer", "-dates", "-serial",
             "-ext", "subjectAltName", "-text"],
            stdin_data=pem_cert,
            timeout=CONNECT_TIMEOUT,
        )

        x509_combined = x509_out + "\n" + x509_err

        # Parse subject
        subj_match = re.search(r"subject\s*=\s*(.*)", x509_combined, re.IGNORECASE)
        if subj_match:
            cert_info["subject"] = subj_match.group(1).strip()

        # Parse issuer
        issuer_match = re.search(r"issuer\s*=\s*(.*)", x509_combined, re.IGNORECASE)
        if issuer_match:
            cert_info["issuer"] = issuer_match.group(1).strip()

        # Parse dates
        nb_match = re.search(r"notBefore\s*=\s*(.*)", x509_combined, re.IGNORECASE)
        if nb_match:
            cert_info["not_before"] = nb_match.group(1).strip()

        na_match = re.search(r"notAfter\s*=\s*(.*)", x509_combined, re.IGNORECASE)
        if na_match:
            cert_info["not_after"] = na_match.group(1).strip()

        # Parse serial
        serial_match = re.search(r"serial\s*=\s*(.*)", x509_combined, re.IGNORECASE)
        if serial_match:
            cert_info["serial"] = serial_match.group(1).strip()

        # Parse signature algorithm
        sig_match = re.search(r"Signature Algorithm:\s*(.*)", x509_combined)
        if sig_match:
            cert_info["signature_algorithm"] = sig_match.group(1).strip()

        # Parse SANs
        san_section = re.search(
            r"X509v3 Subject Alternative Name:\s*\n\s*(.*?)(?:\n\s*\n|\n\s*X509v3|\Z)",
            x509_combined,
            re.DOTALL,
        )
        if san_section:
            san_text = san_section.group(1).strip()
            sans = re.findall(r"DNS:([^\s,]+)", san_text)
            ip_sans = re.findall(r"IP Address:([^\s,]+)", san_text)
            cert_info["san"] = sans + ip_sans

    # Count certificate chain depth from the full connection output
    chain_certs = re.findall(r"-----BEGIN CERTIFICATE-----", full_output)
    cert_info["chain_depth"] = len(chain_certs)

    # Check for chain verification errors
    verify_match = re.search(r"Verify return code:\s*(\d+)\s*\(([^)]*)\)", full_output)
    if verify_match:
        verify_code = int(verify_match.group(1))
        verify_msg = verify_match.group(2).strip()
        if verify_code != 0:
            cert_info["chain_issues"].append(f"Verification failed: {verify_msg} (code {verify_code})")

    return cert_info


def parse_cert_date(date_str: str) -> Optional[datetime]:
    """Parse an openssl date string into a datetime object."""
    if not date_str:
        return None

    # openssl outputs dates like: "Jan 15 00:00:00 2025 GMT"
    formats = [
        "%b %d %H:%M:%S %Y %Z",
        "%b  %d %H:%M:%S %Y %Z",
        "%Y-%m-%dT%H:%M:%SZ",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    # Fallback: try to extract with a broader regex
    try:
        # Handle "Month DD HH:MM:SS YYYY GMT" with varying whitespace
        cleaned = re.sub(r'\s+', ' ', date_str.strip())
        return datetime.strptime(cleaned, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def test_protocol_versions(host: str, port: int) -> Dict[str, bool]:
    """Test which TLS/SSL protocol versions are supported."""
    connect_str = f"{host}:{port}"
    results = {}

    for proto_name, proto_flag in PROTOCOL_TESTS:
        log_progress(f"  Testing {proto_name} on {connect_str}")
        rc, stdout, stderr = run_openssl(
            ["s_client", "-connect", connect_str, "-servername", host, proto_flag],
            stdin_data="",
            timeout=CONNECT_TIMEOUT,
        )
        combined = stdout + "\n" + stderr

        # Protocol is supported if we get a successful connection
        # Check for successful handshake indicators
        supported = False
        if rc == 0:
            # Look for positive indicators of a successful handshake
            if "Cipher is " in combined and "Cipher is (NONE)" not in combined:
                supported = True
            elif "Protocol  :" in combined or "Protocol version:" in combined:
                # Verify it's not reporting an error
                if "error" not in combined.lower().split("protocol")[0][-50:]:
                    supported = True

        # Check for explicit failure indicators
        if "no protocols available" in combined.lower():
            supported = False
        if "wrong version number" in combined.lower():
            supported = False
        if "alert protocol version" in combined.lower():
            supported = False
        if "alert handshake failure" in combined.lower():
            supported = False
        if "Connection refused" in combined:
            supported = False
        if "connect:errno=" in combined:
            supported = False

        results[proto_name] = supported

    return results


def test_weak_ciphers(host: str, port: int) -> List[str]:
    """Test for known weak cipher suites."""
    connect_str = f"{host}:{port}"
    weak_found = []

    for cipher_pattern in WEAK_CIPHER_PATTERNS:
        log_progress(f"  Testing cipher pattern: {cipher_pattern} on {connect_str}")
        rc, stdout, stderr = run_openssl(
            ["s_client", "-connect", connect_str, "-servername", host,
             "-cipher", cipher_pattern],
            stdin_data="",
            timeout=CONNECT_TIMEOUT,
        )
        combined = stdout + "\n" + stderr

        # If connection succeeded with this cipher, it's supported
        if rc == 0 and "Cipher is " in combined and "Cipher is (NONE)" not in combined:
            # Extract the actual cipher negotiated
            cipher_match = re.search(r"Cipher\s+(?:is\s+)?:\s*(\S+)", combined)
            if cipher_match:
                actual_cipher = cipher_match.group(1)
                if actual_cipher != "(NONE)" and actual_cipher != "0000":
                    weak_found.append(f"{cipher_pattern}:{actual_cipher}")
            else:
                weak_found.append(cipher_pattern)

    return weak_found


def check_hsts(host: str, port: int) -> Dict[str, Any]:
    """Check for HSTS header using curl."""
    url = f"https://{host}:{port}/" if port != 443 else f"https://{host}/"
    log_progress(f"  Checking HSTS header on {url}")

    rc, stdout, stderr = run_curl(
        ["-sI", "-m", str(CONNECT_TIMEOUT), "--insecure", "-o", "/dev/null",
         "-w", "%{http_code}", "-D", "-", url],
        timeout=CONNECT_TIMEOUT + 5,
    )

    hsts_info: Dict[str, Any] = {
        "present": False,
        "max_age": 0,
        "include_subdomains": False,
        "preload": False,
        "header_value": "",
        "error": "",
    }

    if rc != 0:
        hsts_info["error"] = f"curl failed (code {rc})"
        return hsts_info

    # Look for Strict-Transport-Security header
    hsts_match = re.search(
        r"Strict-Transport-Security:\s*(.*)",
        stdout,
        re.IGNORECASE,
    )

    if hsts_match:
        hsts_info["present"] = True
        header_val = hsts_match.group(1).strip()
        hsts_info["header_value"] = header_val

        # Parse max-age
        max_age_match = re.search(r"max-age=(\d+)", header_val, re.IGNORECASE)
        if max_age_match:
            hsts_info["max_age"] = int(max_age_match.group(1))

        hsts_info["include_subdomains"] = "includesubdomains" in header_val.lower()
        hsts_info["preload"] = "preload" in header_val.lower()
    else:
        hsts_info["present"] = False

    return hsts_info


def audit_target(host: str, port: int) -> Dict[str, Any]:
    """Run the full audit on a single target."""
    target_str = f"{host}:{port}"
    log_progress(f"Starting audit of {target_str}")

    result: Dict[str, Any] = {
        "target": target_str,
        "host": host,
        "port": port,
        "audit_timestamp": datetime.now(timezone.utc).isoformat(),
        "dns_resolves": True,
        "certificate": {},
        "protocols": {},
        "weak_ciphers": [],
        "hsts": {},
        "findings": [],
        "error": "",
    }

    # Step 0: DNS resolution check
    if not check_dns_resolution(host):
        result["dns_resolves"] = False
        result["error"] = f"DNS resolution failed for {host}"
        result["findings"].append({
            "severity": "CRITICAL",
            "title": f"DNS resolution failed for {host}",
            "evidence": f"Socket getaddrinfo() failed for hostname {host}",
            "recommendation": "Verify the domain name is correct and DNS is properly configured.",
        })
        log_warning(f"DNS resolution failed for {host}")
        return result

    # Step 1: Get certificate info
    cert_info = get_certificate_info(host, port)
    result["certificate"] = cert_info

    if not cert_info["connected"]:
        result["error"] = cert_info.get("error", "Failed to connect")
        result["findings"].append({
            "severity": "CRITICAL",
            "title": f"Cannot establish SSL/TLS connection to {target_str}",
            "evidence": cert_info.get("error", "Connection failed"),
            "recommendation": "Verify the server is running, accepts TLS connections on this port, and is not blocked by a firewall.",
        })
        log_warning(f"Could not connect to {target_str}: {cert_info.get('error', 'unknown')}")
        return result

    # Step 2: Check certificate expiry
    now = datetime.now(timezone.utc)
    not_after = parse_cert_date(cert_info["not_after"])
    not_before = parse_cert_date(cert_info["not_before"])

    if not_after:
        days_remaining = (not_after - now).days
        cert_info["days_until_expiry"] = days_remaining

        if days_remaining < 0:
            result["findings"].append({
                "severity": "CRITICAL",
                "title": f"Certificate EXPIRED on {target_str}",
                "evidence": f"Certificate notAfter={cert_info['not_after']}, expired {abs(days_remaining)} days ago",
                "recommendation": "Renew the certificate immediately. Expired certificates cause browser warnings and break trust.",
            })
        elif days_remaining < 7:
            result["findings"].append({
                "severity": "HIGH",
                "title": f"Certificate expiring within 7 days on {target_str}",
                "evidence": f"Certificate notAfter={cert_info['not_after']}, {days_remaining} days remaining",
                "recommendation": "Renew the certificate urgently. Consider automated renewal with tools like certbot.",
            })
        elif days_remaining < 30:
            result["findings"].append({
                "severity": "MEDIUM",
                "title": f"Certificate expiring within 30 days on {target_str}",
                "evidence": f"Certificate notAfter={cert_info['not_after']}, {days_remaining} days remaining",
                "recommendation": "Plan certificate renewal soon. Consider automated renewal with tools like certbot.",
            })
    else:
        if cert_info["not_after"]:
            log_warning(f"Could not parse certificate expiry date: {cert_info['not_after']}")

    if not_before and not_before > now:
        result["findings"].append({
            "severity": "CRITICAL",
            "title": f"Certificate not yet valid on {target_str}",
            "evidence": f"Certificate notBefore={cert_info['not_before']}, not valid for another {(not_before - now).days} days",
            "recommendation": "Check server clock synchronization or wait until the certificate's validity period begins.",
        })

    # Step 3: Check certificate chain
    if cert_info["chain_issues"]:
        for issue in cert_info["chain_issues"]:
            result["findings"].append({
                "severity": "HIGH",
                "title": f"Certificate chain issue on {target_str}",
                "evidence": issue,
                "recommendation": "Verify the full certificate chain is correctly installed, including intermediate certificates.",
            })

    # Step 4: Test protocol versions
    log_progress(f"Testing protocol versions on {target_str}")
    protocols = test_protocol_versions(host, port)
    result["protocols"] = protocols

    for proto_name, supported in protocols.items():
        if supported and proto_name in DEPRECATED_PROTOCOLS:
            if proto_name == "SSLv3":
                severity = "CRITICAL"
            else:
                severity = "HIGH"
            result["findings"].append({
                "severity": severity,
                "title": f"Deprecated protocol {proto_name} supported on {target_str}",
                "evidence": f"openssl s_client successfully connected using {proto_name}",
                "recommendation": f"Disable {proto_name} on the server. Only TLSv1.2 and TLSv1.3 should be enabled.",
            })

    if not protocols.get("TLSv1.2") and not protocols.get("TLSv1.3"):
        result["findings"].append({
            "severity": "HIGH",
            "title": f"No modern TLS protocol supported on {target_str}",
            "evidence": "Neither TLSv1.2 nor TLSv1.3 was successfully negotiated",
            "recommendation": "Enable TLSv1.2 and/or TLSv1.3 on the server.",
        })

    # Step 5: Test weak ciphers
    log_progress(f"Testing weak ciphers on {target_str}")
    weak_ciphers = test_weak_ciphers(host, port)
    result["weak_ciphers"] = weak_ciphers

    if weak_ciphers:
        result["findings"].append({
            "severity": "MEDIUM",
            "title": f"Weak cipher suites supported on {target_str}",
            "evidence": f"The following weak ciphers were accepted: {', '.join(weak_ciphers)}",
            "recommendation": "Disable weak cipher suites (RC4, DES, NULL, EXPORT, anonymous, MD5) in the server configuration.",
        })

    # Step 6: Check HSTS
    log_progress(f"Checking HSTS on {target_str}")
    hsts = check_hsts(host, port)
    result["hsts"] = hsts

    if not hsts.get("error"):
        if not hsts["present"]:
            result["findings"].append({
                "severity": "HIGH",
                "title": f"HSTS header missing on {target_str}",
                "evidence": "No Strict-Transport-Security header found in HTTP response",
                "recommendation": "Add the Strict-Transport-Security header. Recommended: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'",
            })
        else:
            if hsts["max_age"] < 15768000:  # Less than 6 months
                result["findings"].append({
                    "severity": "LOW",
                    "title": f"HSTS max-age is short on {target_str}",
                    "evidence": f"HSTS max-age={hsts['max_age']} seconds ({hsts['max_age'] // 86400} days). Recommended minimum is 6 months (15768000s).",
                    "recommendation": "Increase HSTS max-age to at least 15768000 (6 months), ideally 31536000 (1 year).",
                })

    # Step 7: Self-signed certificate check
    if cert_info["subject"] and cert_info["issuer"]:
        # Rough heuristic: if subject CN equals issuer CN, likely self-signed
        subj_cn = re.search(r"CN\s*=\s*([^,/]+)", cert_info["subject"])
        issuer_cn = re.search(r"CN\s*=\s*([^,/]+)", cert_info["issuer"])
        if subj_cn and issuer_cn:
            if subj_cn.group(1).strip() == issuer_cn.group(1).strip() and cert_info["chain_depth"] <= 1:
                result["findings"].append({
                    "severity": "HIGH",
                    "title": f"Potentially self-signed certificate on {target_str}",
                    "evidence": f"Subject CN ({subj_cn.group(1).strip()}) matches Issuer CN ({issuer_cn.group(1).strip()}) with chain depth {cert_info['chain_depth']}",
                    "recommendation": "Use a certificate from a trusted Certificate Authority (e.g., Let's Encrypt).",
                })

    # Step 8: Signature algorithm check
    if cert_info["signature_algorithm"]:
        sig_alg = cert_info["signature_algorithm"].lower()
        if "sha1" in sig_alg or "md5" in sig_alg:
            result["findings"].append({
                "severity": "MEDIUM",
                "title": f"Weak signature algorithm on {target_str}",
                "evidence": f"Certificate uses {cert_info['signature_algorithm']}",
                "recommendation": "Reissue the certificate with SHA-256 or stronger signature algorithm.",
            })

    # Always add INFO finding with certificate details
    info_parts = []
    if cert_info["subject"]:
        info_parts.append(f"Subject: {cert_info['subject']}")
    if cert_info["issuer"]:
        info_parts.append(f"Issuer: {cert_info['issuer']}")
    if cert_info["not_before"]:
        info_parts.append(f"Valid from: {cert_info['not_before']}")
    if cert_info["not_after"]:
        info_parts.append(f"Valid until: {cert_info['not_after']}")
        if not_after:
            info_parts.append(f"Days remaining: {(not_after - now).days}")
    if cert_info["san"]:
        info_parts.append(f"SANs: {', '.join(cert_info['san'][:10])}")
    if cert_info["signature_algorithm"]:
        info_parts.append(f"Signature: {cert_info['signature_algorithm']}")
    proto_supported = [p for p, s in protocols.items() if s]
    if proto_supported:
        info_parts.append(f"Protocols: {', '.join(proto_supported)}")
    if cert_info["cipher_negotiated"]:
        info_parts.append(f"Negotiated cipher: {cert_info['cipher_negotiated']}")

    result["findings"].append({
        "severity": "INFO",
        "title": f"Certificate details for {target_str}",
        "evidence": "; ".join(info_parts) if info_parts else "No certificate details available",
        "recommendation": "No action required.",
    })

    log_progress(f"Audit of {target_str} complete — {len(result['findings'])} findings")
    return result


def assign_finding_ids(all_results: List[Dict[str, Any]]) -> None:
    """Assign sequential F-NNN IDs to all findings across all targets."""
    counter = 0
    for result in all_results:
        for finding in result.get("findings", []):
            counter += 1
            finding["finding_id"] = f"F-{counter:03d}"


def build_summary(all_results: List[Dict[str, Any]], audit_id: str) -> str:
    """Build a human-readable summary (~500 tokens) of the audit."""
    lines = []
    lines.append(f"SSL/TLS AUDIT SUMMARY — ID: {audit_id}")
    lines.append(f"Targets: {len(all_results)} | Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append("")

    # Aggregate severity counts
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    all_findings = []
    for r in all_results:
        for f in r.get("findings", []):
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            all_findings.append(f)

    lines.append(f"SEVERITY BREAKDOWN: {severity_counts['CRITICAL']} critical, "
                 f"{severity_counts['HIGH']} high, {severity_counts['MEDIUM']} medium, "
                 f"{severity_counts['LOW']} low, {severity_counts['INFO']} info")
    lines.append("")

    # Per-target summary
    for r in all_results:
        target = r.get("target", "unknown")
        lines.append(f"--- {target} ---")

        if r.get("error"):
            lines.append(f"  ERROR: {r['error']}")
            lines.append("")
            continue

        cert = r.get("certificate", {})
        if cert.get("subject"):
            lines.append(f"  Subject: {cert['subject']}")
        if cert.get("issuer"):
            lines.append(f"  Issuer: {cert['issuer']}")
        if cert.get("not_after"):
            days = cert.get("days_until_expiry", "?")
            lines.append(f"  Expires: {cert['not_after']} ({days} days remaining)")

        protocols = r.get("protocols", {})
        supported = [p for p, s in protocols.items() if s]
        if supported:
            lines.append(f"  Protocols: {', '.join(supported)}")

        hsts = r.get("hsts", {})
        if hsts.get("present"):
            lines.append(f"  HSTS: present (max-age={hsts.get('max_age', '?')})")
        elif not hsts.get("error"):
            lines.append("  HSTS: MISSING")

        lines.append("")

    # Findings sorted by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(all_findings, key=lambda f: sev_order.get(f.get("severity", "INFO"), 5))

    actionable = [f for f in sorted_findings if f.get("severity") != "INFO"]
    if actionable:
        lines.append("FINDINGS:")
        for f in actionable:
            fid = f.get("finding_id", "F-???")
            lines.append(f"  [{f['severity']}] {fid}: {f['title']}")
            lines.append(f"    Evidence: {f['evidence']}")
            lines.append(f"    Action: {f['recommendation']}")
        lines.append("")

    info_findings = [f for f in sorted_findings if f.get("severity") == "INFO"]
    if info_findings:
        lines.append("INFO:")
        for f in info_findings:
            fid = f.get("finding_id", "F-???")
            lines.append(f"  [{fid}] {f['title']}")
            lines.append(f"    {f['evidence']}")
        lines.append("")

    # Overall assessment
    if severity_counts["CRITICAL"] > 0:
        posture = "CRITICAL — Immediate action required. Expired certificates or critical protocol issues detected."
    elif severity_counts["HIGH"] > 0:
        posture = "POOR — Significant issues found that should be addressed promptly."
    elif severity_counts["MEDIUM"] > 0:
        posture = "FAIR — Some issues found that should be reviewed and addressed."
    elif severity_counts["LOW"] > 0:
        posture = "GOOD — Minor improvements recommended."
    else:
        posture = "STRONG — No significant issues detected."

    lines.append(f"OVERALL POSTURE: {posture}")

    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(
        description="SSL/TLS certificate auditor: openssl probes -> structured JSON"
    )
    parser.add_argument(
        "--targets", required=True,
        help="Comma-separated list of domains/IPs to audit (max 5). Port defaults to 443."
    )
    parser.add_argument(
        "--output", required=True,
        help="Directory to write audit artifacts"
    )
    args = parser.parse_args()

    # Parse and validate targets
    targets = parse_targets(args.targets)

    log_progress(f"SSL/TLS audit starting for {len(targets)} target(s)")
    for t in targets:
        log_progress(f"  Target: {t}")

    # Prepare output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    audit_id = str(uuid.uuid4())[:8]
    audit_start = datetime.now(timezone.utc).isoformat()

    # Audit each target
    all_results: List[Dict[str, Any]] = []
    for target_str in targets:
        host, port_str = target_str.rsplit(":", 1)
        port = int(port_str)
        result = audit_target(host, port)
        all_results.append(result)

    # Assign finding IDs across all results
    assign_finding_ids(all_results)

    audit_end = datetime.now(timezone.utc).isoformat()

    # Build full audit output
    audit_output = {
        "audit_id": audit_id,
        "audit_start": audit_start,
        "audit_end": audit_end,
        "target_count": len(all_results),
        "targets": all_results,
    }

    # Write JSON results
    json_path = output_dir / "audit-results.json"
    json_path.write_text(json.dumps(audit_output, indent=2))

    # Write human-readable summary
    summary_text = build_summary(all_results, audit_id)
    summary_path = output_dir / "audit-summary.txt"
    summary_path.write_text(summary_text)

    # Print completion info
    total_findings = sum(len(r.get("findings", [])) for r in all_results)
    print(f"\n[*] Audit complete:")
    print(f"    Targets: {len(all_results)}")
    print(f"    Findings: {total_findings}")
    print(f"    Results: {json_path}")
    print(f"    Summary: {summary_path}")

    # Print summary to stdout so LLM can see it directly
    print(f"\n{'='*60}")
    print(summary_text)
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
