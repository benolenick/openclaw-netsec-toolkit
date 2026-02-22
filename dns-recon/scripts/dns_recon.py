#!/usr/bin/env python3
"""
DNS Reconnaissance & Security Auditor
OpenClaw Skill — dns-recon

Performs passive DNS reconnaissance using dig, whois, and host.
Enumerates records, checks email security (SPF/DKIM/DMARC), detects
zone transfer vulnerabilities, DNSSEC status, open resolvers, and
common subdomain presence.

Safety: Standard DNS queries only. No brute-force. Max 3 domains.
        0.5s delay between queries. Zone transfers only against
        authoritative nameservers.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_DOMAINS = 3
QUERY_DELAY = 0.5  # seconds between queries
QUERY_TIMEOUT = 5  # seconds per subprocess call

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "remote", "blog", "shop",
    "api", "dev", "staging", "test", "admin", "vpn", "cdn",
    "ns1", "ns2", "mx",
]

DKIM_SELECTORS = [
    "default._domainkey",
    "google._domainkey",
    "selector1._domainkey",
    "selector2._domainkey",
]

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]

# An unrelated domain used to test if a nameserver is an open resolver.
OPEN_RESOLVER_TEST_DOMAIN = "example.com"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def info(msg):
    print(f"[*] {msg}", flush=True)


def warn(msg):
    print(f"WARNING: {msg}", file=sys.stderr, flush=True)


def error(msg):
    print(f"ERROR: {msg}", file=sys.stderr, flush=True)


def abort(msg):
    print(f"ABORT: {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def run_cmd(cmd, timeout=QUERY_TIMEOUT):
    """Run a shell command and return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as exc:
        return -1, "", str(exc)


def delay():
    """Rate-limiting pause between queries."""
    time.sleep(QUERY_DELAY)


def check_tool(name):
    """Return True if *name* is on PATH."""
    rc, _, _ = run_cmd(["which", name])
    return rc == 0


# ---------------------------------------------------------------------------
# DNS query wrappers
# ---------------------------------------------------------------------------


def dig_query(domain, rtype, server=None):
    """Run dig and return raw output text."""
    cmd = ["dig", "+noall", "+answer", "+authority", "+time=5", "+tries=1", domain, rtype]
    if server:
        cmd.insert(1, f"@{server}")
    delay()
    rc, stdout, stderr = run_cmd(cmd)
    return stdout.strip(), stderr.strip(), rc


def dig_query_full(domain, rtype, server=None):
    """Run dig with full output (for raw log)."""
    cmd = ["dig", "+time=5", "+tries=1", domain, rtype]
    if server:
        cmd.insert(1, f"@{server}")
    delay()
    rc, stdout, stderr = run_cmd(cmd)
    return stdout.strip(), stderr.strip(), rc


def dig_axfr(domain, server):
    """Attempt an AXFR zone transfer against *server* for *domain*."""
    cmd = ["dig", f"@{server}", domain, "AXFR", "+time=5", "+tries=1"]
    delay()
    rc, stdout, stderr = run_cmd(cmd, timeout=10)
    return stdout.strip(), stderr.strip(), rc


def whois_query(domain):
    """Run whois and return raw output."""
    delay()
    rc, stdout, stderr = run_cmd(["whois", domain], timeout=15)
    return stdout.strip(), stderr.strip(), rc


def host_reverse(ip):
    """Run host for reverse lookup."""
    delay()
    rc, stdout, stderr = run_cmd(["host", ip])
    return stdout.strip(), stderr.strip(), rc


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def parse_dig_answer(raw, rtype=None):
    """Return a list of answer values from dig +noall +answer output."""
    results = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split()
        if len(parts) >= 5:
            rec_type = parts[3]
            value = " ".join(parts[4:])
            if rtype is None or rec_type == rtype:
                results.append({"type": rec_type, "ttl": parts[1], "value": value})
    return results


def parse_whois(raw):
    """Extract key WHOIS fields from raw output."""
    fields = {
        "registrar": None,
        "creation_date": None,
        "expiry_date": None,
        "updated_date": None,
        "registrant": None,
        "privacy": False,
        "raw_snippet": "",
    }

    patterns = {
        "registrar": [
            r"(?i)registrar\s*:\s*(.+)",
            r"(?i)registrar name\s*:\s*(.+)",
            r"(?i)sponsoring registrar\s*:\s*(.+)",
        ],
        "creation_date": [
            r"(?i)creation date\s*:\s*(.+)",
            r"(?i)created\s*:\s*(.+)",
            r"(?i)registered on\s*:\s*(.+)",
            r"(?i)registration date\s*:\s*(.+)",
        ],
        "expiry_date": [
            r"(?i)expir(?:y|ation) date\s*:\s*(.+)",
            r"(?i)registry expiry date\s*:\s*(.+)",
            r"(?i)paid-till\s*:\s*(.+)",
            r"(?i)expires on\s*:\s*(.+)",
        ],
        "updated_date": [
            r"(?i)updated date\s*:\s*(.+)",
            r"(?i)last updated\s*:\s*(.+)",
            r"(?i)last modified\s*:\s*(.+)",
        ],
        "registrant": [
            r"(?i)registrant\s*:\s*(.+)",
            r"(?i)registrant name\s*:\s*(.+)",
            r"(?i)registrant organi[sz]ation\s*:\s*(.+)",
        ],
    }

    for field, pats in patterns.items():
        for pat in pats:
            m = re.search(pat, raw)
            if m:
                fields[field] = m.group(1).strip()
                break

    # Detect privacy/redaction
    privacy_indicators = [
        "redact", "privacy", "whoisguard", "domains by proxy",
        "contact privacy", "data protected", "withheld for privacy",
        "not disclosed", "gdpr masked",
    ]
    lower_raw = raw.lower()
    for indicator in privacy_indicators:
        if indicator in lower_raw:
            fields["privacy"] = True
            break

    # Keep first 40 lines as snippet
    snippet_lines = raw.splitlines()[:40]
    fields["raw_snippet"] = "\n".join(snippet_lines)

    return fields


def is_nxdomain(dig_stderr, dig_stdout):
    """Check if a dig result indicates NXDOMAIN."""
    combined = (dig_stdout + "\n" + dig_stderr).lower()
    return "nxdomain" in combined or "status: nxdomain" in combined


# ---------------------------------------------------------------------------
# Per-domain reconnaissance
# ---------------------------------------------------------------------------


def recon_domain(domain, raw_log):
    """Run full recon on a single domain. Return a result dict."""
    info(f"Starting reconnaissance on: {domain}")
    result = {
        "domain": domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "records": {},
        "subdomains": {},
        "whois": {},
        "email_security": {"spf": None, "dkim": {}, "dmarc": None},
        "zone_transfer": {},
        "dnssec": {"dnskey": [], "ds": []},
        "open_resolvers": {},
        "caa": [],
        "reverse_lookups": {},
        "findings": [],
        "nxdomain": False,
    }

    raw_log.append(f"\n{'='*72}")
    raw_log.append(f"  DOMAIN: {domain}")
    raw_log.append(f"  TIME:   {result['timestamp']}")
    raw_log.append(f"{'='*72}\n")

    # ------------------------------------------------------------------
    # 0. Quick existence check
    # ------------------------------------------------------------------
    info(f"  Checking if {domain} exists ...")
    soa_raw, soa_err, soa_rc = dig_query_full(domain, "SOA")
    raw_log.append(f"--- dig {domain} SOA ---\n{soa_raw}\n")
    if is_nxdomain(soa_err, soa_raw):
        warn(f"Domain {domain} returned NXDOMAIN — does not exist.")
        result["nxdomain"] = True
        result["findings"].append({
            "severity": "INFO",
            "title": "Domain does not exist (NXDOMAIN)",
            "detail": f"The domain {domain} returned NXDOMAIN. No further checks possible.",
        })
        return result

    # ------------------------------------------------------------------
    # 1. Standard record enumeration
    # ------------------------------------------------------------------
    info(f"  Querying standard DNS records ...")
    for rtype in RECORD_TYPES:
        raw, stderr, rc = dig_query(domain, rtype)
        full_raw, _, _ = dig_query_full(domain, rtype)
        raw_log.append(f"--- dig {domain} {rtype} ---\n{full_raw}\n")
        parsed = parse_dig_answer(raw, rtype)
        result["records"][rtype] = parsed

    # ------------------------------------------------------------------
    # 2. CAA records
    # ------------------------------------------------------------------
    info(f"  Checking CAA records ...")
    caa_raw, _, _ = dig_query(domain, "CAA")
    caa_full, _, _ = dig_query_full(domain, "CAA")
    raw_log.append(f"--- dig {domain} CAA ---\n{caa_full}\n")
    result["caa"] = parse_dig_answer(caa_raw, "CAA")

    # ------------------------------------------------------------------
    # 3. WHOIS
    # ------------------------------------------------------------------
    info(f"  Running WHOIS lookup ...")
    whois_raw, whois_err, whois_rc = whois_query(domain)
    raw_log.append(f"--- whois {domain} ---\n{whois_raw}\n")
    if whois_rc == 0 and whois_raw:
        result["whois"] = parse_whois(whois_raw)
    else:
        result["whois"] = {"error": whois_err or "WHOIS lookup failed"}

    # ------------------------------------------------------------------
    # 4. Reverse lookups on A records
    # ------------------------------------------------------------------
    a_records = result["records"].get("A", [])
    if a_records:
        info(f"  Performing reverse lookups on {len(a_records)} IP(s) ...")
    for rec in a_records:
        ip = rec["value"]
        rev_raw, _, _ = host_reverse(ip)
        raw_log.append(f"--- host {ip} ---\n{rev_raw}\n")
        result["reverse_lookups"][ip] = rev_raw

    # ------------------------------------------------------------------
    # 5. Common subdomain lookups
    # ------------------------------------------------------------------
    info(f"  Checking {len(COMMON_SUBDOMAINS)} common subdomains ...")
    for sub in COMMON_SUBDOMAINS:
        fqdn = f"{sub}.{domain}"
        raw, stderr, rc = dig_query(fqdn, "A")
        parsed = parse_dig_answer(raw, "A")
        if parsed:
            result["subdomains"][sub] = [r["value"] for r in parsed]
            info(f"    Found: {fqdn} -> {', '.join(result['subdomains'][sub])}")
        # Also log CNAME if present
        cname_parsed = parse_dig_answer(raw, "CNAME")
        if cname_parsed:
            result["subdomains"][sub] = [r["value"] for r in cname_parsed]
            info(f"    Found: {fqdn} -> CNAME {', '.join(result['subdomains'][sub])}")

    # ------------------------------------------------------------------
    # 6. Zone transfer attempts (AXFR on authoritative NSes)
    # ------------------------------------------------------------------
    ns_records = result["records"].get("NS", [])
    ns_names = [r["value"].rstrip(".") for r in ns_records]
    if ns_names:
        info(f"  Testing zone transfer on {len(ns_names)} nameserver(s) ...")
    for ns in ns_names:
        info(f"    AXFR {domain} @{ns} ...")
        axfr_raw, axfr_err, axfr_rc = dig_axfr(domain, ns)
        raw_log.append(f"--- dig @{ns} {domain} AXFR ---\n{axfr_raw}\n")
        # A successful AXFR typically returns multiple records (more than
        # just the SOA bookend lines). A refused transfer contains
        # "Transfer failed" or "; Transfer size" of 0 or very few lines.
        axfr_lines = [l for l in axfr_raw.splitlines()
                       if l.strip() and not l.strip().startswith(";")]
        allowed = len(axfr_lines) > 2
        result["zone_transfer"][ns] = {
            "allowed": allowed,
            "record_count": len(axfr_lines),
            "snippet": "\n".join(axfr_raw.splitlines()[:20]),
        }
        if allowed:
            info(f"    *** ZONE TRANSFER ALLOWED on {ns}! ***")

    # ------------------------------------------------------------------
    # 7. Email security checks
    # ------------------------------------------------------------------
    info(f"  Checking email security (SPF/DKIM/DMARC) ...")

    # SPF — look through TXT records
    txt_records = result["records"].get("TXT", [])
    spf_records = [r for r in txt_records if "v=spf1" in r["value"].lower()]
    if spf_records:
        spf_value = spf_records[0]["value"]
        result["email_security"]["spf"] = {
            "found": True,
            "record": spf_value,
            "has_plus_all": "+all" in spf_value.lower(),
            "has_minus_all": "-all" in spf_value.lower(),
            "has_tilde_all": "~all" in spf_value.lower(),
        }
    else:
        result["email_security"]["spf"] = {"found": False, "record": None}

    # DKIM — check common selectors
    for selector in DKIM_SELECTORS:
        fqdn = f"{selector}.{domain}"
        dkim_raw, _, _ = dig_query(fqdn, "TXT")
        dkim_full, _, _ = dig_query_full(fqdn, "TXT")
        raw_log.append(f"--- dig {fqdn} TXT ---\n{dkim_full}\n")
        parsed = parse_dig_answer(dkim_raw, "TXT")
        if parsed:
            result["email_security"]["dkim"][selector] = parsed[0]["value"]
            info(f"    DKIM found: {selector}")

    # DMARC
    dmarc_fqdn = f"_dmarc.{domain}"
    dmarc_raw, _, _ = dig_query(dmarc_fqdn, "TXT")
    dmarc_full, _, _ = dig_query_full(dmarc_fqdn, "TXT")
    raw_log.append(f"--- dig {dmarc_fqdn} TXT ---\n{dmarc_full}\n")
    dmarc_parsed = parse_dig_answer(dmarc_raw, "TXT")
    dmarc_txt = [r for r in dmarc_parsed if "v=dmarc1" in r["value"].lower()]
    if dmarc_txt:
        dmarc_value = dmarc_txt[0]["value"]
        # Extract policy
        policy_match = re.search(r"p\s*=\s*(\w+)", dmarc_value, re.IGNORECASE)
        policy = policy_match.group(1).lower() if policy_match else "unknown"
        result["email_security"]["dmarc"] = {
            "found": True,
            "record": dmarc_value,
            "policy": policy,
        }
    else:
        result["email_security"]["dmarc"] = {"found": False, "record": None, "policy": None}

    # ------------------------------------------------------------------
    # 8. DNSSEC
    # ------------------------------------------------------------------
    info(f"  Checking DNSSEC ...")
    for dtype in ("DNSKEY", "DS"):
        dsec_raw, _, _ = dig_query(domain, dtype)
        dsec_full, _, _ = dig_query_full(domain, dtype)
        raw_log.append(f"--- dig {domain} {dtype} ---\n{dsec_full}\n")
        result["dnssec"][dtype.lower()] = parse_dig_answer(dsec_raw, dtype)

    # ------------------------------------------------------------------
    # 9. Open resolver check on authoritative NSes
    # ------------------------------------------------------------------
    if ns_names:
        info(f"  Checking for open resolvers ...")
    for ns in ns_names:
        # Try to resolve an unrelated domain through this NS
        or_raw, or_err, or_rc = dig_query(OPEN_RESOLVER_TEST_DOMAIN, "A", server=ns)
        raw_log.append(f"--- dig @{ns} {OPEN_RESOLVER_TEST_DOMAIN} A (open resolver test) ---\n{or_raw}\n")
        a_answers = parse_dig_answer(or_raw, "A")
        # If we get A records for the unrelated domain, it's an open resolver
        is_open = len(a_answers) > 0
        result["open_resolvers"][ns] = is_open
        if is_open:
            info(f"    *** OPEN RESOLVER: {ns} ***")

    # ------------------------------------------------------------------
    # 10. Generate findings
    # ------------------------------------------------------------------
    info(f"  Generating findings ...")
    generate_findings(result)

    return result


# ---------------------------------------------------------------------------
# Findings generation
# ---------------------------------------------------------------------------


def generate_findings(result):
    """Populate result['findings'] based on collected data."""
    findings = result["findings"]
    domain = result["domain"]

    if result["nxdomain"]:
        return  # Already has the NXDOMAIN info finding

    # --- CRITICAL ---

    # Zone transfer allowed
    for ns, zt in result.get("zone_transfer", {}).items():
        if zt["allowed"]:
            findings.append({
                "severity": "CRITICAL",
                "title": f"Zone transfer (AXFR) allowed on {ns}",
                "detail": (
                    f"Nameserver {ns} allows zone transfer for {domain}. "
                    f"Returned {zt['record_count']} records. An attacker can "
                    f"enumerate all DNS records for the domain."
                ),
            })

    # Open resolvers
    for ns, is_open in result.get("open_resolvers", {}).items():
        if is_open:
            findings.append({
                "severity": "CRITICAL",
                "title": f"Open resolver detected: {ns}",
                "detail": (
                    f"Authoritative nameserver {ns} resolves queries for "
                    f"unrelated domains. This can be exploited for DNS "
                    f"amplification attacks."
                ),
            })

    # --- HIGH ---

    # No SPF
    spf = result["email_security"].get("spf", {})
    if not spf.get("found"):
        findings.append({
            "severity": "HIGH",
            "title": "No SPF record found",
            "detail": (
                f"Domain {domain} has no SPF (Sender Policy Framework) TXT record. "
                f"This allows anyone to send email appearing to come from this domain."
            ),
        })

    # No DMARC
    dmarc = result["email_security"].get("dmarc", {})
    if not dmarc.get("found"):
        findings.append({
            "severity": "HIGH",
            "title": "No DMARC record found",
            "detail": (
                f"Domain {domain} has no DMARC record at _dmarc.{domain}. "
                f"Without DMARC, email receivers cannot enforce SPF/DKIM alignment "
                f"and the domain is vulnerable to spoofing."
            ),
        })

    # DMARC policy is "none"
    if dmarc.get("found") and dmarc.get("policy") == "none":
        findings.append({
            "severity": "HIGH",
            "title": "DMARC policy is 'none' (monitoring only)",
            "detail": (
                f"The DMARC record for {domain} has p=none, which means "
                f"no enforcement. Spoofed emails will still be delivered. "
                f"Consider upgrading to p=quarantine or p=reject."
            ),
        })

    # --- MEDIUM ---

    # No DKIM
    dkim = result["email_security"].get("dkim", {})
    if not dkim:
        findings.append({
            "severity": "MEDIUM",
            "title": "No DKIM records found for common selectors",
            "detail": (
                f"No DKIM TXT records were found for the checked selectors "
                f"({', '.join(DKIM_SELECTORS)}). Note: the domain may use "
                f"custom selectors not checked by this tool."
            ),
        })

    # No DNSSEC
    has_dnskey = bool(result["dnssec"].get("dnskey"))
    has_ds = bool(result["dnssec"].get("ds"))
    if not has_dnskey and not has_ds:
        findings.append({
            "severity": "MEDIUM",
            "title": "DNSSEC not deployed",
            "detail": (
                f"No DNSKEY or DS records found for {domain}. Without DNSSEC, "
                f"DNS responses can be spoofed via cache poisoning attacks."
            ),
        })

    # No CAA
    if not result.get("caa"):
        findings.append({
            "severity": "MEDIUM",
            "title": "No CAA records found",
            "detail": (
                f"Domain {domain} has no CAA (Certificate Authority Authorization) "
                f"records. Any CA can issue certificates for this domain. "
                f"CAA records restrict which CAs are permitted."
            ),
        })

    # SPF with +all
    if spf.get("found") and spf.get("has_plus_all"):
        findings.append({
            "severity": "MEDIUM",
            "title": "SPF record uses +all (pass all)",
            "detail": (
                f"The SPF record for {domain} contains '+all', which means "
                f"every server is authorized to send email for this domain. "
                f"This effectively disables SPF protection."
            ),
        })

    # --- LOW ---

    # No AAAA records
    if not result["records"].get("AAAA"):
        findings.append({
            "severity": "LOW",
            "title": "No AAAA (IPv6) records found",
            "detail": (
                f"Domain {domain} has no IPv6 (AAAA) records. While not a "
                f"security issue, IPv6 readiness is a modern best practice."
            ),
        })

    # WHOIS privacy not enabled
    whois_data = result.get("whois", {})
    if isinstance(whois_data, dict) and not whois_data.get("privacy") and not whois_data.get("error"):
        findings.append({
            "severity": "LOW",
            "title": "WHOIS privacy may not be enabled",
            "detail": (
                f"WHOIS data for {domain} does not appear to use privacy "
                f"protection. Registrant details may be publicly visible."
            ),
        })

    # Short TTLs (check A records)
    for rec in result["records"].get("A", []):
        try:
            ttl = int(rec["ttl"])
            if ttl < 300:
                findings.append({
                    "severity": "LOW",
                    "title": f"Short TTL on A record ({ttl}s)",
                    "detail": (
                        f"A record for {domain} has a TTL of {ttl} seconds. "
                        f"Very short TTLs may indicate fast-flux DNS or simply "
                        f"a CDN configuration."
                    ),
                })
                break  # Only report once
        except ValueError:
            pass

    # --- INFO ---

    # General summary
    record_summary_parts = []
    for rtype in RECORD_TYPES + ["CAA"]:
        recs = result["records"].get(rtype, [])
        if rtype == "CAA":
            recs = result.get("caa", [])
        if recs:
            record_summary_parts.append(f"{rtype}:{len(recs)}")
    findings.append({
        "severity": "INFO",
        "title": "DNS configuration summary",
        "detail": (
            f"Records found for {domain}: {', '.join(record_summary_parts) if record_summary_parts else 'none'}. "
            f"Subdomains discovered: {len(result.get('subdomains', {}))}. "
            f"Nameservers: {', '.join(ns['value'].rstrip('.') for ns in result['records'].get('NS', []))}."
        ),
    })

    # Nameserver locations (just list them)
    if result["records"].get("NS"):
        ns_list = [r["value"].rstrip(".") for r in result["records"]["NS"]]
        findings.append({
            "severity": "INFO",
            "title": "Authoritative nameservers",
            "detail": f"Nameservers for {domain}: {', '.join(ns_list)}",
        })


# ---------------------------------------------------------------------------
# Output generation
# ---------------------------------------------------------------------------


def write_outputs(all_results, output_dir, raw_log):
    """Write the three output files."""

    # --- recon-results.json ---
    json_path = os.path.join(output_dir, "recon-results.json")
    with open(json_path, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    info(f"JSON results written to {json_path}")

    # --- raw-records.txt ---
    raw_path = os.path.join(output_dir, "raw-records.txt")
    with open(raw_path, "w") as f:
        f.write("\n".join(raw_log))
    info(f"Raw records written to {raw_path}")

    # --- recon-summary.txt ---
    summary_path = os.path.join(output_dir, "recon-summary.txt")
    lines = []
    lines.append("=" * 72)
    lines.append("  DNS RECONNAISSANCE SUMMARY")
    lines.append(f"  Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("=" * 72)

    for res in all_results:
        domain = res["domain"]
        lines.append("")
        lines.append("-" * 72)
        lines.append(f"  DOMAIN: {domain}")
        lines.append("-" * 72)

        if res.get("nxdomain"):
            lines.append("  *** DOMAIN DOES NOT EXIST (NXDOMAIN) ***")
            lines.append("")
            continue

        # Records overview
        lines.append("")
        lines.append("  DNS RECORDS:")
        for rtype in RECORD_TYPES:
            recs = res["records"].get(rtype, [])
            if recs:
                for r in recs:
                    lines.append(f"    {rtype:6s}  {r['value']}  (TTL: {r['ttl']})")
            else:
                lines.append(f"    {rtype:6s}  (none)")

        # CAA
        caa = res.get("caa", [])
        if caa:
            for r in caa:
                lines.append(f"    CAA     {r['value']}  (TTL: {r['ttl']})")
        else:
            lines.append(f"    CAA     (none)")

        # Subdomains
        subs = res.get("subdomains", {})
        if subs:
            lines.append("")
            lines.append("  DISCOVERED SUBDOMAINS:")
            for sub, ips in sorted(subs.items()):
                lines.append(f"    {sub}.{domain}  ->  {', '.join(ips)}")
        else:
            lines.append("")
            lines.append("  DISCOVERED SUBDOMAINS: (none)")

        # Email Security
        lines.append("")
        lines.append("  EMAIL SECURITY:")
        spf = res["email_security"].get("spf", {})
        if spf.get("found"):
            lines.append(f"    SPF:    FOUND  {spf['record']}")
        else:
            lines.append(f"    SPF:    NOT FOUND")

        dkim = res["email_security"].get("dkim", {})
        if dkim:
            for sel, val in dkim.items():
                lines.append(f"    DKIM:   FOUND  {sel} = {val[:80]}...")
        else:
            lines.append(f"    DKIM:   NOT FOUND (common selectors checked)")

        dmarc = res["email_security"].get("dmarc", {})
        if dmarc.get("found"):
            lines.append(f"    DMARC:  FOUND  policy={dmarc['policy']}  {dmarc['record']}")
        else:
            lines.append(f"    DMARC:  NOT FOUND")

        # Zone Transfer
        zt = res.get("zone_transfer", {})
        if zt:
            lines.append("")
            lines.append("  ZONE TRANSFER:")
            for ns, info_zt in zt.items():
                status = "ALLOWED ***CRITICAL***" if info_zt["allowed"] else "REFUSED (good)"
                lines.append(f"    {ns}:  {status}")
        else:
            lines.append("")
            lines.append("  ZONE TRANSFER: (no nameservers to test)")

        # DNSSEC
        lines.append("")
        has_dnskey = bool(res["dnssec"].get("dnskey"))
        has_ds = bool(res["dnssec"].get("ds"))
        if has_dnskey or has_ds:
            lines.append(f"  DNSSEC:   ENABLED (DNSKEY: {'yes' if has_dnskey else 'no'}, DS: {'yes' if has_ds else 'no'})")
        else:
            lines.append(f"  DNSSEC:   NOT DEPLOYED")

        # Open Resolvers
        ores = res.get("open_resolvers", {})
        if ores:
            lines.append("")
            lines.append("  OPEN RESOLVER CHECK:")
            for ns, is_open in ores.items():
                status = "OPEN ***CRITICAL***" if is_open else "NOT OPEN (good)"
                lines.append(f"    {ns}:  {status}")

        # WHOIS
        whois_data = res.get("whois", {})
        lines.append("")
        lines.append("  WHOIS:")
        if whois_data.get("error"):
            lines.append(f"    Error: {whois_data['error']}")
        else:
            lines.append(f"    Registrar:  {whois_data.get('registrar', 'N/A')}")
            lines.append(f"    Created:    {whois_data.get('creation_date', 'N/A')}")
            lines.append(f"    Expires:    {whois_data.get('expiry_date', 'N/A')}")
            lines.append(f"    Privacy:    {'Yes' if whois_data.get('privacy') else 'No / Unknown'}")

        # Reverse lookups
        rev = res.get("reverse_lookups", {})
        if rev:
            lines.append("")
            lines.append("  REVERSE LOOKUPS:")
            for ip, rev_out in rev.items():
                first_line = rev_out.splitlines()[0] if rev_out else "(no result)"
                lines.append(f"    {ip}  ->  {first_line}")

        # Findings
        lines.append("")
        lines.append("  FINDINGS:")
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(
            res.get("findings", []),
            key=lambda f: severity_order.get(f["severity"], 99),
        )
        counts = {}
        for f in sorted_findings:
            sev = f["severity"]
            counts[sev] = counts.get(sev, 0) + 1
            lines.append(f"    [{sev}] {f['title']}")
            # Wrap detail at ~70 chars for readability
            detail = f["detail"]
            while detail:
                chunk = detail[:68]
                detail = detail[68:]
                lines.append(f"           {chunk}")

        lines.append("")
        count_strs = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            c = counts.get(sev, 0)
            if c:
                count_strs.append(f"{c} {sev}")
        lines.append(f"  TOTALS: {', '.join(count_strs) if count_strs else 'No findings'}")

    lines.append("")
    lines.append("=" * 72)
    lines.append("  END OF REPORT")
    lines.append("=" * 72)

    summary_text = "\n".join(lines)
    with open(summary_path, "w") as f:
        f.write(summary_text)
    info(f"Summary written to {summary_path}")

    # Also print summary to stdout
    print()
    print(summary_text)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="DNS Reconnaissance & Security Auditor (OpenClaw Skill)",
    )
    parser.add_argument(
        "--domains",
        required=True,
        help="Comma-separated list of domains to audit (max 3).",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output directory for results.",
    )
    args = parser.parse_args()

    # Parse and validate domains
    domains = [d.strip() for d in args.domains.split(",") if d.strip()]
    if not domains:
        error("No domains specified.")
        sys.exit(2)

    if len(domains) > MAX_DOMAINS:
        error(f"Too many domains ({len(domains)}). Maximum is {MAX_DOMAINS}.")
        sys.exit(2)

    # Validate domain format (basic check)
    domain_re = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$")
    for d in domains:
        if not domain_re.match(d):
            error(f"Invalid domain format: {d}")
            sys.exit(2)

    # Check required tools
    info("Checking required tools ...")
    missing = []
    for tool in ("dig", "whois", "host"):
        if not check_tool(tool):
            missing.append(tool)
    if missing:
        abort(
            f"Missing required tools: {', '.join(missing)}. "
            f"Install with: sudo apt install dnsutils whois"
        )

    # Create output directory
    output_dir = args.output
    os.makedirs(output_dir, exist_ok=True)
    info(f"Output directory: {output_dir}")

    # Run recon
    info(f"Starting DNS reconnaissance on {len(domains)} domain(s): {', '.join(domains)}")
    info(f"Rate limiting: {QUERY_DELAY}s delay between queries, {QUERY_TIMEOUT}s timeout per query")
    print()

    raw_log = [
        f"DNS Reconnaissance Raw Records",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Domains: {', '.join(domains)}",
        f"Tool: OpenClaw dns-recon skill",
    ]

    all_results = []
    for domain in domains:
        result = recon_domain(domain, raw_log)
        all_results.append(result)
        print()

    # Write outputs
    info("Writing output files ...")
    write_outputs(all_results, output_dir, raw_log)

    # Determine exit code based on findings
    has_critical = any(
        f["severity"] == "CRITICAL"
        for res in all_results
        for f in res.get("findings", [])
    )
    if has_critical:
        info("Reconnaissance complete. CRITICAL findings detected.")
    else:
        info("Reconnaissance complete.")

    sys.exit(0)


if __name__ == "__main__":
    main()
