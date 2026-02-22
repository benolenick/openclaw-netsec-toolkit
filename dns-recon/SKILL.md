---
name: dns-recon
description: >
  DNS RECONNAISSANCE & SECURITY AUDITOR. You MUST use this skill whenever the user mentions:
  "dns recon", "dns audit", "check dns", "domain reconnaissance", "dns security",
  "check spf", "check dmarc", "dns misconfiguration", "subdomain enumeration",
  or any request about enumerating DNS records, checking email authentication records,
  detecting zone transfer vulnerabilities, or auditing domain configurations.
  This skill uses dig, whois, and host to perform passive DNS reconnaissance and produces
  a structured security assessment. Read this SKILL.md FIRST before running any dig/whois
  commands yourself.
metadata:
  {
    "openclaw":
      {
        "emoji": "🌐",
        "os": ["linux"],
        "requires": { "bins": ["dig", "whois", "host", "python3"] },
        "install":
          [
            {
              "id": "apt-dnsutils",
              "kind": "apt",
              "package": "dnsutils",
              "bins": ["dig", "host", "nslookup"],
              "label": "Install dnsutils (apt) — provides dig, host, nslookup",
            },
            {
              "id": "apt-whois",
              "kind": "apt",
              "package": "whois",
              "bins": ["whois"],
              "label": "Install whois (apt)",
            },
          ],
      },
  }
---

# DNS Reconnaissance & Security Audit

Enumerate DNS records, check email security (SPF/DKIM/DMARC), detect zone transfer vulnerabilities, and identify DNS misconfigurations using passive, standard queries only.

## Safety Constraints

- **Passive/standard DNS queries only**: No brute-force subdomain enumeration. Only checks a short list of common subdomain names via standard A-record lookups.
- **Authorized domains only**: The user must confirm they own or are authorized to test the target domain(s).
- **Rate limiting**: Maximum 3 domains per run, with a 0.5-second delay between individual queries to prevent flooding.
- **No DNS amplification or flood techniques**: All queries are single, standard-sized requests.
- **Zone transfer attempts are limited**: AXFR is only attempted against authoritative nameservers for the target domain and each attempt is logged.

## Quick Workflow (default)

Follow the instructions in TOOLS.md — they tell you exactly what to do.
The scanner prints a human-readable summary. Reply to the user with that summary.
Do NOT read analyst-prompt.md or report-template.md — those are for the full workflow below.

## Full Workflow (only if user asks for a "full report" or "detailed audit")

Execute these three phases in order:

### Phase 1 — Reconnaissance

Run the DNS recon scanner (use domains from the user, output to /tmp/dns-recon-latest):

```bash
python3 {baseDir}/scripts/dns_recon.py \
  --domains "example.com" \
  --output /tmp/dns-recon-latest
```

Read the `recon-summary.txt` from the output directory.

### Phase 2 — Analyze

Read `{baseDir}/references/analyst-prompt.md` and follow its instructions to analyze
the recon results. Produce structured findings in the specified format.

### Phase 3 — Report

Read `{baseDir}/assets/report-template.md` and fill in the template.
Save the final report to the output directory as `dns-recon-report.md`.
Present a concise summary to the user with the key findings and the report path.
