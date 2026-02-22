---
name: ssl-audit
description: >
  SSL/TLS CERTIFICATE AUDITOR. You MUST use this skill whenever the user mentions:
  "check ssl", "ssl audit", "certificate check", "tls scan", "check certificate expiry",
  "ssl security", "https check", or any request about auditing, scanning, or assessing
  SSL/TLS certificates, HTTPS configurations, or certificate expiry on domains.
  This skill uses openssl s_client and curl to probe SSL/TLS endpoints and produces
  a structured security audit. Read this SKILL.md FIRST before running any openssl
  commands yourself.
metadata:
  {
    "openclaw":
      {
        "emoji": "🔒",
        "os": ["linux"],
        "requires": { "bins": ["openssl", "curl", "python3"] },
        "install":
          [
            {
              "id": "apt-openssl",
              "kind": "apt",
              "package": "openssl",
              "bins": ["openssl"],
              "label": "Install openssl (apt)",
            },
            {
              "id": "apt-curl",
              "kind": "apt",
              "package": "curl",
              "bins": ["curl"],
              "label": "Install curl (apt)",
            },
          ],
      },
  }
---

# SSL/TLS Certificate Audit

Audit SSL/TLS configurations on domains and IP addresses using read-only probes.

## Safety Constraints

- **Read-only probes only**: Uses openssl s_client and curl HEAD requests. No exploitation, no fuzzing, no data exfiltration.
- **Authorized targets only**: The user must confirm they own or are authorized to test the target domain(s).
- **Rate limiting**: Maximum 5 domains per run to prevent abuse and keep output manageable.
- **No credential testing**: Never attempt authentication, brute-force, or bypass of any kind.
- **Evidence-only claims**: Every finding must cite specific probe evidence. Do not speculate beyond what openssl and curl reported.

## Quick Workflow (default)

Follow the instructions in TOOLS.md — they tell you exactly what to do.
The scanner prints a human-readable summary. Reply to the user with that summary.
Do NOT read analyst-prompt.md or report-template.md — those are for the full workflow below.

## Full Workflow (only if user asks for a "full report" or "detailed audit")

Execute these three phases in order:

### Phase 1 — Scan

Run the SSL audit scanner (use targets from the user, output to /tmp/ssl-audit-latest):

```bash
python3 {baseDir}/scripts/ssl_audit.py \
  --targets "example.com,example.org" \
  --output /tmp/ssl-audit-latest
```

Read the `audit-summary.txt` from the output directory.

### Phase 2 — Analyze

Read `{baseDir}/references/analyst-prompt.md` and follow its instructions to analyze
the audit results. Produce structured findings in the specified format.

### Phase 3 — Report

Read `{baseDir}/assets/report-template.md` and fill in the template.
Save the final report to the output directory as `ssl-audit-report.md`.
Present a concise summary to the user with the key findings and the report path.
