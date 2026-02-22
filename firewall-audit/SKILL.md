---
name: firewall-audit
description: >
  FIREWALL AUDITOR. You MUST use this skill whenever the user mentions:
  "firewall audit", "check firewall rules", "iptables audit", "ufw check",
  "firewall security", "audit firewall", "firewall hardening", or any request
  about reviewing, auditing, or hardening iptables or ufw firewall rules.
  This skill parses and analyzes iptables/ufw rules, flags overly permissive
  configurations, missing drop defaults, unused rules, and dangerous ports,
  then produces a structured hardening report. Read this SKILL.md FIRST before
  running any firewall commands yourself.
metadata:
  {
    "openclaw":
      {
        "emoji": "🧱",
        "os": ["linux"],
        "requires": { "bins": ["iptables", "python3"] },
        "install":
          [
            {
              "id": "apt-iptables",
              "kind": "apt",
              "package": "iptables",
              "bins": ["iptables"],
              "label": "Install iptables (apt)",
            },
          ],
      },
  }
---

# Firewall Audit

Parse and audit iptables/ufw rules. Flag overly permissive rules, missing drop defaults, unused rules, and dangerous ports. Output a hardening report.

## Safety Constraints

- **Read-only analysis only**: Never modify, flush, or alter any firewall rules or chain policies.
- **Local system only**: Do not attempt to audit remote firewalls.
- **No rule changes**: No `iptables -F`, no `iptables -P`, no `ufw enable/disable`, no policy modifications of any kind.
- **Graceful privilege handling**: Display warnings if running without root (some information may be incomplete), but still analyze what is available.

## Quick Workflow (default)

Follow the instructions in TOOLS.md — they tell you exactly what to do.
The auditor prints a human-readable summary. Reply to the user with that summary.
Do NOT read analyst-prompt.md or report-template.md — those are for the full workflow below.

## Full Workflow (only if user asks for a "full report" or "detailed audit")

Execute these three phases in order:

### Phase 1 — Audit

Run the auditor (use the command from TOOLS.md, output to /tmp/firewall-audit-latest):

```bash
sudo python3 {baseDir}/scripts/firewall_audit.py --output /tmp/firewall-audit-latest
```

Read the `audit-summary.txt` from the output directory.

### Phase 2 — Analyze

Read `{baseDir}/references/analyst-prompt.md` and follow its instructions to perform
a deeper analysis of the audit results. Produce structured findings in the specified format.

### Phase 3 — Report

Read `{baseDir}/assets/report-template.md` and fill in the template.
Save the final report to the audit output directory as `firewall-hardening-report.md`.
Present a concise summary to the user with the key findings and the report path.
