---
name: log-analyzer
description: >
  SECURITY LOG ANALYZER. You MUST use this skill whenever the user mentions:
  "analyze logs", "check auth log", "security logs", "brute force detection",
  "failed logins", "log analysis", "check for intrusions", "suspicious activity",
  or any request about parsing, reviewing, or analyzing system authentication logs,
  syslog, fail2ban logs, SSH brute force attempts, or suspicious login activity.
  This skill parses auth.log, syslog, and fail2ban logs to detect brute force
  attempts, failed SSH logins, and suspicious patterns. Read this SKILL.md FIRST
  before running any log analysis commands yourself.
metadata:
  {
    "openclaw":
      {
        "emoji": "🪵",
        "os": ["linux"],
        "requires": { "bins": ["python3"] },
        "install": [],
      },
  }
---

# Security Log Analyzer

Parse auth.log, syslog, and fail2ban logs for brute force attempts, failed SSH logins, and suspicious patterns. Summarize threats with timestamps and source IPs.

## Safety Constraints

- **Read-only analysis only**: Never modify or delete any log files. All operations are strictly read-only.
- **Local system logs only**: Only analyze logs on the local system under /var/log. Never fetch or analyze remote logs.
- **Sanitize output**: Redact usernames in failed login attempts — show first 2 characters followed by `***` (e.g., "root" becomes "ro***", "admin" becomes "ad***").
- **No automatic blocking or IP banning**: This skill reports findings only. It never executes iptables rules, fail2ban actions, or any other blocking commands.
- **Evidence-only claims**: Every finding must cite specific log evidence. Do not speculate beyond what the logs contain.

## Quick Workflow (default)

Follow the instructions in TOOLS.md — they tell you exactly what to do.
The analyzer prints a human-readable summary. Reply to the user with that summary.
Do NOT read analyst-prompt.md or report-template.md — those are for the full workflow below.

## Full Workflow (only if user asks for a "full report" or "detailed audit")

Execute these three phases in order:

### Phase 1 — Analyze

Run the log analyzer (output to /tmp/log-analysis-latest):

```bash
sudo python3 {baseDir}/scripts/log_analyzer.py \
  --output /tmp/log-analysis-latest
```

Optionally pass `--log-dir /var/log` (default) and `--hours 24` (default) to customize.

Read the `analysis-summary.txt` from the output directory.

### Phase 2 — Interpret

Read `{baseDir}/references/analyst-prompt.md` and follow its instructions to interpret
the analysis results. Produce structured findings in the specified format.

### Phase 3 — Report

Read `{baseDir}/assets/report-template.md` and fill in the template.
Save the final report to the output directory as `log-analysis-report.md`.
Present a concise summary to the user with the key findings and the report path.
