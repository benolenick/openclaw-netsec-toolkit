# Security Log Analyzer — Tool Instructions

When the user asks to analyze security logs, check for brute force attempts, or review authentication logs, run this command:

```bash
sudo python3 {baseDir}/scripts/log_analyzer.py \
  --output /tmp/log-analysis-latest
```

You may add optional flags:
- `--log-dir /var/log` — path to log directory (default: /var/log)
- `--hours 48` — how many hours back to analyze (default: 24)

After the analysis completes, read the summary:
```bash
cat /tmp/log-analysis-latest/analysis-summary.txt
```

Present the findings to the user in a clear, structured format highlighting:
- Time window analyzed and total events processed
- Total failed authentication events and unique source IPs
- Top offending IPs with attempt counts and first/last seen timestamps
- Active brute force campaigns (CRITICAL/HIGH severity)
- Account enumeration attempts (many different usernames from one IP)
- Successful logins from IPs that previously had failures
- sudo authentication failures
- fail2ban effectiveness stats (bans issued, if applicable)
- Severity breakdown: CRITICAL, HIGH, MEDIUM, LOW, INFO findings
- Recommended actions for the most severe findings

If the analysis fails, check that:
- The command was run with sudo (log files typically require root access)
- python3 is installed (`which python3`)
- Log files exist under /var/log (auth.log, syslog)
