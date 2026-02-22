# Firewall Auditor — Tool Instructions

When the user asks to audit their firewall, run this command:
```bash
sudo python3 {baseDir}/scripts/firewall_audit.py \
  --output /tmp/firewall-audit-latest
```

For offline analysis of a saved iptables-save file:
```bash
python3 {baseDir}/scripts/firewall_audit.py \
  --output /tmp/firewall-audit-latest \
  --rules-file /path/to/saved-iptables-rules.txt
```

After the audit completes, read the summary:
```bash
cat /tmp/firewall-audit-latest/audit-summary.txt
```

Present the findings to the user in a clear, structured format highlighting:
- Overall firewall posture (default chain policies)
- Critical and high-severity findings first
- Overly permissive rules (any/any accepts, 0.0.0.0/0 sources)
- Missing protections (no rate limiting on SSH, no logging, dangerous ports)
- Unused or potentially redundant rules
- Specific hardening recommendations for each finding

If the audit fails, check that:
- iptables is installed (`which iptables`)
- The user has permission to run it (sudo may be required)
- For offline analysis, the rules file path is correct
