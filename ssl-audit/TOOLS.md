# SSL/TLS Certificate Audit — Tool Instructions

When the user asks to check SSL/TLS on one or more domains, run this command:
```bash
python3 {baseDir}/scripts/ssl_audit.py \
  --targets "example.com,example.org" \
  --output /tmp/ssl-audit-latest
```

Replace `example.com,example.org` with the actual domain(s) the user wants to audit. Multiple domains should be comma-separated with no spaces.

After the audit completes, read the summary:
```bash
cat /tmp/ssl-audit-latest/audit-summary.txt
```

Present the findings to the user in a clear, structured format highlighting:
- Certificate validity status (expired, expiring soon, or valid)
- Certificate subject, issuer, and validity dates
- Supported TLS protocol versions and any deprecated protocols
- HSTS header presence and configuration
- Weak cipher suites detected
- Overall risk assessment with severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Specific recommendations for remediation

If the audit fails, check that openssl is installed (`which openssl`), curl is installed (`which curl`), and that the target domain is reachable.
