# DNS Reconnaissance — Tool Instructions

When the user asks to check DNS, audit a domain, or perform DNS reconnaissance, run this command:
```bash
python3 {baseDir}/scripts/dns_recon.py \
  --domains "example.com" \
  --output /tmp/dns-recon-latest
```

Replace `example.com` with the actual domain(s) the user wants to audit. Multiple domains should be comma-separated with no spaces (max 3 domains).

After the recon completes, read the summary:
```bash
cat /tmp/dns-recon-latest/recon-summary.txt
```

Present the findings to the user in a clear, structured format highlighting:
- DNS record overview (A, AAAA, MX, NS, SOA, TXT, CNAME records found)
- Discovered subdomains from the common-name check
- Email security posture: SPF, DKIM, and DMARC status and policy details
- Zone transfer vulnerability (CRITICAL if any nameserver allows AXFR)
- DNSSEC deployment status
- CAA record presence and policy
- Open resolver detection on authoritative nameservers
- WHOIS summary (registrar, dates, privacy status)
- Overall risk assessment with severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Specific recommendations for remediation, ordered by severity

If the recon fails, check that dnsutils is installed (`which dig`), whois is installed (`which whois`), and that the target domain exists and is reachable.
