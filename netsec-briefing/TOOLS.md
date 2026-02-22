# Network Security Scanner — Tool Instructions

When the user asks to scan their network, run this command:
```bash
python3 {baseDir}/scripts/scan_network.py \
  --subnet 192.168.2.0/24 \
  --output-dir /tmp/netsec-latest
```

After the scan completes, read the summary:
```bash
cat /tmp/netsec-latest/scan-summary.txt
```

Present the findings to the user in a clear, structured format highlighting:
- Total hosts discovered
- Open ports and services found
- Any potentially risky services (telnet, FTP, unencrypted HTTP, SMB, etc.)
- Recommendations for hardening

If the scan fails, check that nmap is installed (`which nmap`) and that the user has permission to run it.
