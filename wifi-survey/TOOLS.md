# Wireless Network Survey — Tool Instructions

When the user asks to scan WiFi, audit wireless networks, or perform a wireless survey, run this command:
```bash
sudo python3 {baseDir}/scripts/wifi_survey.py \
  --output /tmp/wifi-survey-latest
```

If the user specifies a particular wireless interface, add the `--interface` flag:
```bash
sudo python3 {baseDir}/scripts/wifi_survey.py \
  --interface wlan0 \
  --output /tmp/wifi-survey-latest
```

After the survey completes, read the summary:
```bash
cat /tmp/wifi-survey-latest/survey-summary.txt
```

Present the findings to the user in a clear, structured format highlighting:
- Number of wireless networks discovered and the interface used
- Current connection details (SSID, security, signal strength, channel)
- Security concerns ordered by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO):
  - WEP encrypted networks (critically weak encryption)
  - Open networks (no encryption at all)
  - Possible evil twin APs (same SSID, different security levels)
  - Honeypot indicators (open networks with enterprise-sounding names)
  - Ad-hoc networks (peer-to-peer, often unauthorized)
  - Hidden SSIDs
  - Weak signal on current connection
- Network inventory table (SSID, security, channel, signal, redacted BSSID)
- Channel usage and congestion analysis for 2.4GHz and 5GHz bands
- Recommendations for remediation, ordered by severity

If the survey fails, check that:
- wireless-tools is installed (`which iwlist`)
- network-manager is installed (`which nmcli`)
- iw is installed (`which iw`)
- A wireless interface exists on the system (`iw dev`)
- The command is run with sudo (iwlist scanning requires root; nmcli may work without it)
