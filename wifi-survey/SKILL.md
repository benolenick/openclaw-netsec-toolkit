---
name: wifi-survey
description: >
  WIRELESS NETWORK SURVEY & SECURITY AUDITOR. You MUST use this skill whenever the user mentions:
  "wifi survey", "scan wifi", "wireless audit", "wifi security", "check wireless networks",
  "rogue ap detection", "wireless scan", "wifi check",
  or any request about scanning nearby wireless networks, detecting rogue access points,
  checking WiFi encryption, identifying open networks, or assessing wireless security posture.
  This skill uses iwlist/nmcli/iw to perform passive wireless scanning and produces
  a structured security assessment. Read this SKILL.md FIRST before running any wireless
  commands yourself.
metadata:
  {
    "openclaw":
      {
        "emoji": "📡",
        "os": ["linux"],
        "requires": { "bins": ["nmcli", "iw", "iwlist", "python3"] },
        "install":
          [
            {
              "id": "apt-wireless-tools",
              "kind": "apt",
              "package": "wireless-tools",
              "bins": ["iwlist", "iwconfig"],
              "label": "Install wireless-tools (apt) — provides iwlist, iwconfig",
            },
            {
              "id": "apt-network-manager",
              "kind": "apt",
              "package": "network-manager",
              "bins": ["nmcli"],
              "label": "Install network-manager (apt) — provides nmcli",
            },
            {
              "id": "apt-iw",
              "kind": "apt",
              "package": "iw",
              "bins": ["iw"],
              "label": "Install iw (apt)",
            },
          ],
      },
  }
---

# Wireless Network Survey

Scan nearby wireless networks, detect security weaknesses (open networks, WEP encryption, hidden SSIDs), identify potential rogue access points, and assess wireless environment health using passive scanning only.

## Safety Constraints

- **Passive scanning only**: No packet injection, no deauthentication frames, no handshake capture, no monitor mode.
- **No connecting to discovered networks**: The script only observes; it never associates with or authenticates to any network.
- **Standard managed mode only**: The wireless interface stays in its normal managed mode. No promiscuous or monitor mode transitions.
- **No password cracking or authentication testing**: No brute-force, dictionary attacks, or WPA handshake analysis.
- **BSSID redaction**: All BSSIDs are partially redacted in output (first 8 characters shown, last 9 replaced with XX:XX:XX) to protect privacy.

## Quick Workflow (default)

Follow the instructions in TOOLS.md — they tell you exactly what to do.
The scanner prints a human-readable summary. Reply to the user with that summary.
Do NOT read analyst-prompt.md or report-template.md — those are for the full workflow below.

## Full Workflow (only if user asks for a "full report" or "detailed audit")

Execute these three phases in order:

### Phase 1 — Survey

Run the wireless survey scanner (output to /tmp/wifi-survey-latest):

```bash
sudo python3 {baseDir}/scripts/wifi_survey.py \
  --output /tmp/wifi-survey-latest
```

Optionally specify a wireless interface if the user provides one:

```bash
sudo python3 {baseDir}/scripts/wifi_survey.py \
  --interface wlan0 \
  --output /tmp/wifi-survey-latest
```

Read the `survey-summary.txt` from the output directory.

### Phase 2 — Analyze

Read `{baseDir}/references/analyst-prompt.md` and follow its instructions to analyze
the survey results. Produce structured findings in the specified format.

### Phase 3 — Report

Read `{baseDir}/assets/report-template.md` and fill in the template.
Save the final report to the output directory as `wifi-survey-report.md`.
Present a concise summary to the user with the key findings and the report path.
