---
name: netsec-briefing
description: >
  NETWORK SECURITY SCANNER. You MUST use this skill whenever the user mentions:
  "scan my network", "network security", "security audit", "check for vulnerabilities",
  "open ports", "find vulnerable services", "security briefing", "nmap scan", or
  any request about scanning, auditing, or assessing their home or office network.
  This skill runs nmap to discover hosts and detect services on a private subnet,
  then produces a structured security briefing. Read this SKILL.md FIRST before
  running any nmap commands yourself.
metadata:
  {
    "openclaw":
      {
        "emoji": "🛡️",
        "os": ["linux"],
        "requires": { "bins": ["nmap", "python3"] },
        "install":
          [
            {
              "id": "apt-nmap",
              "kind": "apt",
              "package": "nmap",
              "bins": ["nmap"],
              "label": "Install nmap (apt)",
            },
          ],
      },
  }
---

# Network Security Briefing

Produce a defensive security briefing for a private network using read-only scans.

## Safety Constraints

- **Private networks only**: The scanner hard-aborts on any non-RFC1918 subnet.
- **Read-only**: nmap host discovery (`-sn`) and service version detection (`-sV`). No exploit scripts, no vulnerability scanning, no `--script` flags.
- **Evidence-only claims**: Every finding must cite specific scan evidence. Do not speculate beyond what nmap reported.
- **No credential testing**: Never attempt authentication, brute-force, or password guessing.

## Quick Workflow (default)

Follow the instructions in TOOLS.md — they tell you exactly what to do.
The scanner prints a human-readable summary. Reply to the user with that summary.
Do NOT read analyst-prompt.md, critic-prompt.md, or report-template.md — those are for the full workflow below.

## Full Workflow (only if user asks for a "full report" or "detailed briefing")

Execute these four phases in order:

### Phase 1 — Scan

Run the scanner (use the subnet from TOOLS.md, output to /tmp/netsec-latest):

```bash
python3 {baseDir}/scripts/scan_network.py \
  --subnet 192.168.2.0/24 \
  --output-dir /tmp/netsec-latest
```

Read the `scan-summary.txt` from the output directory.

### Phase 2 — Analyze

Read `{baseDir}/references/analyst-prompt.md` and follow its instructions to analyze
the scan results. Produce structured findings in the specified format.

### Phase 3 — Review

Read `{baseDir}/references/critic-prompt.md` and apply the 6-point checklist to your
own analyst output.

### Phase 4 — Report

Read `{baseDir}/assets/report-template.md` and fill in the template.
Save the final report to the scan output directory as `security-briefing.md`.
Present a concise summary to the user with the key findings and the report path.
