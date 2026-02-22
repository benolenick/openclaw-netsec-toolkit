# OpenClaw Network Security Toolkit

A comprehensive cybersecurity toolkit built as modular [OpenClaw](https://github.com/openclaw) skills. Each skill is self-contained with its own scanner script, analysis guides, and report templates — designed to be invoked by an AI agent via natural language.

## Skills Overview

| Skill | Purpose | Key Tools | Trigger Phrases |
|-------|---------|-----------|-----------------|
| [netsec-briefing](#netsec-briefing) | Network scan & service enumeration | nmap | "scan my network", "security briefing" |
| [ssl-audit](#ssl-audit) | SSL/TLS certificate & config audit | openssl, curl | "check ssl", "certificate check" |
| [firewall-audit](#firewall-audit) | iptables/ufw rule analysis | iptables, ufw | "firewall audit", "check firewall rules" |
| [log-analyzer](#log-analyzer) | Auth log brute-force detection | python3 (stdlib) | "analyze logs", "failed logins" |
| [dns-recon](#dns-recon) | DNS reconnaissance & email security | dig, whois, host | "dns recon", "check spf", "check dmarc" |
| [container-scan](#container-scan) | Docker CVE & config scanning | trivy, docker | "scan containers", "docker vulnerabilities" |
| [wifi-survey](#wifi-survey) | Wireless network security survey | nmcli, iwlist, iw | "wifi survey", "scan wifi" |

## Requirements

- **OS:** Ubuntu 24.04 (or compatible Debian-based Linux)
- **Python:** 3.10+
- **No pip dependencies** — all scripts use Python standard library only

### Per-Skill Dependencies

```bash
# netsec-briefing
sudo apt install nmap

# ssl-audit
sudo apt install openssl curl

# firewall-audit
sudo apt install iptables ufw

# log-analyzer
# No additional packages (stdlib only)

# dns-recon
sudo apt install dnsutils whois

# container-scan
sudo apt install docker.io
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin

# wifi-survey
sudo apt install wireless-tools network-manager iw
```

Install everything at once:
```bash
sudo apt install nmap openssl curl iptables ufw dnsutils whois docker.io wireless-tools network-manager iw
```

## Installation

OpenClaw auto-discovers any directory containing a `SKILL.md` file under `~/.openclaw/skills/`. No registration or manifest needed — just drop the skill folders in and they're available.

### Option 1: Clone the whole toolkit (recommended)

```bash
# Clone directly into the OpenClaw skills directory
git clone https://github.com/benolenick/openclaw-netsec-toolkit.git ~/.openclaw/skills

# Make scripts executable
chmod +x ~/.openclaw/skills/*/scripts/*.py

# Install system dependencies (all at once)
sudo apt install nmap openssl curl dnsutils whois docker.io wireless-tools network-manager iw
```

### Option 2: Install individual skills

```bash
# Clone to a temp location, then copy only the skills you want
git clone https://github.com/benolenick/openclaw-netsec-toolkit.git /tmp/netsec-toolkit
mkdir -p ~/.openclaw/skills

# Copy individual skills (pick what you need)
cp -r /tmp/netsec-toolkit/ssl-audit ~/.openclaw/skills/
cp -r /tmp/netsec-toolkit/firewall-audit ~/.openclaw/skills/

# Make scripts executable
chmod +x ~/.openclaw/skills/*/scripts/*.py

# Clean up
rm -rf /tmp/netsec-toolkit
```

### Option 3: Add to an existing skills directory

If you already have skills installed at `~/.openclaw/skills/`:

```bash
cd ~/.openclaw/skills
git clone https://github.com/benolenick/openclaw-netsec-toolkit.git /tmp/netsec-toolkit
cp -r /tmp/netsec-toolkit/{ssl-audit,firewall-audit,log-analyzer,dns-recon,container-scan,wifi-survey,netsec-briefing} .
chmod +x */scripts/*.py
rm -rf /tmp/netsec-toolkit
```

### Verify installation

After installing, confirm the skills are detected by asking your OpenClaw agent any trigger phrase:

- *"scan my network"* — should activate netsec-briefing
- *"check ssl on example.com"* — should activate ssl-audit
- *"audit my firewall"* — should activate firewall-audit

Skills load on next agent startup. No restart is required if the agent is already watching the skills directory.

## Skill Directory Structure

Every skill follows the same pattern:

```
skill-name/
  SKILL.md              # Skill definition (triggers, safety rules, workflows)
  TOOLS.md              # Exact commands for the agent to run
  scripts/
    scanner.py          # Main Python3 scanner script
  references/
    analyst-prompt.md   # Deep analysis guide (full workflow only)
  assets/
    report-template.md  # Report template with placeholders (full workflow only)
```

## Safety Design

All skills enforce defensive security principles:

- **Read-only operations** — no modifications, no exploitation, no credential testing
- **Scope restrictions** — private networks only (where applicable), rate limiting, target caps
- **Evidence-based findings** — every finding cites specific probe data
- **Severity classification** — CRITICAL > HIGH > MEDIUM > LOW > INFO
- **Graceful degradation** — handles missing tools, permissions, and timeouts
- **Output sanitization** — redacts usernames, partially masks BSSIDs

## Skill Details

---

### netsec-briefing

**Network Security Briefing** — Nmap-based network scanning and service enumeration for private networks.

```bash
python3 ~/.openclaw/skills/netsec-briefing/scripts/scan_network.py \
  --subnet 192.168.1.0/24 \
  --output-dir /tmp/netsec-latest
```

**Detects:** Open ports, risky services (telnet, FTP, exposed databases), legacy protocols, unauthenticated admin interfaces.

**Safety:** RFC1918 private subnets only. Hard abort on public IPs. Read-only scans (`-sn` and `-sV` only).

---

### ssl-audit

**SSL/TLS Certificate Audit** — Probes HTTPS endpoints for certificate validity, protocol support, cipher strength, and HSTS configuration.

```bash
python3 ~/.openclaw/skills/ssl-audit/scripts/ssl_audit.py \
  --targets "example.com,api.example.com" \
  --output /tmp/ssl-audit-latest
```

**Detects:** Expired/expiring certificates, TLSv1.0/1.1 support, SSLv3, weak ciphers (RC4, DES, NULL, EXPORT), missing HSTS, self-signed certificates, SHA-1 signatures, chain validation errors.

**Safety:** Max 5 domains per run. Authorized targets only. 10-second connection timeouts.

**Output:** `audit-results.json`, `audit-summary.txt` (869 lines of Python)

---

### firewall-audit

**Firewall Rule Auditor** — Parses iptables-save and ufw status to identify misconfigurations and overly permissive rules.

```bash
sudo python3 ~/.openclaw/skills/firewall-audit/scripts/firewall_audit.py \
  --output /tmp/firewall-audit-latest
```

Offline analysis from saved rules:
```bash
python3 ~/.openclaw/skills/firewall-audit/scripts/firewall_audit.py \
  --rules-file /path/to/iptables-save.txt \
  --output /tmp/firewall-audit-latest
```

**10 automated checks:**
1. Default chain policies (INPUT/FORWARD/OUTPUT)
2. Overly permissive 0.0.0.0/0 ACCEPT rules
3. SSH without rate limiting
4. Dangerous ports (telnet, rsh, tftp, SMB, databases)
5. Missing LOG rules
6. Unused rules (zero packet counters)
7. FORWARD chain wide open
8. Rule ordering issues
9. Redundant/duplicate rules
10. UFW-specific misconfigurations

**Safety:** Read-only analysis. Never modifies rules. Works without root (with warnings).

**Output:** `audit-results.json`, `audit-summary.txt`, `raw-iptables.txt` (1,077 lines of Python)

---

### log-analyzer

**Security Log Analyzer** — Parses auth.log, syslog, and fail2ban logs for brute force attempts, failed SSH logins, and suspicious authentication patterns.

```bash
sudo python3 ~/.openclaw/skills/log-analyzer/scripts/log_analyzer.py \
  --output /tmp/log-analysis-latest \
  --hours 48
```

**Detects:**
- Failed SSH password attempts with IP/username extraction
- Invalid user enumeration (many usernames from one IP)
- Brute force bursts (>5 failures in 10 minutes from same IP)
- Successful logins after prior failures (potential compromise)
- Sudo authentication failures
- fail2ban ban/unban activity

**Safety:** Read-only. Usernames redacted (shows first 2 chars + `***`). Memory-efficient line-by-line parsing. No automatic blocking.

**Output:** `analysis-results.json`, `analysis-summary.txt`, `top-offenders.json` (806 lines of Python)

---

### dns-recon

**DNS Reconnaissance** — Domain intelligence gathering using standard DNS queries, WHOIS lookups, and email security validation.

```bash
python3 ~/.openclaw/skills/dns-recon/scripts/dns_recon.py \
  --domains "example.com,example.org" \
  --output /tmp/dns-recon-latest
```

**Checks:**
- Full DNS record enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME, CAA)
- 17 common subdomain lookups (www, mail, api, dev, staging, admin, vpn, etc.)
- Zone transfer (AXFR) against authoritative nameservers
- SPF record validation (flags `+all`)
- DKIM selector checks (4 common selectors)
- DMARC policy analysis (flags `p=none`)
- DNSSEC presence (DNSKEY + DS records)
- Open resolver detection on nameservers
- WHOIS registration data

**Safety:** Max 3 domains. 0.5s delay between queries. Passive queries only (no brute-force enumeration). AXFR attempts limited to authoritative NS.

**Output:** `recon-results.json`, `recon-summary.txt`, `raw-records.txt` (941 lines of Python)

---

### container-scan

**Container Security Scanner** — Scans Docker images for CVEs using Trivy and audits running container configurations.

```bash
# Scan running containers
python3 ~/.openclaw/skills/container-scan/scripts/container_scan.py \
  --output /tmp/container-scan-latest

# Scan specific images
python3 ~/.openclaw/skills/container-scan/scripts/container_scan.py \
  --images "nginx:latest,python:3.11" \
  --output /tmp/container-scan-latest
```

**Vulnerability scanning:** Runs `trivy image --format json` per image, parses CVE ID, severity, package name, installed/fixed versions.

**Configuration checks on running containers:**
- Running as root
- Privileged mode
- Host network mode
- docker.sock mounted
- Sensitive path mounts (/etc, /proc, /sys, /root)
- Dangerous capabilities (SYS_ADMIN, NET_ADMIN, etc.)
- Missing resource limits (memory, CPU)
- Missing healthcheck

**Safety:** Read-only. No container exec. No image pulling (unless explicitly requested). 5-minute timeout per scan.

**Output:** `scan-results.json`, `scan-summary.txt`, `image-configs.json` (718 lines of Python)

---

### wifi-survey

**Wireless Network Survey** — Scans nearby Wi-Fi networks to identify security issues, rogue APs, and channel congestion.

```bash
sudo python3 ~/.openclaw/skills/wifi-survey/scripts/wifi_survey.py \
  --output /tmp/wifi-survey-latest
```

**Detects:**
- Open (unencrypted) networks
- WEP-encrypted networks
- Evil twin candidates (same SSID, different security)
- Honeypot indicators (common names like "Free_WiFi", "guest")
- Hidden SSIDs
- Ad-hoc networks
- WPA v1 networks
- Channel congestion and overlap
- Weak signal on current connection

**Scanning methods** (fallback chain): nmcli (primary, no root needed) -> iwlist (fallback, needs root)

**Interface detection** (3 methods): /proc/net/wireless -> `iw dev` -> `nmcli device status`

**Safety:** Passive scanning only. No monitor mode, no packet injection, no deauth. BSSIDs partially redacted. No connecting to discovered networks.

**Output:** `survey-results.json`, `survey-summary.txt` with signal strength bars (926 lines of Python)

---

## Output Format

All skills produce consistent output:

- **JSON results file** — Full structured data for programmatic consumption
- **Text summary file** — Human-readable ~500 token summary for LLM consumption
- **Finding IDs** — Sequential `F-001`, `F-002`, etc.
- **Severity levels** — CRITICAL, HIGH, MEDIUM, LOW, INFO
- **Progress output** — `[*]` prefix to stdout
- **Error output** — `ERROR:`/`WARNING:`/`ABORT:` prefix to stderr
- **Exit codes** — 0 (success), 1 (error), 2 (usage)

## Workflows

Each skill supports two workflows:

### Quick Workflow (default)
1. Agent runs the scanner script
2. Reads the text summary
3. Presents findings to the user

### Full Workflow (on request)
1. Agent runs the scanner script
2. Reads `references/analyst-prompt.md` for deep analysis guidance
3. Performs structured analysis of the JSON results
4. Fills in `assets/report-template.md`
5. Saves a complete security report

## Total Codebase

```
7 skills | 35 files | ~5,800 lines of Python | 0 external dependencies
```

## License

MIT

## Contributing

Each skill is independent. To add a new skill:

1. Create a directory under `~/.openclaw/skills/your-skill-name/`
2. Add `SKILL.md` with YAML frontmatter (name, description, triggers, requirements)
3. Add `TOOLS.md` with exact commands
4. Add `scripts/your_script.py` using Python3 stdlib only
5. Add `references/analyst-prompt.md` for deep analysis
6. Add `assets/report-template.md` for full reports
7. Follow the safety constraints pattern (read-only, evidence-based, severity-classified)
