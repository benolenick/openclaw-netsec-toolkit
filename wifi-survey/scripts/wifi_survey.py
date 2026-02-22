#!/usr/bin/env python3
"""
Wireless Network Survey — OpenClaw Skill
Passive WiFi scanning with security analysis.
Uses nmcli (primary) and iwlist (fallback) to discover nearby networks.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log(msg):
    """Progress output to stdout."""
    print(f"[*] {msg}", flush=True)


def warn(msg):
    """Warning to stderr."""
    print(f"WARNING: {msg}", file=sys.stderr, flush=True)


def error(msg):
    """Error to stderr."""
    print(f"ERROR: {msg}", file=sys.stderr, flush=True)


def abort(msg, code=1):
    """Fatal error — print and exit."""
    print(f"ABORT: {msg}", file=sys.stderr, flush=True)
    sys.exit(code)


def run_cmd(cmd, timeout=30):
    """Run a shell command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 1, "", "Command timed out"
    except Exception as e:
        return 1, "", str(e)


def redact_bssid(bssid):
    """Partially redact a BSSID — show first 8 chars, mask last 9."""
    if not bssid or len(bssid) < 17:
        return bssid or "N/A"
    return bssid[:8] + ":XX:XX:XX"


def signal_bar(dbm):
    """Return a visual signal bar from dBm value (5 blocks max)."""
    if dbm is None:
        return "?"
    # Map dBm to 0-10 half-blocks.  -30 = full, -90 = empty.
    clamped = max(-90, min(-30, dbm))
    fraction = (clamped + 90) / 60.0          # 0.0 .. 1.0
    half_blocks = int(round(fraction * 10))    # 0 .. 10

    full = half_blocks // 2
    half = half_blocks % 2

    FULL_BLOCK = "\u2588"   # █
    HALF_BLOCK = "\u258c"   # ▌

    bar = FULL_BLOCK * full
    if half:
        bar += HALF_BLOCK
    return bar if bar else "\u2581"  # ▁ (minimum visible)


def dbm_from_quality(quality):
    """Convert iwlist quality (e.g. 70/100 or 38/70) to approximate dBm."""
    m = re.match(r"(\d+)/(\d+)", quality)
    if not m:
        return None
    num, den = int(m.group(1)), int(m.group(2))
    if den == 0:
        return None
    if den == 100:
        # percentage → dBm rough mapping
        return int(-100 + (num / 100.0) * 70)
    else:
        # x/70 scale (common on Linux)
        return int(num / 2 - 100)


def classify_security(raw):
    """Normalize a security string to a canonical label."""
    if not raw:
        return "Open"
    up = raw.upper().replace(" ", "")
    if "WPA3" in up or "SAE" in up:
        if "ENTERPRISE" in up or "802.1X" in up:
            return "WPA3-Enterprise"
        return "WPA3"
    if "WPA2" in up:
        if "ENTERPRISE" in up or "802.1X" in up:
            return "WPA2-Enterprise"
        return "WPA2"
    if "WPA" in up:
        return "WPA"
    if "WEP" in up:
        return "WEP"
    if up in ("--", "", "NONE"):
        return "Open"
    return raw.strip()


def channel_from_freq(freq_mhz):
    """Convert frequency in MHz to WiFi channel number."""
    freq = int(freq_mhz)
    if 2412 <= freq <= 2484:
        if freq == 2484:
            return 14
        return (freq - 2407) // 5
    if 5170 <= freq <= 5825:
        return (freq - 5000) // 5
    if 5955 <= freq <= 7115:
        return (freq - 5950) // 5
    return 0


def freq_band(freq_mhz):
    """Return '2.4GHz' or '5GHz' (or '6GHz') based on frequency."""
    freq = int(freq_mhz) if freq_mhz else 0
    if 2400 <= freq <= 2500:
        return "2.4GHz"
    if 5100 <= freq <= 5900:
        return "5GHz"
    if 5925 <= freq <= 7125:
        return "6GHz"
    return "unknown"


# ---------------------------------------------------------------------------
# Interface detection
# ---------------------------------------------------------------------------

def detect_interface_proc():
    """Try /proc/net/wireless."""
    try:
        with open("/proc/net/wireless", "r") as fh:
            lines = fh.readlines()
        for line in lines[2:]:   # first two lines are headers
            parts = line.strip().split(":")
            if parts and parts[0].strip():
                return parts[0].strip()
    except FileNotFoundError:
        pass
    return None


def detect_interface_iw():
    """Try `iw dev`."""
    rc, out, _ = run_cmd("iw dev")
    if rc == 0:
        for line in out.splitlines():
            m = re.match(r"\s*Interface\s+(\S+)", line)
            if m:
                return m.group(1)
    return None


def detect_interface_nmcli():
    """Try `nmcli device status`."""
    rc, out, _ = run_cmd("nmcli device status")
    if rc == 0:
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "wifi":
                return parts[0]
    return None


def detect_interface():
    """Auto-detect wireless interface via multiple methods."""
    iface = detect_interface_proc()
    if iface:
        log(f"Detected wireless interface via /proc/net/wireless: {iface}")
        return iface
    iface = detect_interface_iw()
    if iface:
        log(f"Detected wireless interface via iw dev: {iface}")
        return iface
    iface = detect_interface_nmcli()
    if iface:
        log(f"Detected wireless interface via nmcli: {iface}")
        return iface
    return None


# ---------------------------------------------------------------------------
# Scanning — nmcli (primary)
# ---------------------------------------------------------------------------

def scan_nmcli(iface):
    """Scan using nmcli. Returns list of network dicts or None on failure."""
    log("Scanning with nmcli ...")
    cmd = (
        f"nmcli -t -f SSID,BSSID,MODE,CHAN,FREQ,SIGNAL,SECURITY,BARS "
        f"device wifi list ifname {iface} --rescan yes"
    )
    rc, out, err = run_cmd(cmd, timeout=45)
    if rc != 0:
        warn(f"nmcli scan failed: {err.strip()}")
        return None

    networks = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        # nmcli -t uses ':' as separator; BSSIDs contain '\:' (escaped colons)
        # Strategy: replace escaped colons in BSSID with placeholder, split, restore
        # Fields: SSID, BSSID, MODE, CHAN, FREQ, SIGNAL, SECURITY, BARS
        # However SSID itself can contain colons, so we must parse carefully.
        # nmcli -t escapes colons inside field values as \:
        # We split on un-escaped colons.
        parts = re.split(r"(?<!\\):", line)
        # Unescape colons in each part
        parts = [p.replace("\\:", ":") for p in parts]

        if len(parts) < 7:
            continue

        ssid = parts[0] if parts[0] else "<hidden>"
        bssid = parts[1].strip() if len(parts) > 1 else ""
        mode = parts[2] if len(parts) > 2 else ""
        chan_str = parts[3] if len(parts) > 3 else "0"
        freq_str = parts[4] if len(parts) > 4 else "0"
        signal_pct = parts[5] if len(parts) > 5 else ""
        security = parts[6] if len(parts) > 6 else ""
        bars = parts[7] if len(parts) > 7 else ""

        try:
            channel = int(chan_str)
        except ValueError:
            channel = 0

        # Frequency: nmcli reports in MHz, e.g. "2437 MHz" or just "2437"
        freq_match = re.search(r"(\d+)", freq_str)
        freq_mhz = int(freq_match.group(1)) if freq_match else 0

        # Signal: nmcli gives percentage (0-100)
        try:
            sig_pct = int(signal_pct)
        except ValueError:
            sig_pct = 0
        # Convert percentage to approximate dBm:  0% → -100 dBm, 100% → -30 dBm
        dbm = int(-100 + (sig_pct / 100.0) * 70) if sig_pct else -100

        sec_label = classify_security(security)

        net = {
            "ssid": ssid,
            "bssid": bssid,
            "bssid_redacted": redact_bssid(bssid),
            "mode": mode.strip(),
            "channel": channel,
            "frequency_mhz": freq_mhz,
            "band": freq_band(freq_mhz) if freq_mhz else freq_band(channel * 5 + 2407 if 1 <= channel <= 14 else 5000 + channel * 5),
            "signal_dbm": dbm,
            "signal_pct": sig_pct,
            "security": sec_label,
            "security_raw": security,
            "bars_raw": bars,
        }
        networks.append(net)

    if networks:
        log(f"nmcli found {len(networks)} network(s)")
    return networks if networks else None


# ---------------------------------------------------------------------------
# Scanning — iwlist (fallback)
# ---------------------------------------------------------------------------

def scan_iwlist(iface):
    """Scan using iwlist. Returns list of network dicts or None on failure."""
    log("Scanning with iwlist (fallback) ...")
    cmd = f"iwlist {iface} scan"
    rc, out, err = run_cmd(cmd, timeout=30)
    if rc != 0:
        warn(f"iwlist scan failed: {err.strip()}")
        return None

    networks = []
    current = None
    for line in out.splitlines():
        line = line.strip()

        # New cell
        m = re.match(r"Cell \d+ - Address:\s*(\S+)", line)
        if m:
            if current:
                networks.append(current)
            bssid = m.group(1)
            current = {
                "ssid": "<hidden>",
                "bssid": bssid,
                "bssid_redacted": redact_bssid(bssid),
                "mode": "",
                "channel": 0,
                "frequency_mhz": 0,
                "band": "unknown",
                "signal_dbm": -100,
                "signal_pct": 0,
                "security": "Open",
                "security_raw": "",
                "bars_raw": "",
                "_enc_flags": [],
            }
            continue

        if current is None:
            continue

        # Channel
        m = re.search(r"Channel[:\s]*(\d+)", line)
        if m:
            current["channel"] = int(m.group(1))

        # Frequency
        m = re.search(r"Frequency[:\s]*([\d.]+)\s*GHz", line)
        if m:
            freq_ghz = float(m.group(1))
            current["frequency_mhz"] = int(freq_ghz * 1000)
            current["band"] = freq_band(current["frequency_mhz"])

        # ESSID
        m = re.search(r'ESSID:"(.*)"', line)
        if m:
            current["ssid"] = m.group(1) if m.group(1) else "<hidden>"

        # Quality / signal
        m = re.search(r"Quality[=:](\S+)\s+Signal level[=:]\s*(-?\d+)\s*dBm", line)
        if m:
            current["signal_dbm"] = int(m.group(2))
            current["signal_pct"] = max(0, min(100, int((int(m.group(2)) + 100) * (100 / 70.0))))
        else:
            m = re.search(r"Quality[=:](\S+)", line)
            if m:
                dbm_val = dbm_from_quality(m.group(1))
                if dbm_val is not None:
                    current["signal_dbm"] = dbm_val
                    current["signal_pct"] = max(0, min(100, int((dbm_val + 100) * (100 / 70.0))))

        # Mode
        m = re.search(r"Mode:\s*(\S+)", line)
        if m:
            current["mode"] = m.group(1)

        # Encryption key
        m = re.search(r"Encryption key:\s*(\S+)", line)
        if m:
            if m.group(1).lower() == "off":
                current["_enc_flags"].append("OPEN")

        # IE: IEEE 802.11i/WPA2 Version ...
        if re.search(r"IE:\s*IEEE 802\.11i", line, re.IGNORECASE):
            current["_enc_flags"].append("WPA2")
        elif re.search(r"IE:\s*WPA Version", line, re.IGNORECASE):
            current["_enc_flags"].append("WPA")

        # WEP
        if re.search(r"Group Cipher\s*:\s*WEP", line, re.IGNORECASE):
            current["_enc_flags"].append("WEP")

        # Authentication Suites
        if re.search(r"Authentication Suites.*802\.1X", line, re.IGNORECASE):
            current["_enc_flags"].append("Enterprise")
        if re.search(r"Authentication Suites.*SAE", line, re.IGNORECASE):
            current["_enc_flags"].append("SAE")

    if current:
        networks.append(current)

    # Post-process encryption flags
    for net in networks:
        flags = net.pop("_enc_flags", [])
        if "SAE" in flags:
            net["security"] = "WPA3"
        elif "WPA2" in flags and "Enterprise" in flags:
            net["security"] = "WPA2-Enterprise"
        elif "WPA2" in flags:
            net["security"] = "WPA2"
        elif "WPA" in flags:
            net["security"] = "WPA"
        elif "WEP" in flags:
            net["security"] = "WEP"
        elif "OPEN" in flags:
            net["security"] = "Open"
        net["security_raw"] = net["security"]

        # Ensure band is set from channel if frequency was not parsed
        if net["band"] == "unknown" and net["channel"] > 0:
            ch = net["channel"]
            if 1 <= ch <= 14:
                net["band"] = "2.4GHz"
                if net["frequency_mhz"] == 0:
                    net["frequency_mhz"] = 2407 + ch * 5 if ch < 14 else 2484
            elif ch >= 32:
                net["band"] = "5GHz"
                if net["frequency_mhz"] == 0:
                    net["frequency_mhz"] = 5000 + ch * 5

    if networks:
        log(f"iwlist found {len(networks)} network(s)")
    return networks if networks else None


# ---------------------------------------------------------------------------
# Current connection info
# ---------------------------------------------------------------------------

def get_current_connection():
    """Get details about the currently active WiFi connection."""
    conn = {
        "ssid": None,
        "bssid": None,
        "bssid_redacted": None,
        "security": None,
        "signal_dbm": None,
        "channel": None,
        "frequency_mhz": None,
        "interface": None,
    }

    # Try nmcli first
    rc, out, _ = run_cmd(
        "nmcli -t -f NAME,TYPE,DEVICE connection show --active"
    )
    if rc == 0:
        for line in out.splitlines():
            parts = line.split(":")
            if len(parts) >= 3 and parts[1].strip().startswith("802-11-wireless"):
                conn["ssid"] = parts[0].strip()
                conn["interface"] = parts[2].strip()
                break

    # Get BSSID and signal via nmcli device show or iw
    if conn["interface"]:
        rc2, out2, _ = run_cmd(
            f"nmcli -t -f GENERAL.CONNECTION,WIFI.SSID,WIFI.BSSID,WIFI.CHAN,WIFI.FREQ,WIFI.SIGNAL,WIFI.SECURITY "
            f"device show {conn['interface']}"
        )
        if rc2 == 0:
            for line in out2.splitlines():
                parts = line.split(":", 1)
                if len(parts) < 2:
                    continue
                key = parts[0].strip()
                val = parts[1].strip()
                if key == "WIFI.SSID" and val:
                    conn["ssid"] = val
                elif key == "WIFI.BSSID" and val:
                    # nmcli may print BSSID with escaped colons
                    conn["bssid"] = val.replace("\\:", ":")
                    conn["bssid_redacted"] = redact_bssid(conn["bssid"])
                elif key == "WIFI.CHAN" and val:
                    try:
                        conn["channel"] = int(val)
                    except ValueError:
                        pass
                elif key == "WIFI.FREQ" and val:
                    fm = re.search(r"(\d+)", val)
                    if fm:
                        conn["frequency_mhz"] = int(fm.group(1))
                elif key == "WIFI.SIGNAL" and val:
                    try:
                        pct = int(val)
                        conn["signal_dbm"] = int(-100 + (pct / 100.0) * 70)
                    except ValueError:
                        pass
                elif key == "WIFI.SECURITY" and val:
                    conn["security"] = classify_security(val)

    # Fallback: iwconfig
    if not conn["ssid"]:
        rc, out, _ = run_cmd("iwconfig 2>/dev/null")
        if rc == 0:
            for line in out.splitlines():
                m = re.search(r'ESSID:"([^"]*)"', line)
                if m and m.group(1):
                    conn["ssid"] = m.group(1)
                m = re.search(r"Access Point:\s*(\S+)", line)
                if m and m.group(1) != "Not-Associated":
                    conn["bssid"] = m.group(1)
                    conn["bssid_redacted"] = redact_bssid(conn["bssid"])
                m = re.search(r"Frequency[:\s]*([\d.]+)\s*GHz", line)
                if m:
                    conn["frequency_mhz"] = int(float(m.group(1)) * 1000)
                m = re.search(r"Signal level[=:]\s*(-?\d+)\s*dBm", line)
                if m:
                    conn["signal_dbm"] = int(m.group(1))

    if conn["ssid"]:
        log(f"Currently connected to: {conn['ssid']}")
    else:
        log("No active WiFi connection detected")

    return conn


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze_networks(networks, current_conn):
    """Analyze the network list and produce findings."""
    findings = []
    finding_counter = [0]

    def add_finding(severity, title, detail, recommendation):
        finding_counter[0] += 1
        fid = f"F-{finding_counter[0]:03d}"
        findings.append({
            "id": fid,
            "severity": severity,
            "title": title,
            "detail": detail,
            "recommendation": recommendation,
        })

    # --- WEP networks (CRITICAL) ---
    wep_nets = [n for n in networks if n["security"] == "WEP"]
    for n in wep_nets:
        add_finding(
            "CRITICAL",
            f'WEP network "{n["ssid"]}" detected',
            f'{n["bssid_redacted"]} Ch{n["channel"]} {n["signal_dbm"]}dBm',
            "WEP can be cracked in minutes. Upgrade to WPA2/WPA3 immediately.",
        )

    # --- Evil twin detection (CRITICAL) ---
    ssid_security_map = {}
    for n in networks:
        if n["ssid"] == "<hidden>":
            continue
        ssid_security_map.setdefault(n["ssid"], set()).add(n["security"])
    for ssid, secs in ssid_security_map.items():
        if len(secs) > 1:
            sec_list = ", ".join(sorted(secs))
            matching = [n for n in networks if n["ssid"] == ssid]
            bssid_list = ", ".join(n["bssid_redacted"] for n in matching)
            add_finding(
                "CRITICAL",
                f'Possible evil twin: "{ssid}" seen with different security levels',
                f"Security types: {sec_list}. BSSIDs: {bssid_list}",
                "Investigate immediately. Verify all APs are authorized. The AP with weaker security may be rogue.",
            )

    # --- Open networks (HIGH) ---
    open_nets = [n for n in networks if n["security"] == "Open"]
    # Common enterprise / honeypot names
    honeypot_names = {
        "free", "free_wifi", "free wifi", "freewifi", "guest", "public",
        "hotel", "airport", "starbucks", "xfinity", "attwifi", "open",
    }
    for n in open_nets:
        lower_ssid = n["ssid"].lower().replace("-", "_").replace(" ", "_")
        is_honeypot_name = any(h in lower_ssid for h in honeypot_names)
        if is_honeypot_name:
            add_finding(
                "HIGH",
                f'Open network "{n["ssid"]}" — possible honeypot',
                f'{n["bssid_redacted"]} Ch{n["channel"]} {n["signal_dbm"]}dBm',
                "Avoid connecting. If this is your network, enable WPA2/WPA3 encryption.",
            )
        else:
            add_finding(
                "HIGH",
                f'Open network "{n["ssid"]}" — no encryption',
                f'{n["bssid_redacted"]} Ch{n["channel"]} {n["signal_dbm"]}dBm',
                "If this is your network, enable WPA2/WPA3 encryption immediately.",
            )

    # --- Ad-hoc networks (HIGH) ---
    adhoc_nets = [n for n in networks if n["mode"].lower() in ("ad-hoc", "ibss", "ad hoc")]
    for n in adhoc_nets:
        add_finding(
            "HIGH",
            f'Ad-hoc network "{n["ssid"]}" detected',
            f'{n["bssid_redacted"]} Ch{n["channel"]} {n["signal_dbm"]}dBm Mode={n["mode"]}',
            "Ad-hoc (peer-to-peer) networks are often unauthorized. Investigate if in a managed environment.",
        )

    # --- Hidden SSIDs (MEDIUM) ---
    hidden_nets = [n for n in networks if n["ssid"] == "<hidden>"]
    if hidden_nets:
        for n in hidden_nets:
            add_finding(
                "MEDIUM",
                "Hidden SSID detected",
                f'{n["bssid_redacted"]} Ch{n["channel"]} {n["signal_dbm"]}dBm Security={n["security"]}',
                "Hidden SSIDs are trivially discoverable and provide no real security. If yours, consider making the SSID visible.",
            )

    # --- Weak signal on current connection (MEDIUM) ---
    if current_conn.get("ssid") and current_conn.get("signal_dbm") is not None:
        if current_conn["signal_dbm"] < -70:
            add_finding(
                "MEDIUM",
                f'Weak signal on current connection "{current_conn["ssid"]}"',
                f'{current_conn["signal_dbm"]}dBm',
                "Consider moving closer to the access point, relocating the AP, or adding a repeater/mesh node.",
            )

    # --- WPA (original, no WPA2) (MEDIUM) ---
    wpa1_nets = [n for n in networks if n["security"] == "WPA"]
    for n in wpa1_nets:
        add_finding(
            "MEDIUM",
            f'WPA (v1) network "{n["ssid"]}" — outdated encryption',
            f'{n["bssid_redacted"]} Ch{n["channel"]} {n["signal_dbm"]}dBm',
            "WPA-TKIP has known weaknesses. Upgrade to WPA2-AES or WPA3.",
        )

    # --- Channel congestion analysis (LOW / INFO) ---
    chan_count = {}
    for n in networks:
        ch = n["channel"]
        if ch > 0:
            chan_count[ch] = chan_count.get(ch, 0) + 1

    congested_channels = [(ch, cnt) for ch, cnt in chan_count.items() if cnt >= 4]
    for ch, cnt in sorted(congested_channels, key=lambda x: -x[1]):
        band = "2.4GHz" if 1 <= ch <= 14 else "5GHz"
        add_finding(
            "LOW",
            f"Channel {ch} ({band}) congestion — {cnt} networks",
            f"{cnt} networks share channel {ch}",
            f"If your network is on channel {ch}, consider switching to a less congested channel.",
        )

    # --- Overlapping 2.4GHz channels (LOW) ---
    non_standard_24 = [ch for ch in chan_count if 1 <= ch <= 14 and ch not in (1, 6, 11, 14)]
    if non_standard_24:
        add_finding(
            "LOW",
            "Networks on overlapping 2.4GHz channels",
            f"Channels: {', '.join(str(c) for c in sorted(non_standard_24))}",
            "Channels 1, 6, and 11 are the only non-overlapping 2.4GHz channels. Using other channels causes interference.",
        )

    # --- Channel usage heatmap (INFO) ---
    channels_24 = {ch: cnt for ch, cnt in chan_count.items() if 1 <= ch <= 14}
    channels_5 = {ch: cnt for ch, cnt in chan_count.items() if ch >= 32}
    ch24_summary = " ".join(f"Ch{ch}({cnt})" for ch, cnt in sorted(channels_24.items())) if channels_24 else "none"
    ch5_summary = " ".join(f"Ch{ch}({cnt})" for ch, cnt in sorted(channels_5.items())) if channels_5 else "none"
    add_finding(
        "INFO",
        "Channel usage summary",
        f"2.4GHz: {ch24_summary} | 5GHz: {ch5_summary}",
        "Use this data to choose the least congested channel for your network.",
    )

    # --- General environment summary (INFO) ---
    sec_counts = {}
    for n in networks:
        sec_counts[n["security"]] = sec_counts.get(n["security"], 0) + 1
    sec_summary = ", ".join(f"{s}: {c}" for s, c in sorted(sec_counts.items()))
    add_finding(
        "INFO",
        f"Wireless environment: {len(networks)} networks detected",
        f"Security breakdown — {sec_summary}",
        "Review the full network inventory below for details.",
    )

    return findings, chan_count


# ---------------------------------------------------------------------------
# Output generation
# ---------------------------------------------------------------------------

def generate_summary(iface, networks, current_conn, findings, chan_count):
    """Generate the human-readable survey-summary.txt content."""
    lines = []
    lines.append("WIRELESS NETWORK SURVEY")
    lines.append(f"Scan Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append(f"Interface: {iface} | Networks Found: {len(networks)}")

    if current_conn.get("ssid"):
        sec = current_conn.get("security") or "unknown"
        sig = f"{current_conn['signal_dbm']}dBm" if current_conn.get("signal_dbm") is not None else "N/A"
        ch = f"Ch{current_conn['channel']}" if current_conn.get("channel") else ""
        lines.append(f"Currently Connected: {current_conn['ssid']} ({sec}, {sig}, {ch})")
    else:
        lines.append("Currently Connected: None")

    lines.append("")

    # Security concerns
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    concern_findings = [f for f in findings if f["severity"] != "INFO"]
    if concern_findings:
        lines.append("SECURITY CONCERNS:")
        for f in concern_findings:
            lines.append(f'  [{f["severity"]}] {f["id"]}: {f["title"]}')
            lines.append(f'    \u2192 {f["recommendation"]}')
        lines.append("")

    # Network inventory
    lines.append("NETWORK INVENTORY:")
    # Column headers
    header = f"  {'SSID':<24} {'Security':<16} {'Ch':>3}  {'Signal':<8} {'BSSID':<20}"
    lines.append(header)
    lines.append("  " + "-" * (len(header) - 2))
    # Sort: by signal strength descending
    sorted_nets = sorted(networks, key=lambda n: n["signal_dbm"], reverse=True)
    for n in sorted_nets:
        ssid_display = n["ssid"][:22]
        if len(n["ssid"]) > 22:
            ssid_display = n["ssid"][:20] + ".."
        bar = signal_bar(n["signal_dbm"])
        ch_str = str(n["channel"]) if n["channel"] else "?"
        row = f"  {ssid_display:<24} {n['security']:<16} {ch_str:>3}  {bar:<8} {n['bssid_redacted']:<20}"
        lines.append(row)
    lines.append("")

    # Channel usage
    channels_24 = {ch: cnt for ch, cnt in chan_count.items() if 1 <= ch <= 14}
    channels_5 = {ch: cnt for ch, cnt in chan_count.items() if ch >= 32}

    lines.append("CHANNEL USAGE:")
    if channels_24:
        parts_24 = []
        for ch in sorted(channels_24):
            cnt = channels_24[ch]
            label = f"Ch{ch}({cnt})"
            if cnt >= 4:
                label += "*"  # congested marker
            parts_24.append(label)
        congested_24 = [f"Ch{ch}" for ch, cnt in channels_24.items() if cnt >= 4]
        suffix = f" \u2014 {', '.join(congested_24)} congested" if congested_24 else ""
        lines.append(f"  2.4GHz: {' '.join(parts_24)}{suffix}")
    else:
        lines.append("  2.4GHz: no networks detected")

    if channels_5:
        parts_5 = []
        for ch in sorted(channels_5):
            cnt = channels_5[ch]
            label = f"Ch{ch}({cnt})"
            if cnt >= 4:
                label += "*"
            parts_5.append(label)
        congested_5 = [f"Ch{ch}" for ch, cnt in channels_5.items() if cnt >= 4]
        suffix = f" \u2014 {', '.join(congested_5)} congested" if congested_5 else " \u2014 low congestion"
        lines.append(f"  5GHz:   {' '.join(parts_5)}{suffix}")
    else:
        lines.append("  5GHz:   no networks detected")

    lines.append("")

    # Info findings at the end
    info_findings = [f for f in findings if f["severity"] == "INFO"]
    if info_findings:
        lines.append("SUMMARY:")
        for f in info_findings:
            lines.append(f"  {f['id']}: {f['title']}")
            lines.append(f"    {f['detail']}")
        lines.append("")

    return "\n".join(lines)


def generate_json_results(iface, networks, current_conn, findings, chan_count):
    """Generate the structured JSON results."""
    return {
        "scan_metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "interface": iface,
            "network_count": len(networks),
        },
        "current_connection": current_conn,
        "networks": networks,
        "findings": findings,
        "channel_usage": {str(ch): cnt for ch, cnt in sorted(chan_count.items())},
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Wireless Network Survey — Passive WiFi scanning with security analysis.",
        epilog="Example: sudo python3 wifi_survey.py --output /tmp/wifi-survey-latest",
    )
    parser.add_argument(
        "--output", "-o",
        required=True,
        help="Output directory for survey results.",
    )
    parser.add_argument(
        "--interface", "-i",
        default=None,
        help="Wireless interface to scan (auto-detected if not specified).",
    )

    args = parser.parse_args()

    log("Wireless Network Survey starting")
    log("Mode: passive scan only — no injection, no monitor mode")

    # --- Detect or validate interface ---
    if args.interface:
        iface = args.interface
        log(f"Using specified interface: {iface}")
    else:
        log("Auto-detecting wireless interface ...")
        iface = detect_interface()
        if not iface:
            abort(
                "No wireless interface found. "
                "Ensure a WiFi adapter is connected and recognized by the system. "
                "Check with: iw dev, nmcli device status, or /proc/net/wireless"
            )

    # Verify interface exists
    rc, _, _ = run_cmd(f"ip link show {iface}")
    if rc != 0:
        abort(f"Interface '{iface}' does not exist. Check with: ip link show")

    # --- Scan networks ---
    log(f"Scanning on interface: {iface}")
    networks = scan_nmcli(iface)
    if networks is None:
        log("nmcli scan did not return results, trying iwlist fallback ...")
        networks = scan_iwlist(iface)
    if networks is None:
        # One more try: nmcli without rescan (may return cached results)
        log("iwlist also failed, trying nmcli cached results ...")
        rc, out, _ = run_cmd(
            f"nmcli -t -f SSID,BSSID,MODE,CHAN,FREQ,SIGNAL,SECURITY,BARS device wifi list ifname {iface}"
        )
        if rc == 0 and out.strip():
            networks = scan_nmcli(iface)  # re-parse

    if not networks:
        # Produce empty results rather than aborting
        warn("No networks discovered. The adapter may not support scanning, or no networks are in range.")
        networks = []

    # --- Deduplicate by BSSID ---
    seen_bssids = set()
    unique_networks = []
    for n in networks:
        key = n["bssid"].upper()
        if key and key not in seen_bssids:
            seen_bssids.add(key)
            unique_networks.append(n)
        elif not key:
            unique_networks.append(n)
    networks = unique_networks
    log(f"Unique networks after deduplication: {len(networks)}")

    # --- Current connection ---
    log("Checking current WiFi connection ...")
    current_conn = get_current_connection()

    # --- Analysis ---
    log("Analyzing networks ...")
    findings, chan_count = analyze_networks(networks, current_conn)

    sev_counts = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
    log(
        f"Analysis complete — "
        f"{sev_counts.get('CRITICAL', 0)} critical, "
        f"{sev_counts.get('HIGH', 0)} high, "
        f"{sev_counts.get('MEDIUM', 0)} medium, "
        f"{sev_counts.get('LOW', 0)} low, "
        f"{sev_counts.get('INFO', 0)} info"
    )

    # --- Write output ---
    outdir = args.output
    os.makedirs(outdir, exist_ok=True)

    summary_text = generate_summary(iface, networks, current_conn, findings, chan_count)
    summary_path = os.path.join(outdir, "survey-summary.txt")
    with open(summary_path, "w") as fh:
        fh.write(summary_text)
    log(f"Summary written to: {summary_path}")

    json_data = generate_json_results(iface, networks, current_conn, findings, chan_count)
    json_path = os.path.join(outdir, "survey-results.json")
    with open(json_path, "w") as fh:
        json.dump(json_data, fh, indent=2, default=str)
    log(f"JSON results written to: {json_path}")

    log("Wireless network survey complete")
    print()
    print(summary_text)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nABORT: Interrupted by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Unhandled exception: {e}", file=sys.stderr)
        sys.exit(1)
