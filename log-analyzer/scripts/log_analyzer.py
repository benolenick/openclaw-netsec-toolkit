#!/usr/bin/env python3
"""
Security Log Analyzer — OpenClaw Skill
Parses auth.log, syslog, and fail2ban logs for brute force attempts,
failed SSH logins, and suspicious patterns.

Read-only analysis only. Never modifies or deletes log files.
"""

import argparse
import collections
import datetime
import json
import os
import re
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SYSLOG_TS_FMT = "%b %d %H:%M:%S"  # e.g. "Feb 21 14:03:22"

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

# Brute force thresholds
BRUTE_FORCE_WINDOW_MINUTES = 10
BRUTE_FORCE_WINDOW_THRESHOLD = 5
CRITICAL_ATTEMPT_THRESHOLD = 50
HIGH_ATTEMPT_THRESHOLD = 20
MEDIUM_ATTEMPT_THRESHOLD = 5
ENUMERATION_THRESHOLD = 10

TOP_OFFENDERS_COUNT = 20
TOP_DISPLAY_COUNT = 10


# ---------------------------------------------------------------------------
# Regex patterns (Ubuntu/Debian auth.log format)
# ---------------------------------------------------------------------------

# "Feb 21 14:03:22 hostname sshd[12345]: Failed password for root from 10.0.0.1 port 22 ssh2"
RE_FAILED_PASSWORD = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (?:invalid user )?(\S+)\s+from\s+(\S+)\s+port\s+\d+"
)

# "Feb 21 14:03:22 hostname sshd[12345]: Invalid user test from 10.0.0.1 port 54321"
RE_INVALID_USER = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Invalid user\s+(\S+)\s+from\s+(\S+)"
)

# "Feb 21 14:05:00 hostname sshd[12345]: Accepted password for root from 10.0.0.1 port 22 ssh2"
# "Feb 21 14:05:00 hostname sshd[12345]: Accepted publickey for root from 10.0.0.1 port 22 ssh2"
RE_ACCEPTED_AUTH = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted\s+(?:password|publickey)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+\d+"
)

# sudo authentication failure
# "Feb 21 14:05:00 hostname sudo: pam_unix(sudo:auth): authentication failure; ... user=admin"
RE_SUDO_FAILURE = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sudo.*authentication failure.*"
    r"(?:user=(\S+))?"
)

# Alternative sudo failure: "Feb 21 14:05:00 hostname sudo: username : ... ; command not allowed"
# Or: "... 3 incorrect password attempts"
RE_SUDO_FAILURE_ALT = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sudo.*"
    r"(?:incorrect password attempts|NOT in sudoers|command not allowed)"
)

# Connection refused/reset in syslog
RE_CONN_REFUSED = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+.*"
    r"(?:Connection refused|Connection reset).*?(\d{1,3}(?:\.\d{1,3}){3})"
)

# fail2ban ban
# "2026-02-21 14:03:22,123 fail2ban.actions ... Ban 10.0.0.1"
RE_F2B_BAN = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}),\d+\s+.*\bBan\s+(\S+)"
)

# fail2ban unban
RE_F2B_UNBAN = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}),\d+\s+.*\bUnban\s+(\S+)"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def redact_username(username):
    """Redact a username: show first 2 chars + '***'."""
    if len(username) <= 2:
        return username + "***"
    return username[:2] + "***"


def parse_syslog_timestamp(ts_str, reference_year=None):
    """Parse a syslog-style timestamp (no year) and return a datetime.

    Uses *reference_year* to assign the year. If the resulting date is
    in the future (can happen around year boundaries), subtract one year.
    """
    if reference_year is None:
        reference_year = datetime.datetime.now().year
    try:
        dt = datetime.datetime.strptime(ts_str.strip(), SYSLOG_TS_FMT)
        dt = dt.replace(year=reference_year)
        # Handle year boundary: if parsed date is in the future, assume previous year
        if dt > datetime.datetime.now() + datetime.timedelta(days=1):
            dt = dt.replace(year=reference_year - 1)
        return dt
    except ValueError:
        return None


def parse_f2b_timestamp(ts_str):
    """Parse a fail2ban timestamp and return a datetime."""
    try:
        return datetime.datetime.strptime(ts_str.strip(), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def progress(msg):
    """Print progress to stdout."""
    print(f"[*] {msg}", flush=True)


def warn(msg):
    """Print warning to stderr."""
    print(f"WARNING: {msg}", file=sys.stderr, flush=True)


def error(msg):
    """Print error to stderr."""
    print(f"ERROR: {msg}", file=sys.stderr, flush=True)


def abort(msg):
    """Print abort message to stderr and exit."""
    print(f"ABORT: {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class IPRecord:
    """Tracks activity for a single source IP."""

    __slots__ = (
        "ip", "failed_attempts", "invalid_user_attempts",
        "usernames", "first_seen", "last_seen",
        "successful_logins", "sudo_failures",
        "conn_refused", "f2b_bans", "f2b_unbans",
        "timestamps",
    )

    def __init__(self, ip):
        self.ip = ip
        self.failed_attempts = 0
        self.invalid_user_attempts = 0
        self.usernames = set()
        self.first_seen = None
        self.last_seen = None
        self.successful_logins = []
        self.sudo_failures = 0
        self.conn_refused = 0
        self.f2b_bans = 0
        self.f2b_unbans = 0
        self.timestamps = []  # timestamps of failed attempts for burst detection

    def update_seen(self, dt):
        if dt is None:
            return
        if self.first_seen is None or dt < self.first_seen:
            self.first_seen = dt
        if self.last_seen is None or dt > self.last_seen:
            self.last_seen = dt

    def to_dict(self):
        return {
            "ip": self.ip,
            "failed_attempts": self.failed_attempts,
            "invalid_user_attempts": self.invalid_user_attempts,
            "usernames_redacted": sorted(redact_username(u) for u in self.usernames),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "successful_logins_after_failure": len(self.successful_logins),
            "sudo_failures": self.sudo_failures,
            "connection_refused": self.conn_refused,
            "f2b_bans": self.f2b_bans,
            "f2b_unbans": self.f2b_unbans,
        }


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

class LogAnalyzer:
    """Main log analysis engine."""

    def __init__(self, log_dir, hours):
        self.log_dir = Path(log_dir)
        self.hours = hours
        self.cutoff = datetime.datetime.now() - datetime.timedelta(hours=hours)
        self.reference_year = datetime.datetime.now().year
        self.ip_records = {}          # ip -> IPRecord
        self.findings = []            # list of finding dicts
        self.stats = {
            "total_failed_auth": 0,
            "total_invalid_user": 0,
            "total_accepted_auth": 0,
            "total_sudo_failures": 0,
            "total_conn_refused": 0,
            "total_f2b_bans": 0,
            "total_f2b_unbans": 0,
            "files_parsed": [],
            "lines_processed": 0,
            "parse_errors": 0,
        }

    def _get_ip(self, ip):
        """Get or create an IPRecord."""
        if ip not in self.ip_records:
            self.ip_records[ip] = IPRecord(ip)
        return self.ip_records[ip]

    # -- File reading (line by line, handles large files) -------------------

    def _iter_lines(self, filepath):
        """Iterate over lines of a file. Handles permission errors gracefully."""
        try:
            with open(filepath, "r", errors="replace") as fh:
                for line in fh:
                    yield line
        except PermissionError:
            warn(f"Permission denied reading {filepath}. Run with sudo for full analysis.")
        except OSError as exc:
            warn(f"Could not read {filepath}: {exc}")

    # -- Parsers ------------------------------------------------------------

    def _parse_auth_line(self, line):
        """Parse a single auth.log line."""

        # Failed password
        m = RE_FAILED_PASSWORD.match(line)
        if m:
            ts_str, username, ip = m.group(1), m.group(2), m.group(3)
            dt = parse_syslog_timestamp(ts_str, self.reference_year)
            if dt and dt < self.cutoff:
                return
            rec = self._get_ip(ip)
            rec.failed_attempts += 1
            rec.usernames.add(username)
            rec.update_seen(dt)
            if dt:
                rec.timestamps.append(dt)
            self.stats["total_failed_auth"] += 1
            return

        # Invalid user
        m = RE_INVALID_USER.match(line)
        if m:
            ts_str, username, ip = m.group(1), m.group(2), m.group(3)
            dt = parse_syslog_timestamp(ts_str, self.reference_year)
            if dt and dt < self.cutoff:
                return
            rec = self._get_ip(ip)
            rec.invalid_user_attempts += 1
            rec.usernames.add(username)
            rec.update_seen(dt)
            if dt:
                rec.timestamps.append(dt)
            self.stats["total_invalid_user"] += 1
            return

        # Accepted auth
        m = RE_ACCEPTED_AUTH.match(line)
        if m:
            ts_str, username, ip = m.group(1), m.group(2), m.group(3)
            dt = parse_syslog_timestamp(ts_str, self.reference_year)
            if dt and dt < self.cutoff:
                return
            rec = self._get_ip(ip)
            rec.successful_logins.append({
                "username": username,
                "timestamp": dt.isoformat() if dt else None,
            })
            rec.update_seen(dt)
            self.stats["total_accepted_auth"] += 1
            return

        # sudo failure
        m = RE_SUDO_FAILURE.match(line)
        if not m:
            m = RE_SUDO_FAILURE_ALT.match(line)
        if m:
            ts_str = m.group(1)
            dt = parse_syslog_timestamp(ts_str, self.reference_year)
            if dt and dt < self.cutoff:
                return
            self.stats["total_sudo_failures"] += 1
            # sudo failures may not always have an IP; record as local
            # Try to extract user if available
            user_match = re.search(r"user=(\S+)", line)
            username = user_match.group(1) if user_match else "unknown"
            rec = self._get_ip("127.0.0.1")
            rec.sudo_failures += 1
            rec.usernames.add(username)
            rec.update_seen(dt)
            return

    def _parse_syslog_line(self, line):
        """Parse a single syslog line for connection refused/reset."""
        m = RE_CONN_REFUSED.match(line)
        if m:
            ts_str, ip = m.group(1), m.group(2)
            dt = parse_syslog_timestamp(ts_str, self.reference_year)
            if dt and dt < self.cutoff:
                return
            rec = self._get_ip(ip)
            rec.conn_refused += 1
            rec.update_seen(dt)
            self.stats["total_conn_refused"] += 1

    def _parse_f2b_line(self, line):
        """Parse a single fail2ban log line."""
        m = RE_F2B_BAN.match(line)
        if m:
            ts_str, ip = m.group(1), m.group(2)
            dt = parse_f2b_timestamp(ts_str)
            if dt and dt < self.cutoff:
                return
            rec = self._get_ip(ip)
            rec.f2b_bans += 1
            rec.update_seen(dt)
            self.stats["total_f2b_bans"] += 1
            return

        m = RE_F2B_UNBAN.match(line)
        if m:
            ts_str, ip = m.group(1), m.group(2)
            dt = parse_f2b_timestamp(ts_str)
            if dt and dt < self.cutoff:
                return
            rec = self._get_ip(ip)
            rec.f2b_unbans += 1
            self.stats["total_f2b_unbans"] += 1

    # -- File dispatch ------------------------------------------------------

    def _parse_file(self, filepath, parser_fn):
        """Parse a log file using the given parser function, line by line."""
        fp = Path(filepath)
        if not fp.exists():
            return
        progress(f"Parsing {fp} ...")
        self.stats["files_parsed"].append(str(fp))
        count = 0
        for line in self._iter_lines(fp):
            count += 1
            try:
                parser_fn(line)
            except Exception:
                self.stats["parse_errors"] += 1
        self.stats["lines_processed"] += count
        progress(f"  Processed {count} lines from {fp.name}")

    # -- Burst / brute-force detection --------------------------------------

    def _detect_brute_force_bursts(self, rec):
        """Check if an IP has bursts of >THRESHOLD failures within WINDOW minutes."""
        if len(rec.timestamps) < BRUTE_FORCE_WINDOW_THRESHOLD:
            return False
        sorted_ts = sorted(rec.timestamps)
        window = datetime.timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)
        for i in range(len(sorted_ts)):
            # Count how many timestamps fall within the window starting at sorted_ts[i]
            count = 0
            for j in range(i, len(sorted_ts)):
                if sorted_ts[j] - sorted_ts[i] <= window:
                    count += 1
                else:
                    break
            if count >= BRUTE_FORCE_WINDOW_THRESHOLD:
                return True
        return False

    # -- Finding generation -------------------------------------------------

    def _generate_findings(self):
        """Analyze collected records and produce severity-rated findings."""

        for ip, rec in self.ip_records.items():
            if ip == "127.0.0.1" and rec.sudo_failures > 0 and rec.failed_attempts == 0:
                # sudo-only entry — handle separately
                if rec.sudo_failures >= MEDIUM_ATTEMPT_THRESHOLD:
                    self.findings.append({
                        "severity": SEVERITY_MEDIUM,
                        "category": "sudo_failure",
                        "description": (
                            f"sudo authentication failures detected: "
                            f"{rec.sudo_failures} failure(s)"
                        ),
                        "ip": ip,
                        "details": rec.to_dict(),
                    })
                continue

            total_fail = rec.failed_attempts + rec.invalid_user_attempts

            # -- CRITICAL: active brute force (>50 attempts) --
            if total_fail >= CRITICAL_ATTEMPT_THRESHOLD:
                desc = (
                    f"Active brute force from {ip}: {total_fail} failed attempts, "
                    f"{len(rec.usernames)} unique username(s)"
                )
                self.findings.append({
                    "severity": SEVERITY_CRITICAL,
                    "category": "brute_force_active",
                    "description": desc,
                    "ip": ip,
                    "details": rec.to_dict(),
                })

            # -- CRITICAL: successful auth from IP that had failures --
            elif rec.successful_logins and total_fail > 0:
                desc = (
                    f"Successful login from {ip} after {total_fail} failed attempt(s). "
                    f"Possible credential compromise."
                )
                self.findings.append({
                    "severity": SEVERITY_CRITICAL,
                    "category": "success_after_failure",
                    "description": desc,
                    "ip": ip,
                    "details": rec.to_dict(),
                })

            # -- HIGH: brute force (>20) --
            elif total_fail >= HIGH_ATTEMPT_THRESHOLD:
                desc = (
                    f"Brute force attempts from {ip}: {total_fail} failed attempts"
                )
                self.findings.append({
                    "severity": SEVERITY_HIGH,
                    "category": "brute_force",
                    "description": desc,
                    "ip": ip,
                    "details": rec.to_dict(),
                })

            # -- HIGH: account enumeration (>10 usernames) --
            elif len(rec.usernames) >= ENUMERATION_THRESHOLD:
                desc = (
                    f"Account enumeration from {ip}: {len(rec.usernames)} unique "
                    f"usernames attempted"
                )
                self.findings.append({
                    "severity": SEVERITY_HIGH,
                    "category": "account_enumeration",
                    "description": desc,
                    "ip": ip,
                    "details": rec.to_dict(),
                })

            # -- MEDIUM: moderate attempts (5-20) or burst detected --
            elif total_fail >= MEDIUM_ATTEMPT_THRESHOLD:
                is_burst = self._detect_brute_force_bursts(rec)
                cat = "brute_force_burst" if is_burst else "moderate_failures"
                desc = (
                    f"{'Burst brute force' if is_burst else 'Moderate failed attempts'} "
                    f"from {ip}: {total_fail} attempt(s)"
                )
                self.findings.append({
                    "severity": SEVERITY_MEDIUM,
                    "category": cat,
                    "description": desc,
                    "ip": ip,
                    "details": rec.to_dict(),
                })

            # -- LOW: scattered failures (<5) --
            elif total_fail > 0:
                self.findings.append({
                    "severity": SEVERITY_LOW,
                    "category": "scattered_failures",
                    "description": f"Scattered failed logins from {ip}: {total_fail} attempt(s)",
                    "ip": ip,
                    "details": rec.to_dict(),
                })

        # -- INFO: fail2ban summary --
        if self.stats["total_f2b_bans"] > 0 or self.stats["total_f2b_unbans"] > 0:
            banned_ips = [
                ip for ip, rec in self.ip_records.items() if rec.f2b_bans > 0
            ]
            self.findings.append({
                "severity": SEVERITY_INFO,
                "category": "f2b_summary",
                "description": (
                    f"fail2ban activity: {self.stats['total_f2b_bans']} ban(s), "
                    f"{self.stats['total_f2b_unbans']} unban(s) across "
                    f"{len(banned_ips)} unique IP(s)"
                ),
                "ip": None,
                "details": {
                    "total_bans": self.stats["total_f2b_bans"],
                    "total_unbans": self.stats["total_f2b_unbans"],
                    "banned_ips": banned_ips,
                },
            })

        # Sort findings by severity
        severity_order = {
            SEVERITY_CRITICAL: 0,
            SEVERITY_HIGH: 1,
            SEVERITY_MEDIUM: 2,
            SEVERITY_LOW: 3,
            SEVERITY_INFO: 4,
        }
        self.findings.sort(key=lambda f: severity_order.get(f["severity"], 99))

    # -- Top offenders ------------------------------------------------------

    def _top_offenders(self, n=TOP_OFFENDERS_COUNT):
        """Return top N IPs by total failed attempts."""
        ranked = []
        for ip, rec in self.ip_records.items():
            total = rec.failed_attempts + rec.invalid_user_attempts
            if total == 0:
                continue
            ranked.append({
                "ip": ip,
                "total_failed": total,
                "failed_password": rec.failed_attempts,
                "invalid_user": rec.invalid_user_attempts,
                "unique_usernames": len(rec.usernames),
                "usernames_redacted": sorted(redact_username(u) for u in rec.usernames),
                "first_seen": rec.first_seen.isoformat() if rec.first_seen else None,
                "last_seen": rec.last_seen.isoformat() if rec.last_seen else None,
                "f2b_banned": rec.f2b_bans > 0,
                "successful_logins_after_failure": len(rec.successful_logins),
            })
        ranked.sort(key=lambda r: r["total_failed"], reverse=True)
        return ranked[:n]

    # -- Summary text -------------------------------------------------------

    def _build_summary(self, top_offenders):
        """Build a human-readable summary string."""
        now = datetime.datetime.now()
        lines = []
        lines.append("=" * 72)
        lines.append("  SECURITY LOG ANALYSIS SUMMARY")
        lines.append("=" * 72)
        lines.append("")
        lines.append(f"  Analysis time   : {now.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"  Time window     : last {self.hours} hour(s) (cutoff: {self.cutoff.strftime('%Y-%m-%d %H:%M:%S')})")
        lines.append(f"  Log directory   : {self.log_dir}")
        lines.append(f"  Files parsed    : {len(self.stats['files_parsed'])}")
        lines.append(f"  Lines processed : {self.stats['lines_processed']}")
        if self.stats["parse_errors"] > 0:
            lines.append(f"  Parse errors    : {self.stats['parse_errors']}")
        lines.append("")
        lines.append("-" * 72)
        lines.append("  EVENT TOTALS")
        lines.append("-" * 72)
        lines.append(f"  Failed SSH password attempts   : {self.stats['total_failed_auth']}")
        lines.append(f"  Invalid user attempts          : {self.stats['total_invalid_user']}")
        lines.append(f"  Accepted authentications       : {self.stats['total_accepted_auth']}")
        lines.append(f"  sudo failures                  : {self.stats['total_sudo_failures']}")
        lines.append(f"  Connection refused/reset       : {self.stats['total_conn_refused']}")
        lines.append(f"  Unique source IPs              : {len([ip for ip, r in self.ip_records.items() if r.failed_attempts + r.invalid_user_attempts > 0])}")
        lines.append("")

        if self.stats["total_f2b_bans"] > 0 or self.stats["total_f2b_unbans"] > 0:
            lines.append("-" * 72)
            lines.append("  FAIL2BAN ACTIVITY")
            lines.append("-" * 72)
            lines.append(f"  Total bans     : {self.stats['total_f2b_bans']}")
            lines.append(f"  Total unbans   : {self.stats['total_f2b_unbans']}")
            banned_ips = [ip for ip, r in self.ip_records.items() if r.f2b_bans > 0]
            lines.append(f"  Unique banned  : {len(banned_ips)}")
            lines.append("")

        # Findings by severity
        sev_counts = collections.Counter(f["severity"] for f in self.findings)
        lines.append("-" * 72)
        lines.append("  FINDINGS BY SEVERITY")
        lines.append("-" * 72)
        for sev in [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO]:
            count = sev_counts.get(sev, 0)
            marker = " <<<" if sev == SEVERITY_CRITICAL and count > 0 else ""
            lines.append(f"  {sev:10s} : {count}{marker}")
        lines.append("")

        # Critical and High findings detail
        urgent = [f for f in self.findings if f["severity"] in (SEVERITY_CRITICAL, SEVERITY_HIGH)]
        if urgent:
            lines.append("-" * 72)
            lines.append("  URGENT FINDINGS")
            lines.append("-" * 72)
            for f in urgent:
                lines.append(f"  [{f['severity']}] {f['description']}")
            lines.append("")

        # Top offenders table
        display = top_offenders[:TOP_DISPLAY_COUNT]
        if display:
            lines.append("-" * 72)
            lines.append("  TOP OFFENDING IPs")
            lines.append("-" * 72)
            lines.append(f"  {'Rank':<6}{'IP Address':<20}{'Failed':<10}{'Usernames':<12}{'Banned':<8}{'First Seen':<22}{'Last Seen'}")
            lines.append("  " + "-" * 100)
            for i, o in enumerate(display, 1):
                first = o["first_seen"][:19] if o["first_seen"] else "N/A"
                last = o["last_seen"][:19] if o["last_seen"] else "N/A"
                lines.append(
                    f"  {i:<6}{o['ip']:<20}{o['total_failed']:<10}"
                    f"{o['unique_usernames']:<12}{'Yes' if o['f2b_banned'] else 'No':<8}"
                    f"{first:<22}{last}"
                )
            lines.append("")

        # Successful logins after failures
        suspicious_logins = [
            (ip, rec) for ip, rec in self.ip_records.items()
            if rec.successful_logins and (rec.failed_attempts + rec.invalid_user_attempts) > 0
        ]
        if suspicious_logins:
            lines.append("-" * 72)
            lines.append("  SUCCESSFUL LOGINS AFTER FAILURES (investigate immediately)")
            lines.append("-" * 72)
            for ip, rec in suspicious_logins:
                total_fail = rec.failed_attempts + rec.invalid_user_attempts
                for login in rec.successful_logins:
                    uname = redact_username(login["username"])
                    lines.append(
                        f"  {ip} -> user {uname} at {login['timestamp']} "
                        f"(after {total_fail} failure(s))"
                    )
            lines.append("")

        if not self.findings:
            lines.append("-" * 72)
            lines.append("  No significant findings in the analyzed time window.")
            lines.append("-" * 72)
            lines.append("")

        lines.append("=" * 72)
        lines.append(f"  End of summary — full results in analysis-results.json")
        lines.append("=" * 72)
        return "\n".join(lines)

    # -- Main entry ---------------------------------------------------------

    def run(self):
        """Run the full analysis pipeline."""
        progress(f"Security Log Analyzer starting")
        progress(f"Log directory: {self.log_dir}")
        progress(f"Time window: last {self.hours} hour(s)")
        progress(f"Cutoff: {self.cutoff.strftime('%Y-%m-%d %H:%M:%S')}")

        if os.geteuid() != 0:
            warn("Not running as root. Some log files may be unreadable. Consider running with sudo.")

        if not self.log_dir.is_dir():
            abort(f"Log directory does not exist: {self.log_dir}")

        # Parse auth.log files
        for name in ("auth.log", "auth.log.1"):
            self._parse_file(self.log_dir / name, self._parse_auth_line)

        # Parse syslog files
        for name in ("syslog", "syslog.1"):
            self._parse_file(self.log_dir / name, self._parse_syslog_line)

        # Parse fail2ban log
        self._parse_file(self.log_dir / "fail2ban.log", self._parse_f2b_line)

        if not self.stats["files_parsed"]:
            warn("No log files were found or readable. Check the log directory path and permissions.")

        progress("Generating findings ...")
        self._generate_findings()

        top_offenders = self._top_offenders()

        progress("Building summary ...")
        summary = self._build_summary(top_offenders)

        return {
            "summary": summary,
            "findings": self.findings,
            "top_offenders": top_offenders,
            "stats": self.stats,
        }


# ---------------------------------------------------------------------------
# Output writing
# ---------------------------------------------------------------------------

def write_outputs(output_dir, results):
    """Write analysis results to the output directory."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    # analysis-results.json
    results_path = out / "analysis-results.json"
    with open(results_path, "w") as fh:
        json.dump({
            "findings": results["findings"],
            "top_offenders": results["top_offenders"],
            "stats": results["stats"],
        }, fh, indent=2, default=str)
    progress(f"Wrote {results_path}")

    # analysis-summary.txt
    summary_path = out / "analysis-summary.txt"
    with open(summary_path, "w") as fh:
        fh.write(results["summary"])
        fh.write("\n")
    progress(f"Wrote {summary_path}")

    # top-offenders.json
    offenders_path = out / "top-offenders.json"
    with open(offenders_path, "w") as fh:
        json.dump(results["top_offenders"], fh, indent=2, default=str)
    progress(f"Wrote {offenders_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Security Log Analyzer — parse auth.log, syslog, and fail2ban logs "
                    "for brute force attempts and suspicious patterns.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output directory for results (will be created if it does not exist)",
    )
    parser.add_argument(
        "--log-dir",
        default="/var/log",
        help="Directory containing log files (default: /var/log)",
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="How many hours back to analyze (default: 24)",
    )

    args = parser.parse_args()

    if args.hours < 1:
        error("--hours must be at least 1")
        sys.exit(2)

    analyzer = LogAnalyzer(log_dir=args.log_dir, hours=args.hours)
    results = analyzer.run()

    write_outputs(args.output, results)

    # Print the summary to stdout as well
    print()
    print(results["summary"])
    print()

    # Exit code based on severity
    sev_set = set(f["severity"] for f in results["findings"])
    if SEVERITY_CRITICAL in sev_set:
        progress("Analysis complete. CRITICAL findings detected.")
    elif SEVERITY_HIGH in sev_set:
        progress("Analysis complete. HIGH severity findings detected.")
    else:
        progress("Analysis complete.")

    sys.exit(0)


if __name__ == "__main__":
    main()
