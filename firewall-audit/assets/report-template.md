# Firewall Hardening Report

**Audit Date:** {audit_date}
**System:** {system_info}
**Audit Mode:** {audit_mode}
**Auditor:** OpenClaw Firewall Audit Skill

---

## Executive Summary

{executive_summary}

**Overall Posture:** {posture}

---

## Default Policies

| Chain   | Policy  | Status |
|---------|---------|--------|
{policy_rows}

---

## Findings

{findings_section}

---

## Hardening Action Plan

Execute these actions in priority order. **Test SSH access before applying DROP policies.**

| # | Priority | Action | Command | Finding |
|---|----------|--------|---------|---------|
{action_plan_rows}

---

## Post-Hardening Verification

After applying changes, verify:

1. **Re-audit**: Run the firewall audit again to confirm findings are resolved
2. **SSH access**: Ensure you can still connect via SSH before closing your session
3. **Essential services**: Verify web servers, DNS, and other required services still function
4. **Logging**: Check `/var/log/syslog` or `/var/log/kern.log` for firewall log entries
5. **Persistence**: Ensure rules persist across reboot (`iptables-save > /etc/iptables/rules.v4` or `netfilter-persistent save`)

---

## UFW Status

{ufw_section}

---

## Rule Statistics

| Metric | Value |
|--------|-------|
{stats_rows}

---

## Methodology

This audit was produced using a **read-only** analysis of the system firewall:

1. **Rule Capture**: `iptables-save` to capture all tables and chains in raw format
2. **Counter Analysis**: `iptables -L -n -v --line-numbers` to capture packet/byte counters
3. **UFW Check**: `ufw status verbose` to check for ufw management layer
4. **Automated Analysis**: Pattern matching against known-risk configurations
5. **Finding Generation**: Severity-rated findings with specific remediation steps

**Scope limitations:**
- Only IPv4 iptables rules were analyzed (ip6tables was not checked)
- NAT and mangle table rules were captured but not deeply analyzed for security
- Rule effectiveness depends on interface configuration and routing
- Counter data reflects traffic since last reset, not lifetime

---

## Raw Artifacts

The following files were produced during the audit:

{artifact_list}
