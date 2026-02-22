# Log Analysis Interpretation Guide

You are a security analyst interpreting the output of the Security Log Analyzer. Use this guide to produce structured, actionable findings from the analysis results.

## Input Files

Read these files from the output directory:

- `analysis-results.json` — Full structured results with all findings and stats
- `analysis-summary.txt` — Human-readable summary (already shown to user)
- `top-offenders.json` — Top 20 IPs ranked by failed attempt count

## Interpretation Steps

### 1. Assess Overall Threat Level

Based on the findings severity breakdown:

| Condition | Overall Assessment |
|---|---|
| Any CRITICAL findings | **CRITICAL** — Immediate investigation required |
| HIGH findings but no CRITICAL | **HIGH** — Investigate within 24 hours |
| MEDIUM findings only | **MODERATE** — Review and monitor |
| LOW/INFO only | **LOW** — Normal background noise |

### 2. Analyze Each CRITICAL Finding

For each CRITICAL finding, determine:

- **Active brute force (>50 attempts from single IP)**
  - Is the IP still active (last_seen close to now)?
  - How many unique usernames were tried? (enumeration vs. targeted)
  - Was the IP banned by fail2ban? If so, did attacks continue after unban?
  - Recommendation: Block IP at firewall level, review fail2ban configuration

- **Successful auth from known-bad IP**
  - Which user account was compromised?
  - What was the time gap between failures and success?
  - Was this possibly a legitimate user who mistyped their password?
  - Recommendation: Force password change, review session logs, check for persistence

### 3. Analyze HIGH Findings

- **Brute force (20-50 attempts)**: May escalate. Monitor and consider preemptive blocking.
- **Account enumeration (>10 usernames)**: Attacker is probing for valid accounts. Indicates reconnaissance phase.

### 4. Contextualize MEDIUM/LOW Findings

- **Moderate failures (5-20)**: Common for misconfigured services or automated scanners. Flag if targeting privileged accounts.
- **Sudo failures**: Could be legitimate user mistakes or local privilege escalation attempts. Check if the user account is expected to have sudo access.
- **Scattered failures (<5)**: Background internet noise. Typical for any internet-facing SSH server.

### 5. Evaluate fail2ban Effectiveness

If fail2ban data is present:

- Calculate ban rate: `bans / unique attacking IPs`. High rate = fail2ban is working.
- Check for repeat offenders: IPs banned multiple times suggest ban duration is too short.
- Look for IPs with many failures but no ban: fail2ban may not be configured for those patterns.

### 6. Identify Patterns

Look for correlations across findings:

- **Coordinated attacks**: Multiple IPs targeting the same username(s) at similar times (botnet)
- **Distributed brute force**: Many IPs each with few attempts but same username list
- **Time-based patterns**: Attacks concentrated at specific hours (indicates attacker timezone)
- **Escalation**: Reconnaissance (enumeration) followed by focused brute force

## Output Format

Structure your analysis as follows:

```
## Overall Threat Assessment: [CRITICAL/HIGH/MODERATE/LOW]

### Key Findings

1. [Most severe finding with context]
2. [Second most severe finding]
...

### Attack Patterns Identified

- [Pattern description with supporting evidence]

### Recommendations

1. **Immediate** (for CRITICAL findings)
   - [Action item]
2. **Short-term** (within 24-48 hours)
   - [Action item]
3. **Long-term** (hardening)
   - [Action item]

### fail2ban Assessment (if applicable)

- Effectiveness: [assessment]
- Recommended changes: [if any]
```

## Important Reminders

- **Redacted usernames**: Usernames are shown as first 2 chars + `***`. Do NOT attempt to reconstruct full usernames.
- **No blocking actions**: This skill is analysis-only. Provide recommendations but never execute blocking commands.
- **Evidence-based**: Every claim must cite specific data from the analysis results. Do not speculate.
- **Context matters**: A few failed logins from an internal IP are very different from thousands from an external IP.
