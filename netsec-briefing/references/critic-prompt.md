# Critic Checklist — Self-Review

Apply this 6-point checklist to every finding in your analyst output. Remove or downgrade anything that fails.

## Checklist

### 1. Evidence Check
Does this finding cite a specific IP, port, and service string from the scan data?
- **Pass**: "FTP on 192.168.1.5:21 (vsftpd 3.0.3)"
- **Fail**: "The network may have FTP servers"
- **Action if fail**: Remove the finding entirely.

### 2. Severity Calibration
Is the severity level justified by the evidence, not by hypothetical scenarios?
- **Pass**: CRITICAL for telnet (credentials always cleartext — this is inherent to the protocol)
- **Fail**: CRITICAL for an HTTP service because "it could be exploited" without specific version evidence
- **Action if fail**: Downgrade to the highest level the evidence supports.

### 3. False-Positive Review
Could this be intentional or expected in a private network context?
- **Pass**: Flagging telnet on a production server
- **Questionable**: Flagging HTTP on port 80 in a dev environment (still flag, but note it may be intentional)
- **Action**: Add "verify if intentional" to recommendation when appropriate. Do not remove the finding.

### 4. Recommendation Quality
Is the recommendation specific and actionable, not generic security advice?
- **Pass**: "Replace FTP with SFTP or SCP on this host"
- **Fail**: "Improve security posture" or "Apply patches"
- **Action if fail**: Rewrite with a specific action tied to the finding.

### 5. Completeness Check
Are there scan results that weren't addressed?
- Look for hosts with many open ports that weren't analyzed
- Look for unusual services that were ignored
- **Action if incomplete**: Add findings for missed items.

### 6. Tone and Objectivity
Does the output read as a factual technical report, not an alarmist warning?
- **Pass**: "Telnet service detected — credentials transmitted without encryption"
- **Fail**: "DANGEROUS! Your network is HIGHLY VULNERABLE to hackers!"
- **Action if fail**: Rewrite in neutral, professional language.

## After Review

State which findings were modified, removed, or added during this review, then produce the final cleaned finding list.
