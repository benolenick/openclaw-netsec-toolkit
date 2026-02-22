# Network Security Briefing

**Scan Date:** {scan_date}
**Subnet:** {subnet}
**Scan ID:** {scan_id}

---

## Executive Summary

{executive_summary}

---

## Network Inventory

| # | IP Address | Hostname | Vendor/OS | Open Ports | Findings |
|---|-----------|----------|-----------|------------|----------|
{inventory_rows}

**Total hosts:** {host_count}

---

## Findings

{findings_section}

---

## Recommendations

| Priority | Action | Affected Hosts | Effort |
|----------|--------|---------------|--------|
{recommendations_rows}

---

## Methodology

This briefing was produced using a **read-only** network scan:

1. **Host Discovery**: nmap ping sweep (`-sn`) to identify live hosts on the target subnet
2. **Service Detection**: nmap service version detection (`-sV --top-ports 1000`) on discovered hosts
3. **Analysis**: Structured review of scan results against known-risk service patterns
4. **Verification**: Findings cross-checked against a 6-point evidence/severity checklist

**Scope limitations:**
- Only the top 1000 TCP ports were scanned; UDP and less common ports were not tested
- No vulnerability exploitation or credential testing was performed
- OS detection is based on service fingerprints and may be approximate
- Results reflect a point-in-time snapshot of the network

---

## Raw Artifacts

The following files were produced during the scan:

{artifact_list}
