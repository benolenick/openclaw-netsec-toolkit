# SSL/TLS Certificate Audit Report

**Audit Date:** {audit_date}
**Audit ID:** {audit_id}
**Targets:** {target_list}

---

## Executive Summary

{executive_summary}

---

## Target Inventory

| # | Target | Subject CN | Issuer | Expires | Days Left | Protocols | HSTS | Findings |
|---|--------|-----------|--------|---------|-----------|-----------|------|----------|
{inventory_rows}

**Total targets:** {target_count}

---

## Findings

{findings_section}

---

## Recommendations

| Priority | Action | Affected Targets | Effort |
|----------|--------|-----------------|--------|
{recommendations_rows}

---

## Protocol & Cipher Details

{protocol_details}

---

## Methodology

This audit was performed using **read-only** SSL/TLS probes:

1. **Certificate Retrieval**: openssl s_client connection to retrieve server certificate and chain
2. **Certificate Analysis**: Parsing of subject, issuer, validity dates, SANs, and signature algorithm
3. **Protocol Testing**: Individual TLS version probes (TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3)
4. **Cipher Testing**: Testing for known weak cipher patterns (RC4, DES, NULL, EXPORT, anonymous, MD5)
5. **HSTS Check**: HTTP HEAD request to check for Strict-Transport-Security header
6. **Chain Verification**: openssl verification of the certificate chain of trust

**Scope limitations:**
- Only TCP port 443 (or specified port) was tested; other TLS-enabled ports were not checked
- No vulnerability exploitation or active attacks were performed
- Cipher testing covers common weak patterns but is not exhaustive
- HSTS check only verifies the header on the root path
- Results reflect a point-in-time snapshot of the TLS configuration

---

## Raw Artifacts

The following files were produced during the audit:

{artifact_list}
