# Security Policy

## Supported Versions

SentinelDLP actively supports security updates for the current major development release:

| Version | Supported          |
| ------- | ------------------ |
| 0.11.x  | :white_check_mark: |
| 0.10.x  | :white_check_mark: |
| < 0.10  | :x:                |

---

## Reporting a Vulnerability

The SentinelDLP project takes security vulnerabilities seriously. We appreciate the responsible disclosure of any security concerns.

### How to Report

If you discover a vulnerability or security weakness in SentinelDLP:

1. **Do NOT report security issues through public GitHub Issues or Discussions.**
2. Send an email with a detailed description to the security team at **security@sentineldlp.local** (or submit a private advisory through GitHub Security Advisories).
3. Include the following details where possible:
   - Type of vulnerability (e.g., path traversal, injection, authentication bypass).
   - Component affected (e.g., FastAPI endpoint, network adapter, scanner engine).
   - Step-by-step reproduction instructions or a minimal proof-of-concept.
   - Potential security impact and suggested remediation.

### Responsible Disclosure & Timeline

- **Initial Response:** Within 48 hours of report receipt.
- **Triage & Status Update:** Within 5 business days.
- **Fix Delivery:** High-severity issues are prioritized for remediation within 14 days.
- **Public Disclosure:** We request that reporters coordinate public disclosure after an official fix has been published and released.

---

## Security Architecture & Design Principles

SentinelDLP follows a defense-in-depth security model:
- **Zero Raw Secret Storage:** Cryptographic keys, SSNs, credit card numbers, and API tokens discovered in files are masked before database persistence.
- **Strict Boundary Containment:** File scanning and filesystem monitoring are strictly restricted to administrator-authorized directory allowlists. Directory traversal and symlink escapes are actively blocked.
- **Air-Gapped Privacy First:** Threat intelligence matching and MITRE ATT&CK validations operate entirely offline to prevent private corporate IP or filename leakage to external third-party cloud services.
- **AI Least Privilege:** The AI SOC Analyst is restricted to server-enforced, read-only evidence retrieval tools and cannot execute shell commands, alter firewall settings, or mutate data records.
