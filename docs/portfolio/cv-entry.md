# SentinelDLP — Professional Resume & CV Portfolio Entries

This document provides verified, high-impact resume bullet points highlighting the technical achievements in **SentinelDLP v1.0.0**.

---

## 1. Primary Project Entry (Standard 1-Page CV)

### **SentinelDLP — AI-Powered Data Loss Prevention & Threat Detection Platform**
*Lead Security Engineer & Architect* | Python 3.12, FastAPI, React 18, TypeScript, PostgreSQL, Docker, Ollama | 2026
- Architected an enterprise-grade defensive DLP and exfiltration detection platform comprising 12 modular subsystems and **171 automated unit/integration tests** passing with a 100% success rate.
- Designed a streaming SHA-256 cryptographic file scanner (64 KB chunking) and sensitive content inspector utilizing Luhn checksums and Shannon entropy to detect PCI cards, PII, and API tokens with zero-leakage masking.
- Implemented real-time filesystem monitoring via Python `watchdog` featuring a 400ms sliding-window debouncer and a thread-safe 5,000-event queue with Server-Sent Events (SSE) live telemetry streaming.
- Developed an explainable, deterministic 0–100 threat scoring engine and temporal event correlation pipeline linking sensitive file edits, archive staging (`.zip`), and network egress telemetry across sliding time windows.
- Engineered a privacy-preserving AI SOC Analyst utilizing local Ollama LLMs and deterministic mock fallback, integrating 9 bounded read-only tools, indirect prompt injection defenses, and database entity verification.
- Built an isolated cyberattack simulation laboratory evaluating 11 harmless scenarios, achieving 100% detection precision and recall across synthetic ransomware, staging, and exfiltration attack chains.

---

## 2. Specialized Track: Detection Engineering & SOC Automation

- **Detection Rule Architecture**: Authored and validated 18 production detection rules across filesystem velocity (`RULE-RAPID-MOD`), ransomware bulk renaming (`RULE-BULK-RENAME`), archive staging (`EXFIL-001`), and network anomalies (`NET-001` through `NET-010`).
- **Telemetry Correlation & Modesty**: Built a multi-signal correlation pipeline linking Zeek connection logs, Suricata EVE JSON IDS signatures, and filesystem events while enforcing strict evidence provenance (`OBSERVED`, `IMPORTED`, `LAB_SIMULATED`, `INFERRED`).
- **MITRE ATT&CK Mapping**: Mapped detections to enterprise MITRE ATT&CK techniques including Data Staging (T1074.001), Archive Utilities (T1560.001), Exfiltration Over Web Service (T1567.002), and DNS C2 (T1071.004).
- **Incident Lifecycle Automation**: Created an alert lifecycle state machine (`OPEN` &rarr; `ACKNOWLEDGED` &rarr; `INVESTIGATING` &rarr; `RESOLVED`) featuring a 300-second sliding-window suppression engine to eliminate alert fatigue.

---

## 3. Specialized Track: Application Security & DevSecOps

- **Defense-in-Depth API Hardening**: Implemented timing-safe token verification (`secrets.compare_digest`), 3-tier Role-Based Access Control (`ADMIN`, `ANALYST`, `READONLY`), and strict ASGI security headers (`nosniff`, `DENY`, CSP).
- **Vulnerability Remediation**: Enforced canonical boundary path traversal defenses (CWE-22) across file scanning and network log ingestion pipelines; mitigated DoS vectors via a 10MB payload size limit middleware.
- **Production Guardrails**: Configured automated deployment safety validators blocking launch with insecure credentials and rejecting cyberattack simulation execution in production environments (`HTTP 403`).
- **Containerization & CI/CD**: Packaged the platform using multi-stage Docker Compose running under unprivileged user IDs (`sentinel` UID 1001), automated with GitHub Actions CI executing tests and TypeScript builds.

---

## 4. Specialized Track: AI Security & Safe LLM Engineering

- **Anti-Hallucination Evidence Verification**: Created an automated post-generation verification engine cross-referencing AI-cited record IDs against verified database entities, stripping invalid references before analyst review.
- **Indirect Prompt Injection Defense**: Neutralized untrusted metadata injection risks by wrapping telemetry logs in defensive `<untrusted_telemetry>` enclosures and executing server-side credential redaction prior to prompt synthesis.
- **Controlled Tool Execution**: Bound AI investigation agents to 9 read-only server-side tools with a hard limit of 6 tool invocations per session and non-repudiation audit logging (`AIToolAuditEvent`).
