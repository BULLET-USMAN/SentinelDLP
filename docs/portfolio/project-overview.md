# SentinelDLP — Executive Cybersecurity Portfolio Overview

**Project:** SentinelDLP — AI-Powered Data Loss Prevention & Exfiltration Detection Platform  
**Author / Lead Engineer:** Usman  
**Repository:** [github.com/BULLET-USMAN/SentinelDLP](https://github.com/BULLET-USMAN/SentinelDLP)  
**Version:** `1.0.0` (Production Ready)  
**License:** MIT

---

## 1. Executive Summary & Problem Statement

Modern enterprise organizations face unprecedented data protection challenges:
- **Pervasive Insider Risk & Data Sprawl**: Sensitive intellectual property, credentials, and personal information (PII/PCI) frequently leak into unauthorized directories, unencrypted backups, and cloud staging folders.
- **DLP Fatigue & False Positives**: Traditional DLP engines generate high alert volumes by equating sensitive file discovery with active attacks, exhausting SOC analysts.
- **Privacy Paradox in Cloud AI**: Sending proprietary logs or sensitive file contents to external cloud AI APIs creates fresh compliance and data leakage vulnerabilities.
- **Telemetry Silos**: Filesystem activity, archive compression utilities, and network egress telemetry are rarely correlated in real time on the endpoint.

**SentinelDLP** was engineered to solve these challenges through a modular, defense-in-depth defensive security platform. It pairs low-level endpoint telemetry collection with deterministic risk scoring and a privacy-preserving, locally hosted AI SOC Analyst.

---

## 2. Core Architectural Pillars

### Pillar 1: Zero-Leakage Privacy & Streaming Processing
- **Streaming Cryptographic Hashing**: Memory-bounded (64 KB chunking) SHA-256 calculation for large corporate assets.
- **Deep Content Classification**: Detects PCI-DSS payment cards (with Luhn checksum validation), Pakistani CNICs, US SSNs, AWS Access Keys, GitHub PATs, and generic high-entropy API secrets (Shannon entropy &gt;4.5).
- **Irreversible Redaction**: Findings are automatically masked (e.g., `4532-••••-••••-1111`) before database storage or UI presentation.

### Pillar 2: Explainable, Deterministic Threat Scoring (0–100)
- **Context, Not Accusation**: File sensitivity is treated as threat context, not proof of malicious intent. Ordinary modifications to sensitive assets remain in the `LOW` band unless accompanied by abnormal velocity or structural changes.
- **Normalized Scoring Formulation**: Combines primary detection rule weights with diminishing secondary contributions, capped at 100 and mapped into transparent severity bands (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).

### Pillar 3: Multi-Signal Temporal Correlation
- Correlates independent security signals across sliding time windows (1m to 60m):
  1. Sensitive file access or rapid modification.
  2. Archive compression or staging (`.zip`, `.tar`, `.gz`).
  3. Outbound network egress telemetry or Zeek/Suricata IDS signatures.
- Maintains strict **telemetry modesty**: Links are classified as `circumstantial` or `temporal` without asserting unsupported causal claims.

### Pillar 4: AI SOC Analyst with Anti-Hallucination Verification
- **Dual Engine Architecture**: Zero-dependency deterministic mock provider active by default; zero-rebuild HTTP readiness for local Ollama instances (`llama3.2:3b` on 6GB RTX 2060).
- **Controlled Server-Side Tools**: 9 read-only tools bounded to a maximum of 6 executions per investigation, with complete non-repudiation auditing.
- **Anti-Hallucination Verification**: Cross-references every cited entity ID against verified database records; automatically discards fabricated references and invalid MITRE ATT&CK codes.
- **Defensive Prompt Boundaries**: Untrusted log data is securely enclosed within `<untrusted_telemetry>` blocks to neutralize indirect prompt injection attempts.

### Pillar 5: Cyberattack Simulation & Detection Validation Lab
- **11 Predefined Security Scenarios**: Automated end-to-end evaluation covering benign file activity, sensitive data discovery, ransomware-like renaming, and multi-stage data exfiltration.
- **Isolated Sandbox**: Confined strictly to `sample_data/simulation_lab/` with automatic post-run teardown.
- **Confusion Matrix Engine**: Measures True/False Positives, Precision, Recall, F1 Score, and Detection Latency against ground-truth benchmarks.

---

## 3. Engineering Metrics & Quality Assurance

- **Automated Test Suite:** **171 automated unit/integration tests** (`pytest 8.x`) passing with 100% success rate in ~18 seconds.
- **Frontend Architecture:** React 18 + TypeScript 5.4 + Vite 5 compiled with zero diagnostics; high-density dark cybersecurity theme.
- **Security Hardening:** Timing-safe token comparison (`secrets.compare_digest`), 10MB payload size limit, canonical path traversal rejection (CWE-22), and production deployment guards.
- **Container Readiness:** Multi-stage Docker Compose deployment running under dedicated non-root users (`sentinel` UID 1001) with internal bridge network isolation.

---

## 4. Key Takeaways for Technical Leadership

SentinelDLP demonstrates end-to-end engineering excellence across the modern cybersecurity spectrum:
1. **Low-Level Systems Awareness**: Efficient asynchronous I/O, streaming file processing, and thread-safe queue management.
2. **Detection Engineering Depth**: Practical application of MITRE ATT&CK, Suricata SID integration, and rule-based risk scoring.
3. **Applied AI Defense**: Practical local LLM integration that prioritizes evidence grounding, prompt injection defenses, and zero-leakage privacy over hype.
4. **Production Rigor**: Comprehensive testing, defense-in-depth API hardening, and clear architectural documentation.
