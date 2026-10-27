# Changelog

All notable changes to the **SentinelDLP** platform are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-10-27
### Phase 12: Final Release Engineering, Deployment Packaging & Professional Portfolio
#### Added
- **Production Packaging**: Finalized multi-stage Docker Compose orchestration running backend and frontend services under non-root users (`sentinel` UID 1001 and `nginx`).
- **GitHub Actions CI (`.github/workflows/ci.yml`)**: Continuous integration workflow running syntax checks, full 171-test pytest suite, TypeScript validation, Vite production bundling, and Docker Compose syntax validation.
- **PowerShell Operations Utilities**: Added `scripts/verify_health.ps1` for probing live component health and `scripts/run_demo.ps1` for interactive 15-step synthetic demonstrations.
- **Master Environment Reference**: Upgraded `.env.example` with complete configuration placeholders, security limits, and production safety guards.
- **Comprehensive Portfolio Documentation Suite**:
  - `docs/portfolio/project-overview.md`: Executive-level architecture, detection philosophy, and engineering challenges.
  - `docs/portfolio/cv-entry.md`: Resume-ready impact bullets backed by verified metrics.
  - `docs/portfolio/linkedin-post.md`: Project showcase announcement draft.
  - `docs/portfolio/demo-video-script.md`: 5–8 minute video demonstration walkthrough script.
  - `docs/portfolio/screenshot-guide.md`: Visual asset checklist covering all 10 operations consoles.
- **Future Development Roadmap (`FUTURE_ROADMAP.md`)**: Documented Phase 13+ roadmap including distributed fleet orchestration and automated quarantine.
- **Open Source Licensing**: Released under the standard MIT License (`LICENSE`).

---

## [0.11.0] - 2026-10-25
### Phase 11: Advanced Security Hardening, Vulnerability Assessment & Performance Optimization
#### Added
- **Authentication & RBAC (`app/core/auth.py`)**: Timing-safe token and API key validation (`secrets.compare_digest`) enforcing `ADMIN`, `ANALYST`, and `READONLY` privilege tiers.
- **Defensive ASGI Middlewares (`app/core/middleware.py`)**:
  - `SecurityHeadersMiddleware`: Direct injection of `nosniff`, `DENY`, `X-XSS-Protection`, and `Content-Security-Policy`.
  - `RequestSizeLimitMiddleware`: Rejection of incoming payloads >10MB with HTTP 413.
  - `RateLimitMiddleware`: In-memory sliding-window request throttling per client IP.
- **Path Traversal Defenses in Ingestion**: Boundary verification in `NetworkIngestionService._validate_ingestion_path` preventing directory traversal in PCAP and log ingestion (CWE-22).
- **Production Safety Controls**: Cyberattack simulations automatically blocked in `ENVIRONMENT=production` by default; startup configuration validator rejecting default passwords and keys.
- **Automated Security Regression Suite (`test_security_hardening.py`)**: 15 tests verifying auth bypass, RBAC escalation, path traversal, payload limits, and SQL injection resistance.
#### Changed
- Standardized all UTC timestamps to `datetime.now(timezone.utc)`, eliminating 75+ runtime deprecation warnings and improving test suite execution by 18.2%.

---

## [0.10.0] - 2026-10-25
### Phase 10: Cyberattack Simulation, Detection Validation & Security Testing Laboratory
#### Added
- **Predefined Scenario Library**: 11 deterministic testing scenarios covering benign activity, PII/credential discovery, rapid modification bursts, bulk ransomware-like renaming, archive staging, network flow spikes, and full exfiltration kill-chains.
- **Confined Synthetic Sandbox**: Isolated execution strictly restricted to `sample_data/simulation_lab/` with automated post-run purging.
- **Detection Accuracy Engine**: Evaluator computing True Positives, False Positives, True Negatives, False Negatives, Precision, Recall, F1 Score, FPR, and Latency.
- **Subsystem Coverage Matrix**: Granular mapping across File Scanner, Monitoring, Risk Engine, Exfiltration, Network, and AI Analyst.
- **Automated Markdown Audit Reports**: Stepper execution reports with MITRE ATT&CK mapping and downloadable audit summaries.
- **Interactive Security Lab UI (`SecurityLabPage.tsx`)**: Stepper runner, accuracy metric cards, and report viewer.

---

## [0.9.0] - 2026-10-25
### Phase 9: AI-Powered SOC Analyst, Local LLM Integration & Security Investigation
#### Added
- **Pluggable AI Architecture**: Deterministic Mock Provider for offline/zero-VRAM environments and local Ollama daemon integration (`llama3.2:3b`).
- **Server-Controlled Read-Only Tools**: 9 specialized evidence retrieval tools bounded by a max 6 calls limit per investigation and logged to `AIToolAuditEvent`.
- **Offline MITRE ATT&CK Validator**: Enterprise matrix mapping covering T1074.001, T1560.001, T1567.002, T1071.004, T1048.003, and T1020.
- **Anti-Hallucination Evidence Verification**: Verification validating cited record IDs against verified database entities.
- **Defensive Prompt Wrapping**: Zero-leakage credential masking and defensive wrapping of untrusted telemetry inside `<untrusted_telemetry>` tags.
- **Interactive AI Analyst Console (`AIAnalystPage.tsx`)**: Analyst chat interface, prompt pills, and review feedback.

---

## [0.8.0] - 2026-10-25
### Phase 8: Enterprise Security Operations Center Dashboard & Unified Intelligence
#### Added
- **Unified Executive Overview (`OverviewPage.tsx`)**: Real-time KPI metrics, 24-hour risk trend evolution, and multi-source activity stream.
- **Priority Analyst Triage Queue**: Consolidated triage queue ranking High/Critical alerts and open exfiltration cases.
- **Global Cross-Entity Metadata Search (`GlobalSearchModal.tsx`)**: `Ctrl+K` modal searching Alerts, Investigations, Scanned Files, Threat Intel, and Rules in a single optimized pass.
- **Enterprise SOC Navigation (`Sidebar.tsx`)**: Categorized navigation across Data Protection, Threat Intelligence, and Security Operations.

---

## [0.7.0] - 2026-10-25
### Phase 7: Advanced Network Traffic Monitoring & Threat Intelligence
#### Added
- **Multi-Source Network Telemetry Pipeline**:
  - Offline Zeek JSON Log Adapter (`conn.log`, `dns.log`, `http.log`, `ssl.log`).
  - Suricata EVE JSON Adapter (`flow`, `alert`, `dns`, `http`, `tls`, `stats`).
  - Zero-payload binary PCAP parser inspecting Ethernet, IPv4, TCP, and UDP headers.
- **Unified Normalized Network Event Schema (`NetworkEvent`)**: Standardized 5-tuple, protocol, directionality, packet counts, and DNS/TLS metadata.
- **Local RFC 1918 Threat Intelligence Catalog**: Local indicator registry storing IP, Domain, and CIDR definitions.
- **10 Network Detection Rules (`NET-001` through `NET-010`)**: Anomaly detection for outbound volume, connection velocity, port probes, DNS entropy/tunneling, and exfiltration correlation.

---

## [0.6.0] - 2026-10-25
### Phase 6: Advanced Data Exfiltration Detection & Event Correlation Engine
#### Added
- **Bounded Temporal Correlation**: Evaluation across 1m, 5m, 15m, 30m, and 60m time windows.
- **Staging Archive Recognition**: Heuristic detection of `.zip`, `.tar`, `.gz`, `.7z` archives following sensitive file access.
- **8 Exfiltration Detection Rules (`EXFIL-001` through `EXFIL-008`)**: Multi-signal exfiltration kill-chain reconstruction.
- **Strict Evidence Provenance Taxonomy**: Categorization of evidence into `OBSERVED`, `IMPORTED`, `LAB_SIMULATED`, and `INFERRED`.
- **Exfiltration Investigation Workspace (`ExfiltrationPage.tsx`)**: Forensic timeline reconstruction, link provenance inspection, and analyst case management.

---

## [0.5.0] - 2026-10-24
### Phase 5: Intelligent Threat Risk Scoring & Security Alert Engine
#### Added
- **Deterministic Threat Scoring**: 0–100 score normalization combining primary rule contributions and diminishing secondary weights.
- **Severity Bands**: `LOW` (0–29), `MEDIUM` (30–59), `HIGH` (60–79), and `CRITICAL` (80–100).
- **8 Security Detection Rules**: `RULE-SENS-MOD`, `RULE-RAPID-MOD`, `RULE-BULK-RENAME`, `RULE-SENS-DEL`, `RULE-REPEAT-CHANGE`, `RULE-SENS-VOLUME`, `RULE-EXT-CHANGE`, `RULE-COVERAGE-WARN`.
- **Sliding-Window Alert Suppression**: 300s window with repeat-counter tracking and full lifecycle management (`OPEN` &rarr; `ACKNOWLEDGED` &rarr; `INVESTIGATING` &rarr; `RESOLVED` / `FALSE_POSITIVE`).

---

## [0.4.0] - 2026-10-24
### Phase 4: Real-Time File Activity Monitoring & Security Event Collection
#### Added
- **Continuous Filesystem Monitoring**: Python `watchdog` monitoring authorized scan roots for creations, modifications, deletions, and moves.
- **Event Normalization & Debouncing**: 0.4s sliding window suppressing save storms.
- **Bounded Event Queue**: 5,000 max queue size with non-blocking ingestion and queue overflow telemetry.
- **Background Event Worker**: Automated hashing and sensitive content inspection on modified files.
- **Server-Sent Events (SSE)**: Streaming endpoint (`/monitoring/events/stream`) providing live telemetry to frontend.

---

## [0.3.0] - 2026-10-24
### Phase 3: Advanced Sensitive Data Detection & Classification Engine
#### Added
- **Content Extractors**: Plain text, source code, config files, PDF documents (`pypdf`), and Word documents (`python-docx`/XML).
- **Pattern Detectors**: PCI-DSS Payment Cards (Luhn checksum), US SSNs, AWS Access Keys, GitHub PATs, Bearer tokens (Shannon entropy), Private Keys, and Corporate Confidential Markers.
- **Explainable Classification Tiers**: `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`.
- **Zero-Leakage Masking**: Strict masking before database persistence and display (e.g. `4532-••••-••••-1111`).

---

## [0.2.0] - 2026-10-24
### Phase 2: Intelligent File Scanning Engine & File Inventory System
#### Added
- **Path Traversal & Symlink Defenses**: Strict boundary containment checking against authorized directories.
- **Streaming SHA-256 Hashing**: 64 KB chunking computing cryptographic hashes without memory exhaustion.
- **File Type & Magic Byte Detection**: Anomaly detection identifying extension mismatches (`type_mismatch`).
- **Asynchronous Scan Worker**: Non-blocking cooperative cancellation tokens.

---

## [0.1.0] - 2026-10-24
### Phase 1: Project Foundation & Backend Architecture
#### Added
- **Monorepo Architecture**: FastAPI asynchronous backend, SQLAlchemy 2.0 ORM, and Alembic migrations.
- **Relational Database**: PostgreSQL 16 container with health probes and Docker Compose orchestration.
- **React 18 Frontend**: TypeScript + Vite frontend with dark cybersecurity theme.
- **Dual-Tier Health Probes**: Process liveness (`/health/live`) and dependency readiness (`/health/ready`).
