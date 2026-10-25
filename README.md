# SentinelDLP — AI-Powered Data Loss Prevention & Exfiltration Detection Platform

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green.svg)](https://fastapi.tiangolo.com/)
[![React 18](https://img.shields.io/badge/React-18.3-blue.svg)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.4-blue.svg)](https://www.typescriptlang.org/)
[![Alembic](https://img.shields.io/badge/Alembic-1.20-orange.svg)](https://alembic.sqlalchemy.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com/)

---

## 1. Project Overview

**SentinelDLP** is an enterprise-grade defensive cybersecurity platform designed to monitor authorized endpoint activity, discover and inventory corporate data assets, identify sensitive intellectual property, detect suspicious data exfiltration attempts, and provide AI-assisted security investigations for SOC teams.

Designed with modular, defense-in-depth principles, SentinelDLP emphasizes zero-leakage security, explicit authorization boundaries, accurate telemetry attribution, and robust test-driven engineering.

---

## 2. Implementation Status: Phase 10 Complete

- **[COMPLETED] Phase 1 — Project Foundation & Architecture**
  - Robust FastAPI asynchronous backend, SQLAlchemy 2.0 ORM, and Alembic database migrations.
  - React 18 + TypeScript + Vite frontend with dark cybersecurity operations dashboard.
  - PostgreSQL 16 relational database with health probes and Docker Compose integration.
- **[COMPLETED] Phase 2 — Intelligent File Scanning Engine & Inventory System**
  - Path traversal and symlink escape defenses verifying authorized directories.
  - Streaming SHA-256 cryptographic hashing (64 KB chunking).
  - Multi-category file identification across Documents, Code, Config, Images, and Archives.
  - Magic byte inspection and extension mismatch detection (`type_mismatch` flag).
  - Asynchronous scan worker with non-blocking cooperative cancellation tokens.
- **[COMPLETED] Phase 3 — Sensitive Data Detection & Classification Engine**
  - Content extractors for plain text, source code, configs, PDF, and DOCX documents.
  - Comprehensive sensitive pattern detectors: PCI-DSS Payment Cards (with Luhn checksum validation), US SSNs, AWS Access Keys, GitHub PATs, Generic API Keys & Bearer Tokens (Shannon entropy analysis), Private Keys (RSA/EC/OpenSSH), and Corporate Confidential Markers.
  - Explainable classification tiers: `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`.
  - Zero-leakage redaction: sensitive findings are strictly masked (e.g. `4532-••••-••••-1111`) before database persistence and display.
- **[COMPLETED] Phase 4 — Real-Time File Activity Monitoring & Security Event Collection**
  - Continuous filesystem monitoring across authorized scan roots using Python `watchdog`.
  - Real-time observation of file and directory creations, modifications, deletions, renames, and moves.
  - Deduplication and debouncing engine (0.4s sliding window) suppressing multi-event save storms.
  - Thread-safe bounded event queue (5,000 max size) with non-blocking ingestion and queue overflow telemetry.
  - Background event worker automatically performing Phase 2 metadata extraction/hashing and Phase 3 sensitive content inspection on modified/created files.
  - Server-Sent Events (SSE) streaming endpoint (`/api/v1/monitoring/events/stream`) providing sub-second frontend updates.
  - Live Activity operational UI with live telemetry counters, start/stop session controls, live event feed, and zero-leakage event audit drawer.
  - Strict attribution transparency: Filesystem events record `event_source="watchdog"` and do not fabricate user or process attribution.
- **[COMPLETED] Phase 5 — Intelligent Threat Risk Scoring, Detection Rules & Security Alert Engine**
  - **Deterministic Threat Scoring**: Normalized 0–100 risk score combining primary rule contributions and diminishing secondary rule weights, with soft capping at 100.
  - **Configurable Severity Bands**: `LOW` (0–29), `MEDIUM` (30–59), `HIGH` (60–79), and `CRITICAL` (80–100).
  - **Core Philosophy**: **File sensitivity is context, not proof of malicious activity.** Ordinary modifications to sensitive assets remain in the LOW band unless supported by abnormal velocity, bulk operations, or structural alterations.
  - **8 Operational Threat Rules**: `RULE-SENS-MOD`, `RULE-RAPID-MOD`, `RULE-BULK-RENAME`, `RULE-SENS-DEL`, `RULE-REPEAT-CHANGE`, `RULE-SENS-VOLUME`, `RULE-EXT-CHANGE`, `RULE-COVERAGE-WARN`.
  - **Alert Lifecycle & Sliding-Window Suppression**: Bounded 5-minute suppression window with repeat-counter tracking; supports `OPEN` &rarr; `ACKNOWLEDGED` &rarr; `INVESTIGATING` &rarr; `RESOLVED` / `FALSE_POSITIVE` transitions with immutable audit trails.
- **[COMPLETED] Phase 6 — Advanced Data Exfiltration Detection & Security Event Correlation Engine**
  - **Bounded Temporal Correlation**: Evaluates telemetry across configurable time windows (1m, 5m, 15m, 30m, 60m), linking sensitive file access, archive staging, and outbound transfer telemetry.
  - **Archive Activity Staging Recognition**: Recognizes creation, modification, and renaming of archives (`.zip`, `.tar`, `.gz`, `.7z`, `.rar`, etc.) without asserting unsupported causal claims regarding contents.
  - **Synthetic Transfer Telemetry Interface**: Simulates and ingests outbound transfer evidence explicitly tagged with `LAB_SIMULATED` provenance.
  - **8 Operational Exfiltration Detection Rules**: `EXFIL-001` through `EXFIL-008` linking file activity, staging, volume anomalies, unfamiliar destinations, chunked transfers, and kill-chain exfiltration patterns.
  - **Strict Evidence Provenance Taxonomy**: `OBSERVED`, `IMPORTED`, `LAB_SIMULATED`, `INFERRED`.
  - **Forensic Relationship Modesty**: Labels connections as `temporal`, `circumstantial`, or `verified`.
- **[COMPLETED] Phase 7 — Advanced Network Traffic Monitoring, Detection Engineering & Threat Intelligence**
  - **Multi-Source Network Telemetry Pipeline**:
    - **Offline Zeek Log Adapter**: Ingests JSON log records (`conn.log`, `dns.log`, `http.log`, `ssl.log`/`tls.log`) mapping connection metrics, durations, byte counts, and protocol metadata.
    - **Suricata EVE JSON Adapter**: Parses normalized event streams (`flow`, `alert`, `dns` v1/v2, `http`, `tls`, `stats`), extracting signature metadata and Suricata SIDs.
    - **Offline Pure-Python PCAP Parser**: Zero-dependency binary parser inspecting Global and Packet headers, Ethernet, IPv4, TCP, and UDP structures. Discards raw payload data immediately at the parsing boundary to guarantee zero private payload leakage.
  - **Unified Normalized Network Event Schema (`NetworkEvent`)**:
    - Standardized 5-tuple (`source_ip`, `source_port`, `destination_ip`, `destination_port`, `transport_protocol`), application protocol, directionality (`OUTBOUND`, `INBOUND`, `INTERNAL`, `LATERAL`), duration, byte breakdowns (Tx/Rx), packet counts, DNS query metadata, TLS SNI, HTTP stem, and IDS signature mappings.
  - **Sensor Registry & Health Auditing**:
    - Registers Zeek, Suricata, and PCAP monitoring sensors with explicit health states (`ACTIVE`, `DEGRADED`, `OFFLINE`, `VISIBILITY_GAP`).
    - Explicitly surfaces Windows / Docker container boundary restrictions where promiscuous host packet sniffing is infeasible without driver installation, highlighting offline file and log ingestion capabilities.
  - **Privacy-First Local Threat Intelligence Registry**:
    - Local indicator catalog (`ThreatIntelIndicator`) storing administrator-defined IPv4, Domain, and CIDR indicators categorized as `TRUSTED`, `SUSPICIOUS`, `UNKNOWN`, and `MALICIOUS`.
    - Operates 100% offline with RFC 1918 internal subnet awareness, preventing private corporate IP address leakage to external intelligence APIs.
  - **10 Network Detection Rules (`NET-001` through `NET-010`)**:
    1. `NET-001`: Unusual Outbound Traffic Volume (&ge;10MB standard, &ge;100MB critical).
    2. `NET-002`: Repeated Connection Attempts (&ge;5 outbound flows to same remote endpoint).
    3. `NET-003`: Multi-Port Connection Activity (&ge;4 distinct ports scanned/connected).
    4. `NET-004`: Unusual DNS Query Frequency (&ge;20 queries to single domain within 5m window).
    5. `NET-005`: DNS Query Pattern Anomalies (Shannon entropy &gt;3.8 or subdomain label &gt;52 chars indicative of DNS tunneling).
    6. `NET-006`: Unfamiliar Outbound Destination (external flow outside trusted allowlists).
    7. `NET-007`: Suricata Signature Alert (direct mapping to SentinelDLP alert engine with SID attribution).
    8. `NET-008`: Network and Sensitive File Activity Correlation (bridges network telemetry with Phase 6 exfiltration investigations, tagging transfer evidence as `IMPORTED` or `OBSERVED` with explicit `circumstantial` relationship tags).
    9. `NET-009`: Network Visibility Gap (diagnostic coverage warning when sensor offline or restricted by container boundary).
    10. `NET-010`: Multi-Signal Network Investigation (compound detection requiring multiple independent network risk indicators).
- **[COMPLETED] Phase 8 — Enterprise Security Operations Center Dashboard & Unified Security Intelligence**
  - **Unified Executive SOC Overview (`/api/v1/dashboard/overview`)**:
    - High-density KPI cards: Active Alerts, Open Exfiltration Cases, Sensitive Files Protected, Live Sensors, and Visibility Coverage Gaps.
    - Risk Trend & Score Distribution Visualizations: 24-hour time-bucketed risk evolution and severity tier proportions.
    - Real-Time Multi-Source Security Activity Stream: Unified chronological feed synthesizing filesystem activity, threat alerts, correlation rules, and network IDS signatures.
    - Priority Analyst Triage Queue: Consolidated queue dynamically ranking high/critical alerts and unresolved investigations with quick-action links.
  - **Unified Cross-Entity Metadata Search (`/api/v1/dashboard/search`)**:
    - Global multi-source lookup querying Security Alerts, Exfiltration Cases, Scanned Files, Threat Indicators, and Detection Rules in a single optimized pass.
    - Global Search Modal (`Ctrl+K` or `/`) with real-time debounced queries and immediate tab/item navigation.
  - **Enterprise SOC Navigation Architecture**:
    - Collapsible sidebar with categorized functional groups:
      - **Overview**: SOC Dashboard
      - **Data Protection**: File Scanner, Sensitive Data, File Activity
      - **Threat Intelligence**: Risk Intelligence, Exfiltration Detection, Network Intelligence
      - **Security Operations**: Alerts Console, Investigation Workspace
      - **System**: System Health, Settings & Policy, Architecture Docs
  - **Dedicated Security Operations Consoles**:
    - **Alerts Console**: Centralized alert triage, multi-criteria filtering, threat score explanation breakdown, status lifecycle management (`OPEN` &rarr; `ACKNOWLEDGED` &rarr; `INVESTIGATING` &rarr; `RESOLVED` &rarr; `FALSE_POSITIVE`), and immutable audit trail history.
    - **Investigation Workspace**: Exfiltration case deep-dive, multi-stage forensic event timeline, evidence link provenance inspection, causal modesty disclosures, and investigator case management.
  - **Observability & System Health Matrix**:
    - Subsystem capability matrix for all 8 platform engines and sensors (File Scanner, Watchdog Monitor, Classification Engine, Threat Risk Engine, Exfiltration Correlation, Zeek Sensor, Suricata Sensor, PostgreSQL Database).
    - Container isolation boundary disclosure and telemetry freshness indicators.
  - **Full Automated Testing Suite**:
    - **156 passing automated pytest tests** covering API contracts, correlation logic, risk scoring, network adapters, dashboard aggregation, AI SOC Analyst, and the complete Phase 10 Simulation Laboratory.
- **[COMPLETED] Phase 9 — AI-Powered SOC Analyst, Local LLM Integration & Intelligent Security Investigation**
  - **Modular AI Provider Architecture**: Pluggable provider abstraction with a zero-dependency deterministic Mock AI Provider (active by default for zero-disk, zero-VRAM offline testing) and complete HTTP integration ready for local Ollama daemons (`llama3.2:3b` on 6GB RTX 2060).
  - **Controlled Server-Side Read-Only Tools**: 9 specialized tools (`get_alert`, `get_risk_assessment`, `get_file_classification`, `get_file_activity`, `get_investigation_timeline`, `get_exfiltration_evidence`, `get_network_events`, `get_sensor_status`, `get_mitre_technique`) bounded by a max 6 calls limit per investigation and logged to `AIToolAuditEvent`.
  - **Offline MITRE ATT&CK Enterprise Matrix**: Local catalog and validator covering Data Staging (T1074.001), Archive Utilities (T1560.001), Web Service Exfiltration (T1567.002), DNS C2 (T1071.004), Alternative Protocols (T1048.003), and Automated Exfiltration (T1020).
  - **Anti-Hallucination Evidence Verification**: Automatic post-generation verification validating all cited record IDs against verified database entities; rejects fabricated references and invalid technique codes.
  - **Indirect Prompt Injection & Privacy Safeguards**: Zero-leakage credential redaction (passwords, tokens, payment cards, SSNs) and defensive wrapping of untrusted log metadata inside `<untrusted_telemetry>` tags.
  - **Human-in-the-Loop Analyst Review**: Investigation reports preserve deterministic numerical risk scores, provide qualitative confidence ratings (`STRONG_SUPPORT`, `PARTIAL_SUPPORT`, `LIMITED_SUPPORT`, `INSUFFICIENT_EVIDENCE`), and accept human review feedback (`USEFUL`, `INCORRECT`, `NEEDS_REVIEW`).
  - **Interactive AI SOC Analyst Console & Workspace Integration**: Dedicated chat interface (`/ai-analyst`) with session history and prompt pills, plus deep integration into the Investigation Workspace.
- **[COMPLETED] Phase 10 — Advanced Cyberattack Simulation, Detection Validation & Security Testing Laboratory**
  - **Predefined Security Scenario Library (11 Distinct Scenarios)**:
    1. `SCEN-01`: Ordinary File Activity (Benign baseline & false-positive resistance verification).
    2. `SCEN-02`: Sensitive Data Discovery (Synthetic Pakistani CNIC, Luhn-valid cards, API tokens).
    3. `SCEN-03`: Rapid Sensitive File Modification (Velocity thresholds & threat score escalation).
    4. `SCEN-04`: Bulk File Renaming (Ransomware-like renaming heuristics & extension tampering).
    5. `SCEN-05`: Archive Activity (Safe ZIP staging recognition without plaintext over-claims).
    6. `SCEN-06`: Synthetic Network Traffic Anomalies (Flow spikes, multi-port probes, DNS entropy).
    7. `SCEN-07`: Potential Data Exfiltration (Multi-signal correlation chain: sensitive edit + archive + outbound transfer).
    8. `SCEN-08`: Unrelated Network Activity (Negative control verifying zero cross-endpoint correlation).
    9. `SCEN-09`: Monitoring Coverage Gap / Inactive Sensor Diagnostic (Degraded sensor & boundary detection).
    10. `SCEN-10`: Duplicate & Out-of-Order Event Handling (Idempotency and alert repeat counter suppression).
    11. `SCEN-11`: AI SOC Analyst Evaluation (Evaluates AI report generation, evidence grounding, and anti-prompt injection).
  - **Isolated Synthetic Data Generator & Containment Sandbox**:
    - Generates strictly harmless, fictional test files (Python diagnostic scripts, CSV with Pakistani CNIC, JSON with Luhn credit cards, ENV with synthetic AWS keys, ZIP bundles).
    - Absolute confinement to `sample_data/simulation_lab/` with path traversal rejection and automatic post-run sandbox purging.
  - **Detection Accuracy & Confusion Matrix Analytics Engine**:
    - Calculates True Positives (TP), False Positives (FP), True Negatives (TN), False Negatives (FN), Precision (%), Recall (%), F1 Score (%), False Positive Rate (FPR), and Detection Latency (ms).
  - **Subsystem Coverage Matrix**:
    - Evaluates detection capability across all 6 platform subsystems: File Scanner, Filesystem Monitoring, Threat Risk Engine, Exfiltration Correlation, Network Telemetry, and AI Analyst.
  - **Automated Markdown Audit Reports**:
    - Automatically renders and stores structured audit reports with MITRE ATT&CK mapping, rule comparison breakdown, and step-by-step execution timelines.
  - **Interactive Frontend Testing Laboratory (`SecurityLabPage.tsx`)**:
    - Dedicated laboratory interface with scenario filtering, real-time stepper execution, live accuracy metrics, subsystem coverage matrix, historical runs table, and markdown report viewer/downloader.
- **[PLANNED] Phase 11 — Enterprise Multi-Tenancy & Distributed Agent Fleet Orchestration**

---

## 3. Technology Stack

### Backend
- **Framework**: FastAPI (Asynchronous Web API)
- **Settings & Validation**: Pydantic v2 & Pydantic-Settings
- **ORM & Migrations**: SQLAlchemy 2.0 & Alembic
- **Database**: PostgreSQL 16 (Alpine)
- **Filesystem Monitoring**: Watchdog 4.0
- **Document Parsing**: PyPDF & python-docx
- **Server**: Uvicorn ASGI

### Frontend
- **Framework**: React 18 & TypeScript 5.4
- **Tooling**: Vite 5
- **Icons**: Lucide React
- **Design System**: Cybersecurity Dark Theme (`#0a0e17` background with `#10b981` emerald / `#f59e0b` amber / `#ef4444` red accents)

### Container Architecture
- **Multi-stage Docker** configurations running under non-root users (`sentinel` UID 1001, and `nginx` non-root user).
- **Internal service networking** and persistent named volumes.

---

## 4. Phase 5 Risk Scoring & Security Alert Architecture

```
┌────────────────────────────────────────────────────────┐
│         Normalized File Activity Event (Phase 4)       │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│            Temporal Context Builder (DB-Backed)        │
│  - 5-min window: distinct modified files, renames      │
│  - 15-min window: sensitive deletions, sensitive vol   │
│  - Monitoring health: queue overflow & capture drops   │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│           Security Detection Rules Evaluator           │
│  Evaluates 8 rules against event and temporal metrics  │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│           Deterministic Scoring Engine (0–100)         │
│  - Primary rule points + 0.6 * secondary rule points   │
│  - Capped at 100; maps to LOW, MEDIUM, HIGH, CRITICAL  │
│  - Evidence Completeness & Confidence assessment       │
│  - Human-readable explanation & SOC recommendations    │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│          Alert Service & Suppression Engine            │
│  - Evaluates alerting thresholds (score >= 30)         │
│  - Deduplication key: hash(root + rule + file_path)    │
│  - 300s sliding-window suppression (increments repeat) │
│  - Triage lifecycle: OPEN -> ACK -> INVEST -> RESOLVED │
│  - Immutable audit trail (alert_audit_logs table)      │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│       React Frontend: Risk Intelligence Dashboard      │
│  - Risk overview & severity breakdown tiles            │
│  - Filterable security alerts table                    │
│  - Slide-out alert investigation & triage drawer       │
│  - Detection rules catalog reference                   │
└────────────────────────────────────────────────────────┘
```

### Defensive Technical Boundaries
Filesystem observer telemetry indicates file creation, modification, deletion, and movement. It **does not** confirm process attribution, authenticated user credentials, memory access, or network exfiltration. SentinelDLP documents these boundaries truthfully in every assessment without fabricating telemetry.

---

## 5. API Endpoints Reference

### Health Probes
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health/live` | Application process liveness probe |
| `GET` | `/health/ready` | Dependency readiness probe (PostgreSQL database connectivity) |

### Scanner & Inventory (Phase 2 & Phase 3)
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/scanner/roots` | List administrator-configured authorized scan roots |
| `POST` | `/api/v1/scans` | Start background file scan job on an authorized root |
| `GET` | `/api/v1/scans` | List historical scan runs |
| `GET` | `/api/v1/scans/{scan_id}` | Get status and metrics of a scan job |
| `GET` | `/api/v1/scans/{scan_id}/files` | Paginated file inventory with search, mismatch & sensitivity filters |
| `POST` | `/api/v1/scans/{scan_id}/cancel` | Cancel an ongoing scan job |
| `GET` | `/api/v1/scans/{scan_id}/files/{file_id}/findings` | Retrieve explainable sensitive data detection findings for a file |

### Real-Time Activity Monitoring (Phase 4)
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/monitoring/roots` | List authorized roots available for real-time monitoring |
| `GET` | `/api/v1/monitoring/status` | Current active monitoring sessions and watcher status |
| `POST` | `/api/v1/monitoring/start` | Start real-time monitoring observer on an authorized root |
| `POST` | `/api/v1/monitoring/stop` | Stop monitoring session on an authorized root |
| `GET` | `/api/v1/monitoring/events` | Paginated query of captured file activity events with filters |
| `GET` | `/api/v1/monitoring/events/{event_id}` | Detailed event inspection record |
| `GET` | `/api/v1/monitoring/statistics` | Aggregated telemetry (total events, deduplicated, queue overflows) |
| `GET` | `/api/v1/monitoring/events/stream` | Server-Sent Events (SSE) real-time event stream for dashboards |

### Risk Intelligence & Security Alerts (Phase 5)
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/risk/assessments` | Paginated risk assessments with multi-parameter filtering |
| `GET` | `/api/v1/risk/assessments/{assessment_id}` | Complete assessment detail with granular rule matches and evidence |
| `GET` | `/api/v1/risk/statistics` | Aggregated risk metrics, score distribution, and average threat score |
| `GET` | `/api/v1/risk/rules` | Active detection rules catalog, thresholds, and template definitions |
| `GET` | `/api/v1/alerts` | Paginated security alerts with status and severity filters |
| `GET` | `/api/v1/alerts/{alert_id}` | Comprehensive alert detail with linked assessment and audit trail |
| `PATCH` | `/api/v1/alerts/{alert_id}/status` | Update alert triage lifecycle status with analyst commentary |
| `GET` | `/api/v1/alerts/statistics` | SOC triage metrics (counts by status: OPEN, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE) |

### Data Exfiltration & Event Correlation (Phase 6)
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/exfiltration/investigations` | List correlated exfiltration investigations with multi-parameter filtering |
| `GET` | `/api/v1/exfiltration/investigations/{id}` | Detailed investigation view including matched rules and evidence links |
| `GET` | `/api/v1/exfiltration/investigations/{id}/timeline` | Chronological forensic timeline with provenance tags and relationship taxonomy |
| `GET` | `/api/v1/exfiltration/investigations/{id}/evidence` | List granular evidence items linked to an investigation |
| `PATCH` | `/api/v1/exfiltration/investigations/{id}/status` | Update triage state (OPEN, ACKNOWLEDGED, INVESTIGATING, RESOLVED, etc.) and audit notes |
| `GET` | `/api/v1/exfiltration/statistics` | High-level metrics (total cases, open cases, critical alerts, simulated transfer counts) |
| `GET` | `/api/v1/exfiltration/rules` | Catalog of all 8 exfiltration detection rules with weights and descriptions |
| `POST` | `/api/v1/exfiltration/correlate` | Trigger bounded temporal correlation pass across recent telemetry |
| `POST` | `/api/v1/exfiltration/transfers/import` | Batch ingest outbound transfer telemetry (LAB_SIMULATED / external) |
| `POST` | `/api/v1/exfiltration/transfers/simulate` | Generate synthetic lab exfiltration scenarios for testing & demonstration |
| `GET` | `/api/v1/exfiltration/transfers` | List recorded outbound transfer telemetry events |

### Phase 7 Network Telemetry & Threat Intelligence API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/network/status` | Network sensor health overview, active sensor counts, and visibility gap warnings |
| `GET` | `/api/v1/network/sensors` | List registered network monitoring sensors (Zeek, Suricata, PCAP Analyzer) |
| `GET` | `/api/v1/network/connections` | Paginated flow events filterable by source IP, destination IP, protocol, min bytes |
| `GET` | `/api/v1/network/dns` | DNS query frequency distribution, NXDOMAIN counters, and entropy anomalies |
| `GET` | `/api/v1/network/alerts` | Normalized IDS alerts (Suricata signatures and Zeek notices) with severity tags |
| `GET` | `/api/v1/network/statistics` | Dashboard KPI metrics (connections, outbound bytes, DNS queries, IDS alerts) |
| `GET` | `/api/v1/network/traffic-summary` | Time-series outbound volume trends for `1h`, `24h`, and `7d` intervals |
| `GET` | `/api/v1/network/destinations` | Top outbound remote destinations with threat intelligence categorization badges |
| `GET` | `/api/v1/network/ingestion-jobs` | Ingestion audit trail tracking processed, rejected, and deduplicated records |
| `GET` | `/api/v1/network/rules` | Registered catalog of all 10 network detection rules (NET-001 through NET-010) |
| `POST` | `/api/v1/network/ingest` | Ingest offline Zeek JSON, Suricata EVE JSON, or PCAP binary headers |
| `POST` | `/api/v1/network/simulate` | Generate synthetic test scenarios (Zeek upload, Suricata SID alert, DNS burst) |
| `GET` | `/api/v1/network/threat-intel/indicators` | List administrator-configured offline indicator catalog (IPv4, Domain, CIDR) |
| `POST` | `/api/v1/network/threat-intel/indicators` | Register new local threat intelligence indicator |

---

## 6. Database Schema & Migrations

Database schema management is handled via Alembic migrations:

1. `0001_initial_schema.py`: Base system configurations.
2. `0002_scan_jobs_and_files.py`: `scan_jobs` and `scanned_files` tables for Phase 2 file inventory.
3. `0003_classification_and_findings.py`: `file_classifications` and `detection_findings` tables for Phase 3 sensitive data discovery.
4. `0004_file_activity_monitoring.py`: `monitoring_configurations`, `file_activity_events`, and `monitoring_sessions` tables for Phase 4 real-time tracking.
5. `0005_risk_scoring_and_alerts.py`: `risk_assessments`, `rule_matches`, `security_alerts`, and `alert_audit_logs` tables for Phase 5 risk scoring and SOC triage.
6. `0006_exfiltration_correlation.py`: `transfer_events`, `exfiltration_investigations`, `correlation_records`, and `investigation_evidence_links` tables for Phase 6 multi-signal correlation.
7. `0007_network_monitoring.py`: `network_sensors`, `network_events`, `network_alert_references`, `network_ingestion_jobs`, `network_baselines`, and `threat_intel_indicators` tables for Phase 7 network intelligence.

---

## 7. Quick Start (Windows 11 & Docker)

### Option A: Docker Compose (Full Stack)
```powershell
# Build and start all services in detached mode
docker compose up --build -d

# Check service health
docker compose ps
```
- **Web Dashboard**: [http://localhost:5173](http://localhost:5173)
- **API Swagger Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **System Health Monitor**: [http://localhost:8000/health/ready](http://localhost:8000/health/ready)

### Option B: Local Python & Node Execution
```powershell
# 1. Activate Python virtual environment and install dependencies
.\.venv\Scripts\activate
pip install -r backend\requirements.txt

# 2. Run database migrations
cd backend
alembic upgrade head
cd ..

# 3. Start Backend API
.\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --port 8000 --host 127.0.0.1 --reload

# 4. In a separate terminal, start Frontend
cd frontend
npm.cmd install
npm.cmd run dev
```

---

## 8. Automated Test Suite

SentinelDLP maintains a comprehensive automated test suite spanning unit tests, integration tests, boundary verifications, and cryptographic vectors.

Run the full pytest suite (**156 tests passed across Phases 1 through 10**):

```powershell
.\.venv\Scripts\python.exe -m pytest -v backend\tests
```

### Test Coverage Highlights:
- **Phase 2 Scanner**: Streaming SHA-256 chunking, magic-byte mismatch detection, directory traversal security, and cooperative cancellation tokens.
- **Phase 3 Detection Engine**: Luhn algorithm validation, Shannon entropy calculation, high-confidence secret masking, PDF/DOCX content extraction, and policy classification.
- **Phase 4 Monitoring**: Watchdog event normalization, path traversal blocking, 0.4s sliding-window debouncing, bounded queue saturation & overflow tracking, live session lifecycle, and SSE event streaming.
- **Phase 5 Risk Engine**: 0–100 score normalization, diminishing returns formula, 8 security detection rules evaluated individually and in combinations, alert deduplication and 300s sliding-window suppression, analyst triage lifecycle transitions, audit logging, and REST API validation.
- **Phase 6 Exfiltration Engine**: Bounded temporal correlation across 1m, 5m, 15m, 30m, and 60m windows, 8 deterministic exfiltration rules (EXFIL-001 through EXFIL-008), multi-signal chain reconstruction, strict provenance tagging (OBSERVED, IMPORTED, LAB_SIMULATED, INFERRED), forensic relationship taxonomy (temporal, circumstantial, verified), chronological timeline synthesis, and REST API integration.
- **Phase 7 Network Engine**: Offline Zeek JSON adapter (`conn.log`, `dns.log`, `http.log`, `ssl.log`), Suricata EVE JSON parser, zero-payload binary PCAP parser, 10 network detection rules (NET-001 through NET-010), offline threat intelligence lookup, deduplication logic, and full REST API endpoint validation.
- **Phase 8 Unified Dashboard**: Consolidated executive telemetry KPI aggregation, global multi-source metadata lookup across 5 entities, high-density priority triage queue, and 8-subsystem health matrix.
- **Phase 9 AI SOC Analyst**: Pluggable provider architecture (Deterministic Mock + Ollama local LLM), 9 controlled read-only investigation tools with call-budget limits and audit trails, offline MITRE ATT&CK Enterprise Matrix validator, automated post-generation evidence verification against verified database entities, prompt injection defenses, and qualitative investigation reporting with human-in-the-loop analyst review.
- **Phase 10 Simulation Laboratory**: Comprehensive cyberattack simulation laboratory spanning 11 reproducible attack scenarios, strictly isolated synthetic data generation within sandboxed boundaries, automated detection accuracy & confusion matrix analytics (TP, FP, TN, FN, Precision, Recall, F1, FPR, Latency), 6-subsystem detection coverage matrix, and automated markdown audit reports.

---

## 9. Project Roadmap

- **[x] Phase 1: Project Foundation, Backend Architecture & Development Environment**
- **[x] Phase 2: Intelligent File Scanning Engine & File Inventory System**
- **[x] Phase 3: Advanced Sensitive Data Detection & Classification Engine**
- **[x] Phase 4: Real-Time File Activity Monitoring & Security Event Collection**
- **[x] Phase 5: Intelligent Threat Risk Scoring, Detection Rules & Security Alert Engine**
- **[x] Phase 6: Advanced Data Exfiltration Detection & Security Event Correlation Engine**
- **[x] Phase 7: Advanced Network Traffic Monitoring, Detection Engineering & Threat Intelligence**
- **[x] Phase 8: Enterprise Security Operations Center Dashboard & Unified Security Intelligence**
- **[x] Phase 9: AI-Powered SOC Analyst, Local LLM Integration & Intelligent Security Investigation**
- **[x] Phase 10: Advanced Cyberattack Simulation, Detection Validation & Security Testing Laboratory**
- **[ ] Phase 11: Enterprise Multi-Tenancy & Distributed Agent Fleet Orchestration**
