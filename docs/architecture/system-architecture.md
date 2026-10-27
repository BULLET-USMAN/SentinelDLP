# SentinelDLP — System Architecture Specification (v1.0.0)

This document provides a comprehensive architectural reference for **SentinelDLP**, an AI-powered Data Loss Prevention and Exfiltration Detection Platform.

---

## 1. System Overview Architecture

SentinelDLP follows a modular, defense-in-depth architecture dividing responsibilities across presentation, API mediation, detection intelligence, background workers, and persistent relational storage.

```mermaid
flowchart TD
    subgraph UI ["Frontend Security Operations Center (React 18 + TypeScript 5.4)"]
        Dashboard["SOC Dashboard & Metrics"]
        Consoles["10 Dedicated Security Consoles"]
        AIConsole["AI SOC Analyst Interface"]
        SSEListener["Server-Sent Events Subscriber"]
    end

    subgraph API ["Mediation & Defense Layer (FastAPI + ASGI Middlewares)"]
        SecHeaders["Security Headers Middleware\n(CSP, nosniff, DENY)"]
        RateLimiter["Rate Limiter & Size Guard\n(10MB Bounded)"]
        AuthRBAC["Timing-Safe RBAC\n(ADMIN, ANALYST, READONLY)"]
        Routers["Versioned REST API Endpoints\n(/api/v1/*)"]
    end

    subgraph Engines ["Detection & Intelligence Engines"]
        ScanEngine["File Scanner Engine\n(Streaming SHA-256)"]
        ClassEngine["Sensitive Data Classifier\n(Luhn, Regex, Entropy)"]
        MonitorEngine["Filesystem Watchdog Monitor\n(400ms Debounce Queue)"]
        RiskEngine["Threat Risk Scoring Engine\n(Deterministic 0-100)"]
        ExfilEngine["Exfiltration Correlation Engine\n(Temporal Linker)"]
        NetEngine["Network Telemetry Engine\n(Zeek, Suricata, PCAP)"]
        SimLab["Cyberattack Simulation Lab\n(11 Harmless Scenarios)"]
    end

    subgraph AI ["Cognitive Intelligence Layer"]
        AIOrc["AI SOC Orchestrator"]
        Tools["9 Read-Only Investigation Tools\n(Max 6 Calls Bounded)"]
        Verifier["Anti-Hallucination Verifier"]
        MockLLM["Deterministic Mock Provider"]
        OllamaLLM["Local Ollama Daemon (HTTP)"]
    end

    subgraph Storage ["Persistence & State Layer"]
        Postgres[(PostgreSQL 16 Relational DB)]
        SandboxDir[("sample_data/simulation_lab/ (Isolated)")]
    end

    UI <-->|REST + SSE| API
    API --> Engines
    Engines --> Storage
    Engines --> AI
    AI --> Tools
    Tools --> Storage
    AIOrc --> Verifier
    AIOrc --> MockLLM
    AIOrc -.-> OllamaLLM
```

---

## 2. Telemetry Processing & Detection Pipeline

Every filesystem and network event traverses a multi-stage deterministic pipeline before surfacing as a prioritized SOC alert.

```mermaid
flowchart LR
    EventIn["Filesystem / Network Event"] --> Debounce["Debouncer & Deduplicator\n(0.4s Window)"]
    Debounce --> BoundedQ["Thread-Safe Queue\n(5,000 Capacity)"]
    BoundedQ --> Worker["Asynchronous Event Worker"]
    Worker --> Extract["Content Extraction & Hashing\n(Streaming SHA-256)"]
    Extract --> Classify["Content Inspection\n(Luhn / Regex / Entropy)"]
    Classify --> Redact["Zero-Leakage Redaction\n(Masking at Rest)"]
    Redact --> RiskEval["Deterministic Threat Scoring\n(0-100 Scoring Model)"]
    RiskEval --> ExfilCorr["Temporal Exfiltration Correlation\n(Staging + Transfer)"]
    ExfilCorr --> AlertGen["Alert Lifecycle & Sliding Suppression\n(300s Deduplication)"]
    AlertGen --> SOCView["Enterprise SOC Stream & SSE Push"]
```

---

## 3. Network Telemetry Ingestion Architecture

SentinelDLP accepts normalized security telemetry from industry-standard network sensors while respecting container and OS boundaries:

```mermaid
flowchart TD
    subgraph Sensors ["Telemetry Ingestion Adapters"]
        Zeek["Offline Zeek Adapter\n(conn.log, dns.log, http.log, ssl.log)"]
        Suricata["Suricata EVE JSON Adapter\n(flow, alert, dns, http, tls)"]
        PCAP["Pure-Python PCAP Parser\n(Zero-dependency Ethernet/IP/TCP)"]
    end

    subgraph Boundaries ["Security & Visibility Boundary"]
        ContainerDisc["Sensor Health & Visibility Auditing\n(Surfaces Host Sniffing Gaps)"]
        PayloadDrop["Zero Private Payload Retention\n(Payloads Discarded Immediately)"]
        BoundaryDefense["Canonical Path Traversal Guard\n(CWE-22 Confinement)"]
    end

    subgraph Intel ["Network Detection & Threat Intel"]
        NetRules["10 Network Detection Rules\n(NET-001 through NET-010)"]
        ThreatIntel["Local Offline Indicator Registry\n(RFC 1918 Aware, No Data Leakage)"]
    end

    Sensors --> Boundaries
    Boundaries --> Intel
    Intel --> DB[(PostgreSQL 16)]
```

---

## 4. AI SOC Analyst Investigation & Verification Sequence

The AI SOC Analyst operates strictly under a read-only, audited, and anti-hallucination execution sequence:

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as SOC Security Analyst
    participant API as FastAPI Mediation Layer
    participant Orc as AI SOC Orchestrator
    participant Tools as Controlled Server-Side Tools
    participant DB as PostgreSQL 16
    participant LLM as Deterministic Mock / Ollama
    participant Verifier as Anti-Hallucination Verifier

    Analyst->>API: POST /api/v1/ai/investigate (alert_id)
    API->>Orc: Initiate bounded investigation
    Orc->>Tools: Invoke get_alert(alert_id)
    Tools->>DB: Fetch sanitized alert record
    DB-->>Tools: Return masked alert metadata
    Tools-->>Orc: Log tool call to AIToolAuditEvent
    Orc->>Tools: Invoke get_risk_assessment & get_investigation_timeline
    Tools->>DB: Query correlated records
    DB-->>Tools: Return timeline entities
    Tools-->>Orc: Enforce max 6 tool calls boundary
    Orc->>LLM: Send structured prompt with <untrusted_telemetry> wrapper
    LLM-->>Orc: Return draft investigation report
    Orc->>Verifier: Validate cited entity IDs & MITRE techniques
    Verifier->>DB: Verify record IDs exist in database
    Verifier-->>Orc: Validated findings (strip invalid references)
    Orc->>DB: Persist AIInvestigationReport
    Orc-->>API: Return grounded security report
    API-->>Analyst: Display structured SOC report with Confidence Rating
```

---

## 5. Defensive Security Boundaries & Modesty Taxonomy

### Telemetry Provenance Taxonomy
All security evidence collected or inferred is tagged with explicit provenance:
1. `OBSERVED`: Directly captured by an active local sensor (e.g. Watchdog filesystem event, parsed PCAP header).
2. `IMPORTED`: Parsed from external sensor log exports (e.g. Zeek `conn.log`, Suricata `eve.json`).
3. `LAB_SIMULATED`: Synthetically generated inside the isolated attack testing laboratory.
4. `INFERRED`: Derived algorithmically via temporal correlation or secondary rule weights.

### Causal Modesty in Exfiltration Detection
When SentinelDLP correlates file creation with outbound transfer activity:
- It tags relationships as `temporal` or `circumstantial`.
- It explicitly disclaims deterministic claims of file content exfiltration unless direct payload byte hashes match remote socket streams.

### Isolation & Sandboxing Confinement
- The Cyberattack Simulation Lab operates strictly inside `sample_data/simulation_lab/`.
- Attempts to target files outside this boundary are rejected with canonical path errors.
- Simulation execution is blocked in production environments by default (`ENVIRONMENT=production`).
