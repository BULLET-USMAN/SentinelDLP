# SentinelDLP — Phase 11: Security Hardening & Vulnerability Assessment
## Architecture, Threat Model & Hardening Specifications

**Status:** Phase 11 Active  
**Baseline Tests:** 156 passing tests across Phases 1–10  

---

## 1. Executive Summary

This specification establishes the Phase 11 security hardening, vulnerability assessment, and performance optimization architecture for SentinelDLP. SentinelDLP is a defensive cybersecurity platform that processes endpoint file activity, performs cryptographic hashing and sensitive classification, correlates exfiltration patterns, and provides an AI SOC Analyst with controlled evidence-gathering tools.

---

## 2. STRIDE Threat Model

```mermaid
flowchart TD
    subgraph Client ["Client Perimeter"]
        Browser["Analyst Web Console (React 18)"]
        ExternalAttacker["Unauthorized Network Actor"]
    end

    subgraph Gateway ["Perimeter & Security Middleware"]
        Nginx["Nginx Reverse Proxy"]
        SecHeaders["SecurityHeadersMiddleware"]
        SizeLimit["RequestSizeLimitMiddleware"]
        AuthRBAC["Authentication & RBAC Dependency"]
    end

    subgraph Services ["Application Subsystems"]
        CoreAPI["FastAPI Core Router"]
        Scanner["File Scanner & Inventory"]
        Classifier["Sensitive Data Detection"]
        Monitoring["Watchdog Activity Monitor"]
        RiskEngine["Threat Risk Scoring Engine"]
        ExfilEngine["Exfiltration Correlation"]
        NetworkEngine["Network Telemetry Engine"]
        AIAnalyst["AI SOC Analyst (Bounded Tools)"]
        Simulation["Simulation Laboratory"]
    end

    subgraph DataStore ["Data Storage & File Boundaries"]
        Postgres[(PostgreSQL 16 Database)]
        AuthorizedRoots["Authorized Scan Directories"]
        SimSandbox["Isolated Simulation Sandbox"]
    end

    Browser -->|HTTPS / REST| Nginx
    ExternalAttacker -.->|Unauthorized Requests| Nginx
    Nginx --> SecHeaders
    SecHeaders --> SizeLimit
    SizeLimit --> AuthRBAC
    AuthRBAC --> CoreAPI

    CoreAPI --> Scanner
    CoreAPI --> Classifier
    CoreAPI --> Monitoring
    CoreAPI --> RiskEngine
    CoreAPI --> ExfilEngine
    CoreAPI --> NetworkEngine
    CoreAPI --> AIAnalyst
    CoreAPI --> Simulation

    Scanner -->|Read-Only Boundary| AuthorizedRoots
    Simulation -->|Scoped Execution| SimSandbox
    CoreAPI --> Postgres
```

### STRIDE Assessment Summary

1. **Spoofing**: Addressed via Token / API-Key authentication dependency enforcing roles (`ADMIN`, `ANALYST`, `READONLY`) with timing-safe comparison.
2. **Tampering**: All mutation endpoints (alert acknowledgments, status changes, notes, simulation runs) require `ADMIN` or `ANALYST` role permissions.
3. **Repudiation**: Authenticated user identity is captured in audit logs and mutation events (`AlertAuditLog`, `SystemAuditRecord`).
4. **Information Disclosure**: Sensitive endpoints (`/detection/findings`, `/ai/investigations`) are protected by authentication; security headers prevent MIME-sniffing and clickjacking.
5. **Denial of Service**: Request payload size limit middleware (max 10MB default) and rate limiting protect against memory exhaustion.
6. **Elevation of Privilege**: Path boundaries are enforced in network ingestion (`validate_path_within_boundary`) and simulations are blocked in production environments.
