import React from 'react';

export const DocumentationPage: React.FC = () => {
  return (
    <div style={{ maxWidth: '1000px', margin: '0 auto', padding: '2rem 1.5rem' }}>
      <div style={{ marginBottom: '2rem', paddingBottom: '1.5rem', borderBottom: '1px solid var(--border-subtle)' }}>
        <h1 style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-primary)' }}>
          Platform Architecture & Phase Roadmap
        </h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '0.25rem' }}>
          Defensive cybersecurity engineering specifications, data loss prevention rules, and privacy boundaries.
        </p>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
        {/* Phase 9 Implemented */}
        <div style={{
          backgroundColor: 'var(--bg-card)',
          border: '1px solid rgba(16, 185, 129, 0.4)',
          borderRadius: '8px',
          padding: '1.5rem',
        }}>
          <h2 style={{ fontSize: '1.15rem', color: '#10b981', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span>✓</span> Phase 9 Active: AI-Powered SOC Analyst, Local LLM Integration & Intelligent Security Investigation
          </h2>
          <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Modular Local AI Provider & Deterministic Mock Architecture:</strong>
              Pluggable provider interface featuring a zero-dependency deterministic Mock AI provider for local testing and full HTTP readiness for local Ollama inference daemons (targeting <code>llama3.2:3b</code> on Windows/Linux).
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Server-Controlled Read-Only Investigation Tools:</strong>
              Server-enforced tool execution harness (<code>get_alert</code>, <code>get_risk_assessment</code>, <code>get_file_classification</code>, <code>get_file_activity</code>, <code>get_investigation_timeline</code>, <code>get_exfiltration_evidence</code>, <code>get_network_events</code>, <code>get_sensor_status</code>, <code>get_mitre_technique</code>) bounded to max 6 calls per investigation with immutable PostgreSQL audit logging.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Offline MITRE ATT&amp;CK Enterprise Catalog &amp; Anti-Hallucination:</strong>
              Local offline catalog of DLP-relevant techniques (T1074.001, T1560.001, T1567.002, T1048.003, T1071.004, etc.) and post-generation validation rejecting fabricated record identifiers or invalid technique codes.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Data Privacy &amp; Indirect Prompt Injection Resistance:</strong>
              Zero-leakage credential redaction (passwords, tokens, payment cards, SSNs) and defensive enclosure of untrusted telemetry strings inside <code>&lt;untrusted_telemetry&gt;</code> tags.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Interactive AI SOC Analyst Console &amp; Workspace Integration:</strong>
              Interactive chat assistant with conversation memory, investigation context selector, prompt quick-starts, plus deep integration into the Investigation Workspace with analyst feedback review (USEFUL, INCORRECT, NEEDS_REVIEW).
            </li>
          </ul>
        </div>

        {/* Phase 8 Implemented */}
        <div style={{
          backgroundColor: 'var(--bg-card)',
          border: '1px solid rgba(16, 185, 129, 0.4)',
          borderRadius: '8px',
          padding: '1.5rem',
        }}>
          <h2 style={{ fontSize: '1.15rem', color: '#10b981', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span>✓</span> Phase 8 Active: Enterprise Security Operations Center Dashboard & Unified Security Intelligence
          </h2>
          <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Unified SOC Overview & Metrics Aggregation:</strong>
              Single lightweight backend endpoint (<code>/api/v1/dashboard/overview</code>) delivering executive KPI cards, 24h risk trend charts, recent multi-source activity, capability matrix, and priority triage queue.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Unified Cross-Entity Metadata Search:</strong>
              Global Search Modal accessible via <code>Ctrl+K</code> or <code>/</code>, with debounced multi-source query across alerts, investigations, scanned files, threat indicators, and detection rules (<code>/api/v1/dashboard/search</code>).
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Dedicated Security Operations Consoles:</strong>
              Centralized Alert Console with status transitions (<code>OPEN</code> &rarr; <code>ACKNOWLEDGED</code> &rarr; <code>INVESTIGATING</code> &rarr; <code>RESOLVED</code> &rarr; <code>FALSE_POSITIVE</code>) and immutable audit logging; plus dedicated Investigation Workspace with multi-stage forensic timelines.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• System & Sensor Health Observability:</strong>
              Subsystem capability matrix tracking health, telemetry freshness, PostgreSQL connection latency, and container isolation boundary disclosures.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Enterprise Navigation Architecture:</strong>
              Collapsible sidebar navigation grouping capabilities into Overview, Data Protection, Threat Intelligence, Security Operations, and System.
            </li>
          </ul>
        </div>

        {/* Phase 7 Implemented */}
        <div style={{
          backgroundColor: 'var(--bg-card)',
          border: '1px solid rgba(6, 182, 212, 0.4)',
          borderRadius: '8px',
          padding: '1.5rem',
        }}>
          <h2 style={{ fontSize: '1.15rem', color: '#06b6d4', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span>✓</span> Phase 7 Active: Advanced Network Traffic Monitoring, Detection Engineering & Threat Intelligence
          </h2>
          <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Multi-Technology Ingestion Pipeline:</strong>
              Offline Zeek JSON log adapter (conn, dns, http, ssl), Suricata EVE JSON adapter (flow, alert, dns v1/v2), and pure-Python binary PCAP analyzer with zero raw payload retention.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• 10 Defensive Detection Rules (NET-001 — NET-010):</strong>
              NET-001 (Volume Spikes), NET-002 (Repeated Attempts), NET-003 (Multi-Port Activity), NET-004 (DNS Frequency), NET-005 (DNS Shannon Entropy &gt;3.8), NET-006 (Unfamiliar Destination), NET-007 (Suricata Signatures), NET-008 (Sensitive File &amp; Network Correlation), NET-009 (Visibility Gap Diagnostics), NET-010 (Multi-Signal Network Investigation).
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Privacy-First Threat Intelligence:</strong>
              Local offline indicator lookup registry with RFC 1918 internal boundaries and corporate allowlists. Zero external API calls to prevent internal IP leaks.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Forensic Evidence Lineage & Causal Modesty:</strong>
              Network-to-file activity correlation records transfer evidence with explicit IMPORTED or OBSERVED provenance and marks relationships as circumstantial because encrypted payloads cannot be causally proven from flow headers alone.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Sensor Health & Coverage Gap Auditing:</strong>
              Explicit tracking of container isolation boundaries and sensor statuses with diagnostic warnings.
            </li>
          </ul>
        </div>

        {/* Phase 6 Implemented */}
        <div style={{
          backgroundColor: 'var(--bg-card)',
          border: '1px solid rgba(6, 182, 212, 0.4)',
          borderRadius: '8px',
          padding: '1.5rem',
        }}>
          <h2 style={{ fontSize: '1.15rem', color: '#06b6d4', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span>✓</span> Phase 6 Active: Advanced Data Exfiltration Detection & Security Event Correlation Engine
          </h2>
          <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Bounded Temporal Correlation:</strong>
              Correlates multi-source signals across configurable time windows (1m, 5m, 15m, 30m, 60m), linking sensitive file access, archive staging, and outbound transfer telemetry.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• 8 Operational Exfiltration Detection Rules:</strong>
              EXFIL-001 (High-Volume Sensitive Activity), EXFIL-002 (Sensitive Access &rarr; Archive Staging), EXFIL-003 (Archive &rarr; Outbound Transfer), EXFIL-004 (Unusual Outbound Volume), EXFIL-005 (Unfamiliar Destination), EXFIL-006 (Repeated Chunked Transfers), EXFIL-007 (Complete Multi-Signal Chain), EXFIL-008 (Insufficient Evidence / Coverage Warning).
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Strict Evidence Provenance & Forensic Ethics:</strong>
              Explicitly categorizes and tags evidence sources: OBSERVED (direct filesystem monitor), IMPORTED (perimeter logs), LAB_SIMULATED (synthetic testing fixtures), and INFERRED (correlation engine derived).
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Causal Modesty & Relationship Taxonomy:</strong>
              Maintains strict forensic distinction between temporal proximity, circumstantial overlap, and cryptographically verified links without unsupported causal assumptions.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Chronological Investigation Timelines:</strong>
              Interactive forensic incident drawer presenting an ordered chronological stream of file activity, archive creation, and outbound transfer telemetry.
            </li>
          </ul>
        </div>
        {/* Phase 5 Implemented */}
        <div style={{
          backgroundColor: 'var(--bg-card)',
          border: '1px solid rgba(245, 158, 11, 0.4)',
          borderRadius: '8px',
          padding: '1.5rem',
        }}>
          <h2 style={{ fontSize: '1.15rem', color: '#f59e0b', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span>✓</span> Phase 5 Active: Intelligent Threat Risk Scoring & Security Alert Engine
          </h2>
          <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• 0–100 Normalized Threat Scoring:</strong>
              Deterministic mathematical scoring combining primary triggers and diminishing secondary rule weights, mapped into LOW, MEDIUM, HIGH, and CRITICAL bands.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• 8 Operational Security Detection Rules:</strong>
              Evaluates sensitive modifications, rapid burst changes, bulk renaming, sensitive asset deletions, high-churn file paths, volume anomalies, extension alterations, and coverage failures.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Explainable SOC Findings:</strong>
              Every non-trivial assessment provides human-readable explanations, limitation boundaries, and actionable investigation recommendations.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Alert Deduplication & Sliding-Window Suppression:</strong>
              Clustering repetitive events (5-minute suppression window) with repeat-counter tracking to eliminate SOC alert fatigue.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Analyst Triage Lifecycle & Audit Trail:</strong>
              Supports OPEN &rarr; ACKNOWLEDGED &rarr; INVESTIGATING &rarr; RESOLVED / FALSE_POSITIVE transitions backed by immutable PostgreSQL audit records.
            </li>
          </ul>
        </div>

        {/* Phase 4 Implemented */}
        <div style={{
          backgroundColor: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '8px',
          padding: '1.5rem',
        }}>
          <h2 style={{ fontSize: '1.15rem', color: 'var(--accent-green)', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span>✓</span> Phase 4 Implementation: Real-Time File Activity Monitoring & Security Event Collection
          </h2>
          <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Cross-Platform Observer:</strong>
              Python Watchdog observer integration observing CREATE, MODIFY, DELETE, RENAME, and MOVE operations across authorized roots.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Debouncing & Burst Suppression:</strong>
              Deduplication engine filtering out multi-write save storms while strictly preserving state-changing transitions.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Bounded Queue & Backpressure:</strong>
              Non-blocking event queuing with saturation metrics, preventing memory exhaustion and observer thread starvation.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Dynamic Reclassification:</strong>
              Automatically triggers Phase 2 metadata extraction and Phase 3 sensitive data detection upon file creation or modification.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Real-Time Telemetry Delivery:</strong>
              Live event streaming via Server-Sent Events (SSE) and persistent PostgreSQL event audit logs.
            </li>
          </ul>
        </div>

        {/* Phase 3 Implemented */}
        <div style={{
          backgroundColor: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '8px',
          padding: '1.5rem',
        }}>
          <h2 style={{ fontSize: '1.15rem', color: 'var(--accent-green)', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span>✓</span> Phase 3 Implementation: Sensitive Data Detection & Classification Engine
          </h2>
          <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Safe Multi-Format Extractors:</strong>
              Content extraction supporting TXT, CSV, JSON, XML (with XXE entity defense), DOCX (with zip-bomb prevention), and PDF with strict 1MB truncation boundaries.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Cryptographic & Algorithmic Validators:</strong>
              Luhn mod-10 payment card verification, MOD-97 Pakistani IBAN validation, Pakistani CNIC (5-7-1) verification, and Shannon entropy analysis.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Four Critical Detection Categories:</strong>
              Personal Information (PII), Credentials & Secrets, Financial Data, and Organizational Confidentiality Banners.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Deterministic Precedence Classification:</strong>
              RESTRICTED &gt; CONFIDENTIAL &gt; INTERNAL &gt; PUBLIC &gt; NOT_ASSESSED.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Zero-Leakage Guarantee:</strong>
              Extracted plaintext is immediately purged from memory; database and API responses only retain rule IDs, counts, and confidence ratings.
            </li>
          </ul>
        </div>

        {/* Phase 2 Implemented */}
        <div style={{
          backgroundColor: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '8px',
          padding: '1.5rem',
        }}>
          <h2 style={{ fontSize: '1.15rem', color: 'var(--accent-green)', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span>✓</span> Phase 2 Implementation: Intelligent File Scanner & Cryptographic Inventory
          </h2>
          <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Strict Security Boundaries:</strong>
              Enforced path containment and allowlist root validation preventing directory traversal.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Streaming SHA-256 Hashing:</strong>
              Chunked 64KB reads computing cryptographic digests without memory exhaustion.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Magic Signature Anomaly Detection:</strong>
              Detects file extension spoofing (e.g., plain text disguised as PDF or PNG).
            </li>
          </ul>
        </div>

        {/* Phase 1 Implemented */}
        <div style={{
          backgroundColor: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '8px',
          padding: '1.5rem',
        }}>
          <h2 style={{ fontSize: '1.15rem', color: 'var(--accent-green)', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span>✓</span> Phase 1 Implementation: Monorepo Foundation & Backend Architecture
          </h2>
          <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Architecture:</strong>
              FastAPI backend, React TypeScript frontend, PostgreSQL 16 database, Docker Compose orchestration.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Health Probes:</strong>
              Dual-tier probes (/health/live and /health/ready) monitoring process and dependency states.
            </li>
          </ul>
        </div>

        {/* Development Restrictions & Future Phase Scope */}
        <div style={{
          backgroundColor: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '8px',
          padding: '1.5rem',
        }}>
          <h2 style={{ fontSize: '1.15rem', color: 'var(--accent-blue)', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span>⏳</span> Future Phase Roadmap (Strictly Deferred)
          </h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '1rem', fontSize: '0.85rem' }}>
            <div style={{ padding: '0.75rem', backgroundColor: 'var(--bg-primary)', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
              <h4 style={{ color: 'var(--text-primary)', marginBottom: '0.25rem' }}>Phase 4: Endpoint Activity Monitoring</h4>
              <p style={{ color: 'var(--text-muted)' }}>Authorized local workstation event monitoring, USB device insertion, and clipboard operations.</p>
            </div>
            <div style={{ padding: '0.75rem', backgroundColor: 'var(--bg-primary)', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
              <h4 style={{ color: 'var(--text-primary)', marginBottom: '0.25rem' }}>Phase 5: Exfiltration Heuristics</h4>
              <p style={{ color: 'var(--text-muted)' }}>Volume anomalies, off-hours exfiltration attempts, and suspicious transfer behavior.</p>
            </div>
            <div style={{ padding: '0.75rem', backgroundColor: 'var(--bg-primary)', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
              <h4 style={{ color: 'var(--text-primary)', marginBottom: '0.25rem' }}>Phase 6: AI Incident Assistant</h4>
              <p style={{ color: 'var(--text-muted)' }}>LLM-powered threat summaries, incident risk scoring, and security analyst investigation workflows.</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
