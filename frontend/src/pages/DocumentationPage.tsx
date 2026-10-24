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
        {/* Phase 3 Implemented */}
        <div style={{
          backgroundColor: 'var(--bg-card)',
          border: '1px solid rgba(16, 185, 129, 0.4)',
          borderRadius: '8px',
          padding: '1.5rem',
        }}>
          <h2 style={{ fontSize: '1.15rem', color: 'var(--accent-green)', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span>✓</span> Phase 3 Active: Sensitive Data Detection & Classification Engine
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
