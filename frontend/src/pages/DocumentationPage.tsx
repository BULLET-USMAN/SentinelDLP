import React from 'react';

export const DocumentationPage: React.FC = () => {
  return (
    <div style={{ maxWidth: '1000px', margin: '0 auto', padding: '2rem 1.5rem' }}>
      <div style={{ marginBottom: '2rem', paddingBottom: '1.5rem', borderBottom: '1px solid var(--border-subtle)' }}>
        <h1 style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-primary)' }}>
          Platform Architecture & Phase 1 Scope
        </h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '0.25rem' }}>
          Defensive cybersecurity engineering specifications and implementation boundaries.
        </p>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
        {/* Phase 1 Implemented */}
        <div style={{
          backgroundColor: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '8px',
          padding: '1.5rem',
        }}>
          <h2 style={{ fontSize: '1.15rem', color: 'var(--accent-green)', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span>✓</span> Phase 1 Implementation (Active Baseline)
          </h2>
          <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Modular Monorepo:</strong>
              Organized backend (FastAPI, SQLAlchemy, Alembic) and frontend (React, TypeScript, Vite) architecture.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Health & Readiness Probes:</strong>
              Dual-tier probes (/health/live and /health/ready) monitoring process status and PostgreSQL dependency states.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Defensive Security & Validation:</strong>
              Strict CORS origin restrictions, credential masking in application logs, and centralized exception isolation.
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Database Migration Pipeline:</strong>
              Alembic migration engine initialized with baseline schema (system_audit_records).
            </li>
            <li style={{ display: 'flex', gap: '0.5rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>• Automated Verification Suite:</strong>
              Pytest suite validating configuration, error responses, and mocked database health scenarios.
            </li>
          </ul>
        </div>

        {/* Development Restrictions & Phase 2+ Scope */}
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
              <h4 style={{ color: 'var(--text-primary)', marginBottom: '0.25rem' }}>Phase 2: Detection Engine</h4>
              <p style={{ color: 'var(--text-muted)' }}>Sensitive file scanning, regular expression regex rules, entropy analysis, and data classification.</p>
            </div>
            <div style={{ padding: '0.75rem', backgroundColor: 'var(--bg-primary)', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
              <h4 style={{ color: 'var(--text-primary)', marginBottom: '0.25rem' }}>Phase 3: Exfiltration Heuristics</h4>
              <p style={{ color: 'var(--text-muted)' }}>Endpoint activity monitoring, unauthorized transfer heuristics, and volume anomaly detection.</p>
            </div>
            <div style={{ padding: '0.75rem', backgroundColor: 'var(--bg-primary)', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
              <h4 style={{ color: 'var(--text-primary)', marginBottom: '0.25rem' }}>Phase 4: AI Incident Assistant</h4>
              <p style={{ color: 'var(--text-muted)' }}>LLM-powered threat summaries, incident risk scoring, and security analyst investigation workflows.</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
