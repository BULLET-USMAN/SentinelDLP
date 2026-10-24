import React, { useState, useEffect, useCallback } from 'react';
import { fetchLiveness, fetchReadiness } from '../services/api';
import { LivenessResponse, ReadinessResponse } from '../types/health';
import { StatusCard } from '../components/StatusCard';

export const SystemStatusPage: React.FC = () => {
  const [liveness, setLiveness] = useState<LivenessResponse | null>(null);
  const [readiness, setReadiness] = useState<ReadinessResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [lastChecked, setLastChecked] = useState<Date | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);

  const checkHealth = useCallback(async () => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const [liveData, readyData] = await Promise.allSettled([
        fetchLiveness(),
        fetchReadiness(),
      ]);

      if (liveData.status === 'fulfilled') {
        setLiveness(liveData.value);
      } else {
        setLiveness(null);
        setErrorMsg('Backend process is unreachable. Please verify the FastAPI service is running on http://localhost:8000.');
      }

      if (readyData.status === 'fulfilled') {
        setReadiness(readyData.value);
      } else {
        setReadiness(null);
      }

      setLastChecked(new Date());
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown connectivity failure';
      setErrorMsg(message);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    checkHealth();
  }, [checkHealth]);

  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => {
      checkHealth();
    }, 10000);
    return () => clearInterval(interval);
  }, [autoRefresh, checkHealth]);

  const isLive = !!liveness;
  const isDbUp = readiness?.components?.database?.status === 'up';
  const isOverallReady = readiness?.status === 'ready';

  return (
    <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '2rem 1.5rem' }}>
      {/* Header bar */}
      <div style={{
        display: 'flex',
        flexWrap: 'wrap',
        justifyContent: 'space-between',
        alignItems: 'center',
        gap: '1rem',
        marginBottom: '2rem',
        paddingBottom: '1.5rem',
        borderBottom: '1px solid var(--border-subtle)',
      }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
            System Infrastructure & Readiness
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '0.25rem' }}>
            Phase 1 Baseline: Verified application lifecycle, backend routing, and database connectivity.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <label style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            fontSize: '0.85rem',
            color: 'var(--text-secondary)',
            cursor: 'pointer',
          }}>
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              style={{ accentColor: 'var(--accent-green)' }}
            />
            Auto-refresh (10s)
          </label>

          <button
            onClick={() => checkHealth()}
            disabled={isLoading}
            style={{
              padding: '0.5rem 1.25rem',
              borderRadius: '6px',
              backgroundColor: 'var(--bg-tertiary)',
              border: '1px solid var(--border-active)',
              color: 'var(--text-primary)',
              fontSize: '0.875rem',
              fontWeight: 500,
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              opacity: isLoading ? 0.6 : 1,
            }}
          >
            {isLoading ? 'Checking...' : 'Check Status'}
          </button>
        </div>
      </div>

      {/* Global Banner if Backend Down */}
      {errorMsg && (
        <div style={{
          backgroundColor: 'rgba(239, 68, 68, 0.1)',
          border: '1px solid rgba(239, 68, 68, 0.3)',
          borderRadius: '8px',
          padding: '1rem 1.25rem',
          marginBottom: '2rem',
          display: 'flex',
          alignItems: 'flex-start',
          gap: '0.75rem',
        }}>
          <div style={{ color: 'var(--accent-red)', marginTop: '2px' }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10"/>
              <line x1="12" y1="8" x2="12" y2="12"/>
              <line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
          </div>
          <div>
            <h4 style={{ color: 'var(--accent-red)', fontSize: '0.9rem', fontWeight: 600 }}>
              Backend Connection Warning
            </h4>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '0.2rem' }}>
              {errorMsg}
            </p>
          </div>
        </div>
      )}

      {/* Grid of Status Cards */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
        gap: '1.5rem',
        marginBottom: '2.5rem',
      }}>
        {/* Backend API Service */}
        <StatusCard
          title="Backend API Process"
          badge={isLive ? 'healthy' : 'error'}
          badgeLabel={isLive ? 'Operational' : 'Unreachable'}
          description="FastAPI service process running on port 8000 handling API v1 routing and middleware."
          details={{
            'Application Name': liveness?.app_name,
            'Semantic Version': liveness?.version,
            'Liveness State': liveness?.status,
            'Timestamp': liveness ? new Date(liveness.timestamp).toLocaleTimeString() : undefined,
          }}
        />

        {/* PostgreSQL Database */}
        <StatusCard
          title="PostgreSQL Dependency"
          badge={isDbUp ? 'healthy' : isLive ? 'warning' : 'error'}
          badgeLabel={isDbUp ? 'Connected' : isLive ? 'Unavailable' : 'Unreachable'}
          latency={readiness?.components?.database?.latency_ms}
          description="Primary relational datastore managing schema migrations and platform audit records."
          details={{
            'Connection State': readiness?.components?.database?.status ?? 'Unknown',
            'Diagnostics': readiness?.components?.database?.message ?? 'No probe response',
            'Migration Base': '0001_initial_schema',
          }}
        />

        {/* Platform Readiness */}
        <StatusCard
          title="Overall Platform Readiness"
          badge={isOverallReady ? 'healthy' : 'warning'}
          badgeLabel={isOverallReady ? 'Ready for Traffic' : 'Degraded'}
          description="Aggregated dependency health checked via /health/ready endpoint."
          details={{
            'Readiness Probe': readiness?.status ?? 'unready',
            'Active Modules': 'Core API, Health Probes',
            'Exfiltration Engine': 'Phase 2 Deferred',
          }}
        />
      </div>

      {/* Technical Diagnostics Section */}
      <div style={{
        backgroundColor: 'var(--bg-secondary)',
        border: '1px solid var(--border-subtle)',
        borderRadius: '8px',
        padding: '1.5rem',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h2 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            Raw Probe Payloads & Diagnostics
          </h2>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Last checked: {lastChecked ? lastChecked.toLocaleTimeString() : 'Never'}
          </span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1rem' }}>
          <div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.5rem', fontFamily: 'var(--font-mono)' }}>
              GET /health/live
            </div>
            <pre style={{
              backgroundColor: 'var(--bg-primary)',
              padding: '1rem',
              borderRadius: '6px',
              fontSize: '0.75rem',
              color: 'var(--accent-green)',
              overflowX: 'auto',
              border: '1px solid var(--border-subtle)',
            }}>
              {liveness ? JSON.stringify(liveness, null, 2) : '// No response from liveness probe'}
            </pre>
          </div>

          <div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.5rem', fontFamily: 'var(--font-mono)' }}>
              GET /health/ready
            </div>
            <pre style={{
              backgroundColor: 'var(--bg-primary)',
              padding: '1rem',
              borderRadius: '6px',
              fontSize: '0.75rem',
              color: isDbUp ? 'var(--accent-green)' : 'var(--accent-amber)',
              overflowX: 'auto',
              border: '1px solid var(--border-subtle)',
            }}>
              {readiness ? JSON.stringify(readiness, null, 2) : '// No response from readiness probe'}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
