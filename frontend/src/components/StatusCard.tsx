import React from 'react';

interface StatusCardProps {
  title: string;
  badge: 'healthy' | 'warning' | 'error' | 'neutral';
  badgeLabel: string;
  latency?: number;
  description: string;
  details?: Record<string, string | number | undefined>;
}

export const StatusCard: React.FC<StatusCardProps> = ({
  title,
  badge,
  badgeLabel,
  latency,
  description,
  details,
}) => {
  const getBadgeStyle = () => {
    switch (badge) {
      case 'healthy':
        return {
          bg: 'rgba(16, 185, 129, 0.1)',
          border: 'rgba(16, 185, 129, 0.25)',
          color: 'var(--accent-green)',
        };
      case 'warning':
        return {
          bg: 'rgba(245, 158, 11, 0.1)',
          border: 'rgba(245, 158, 11, 0.25)',
          color: 'var(--accent-amber)',
        };
      case 'error':
        return {
          bg: 'rgba(239, 68, 68, 0.1)',
          border: 'rgba(239, 68, 68, 0.25)',
          color: 'var(--accent-red)',
        };
      case 'neutral':
      default:
        return {
          bg: 'rgba(148, 163, 184, 0.1)',
          border: 'rgba(148, 163, 184, 0.25)',
          color: 'var(--text-secondary)',
        };
    }
  };

  const badgeStyle = getBadgeStyle();

  return (
    <div style={{
      backgroundColor: 'var(--bg-card)',
      border: '1px solid var(--border-subtle)',
      borderRadius: '8px',
      padding: '1.5rem',
      display: 'flex',
      flexDirection: 'column',
      justifyContent: 'space-between',
      gap: '1rem',
      boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
    }}>
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>{title}</h3>
          <span style={{
            fontSize: '0.75rem',
            fontWeight: 600,
            padding: '0.2rem 0.5rem',
            borderRadius: '4px',
            backgroundColor: badgeStyle.bg,
            border: `1px solid ${badgeStyle.border}`,
            color: badgeStyle.color,
            textTransform: 'uppercase',
          }}>
            {badgeLabel}
          </span>
        </div>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
          {description}
        </p>
      </div>

      {details && (
        <div style={{
          backgroundColor: 'var(--bg-primary)',
          borderRadius: '6px',
          padding: '0.75rem',
          fontSize: '0.8rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.4rem',
          border: '1px solid var(--border-subtle)',
        }}>
          {Object.entries(details).map(([key, value]) => (
            <div key={key} style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>{key}:</span>
              <span style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                {value ?? 'N/A'}
              </span>
            </div>
          ))}
          {latency !== undefined && (
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Response Latency:</span>
              <span style={{ color: 'var(--accent-green)', fontFamily: 'var(--font-mono)' }}>
                {latency} ms
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
