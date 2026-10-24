import React from 'react';

interface NavbarProps {
  currentTab: 'activity' | 'detection' | 'scanner' | 'status' | 'docs';
  onSelectTab: (tab: 'activity' | 'detection' | 'scanner' | 'status' | 'docs') => void;
  isBackendConnected: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({ currentTab, onSelectTab, isBackendConnected }) => {
  return (
    <header style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '1rem 2rem',
      backgroundColor: 'var(--bg-secondary)',
      borderBottom: '1px solid var(--border-subtle)',
      position: 'sticky',
      top: 0,
      zIndex: 100,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <div style={{
          width: '36px',
          height: '36px',
          borderRadius: '8px',
          backgroundColor: 'rgba(16, 185, 129, 0.1)',
          border: '1px solid var(--accent-green)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'var(--accent-green)',
        }}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontWeight: 700, fontSize: '1.15rem', letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
              Sentinel<span style={{ color: 'var(--accent-green)' }}>DLP</span>
            </span>
            <span style={{
              fontSize: '0.65rem',
              fontWeight: 600,
              padding: '0.15rem 0.4rem',
              borderRadius: '4px',
              backgroundColor: 'rgba(16, 185, 129, 0.1)',
              color: 'var(--accent-green)',
              border: '1px solid rgba(16, 185, 129, 0.25)',
              textTransform: 'uppercase',
            }}>
              Phase 4 Active
            </span>
          </div>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            AI-Powered Data Loss Prevention & Exfiltration Detection
          </p>
        </div>
      </div>

      <nav style={{ display: 'flex', gap: '0.5rem' }}>
        <button
          onClick={() => onSelectTab('activity')}
          style={{
            padding: '0.5rem 1rem',
            borderRadius: '6px',
            fontSize: '0.875rem',
            fontWeight: 600,
            transition: 'all 0.2s ease',
            backgroundColor: currentTab === 'activity' ? 'var(--bg-tertiary)' : 'transparent',
            color: currentTab === 'activity' ? 'var(--accent-green)' : 'var(--text-secondary)',
            border: currentTab === 'activity' ? '1px solid var(--accent-green)' : '1px solid transparent',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
          }}
        >
          <span>📡</span> Live Activity
        </button>
        <button
          onClick={() => onSelectTab('detection')}
          style={{
            padding: '0.5rem 1rem',
            borderRadius: '6px',
            fontSize: '0.875rem',
            fontWeight: 600,
            transition: 'all 0.2s ease',
            backgroundColor: currentTab === 'detection' ? 'var(--bg-tertiary)' : 'transparent',
            color: currentTab === 'detection' ? 'var(--accent-blue)' : 'var(--text-secondary)',
            border: currentTab === 'detection' ? '1px solid var(--accent-blue)' : '1px solid transparent',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
          }}
        >
          <span>🛡️</span> Sensitive Data
        </button>
        <button
          onClick={() => onSelectTab('scanner')}
          style={{
            padding: '0.5rem 1rem',
            borderRadius: '6px',
            fontSize: '0.875rem',
            fontWeight: 500,
            transition: 'all 0.2s ease',
            backgroundColor: currentTab === 'scanner' ? 'var(--bg-tertiary)' : 'transparent',
            color: currentTab === 'scanner' ? 'var(--text-primary)' : 'var(--text-secondary)',
            border: currentTab === 'scanner' ? '1px solid var(--border-active)' : '1px solid transparent',
          }}
        >
          File Scanner & Inventory
        </button>
        <button
          onClick={() => onSelectTab('status')}
          style={{
            padding: '0.5rem 1rem',
            borderRadius: '6px',
            fontSize: '0.875rem',
            fontWeight: 500,
            transition: 'all 0.2s ease',
            backgroundColor: currentTab === 'status' ? 'var(--bg-tertiary)' : 'transparent',
            color: currentTab === 'status' ? 'var(--text-primary)' : 'var(--text-secondary)',
            border: currentTab === 'status' ? '1px solid var(--border-active)' : '1px solid transparent',
          }}
        >
          System Health
        </button>
        <button
          onClick={() => onSelectTab('docs')}
          style={{
            padding: '0.5rem 1rem',
            borderRadius: '6px',
            fontSize: '0.875rem',
            fontWeight: 500,
            transition: 'all 0.2s ease',
            backgroundColor: currentTab === 'docs' ? 'var(--bg-tertiary)' : 'transparent',
            color: currentTab === 'docs' ? 'var(--text-primary)' : 'var(--text-secondary)',
            border: currentTab === 'docs' ? '1px solid var(--border-active)' : '1px solid transparent',
          }}
        >
          Architecture & Roadmap
        </button>
      </nav>

      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          padding: '0.35rem 0.75rem',
          borderRadius: '9999px',
          backgroundColor: isBackendConnected ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)',
          border: `1px solid ${isBackendConnected ? 'rgba(16, 185, 129, 0.25)' : 'rgba(239, 68, 68, 0.25)'}`,
        }}>
          <span style={{
            width: '8px',
            height: '8px',
            borderRadius: '50%',
            backgroundColor: isBackendConnected ? 'var(--accent-green)' : 'var(--accent-red)',
            boxShadow: isBackendConnected ? '0 0 8px var(--accent-green)' : 'none',
          }} />
          <span style={{
            fontSize: '0.75rem',
            fontWeight: 500,
            color: isBackendConnected ? 'var(--accent-green)' : 'var(--accent-red)',
          }}>
            {isBackendConnected ? 'API Connected' : 'API Unreachable'}
          </span>
        </div>
      </div>
    </header>
  );
};
