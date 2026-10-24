import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { SystemStatusPage } from './pages/SystemStatusPage';
import { DocumentationPage } from './pages/DocumentationPage';
import { fetchLiveness } from './services/api';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<'status' | 'docs'>('status');
  const [isBackendConnected, setIsBackendConnected] = useState<boolean>(false);

  useEffect(() => {
    const checkConnection = async () => {
      try {
        await fetchLiveness();
        setIsBackendConnected(true);
      } catch {
        setIsBackendConnected(false);
      }
    };

    checkConnection();
    const interval = setInterval(checkConnection, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Navbar
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        isBackendConnected={isBackendConnected}
      />

      <main style={{ flex: 1 }}>
        {currentTab === 'status' ? <SystemStatusPage /> : <DocumentationPage />}
      </main>

      <footer style={{
        padding: '1.25rem 2rem',
        borderTop: '1px solid var(--border-subtle)',
        backgroundColor: 'var(--bg-secondary)',
        fontSize: '0.8rem',
        color: 'var(--text-muted)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '0.5rem',
      }}>
        <div>
          <span>SentinelDLP Platform &copy; 2026. Defensive Cybersecurity Architecture.</span>
        </div>
        <div style={{ display: 'flex', gap: '1rem', fontFamily: 'var(--font-mono)' }}>
          <span>Phase 1 Baseline</span>
          <span>•</span>
          <span>Security-First Defaults</span>
        </div>
      </footer>
    </div>
  );
};

export default App;
