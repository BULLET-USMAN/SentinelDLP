import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { NetworkIntelligencePage } from './pages/NetworkIntelligencePage';
import { DataExfiltrationPage } from './pages/DataExfiltrationPage';
import { RiskIntelligencePage } from './pages/RiskIntelligencePage';
import { LiveActivityPage } from './pages/LiveActivityPage';
import { SensitiveDataPage } from './pages/SensitiveDataPage';
import { FileScannerPage } from './pages/FileScannerPage';
import { SystemStatusPage } from './pages/SystemStatusPage';
import { DocumentationPage } from './pages/DocumentationPage';
import { fetchLiveness } from './services/api';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<'network' | 'exfiltration' | 'risk' | 'activity' | 'detection' | 'scanner' | 'status' | 'docs'>('network');
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
        {currentTab === 'network' ? (
          <div style={{ padding: '1.5rem 2rem' }}>
            <NetworkIntelligencePage />
          </div>
        ) : currentTab === 'exfiltration' ? (
          <DataExfiltrationPage />
        ) : currentTab === 'risk' ? (
          <RiskIntelligencePage />
        ) : currentTab === 'activity' ? (
          <LiveActivityPage />
        ) : currentTab === 'detection' ? (
          <SensitiveDataPage />
        ) : currentTab === 'scanner' ? (
          <FileScannerPage />
        ) : currentTab === 'status' ? (
          <SystemStatusPage />
        ) : (
          <DocumentationPage />
        )}
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
          <span>Phase 7: Advanced Network Traffic Monitoring & Threat Intelligence</span>
          <span>•</span>
          <span>Zero-Leakage Telemetry</span>
        </div>
      </footer>
    </div>
  );
};

export default App;
