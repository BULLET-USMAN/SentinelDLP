import React, { useState, useEffect, useCallback } from 'react';
import { AppLayout } from './components/layout/AppLayout';
import { NavigationTab } from './components/layout/Sidebar';

// Pages
import { OverviewPage } from './pages/OverviewPage';
import { AlertsConsolePage } from './pages/AlertsConsolePage';
import { InvestigationWorkspacePage } from './pages/InvestigationWorkspacePage';
import { AISocAnalystPage } from './pages/AISocAnalystPage';
import { SystemHealthPage } from './pages/SystemHealthPage';
import { SettingsPage } from './pages/SettingsPage';
import { NetworkIntelligencePage } from './pages/NetworkIntelligencePage';
import { DataExfiltrationPage } from './pages/DataExfiltrationPage';
import { RiskIntelligencePage } from './pages/RiskIntelligencePage';
import { LiveActivityPage } from './pages/LiveActivityPage';
import { SensitiveDataPage } from './pages/SensitiveDataPage';
import { FileScannerPage } from './pages/FileScannerPage';
import { DocumentationPage } from './pages/DocumentationPage';

import { fetchLiveness } from './services/api';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<NavigationTab>('overview');
  const [targetId, setTargetId] = useState<string | null>(null);
  const [isBackendConnected, setIsBackendConnected] = useState<boolean>(true);
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [refreshKey, setRefreshKey] = useState<number>(0);

  const checkConnection = useCallback(async () => {
    try {
      await fetchLiveness();
      setIsBackendConnected(true);
    } catch {
      setIsBackendConnected(false);
    }
  }, []);

  useEffect(() => {
    checkConnection();
    const interval = setInterval(checkConnection, 10000);
    return () => clearInterval(interval);
  }, [checkConnection]);

  // Periodic Auto-Refresh
  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => {
      setRefreshKey(k => k + 1);
    }, 15000);
    return () => clearInterval(interval);
  }, [autoRefresh]);

  const handleManualRefresh = async () => {
    setIsRefreshing(true);
    await checkConnection();
    setRefreshKey(k => k + 1);
    setTimeout(() => {
      setIsRefreshing(false);
    }, 400);
  };

  const handleSelectTab = (tab: NavigationTab, id?: string) => {
    setCurrentTab(tab);
    setTargetId(id || null);
  };

  return (
    <AppLayout
      currentTab={currentTab}
      onSelectTab={handleSelectTab}
      isBackendConnected={isBackendConnected}
      autoRefresh={autoRefresh}
      onToggleAutoRefresh={() => setAutoRefresh(!autoRefresh)}
      onManualRefresh={handleManualRefresh}
      isRefreshing={isRefreshing}
    >
      <div key={refreshKey} className="transition-all duration-150">
        {currentTab === 'overview' && (
          <OverviewPage onNavigateToTab={handleSelectTab} />
        )}
        {currentTab === 'alerts' && (
          <AlertsConsolePage
            initialAlertId={targetId}
            onNavigateToTab={handleSelectTab}
          />
        )}
        {currentTab === 'investigations' && (
          <InvestigationWorkspacePage
            initialInvestigationId={targetId}
            onNavigateToTab={handleSelectTab}
          />
        )}
        {currentTab === 'ai-analyst' && (
          <AISocAnalystPage />
        )}
        {currentTab === 'network' && (
          <NetworkIntelligencePage />
        )}
        {currentTab === 'exfiltration' && (
          <DataExfiltrationPage />
        )}
        {currentTab === 'risk' && (
          <RiskIntelligencePage />
        )}
        {currentTab === 'activity' && (
          <LiveActivityPage />
        )}
        {currentTab === 'detection' && (
          <SensitiveDataPage />
        )}
        {currentTab === 'scanner' && (
          <FileScannerPage />
        )}
        {currentTab === 'health' && (
          <SystemHealthPage />
        )}
        {currentTab === 'settings' && (
          <SettingsPage />
        )}
        {currentTab === 'docs' && (
          <DocumentationPage />
        )}
      </div>
    </AppLayout>
  );
};

export default App;