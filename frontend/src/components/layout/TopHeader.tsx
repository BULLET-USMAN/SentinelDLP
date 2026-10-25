import React from 'react';
import {
  Activity,
  Menu,
  RefreshCw,
  Search,
  UserCheck,
  Wifi,
  WifiOff,
} from 'lucide-react';
import { NavigationTab } from './Sidebar';

interface TopHeaderProps {
  currentTab: NavigationTab;
  onOpenMobileSidebar: () => void;
  onOpenSearch: () => void;
  isBackendConnected: boolean;
  autoRefresh: boolean;
  onToggleAutoRefresh: () => void;
  onManualRefresh: () => void;
  isRefreshing: boolean;
  analystRole?: string;
}

export const TopHeader: React.FC<TopHeaderProps> = ({
  currentTab,
  onOpenMobileSidebar,
  onOpenSearch,
  isBackendConnected,
  autoRefresh,
  onToggleAutoRefresh,
  onManualRefresh,
  isRefreshing,
  analystRole = 'SOC Analyst (Tier 2)',
}) => {
  const getTabTitle = (tab: NavigationTab): { title: string; category: string } => {
    switch (tab) {
      case 'overview':
        return { title: 'Security Operations Overview', category: 'Executive Dashboard' };
      case 'scanner':
        return { title: 'File Scanner & Inventory', category: 'Data Protection' };
      case 'detection':
        return { title: 'Sensitive Data Classification', category: 'Data Protection' };
      case 'activity':
        return { title: 'Real-Time File Activity', category: 'Data Protection' };
      case 'risk':
        return { title: 'Risk Intelligence & Scoring', category: 'Threat Intelligence' };
      case 'exfiltration':
        return { title: 'Data Exfiltration Correlation', category: 'Threat Intelligence' };
      case 'network':
        return { title: 'Network Intelligence & Traffic', category: 'Threat Intelligence' };
      case 'alerts':
        return { title: 'Centralized Alerts Console', category: 'Security Operations' };
      case 'investigations':
        return { title: 'Investigation Workspace', category: 'Security Operations' };
      case 'health':
        return { title: 'System & Sensor Health', category: 'System Observability' };
      case 'settings':
        return { title: 'Platform Settings & Policy', category: 'System Configuration' };
      case 'docs':
        return { title: 'Architecture & Phase Roadmap', category: 'Documentation' };
      default:
        return { title: 'Security Operations Center', category: 'SentinelDLP' };
    }
  };

  const { title, category } = getTabTitle(currentTab);

  return (
    <header className="h-16 px-4 lg:px-6 bg-slate-900/80 backdrop-blur-md border-b border-slate-800 flex items-center justify-between sticky top-0 z-30">
      {/* Left: Mobile hamburger & Page Title */}
      <div className="flex items-center gap-3">
        <button
          onClick={onOpenMobileSidebar}
          className="p-2 text-slate-400 hover:text-white rounded-lg lg:hidden hover:bg-slate-800 transition"
        >
          <Menu className="w-5 h-5" />
        </button>

        <div className="flex flex-col">
          <span className="text-[10px] font-mono font-semibold text-slate-400 uppercase tracking-wider hidden sm:block">
            {category}
          </span>
          <h1 className="text-sm sm:text-base font-bold text-white tracking-tight">
            {title}
          </h1>
        </div>
      </div>

      {/* Center: Global Search Bar trigger */}
      <div className="flex-1 max-w-md mx-4 hidden md:block">
        <button
          onClick={onOpenSearch}
          className="w-full flex items-center justify-between px-3.5 py-1.5 bg-slate-950/70 border border-slate-800 hover:border-slate-700 text-slate-400 hover:text-slate-200 rounded-xl text-xs transition group shadow-inner"
        >
          <div className="flex items-center gap-2">
            <Search className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 transition" />
            <span>Search alerts, files, rules, network...</span>
          </div>
          <kbd className="px-1.5 py-0.5 bg-slate-800 border border-slate-700 text-[10px] font-mono rounded text-slate-400 shadow-sm">
            Ctrl + K
          </kbd>
        </button>
      </div>

      {/* Right: Operational controls & Analyst badge */}
      <div className="flex items-center gap-2.5">
        {/* Mobile Search Icon Button */}
        <button
          onClick={onOpenSearch}
          className="p-2 text-slate-400 hover:text-white rounded-lg md:hidden hover:bg-slate-800 transition"
          title="Search"
        >
          <Search className="w-4 h-4" />
        </button>

        {/* Auto Refresh Toggle */}
        <button
          onClick={onToggleAutoRefresh}
          className={`hidden sm:flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition ${
            autoRefresh
              ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-400'
              : 'bg-slate-950 border-slate-800 text-slate-400'
          }`}
          title="Auto-refresh every 10 seconds"
        >
          <Activity className="w-3 h-3" />
          <span>{autoRefresh ? 'Live 10s' : 'Paused'}</span>
        </button>

        {/* Manual Refresh */}
        <button
          onClick={onManualRefresh}
          disabled={isRefreshing}
          className="p-1.5 bg-slate-950 hover:bg-slate-800 text-slate-300 rounded-lg border border-slate-800 transition disabled:opacity-50"
          title="Refresh Data"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-emerald-400' : ''}`} />
        </button>

        {/* Backend Connectivity Status Pill */}
        <div
          className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium border ${
            isBackendConnected
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
              : 'bg-red-500/10 border-red-500/30 text-red-400'
          }`}
        >
          {isBackendConnected ? (
            <Wifi className="w-3 h-3 shrink-0" />
          ) : (
            <WifiOff className="w-3 h-3 shrink-0" />
          )}
          <span className="hidden lg:inline">{isBackendConnected ? 'Online' : 'Offline'}</span>
        </div>

        {/* Analyst Role Badge */}
        <div className="hidden xl:flex items-center gap-2 pl-2 border-l border-slate-800 text-xs">
          <div className="w-7 h-7 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center text-cyan-400">
            <UserCheck className="w-4 h-4" />
          </div>
          <div className="flex flex-col">
            <span className="text-white font-medium text-[11px] leading-tight">Analyst Session</span>
            <span className="text-[10px] text-slate-400 font-mono leading-tight">{analystRole}</span>
          </div>
        </div>
      </div>
    </header>
  );
};
