import React from 'react';
import {
  AlertTriangle,
  ArrowUpRight,
  BookOpen,
  ChevronLeft,
  ChevronRight,
  Globe,
  HardDrive,
  HeartPulse,
  LayoutDashboard,
  Radio,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  X,
} from 'lucide-react';

export type NavigationTab =
  | 'overview'
  | 'scanner'
  | 'detection'
  | 'activity'
  | 'risk'
  | 'exfiltration'
  | 'network'
  | 'alerts'
  | 'investigations'
  | 'health'
  | 'settings'
  | 'docs';

interface NavGroup {
  label: string;
  items: {
    id: NavigationTab;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
    badge?: string;
  }[];
}

interface SidebarProps {
  currentTab: NavigationTab;
  onSelectTab: (tab: NavigationTab) => void;
  isCollapsed: boolean;
  onToggleCollapse: () => void;
  isMobileOpen: boolean;
  onCloseMobile: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  isCollapsed,
  onToggleCollapse,
  isMobileOpen,
  onCloseMobile,
}) => {
  const navGroups: NavGroup[] = [
    {
      label: 'OVERVIEW',
      items: [
        { id: 'overview', label: 'SOC Dashboard', icon: LayoutDashboard },
      ],
    },
    {
      label: 'DATA PROTECTION',
      items: [
        { id: 'scanner', label: 'File Scanner', icon: HardDrive },
        { id: 'detection', label: 'Sensitive Data', icon: ShieldCheck },
        { id: 'activity', label: 'File Activity', icon: Radio },
      ],
    },
    {
      label: 'THREAT INTELLIGENCE',
      items: [
        { id: 'risk', label: 'Risk Intelligence', icon: AlertTriangle },
        { id: 'exfiltration', label: 'Exfiltration Detection', icon: ArrowUpRight },
        { id: 'network', label: 'Network Intelligence', icon: Globe },
      ],
    },
    {
      label: 'SECURITY OPERATIONS',
      items: [
        { id: 'alerts', label: 'Alerts Console', icon: ShieldAlert },
        { id: 'investigations', label: 'Investigation Workspace', icon: Search },
      ],
    },
    {
      label: 'SYSTEM',
      items: [
        { id: 'health', label: 'System Health', icon: HeartPulse },
        { id: 'settings', label: 'Settings & Policy', icon: Settings },
        { id: 'docs', label: 'Architecture Docs', icon: BookOpen },
      ],
    },
  ];

  const handleTabClick = (tab: NavigationTab) => {
    onSelectTab(tab);
    onCloseMobile();
  };

  return (
    <>
      {/* Mobile Backdrop */}
      {isMobileOpen && (
        <div
          className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-40 lg:hidden"
          onClick={onCloseMobile}
        />
      )}

      {/* Sidebar Container */}
      <aside
        className={`fixed top-0 bottom-0 left-0 z-50 flex flex-col bg-slate-950 border-r border-slate-800 transition-all duration-300 ease-in-out lg:static ${
          isMobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        } ${isCollapsed ? 'w-20' : 'w-64'}`}
      >
        {/* Brand Header */}
        <div className="flex items-center justify-between h-16 px-4 border-b border-slate-800/80">
          <div className="flex items-center gap-3 overflow-hidden">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-emerald-500/20 to-cyan-500/10 border border-emerald-500/40 flex items-center justify-center text-emerald-400 shrink-0 shadow-sm shadow-emerald-950">
              <Shield className="w-5 h-5" />
            </div>
            {!isCollapsed && (
              <div className="flex flex-col">
                <div className="flex items-center gap-1.5">
                  <span className="font-bold text-sm tracking-tight text-white">
                    Sentinel<span className="text-emerald-400">DLP</span>
                  </span>
                  <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                    SOC
                  </span>
                </div>
                <span className="text-[10px] text-slate-400 tracking-wider font-mono">
                  ENTERPRISE DEFENSE
                </span>
              </div>
            )}
          </div>

          {/* Mobile close button */}
          <button
            onClick={onCloseMobile}
            className="p-1.5 text-slate-400 hover:text-white rounded-lg lg:hidden"
          >
            <X className="w-5 h-5" />
          </button>

          {/* Desktop collapse toggle */}
          <button
            onClick={onToggleCollapse}
            className="hidden lg:flex p-1 text-slate-400 hover:text-white hover:bg-slate-900 rounded-lg transition"
            title={isCollapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
          >
            {isCollapsed ? (
              <ChevronRight className="w-4 h-4" />
            ) : (
              <ChevronLeft className="w-4 h-4" />
            )}
          </button>
        </div>

        {/* Navigation Item Groups */}
        <div className="flex-1 overflow-y-auto py-4 px-2 space-y-6">
          {navGroups.map((group, gIdx) => (
            <div key={gIdx} className="space-y-1">
              {!isCollapsed && (
                <div className="px-3 pb-1 text-[10px] font-bold tracking-wider text-slate-500 uppercase font-mono">
                  {group.label}
                </div>
              )}
              {group.items.map((item) => {
                const Icon = item.icon;
                const isActive = currentTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => handleTabClick(item.id)}
                    className={`w-full flex items-center gap-3 px-3 py-2 rounded-xl text-xs font-medium transition-all group relative ${
                      isActive
                        ? 'bg-gradient-to-r from-emerald-500/15 to-transparent text-emerald-300 border-l-2 border-emerald-400'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                    }`}
                    title={isCollapsed ? item.label : undefined}
                  >
                    <Icon
                      className={`w-4 h-4 shrink-0 transition-transform ${
                        isActive
                          ? 'text-emerald-400 scale-110'
                          : 'text-slate-400 group-hover:text-slate-200'
                      }`}
                    />
                    {!isCollapsed && (
                      <span className="truncate tracking-wide">{item.label}</span>
                    )}
                    {isCollapsed && isActive && (
                      <div className="absolute right-2 w-1.5 h-1.5 rounded-full bg-emerald-400 shadow-sm shadow-emerald-400" />
                    )}
                  </button>
                );
              })}
            </div>
          ))}
        </div>

        {/* Sidebar Footer */}
        <div className="p-3 border-t border-slate-800/80 bg-slate-950/80">
          {!isCollapsed ? (
            <div className="flex items-center justify-between text-[11px] text-slate-400">
              <span className="font-mono">v0.2.0 · Phase 8</span>
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            </div>
          ) : (
            <div className="flex justify-center">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            </div>
          )}
        </div>
      </aside>
    </>
  );
};
