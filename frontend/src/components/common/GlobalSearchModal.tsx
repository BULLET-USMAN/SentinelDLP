import React, { useEffect, useState, useRef } from 'react';
import {
  ArrowRight,
  FileText,
  Globe,
  HardDrive,
  Loader2,
  Search,
  ShieldAlert,
  X,
} from 'lucide-react';
import { fetchDashboardSearch } from '../../services/api';
import { SearchResultItem } from '../../types/dashboard';
import { NavigationTab } from '../layout/Sidebar';

interface GlobalSearchModalProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigateToTab: (tab: NavigationTab, targetId?: string) => void;
}

export const GlobalSearchModal: React.FC<GlobalSearchModalProps> = ({
  isOpen,
  onClose,
  onNavigateToTab,
}) => {
  const [query, setQuery] = useState<string>('');
  const [results, setResults] = useState<SearchResultItem[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [hasSearched, setHasSearched] = useState<boolean>(false);
  const inputRef = useRef<HTMLInputElement>(null);

  // Focus input when opened
  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 50);
    } else {
      setQuery('');
      setResults([]);
      setHasSearched(false);
    }
  }, [isOpen]);

  // Global keyboard shortcut listeners (Ctrl+K and / and Esc)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        if (isOpen) onClose();
        else onNavigateToTab('overview'); // or open
      }
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose, onNavigateToTab]);

  // Debounced search
  useEffect(() => {
    if (!query.trim()) {
      setResults([]);
      setHasSearched(false);
      return;
    }

    const timer = setTimeout(async () => {
      setLoading(true);
      try {
        const res = await fetchDashboardSearch(query.trim(), 15);
        setResults(res.results || []);
        setHasSearched(true);
      } catch (err) {
        console.error('Search failed:', err);
      } finally {
        setLoading(false);
      }
    }, 250);

    return () => clearTimeout(timer);
  }, [query]);

  if (!isOpen) return null;

  const getResultIcon = (type: string) => {
    switch (type) {
      case 'ALERT':
        return <ShieldAlert className="w-4 h-4 text-red-400" />;
      case 'INVESTIGATION':
        return <Search className="w-4 h-4 text-amber-400" />;
      case 'FILE':
        return <HardDrive className="w-4 h-4 text-cyan-400" />;
      case 'INDICATOR':
        return <Globe className="w-4 h-4 text-purple-400" />;
      default:
        return <FileText className="w-4 h-4 text-slate-400" />;
    }
  };

  const handleSelectResult = (item: SearchResultItem) => {
    onClose();
    onNavigateToTab(item.link_tab as NavigationTab, item.link_id || undefined);
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-md flex items-start justify-center pt-16 px-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-2xl shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Search Input Bar */}
        <div className="flex items-center gap-3 px-4 py-3.5 border-b border-slate-800 bg-slate-950/60">
          <Search className="w-5 h-5 text-cyan-400 shrink-0" />
          <input
            ref={inputRef}
            type="text"
            placeholder="Search security alerts, files, investigations, threat indicators..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full bg-transparent text-slate-100 placeholder-slate-500 text-sm outline-none"
          />
          {loading && <Loader2 className="w-4 h-4 text-slate-400 animate-spin shrink-0" />}
          {query && !loading && (
            <button
              onClick={() => setQuery('')}
              className="p-1 text-slate-400 hover:text-white rounded"
            >
              <X className="w-4 h-4" />
            </button>
          )}
          <kbd className="px-2 py-0.5 bg-slate-800 text-[10px] font-mono text-slate-400 rounded border border-slate-700 hidden sm:inline-block">
            ESC
          </kbd>
        </div>

        {/* Search Results List */}
        <div className="max-h-96 overflow-y-auto p-2">
          {!query.trim() ? (
            <div className="py-8 px-4 text-center">
              <Search className="w-8 h-8 text-slate-700 mx-auto mb-2" />
              <div className="text-xs text-slate-400 font-medium">Global SOC Metadata Search</div>
              <div className="text-[11px] text-slate-500 mt-1 max-w-xs mx-auto">
                Type an alert ID, filename, exfiltration keyword, IP address, or detection rule name.
              </div>
            </div>
          ) : results.length === 0 && hasSearched && !loading ? (
            <div className="py-8 text-center text-xs text-slate-500">
              No security assets or metadata matched <strong className="text-slate-300 font-mono">"{query}"</strong>.
            </div>
          ) : (
            <div className="space-y-1">
              {results.map((item) => (
                <button
                  key={`${item.result_type}-${item.id}`}
                  onClick={() => handleSelectResult(item)}
                  className="w-full text-left p-3 rounded-xl hover:bg-slate-800/70 border border-transparent hover:border-slate-700 transition flex items-center justify-between group"
                >
                  <div className="flex items-start gap-3 overflow-hidden">
                    <div className="p-2 rounded-lg bg-slate-950 border border-slate-800 shrink-0 mt-0.5">
                      {getResultIcon(item.result_type)}
                    </div>
                    <div className="overflow-hidden">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-semibold text-white group-hover:text-cyan-300 transition truncate">
                          {item.title}
                        </span>
                        <span className="px-1.5 py-0.2 bg-slate-800 text-[9px] font-mono rounded text-slate-400 uppercase">
                          {item.result_type}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400 truncate mt-0.5">
                        {item.subtitle}
                      </div>
                    </div>
                  </div>
                  <ArrowRight className="w-4 h-4 text-slate-600 group-hover:text-cyan-400 group-hover:translate-x-1 transition shrink-0 ml-2" />
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Search Footer */}
        <div className="px-4 py-2 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between text-[11px] text-slate-500">
          <span>
            Targeted Navigation: <span className="text-slate-300">Alerts · Files · Investigations · Network</span>
          </span>
          <span className="font-mono">Zero raw content indexing</span>
        </div>
      </div>
    </div>
  );
};
