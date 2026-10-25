import React, { useState, useEffect } from 'react';
import {
  Settings,
  ShieldCheck,
  Sliders,
  Plus,
  RefreshCw,
  Info,
} from 'lucide-react';
import {
  fetchAuthorizedRoots,
  fetchDetectionRules,
  fetchThreatIntelIndicators,
  createThreatIntelIndicator,
} from '../services/api';
import { AuthorizedRoot } from '../types/scanner';
import { DetectionRuleInfo } from '../types/detection';
import { ThreatIntelIndicatorItem, ThreatIntelIndicatorCreate } from '../types/network';

export const SettingsPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'roots' | 'rules' | 'intel' | 'preferences'>('roots');

  // Authorized Roots State
  const [roots, setRoots] = useState<AuthorizedRoot[]>([]);
  const [loadingRoots, setLoadingRoots] = useState<boolean>(false);

  // Detection Rules State
  const [rules, setRules] = useState<DetectionRuleInfo[]>([]);
  const [loadingRules, setLoadingRules] = useState<boolean>(false);

  // Threat Intel State
  const [indicators, setIndicators] = useState<ThreatIntelIndicatorItem[]>([]);
  const [loadingIntel, setLoadingIntel] = useState<boolean>(false);
  const [showAddModal, setShowAddModal] = useState<boolean>(false);
  const [newIndicator, setNewIndicator] = useState<ThreatIntelIndicatorCreate>({
    indicator_type: 'DOMAIN',
    indicator_value: '',
    category: 'EXFILTRATION_ENDPOINT',
    confidence: 'HIGH',
    description: '',
  });
  const [submittingIntel, setSubmittingIntel] = useState<boolean>(false);
  const [intelMessage, setIntelMessage] = useState<{ text: string; isError?: boolean } | null>(null);

  // Load Roots
  useEffect(() => {
    const loadRoots = async () => {
      try {
        setLoadingRoots(true);
        const res = await fetchAuthorizedRoots();
        setRoots(res || []);
      } catch (err) {
        console.error('Failed to load authorized roots', err);
      } finally {
        setLoadingRoots(false);
      }
    };
    loadRoots();
  }, []);

  // Load Rules
  useEffect(() => {
    if (activeTab === 'rules' && rules.length === 0) {
      const loadRules = async () => {
        try {
          setLoadingRules(true);
          const res = await fetchDetectionRules();
          setRules(res || []);
        } catch (err) {
          console.error('Failed to load detection rules', err);
        } finally {
          setLoadingRules(false);
        }
      };
      loadRules();
    }
  }, [activeTab, rules.length]);

  // Load Intel Indicators
  const loadIntel = async () => {
    try {
      setLoadingIntel(true);
      const res = await fetchThreatIntelIndicators(50);
      setIndicators(res || []);
    } catch (err) {
      console.error('Failed to load threat intel indicators', err);
    } finally {
      setLoadingIntel(false);
    }
  };

  useEffect(() => {
    if (activeTab === 'intel' && indicators.length === 0) {
      loadIntel();
    }
  }, [activeTab, indicators.length]);

  const handleCreateIndicator = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIndicator.indicator_value.trim()) return;

    try {
      setSubmittingIntel(true);
      setIntelMessage(null);
      await createThreatIntelIndicator(newIndicator);
      setIntelMessage({ text: 'Threat indicator successfully added.' });
      setNewIndicator({
        indicator_type: 'DOMAIN',
        indicator_value: '',
        category: 'EXFILTRATION_ENDPOINT',
        confidence: 'HIGH',
        description: '',
      });
      setShowAddModal(false);
      loadIntel();
    } catch (err: any) {
      setIntelMessage({ text: err.message || 'Failed to add indicator', isError: true });
    } finally {
      setSubmittingIntel(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
              <Settings className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                Settings & Policy Configuration
              </h1>
              <p className="text-sm text-slate-400 mt-0.5">
                Authorized scanning roots, sensitive data classification rules, and threat intelligence indicators.
              </p>
            </div>
          </div>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center bg-slate-900 border border-slate-800 rounded-lg p-1 text-xs">
          <button
            onClick={() => setActiveTab('roots')}
            className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
              activeTab === 'roots'
                ? 'bg-slate-800 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Authorized Roots
          </button>
          <button
            onClick={() => setActiveTab('rules')}
            className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
              activeTab === 'rules'
                ? 'bg-slate-800 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Detection Rules
          </button>
          <button
            onClick={() => setActiveTab('intel')}
            className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
              activeTab === 'intel'
                ? 'bg-slate-800 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Threat Intel
          </button>
          <button
            onClick={() => setActiveTab('preferences')}
            className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
              activeTab === 'preferences'
                ? 'bg-slate-800 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Preferences
          </button>
        </div>
      </div>

      {/* Tab 1: Authorized Scan Roots */}
      {activeTab === 'roots' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex items-start gap-3">
            <Info className="w-5 h-5 text-indigo-400 shrink-0 mt-0.5" />
            <div className="text-xs text-slate-300 leading-relaxed">
              <strong className="text-white">Strict Boundary Enforcement:</strong> SentinelDLP restricts file scanning
              and watchdog event collection strictly to explicitly authorized directory roots. Symlink traversals
              beyond these paths are rejected to prevent path traversal attacks.
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="bg-slate-950 text-xs uppercase text-slate-400 border-b border-slate-800 font-semibold tracking-wider">
                <tr>
                  <th className="py-3 px-4">Root ID</th>
                  <th className="py-3 px-4">Display Name</th>
                  <th className="py-3 px-4">Filesystem Path</th>
                  <th className="py-3 px-4">Description</th>
                  <th className="py-3 px-4 text-right">Access Mode</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {loadingRoots ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-slate-500">
                      <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-slate-400" />
                      Loading authorized roots...
                    </td>
                  </tr>
                ) : roots.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-slate-500">
                      No authorized roots configured.
                    </td>
                  </tr>
                ) : (
                  roots.map(root => (
                    <tr key={root.root_id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-3 px-4 font-mono text-xs text-indigo-400 font-semibold">
                        {root.root_id}
                      </td>
                      <td className="py-3 px-4 font-medium text-slate-200">{root.name}</td>
                      <td className="py-3 px-4 font-mono text-xs text-slate-400 truncate max-w-xs">
                        {root.path}
                      </td>
                      <td className="py-3 px-4 text-xs text-slate-400">{root.description}</td>
                      <td className="py-3 px-4 text-right">
                        <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                          READ-ONLY
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 2: Sensitive Data Detection Rules */}
      {activeTab === 'rules' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex items-start gap-3">
            <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
            <div className="text-xs text-slate-300 leading-relaxed">
              <strong className="text-white">Explainable Privacy Policy:</strong> SentinelDLP inspects file content
              against standardized regular expressions and cryptographic checksums (e.g. Luhn algorithm for PAN).
              Zero confidential values are ever recorded in findings or stored in database tables.
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="bg-slate-950 text-xs uppercase text-slate-400 border-b border-slate-800 font-semibold tracking-wider">
                <tr>
                  <th className="py-3 px-4">Rule Name</th>
                  <th className="py-3 px-4">Category</th>
                  <th className="py-3 px-4">Confidence</th>
                  <th className="py-3 px-4">Suggested Tier</th>
                  <th className="py-3 px-4">Description</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {loadingRules ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-slate-500">
                      <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-slate-400" />
                      Loading detection rules...
                    </td>
                  </tr>
                ) : rules.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-slate-500">
                      No classification rules loaded.
                    </td>
                  </tr>
                ) : (
                  rules.map(rule => (
                    <tr key={rule.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-3 px-4 font-semibold text-slate-200">
                        {rule.name}
                        <div className="text-[10px] text-slate-500 font-mono">{rule.id}</div>
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 rounded text-xs font-mono bg-slate-800 text-slate-300">
                          {rule.category}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className="font-semibold text-xs text-slate-300">{rule.confidence}</span>
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] font-bold border ${
                            rule.suggested_classification === 'RESTRICTED'
                              ? 'bg-red-950/80 text-red-400 border-red-800/80'
                              : rule.suggested_classification === 'CONFIDENTIAL'
                              ? 'bg-orange-950/80 text-orange-400 border-orange-800/80'
                              : 'bg-blue-950/80 text-blue-400 border-blue-800/80'
                          }`}
                        >
                          {rule.suggested_classification}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-xs text-slate-400 max-w-sm">{rule.description}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 3: Threat Intelligence Indicators */}
      {activeTab === 'intel' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-xs text-slate-400">
              Indicators of Compromise (IoCs) matched against live connection logs and DNS requests.
            </p>
            <button
              onClick={() => setShowAddModal(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-sm transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              Add Threat Indicator
            </button>
          </div>

          {intelMessage && (
            <div
              className={`text-xs p-3 rounded-lg border ${
                intelMessage.isError
                  ? 'bg-red-950/60 text-red-300 border-red-800'
                  : 'bg-emerald-950/60 text-emerald-300 border-emerald-800'
              }`}
            >
              {intelMessage.text}
            </div>
          )}

          {/* Add Indicator Form / Drawer */}
          {showAddModal && (
            <form
              onSubmit={handleCreateIndicator}
              className="p-4 rounded-xl bg-slate-900 border border-slate-700 shadow-md space-y-3"
            >
              <h3 className="text-sm font-bold text-white flex items-center justify-between">
                <span>Add Local Threat Intelligence Indicator</span>
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="text-xs text-slate-400 hover:text-white"
                >
                  Cancel
                </button>
              </h3>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                <div>
                  <label className="text-slate-400 block mb-1">Indicator Type</label>
                  <select
                    value={newIndicator.indicator_type}
                    onChange={e =>
                      setNewIndicator({
                        ...newIndicator,
                        indicator_type: e.target.value as any,
                      })
                    }
                    className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none"
                  >
                    <option value="DOMAIN">DOMAIN</option>
                    <option value="IPV4">IPV4</option>
                    <option value="CIDR">CIDR</option>
                  </select>
                </div>

                <div>
                  <label className="text-slate-400 block mb-1">Indicator Value</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. dropzone.suspicious-cloud.com"
                    value={newIndicator.indicator_value}
                    onChange={e =>
                      setNewIndicator({ ...newIndicator, indicator_value: e.target.value })
                    }
                    className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-indigo-500"
                  />
                </div>

                <div>
                  <label className="text-slate-400 block mb-1">Category</label>
                  <select
                    value={newIndicator.category}
                    onChange={e =>
                      setNewIndicator({ ...newIndicator, category: e.target.value })
                    }
                    className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none"
                  >
                    <option value="EXFILTRATION_ENDPOINT">EXFILTRATION_ENDPOINT</option>
                    <option value="COMMAND_AND_CONTROL">COMMAND_AND_CONTROL</option>
                    <option value="UNAUTHORIZED_STORAGE">UNAUTHORIZED_STORAGE</option>
                    <option value="PHISHING">PHISHING</option>
                  </select>
                </div>
              </div>

              <div className="text-xs">
                <label className="text-slate-400 block mb-1">Description / Threat Context</label>
                <input
                  type="text"
                  placeholder="Rationale or source threat actor attribution..."
                  value={newIndicator.description || ''}
                  onChange={e =>
                    setNewIndicator({ ...newIndicator, description: e.target.value })
                  }
                  className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 text-xs hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submittingIntel}
                  className="px-4 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold disabled:opacity-50"
                >
                  {submittingIntel ? 'Saving...' : 'Add Indicator'}
                </button>
              </div>
            </form>
          )}

          {/* Indicators Table */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="bg-slate-950 text-xs uppercase text-slate-400 border-b border-slate-800 font-semibold tracking-wider">
                <tr>
                  <th className="py-3 px-4">Type</th>
                  <th className="py-3 px-4">Indicator Value</th>
                  <th className="py-3 px-4">Category</th>
                  <th className="py-3 px-4">Confidence</th>
                  <th className="py-3 px-4">Source Feed</th>
                  <th className="py-3 px-4">Created</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {loadingIntel ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-slate-500">
                      <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-slate-400" />
                      Loading threat intelligence indicators...
                    </td>
                  </tr>
                ) : indicators.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-slate-500">
                      No threat indicators registered.
                    </td>
                  </tr>
                ) : (
                  indicators.map(ind => (
                    <tr key={ind.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-purple-500/10 text-purple-400 border border-purple-500/20">
                          {ind.indicator_type}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono text-xs font-semibold text-slate-200">
                        {ind.indicator_value}
                      </td>
                      <td className="py-3 px-4 text-xs text-slate-300">{ind.category}</td>
                      <td className="py-3 px-4 text-xs font-semibold text-emerald-400">
                        {ind.confidence}
                      </td>
                      <td className="py-3 px-4 font-mono text-xs text-slate-500">
                        {ind.source_feed}
                      </td>
                      <td className="py-3 px-4 text-xs text-slate-500 font-mono">
                        {new Date(ind.created_at).toLocaleDateString()}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 4: SOC Operational Preferences */}
      {activeTab === 'preferences' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-5">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <Sliders className="w-4 h-4 text-indigo-400" />
            SOC Environment & Preferences
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
              <span className="text-slate-400 font-semibold block">Dashboard Auto-Refresh Interval</span>
              <p className="text-slate-500 text-[11px]">Background polling rate for overview telemetry.</p>
              <div className="font-mono text-sm text-slate-200 pt-1 font-semibold">10 seconds</div>
            </div>

            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
              <span className="text-slate-400 font-semibold block">Exfiltration Correlation Window</span>
              <p className="text-slate-500 text-[11px]">Sliding temporal window for event alignment.</p>
              <div className="font-mono text-sm text-slate-200 pt-1 font-semibold">15 minutes</div>
            </div>

            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
              <span className="text-slate-400 font-semibold block">Risk Alert Threshold</span>
              <p className="text-slate-500 text-[11px]">Minimum threat score triggering an automatic alert.</p>
              <div className="font-mono text-sm text-amber-400 pt-1 font-semibold">60 / 100 (HIGH)</div>
            </div>

            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
              <span className="text-slate-400 font-semibold block">Container Isolation Strategy</span>
              <p className="text-slate-500 text-[11px]">Packet capture model deployed in Docker container.</p>
              <div className="font-mono text-sm text-emerald-400 pt-1 font-semibold">Offline-First Log Ingest</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
export default SettingsPage;