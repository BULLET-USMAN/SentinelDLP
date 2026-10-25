import React, { useState, useEffect, useRef } from 'react';
import {
  Bot,
  Send,
  Sparkles,
  RefreshCw,
  Plus,
  Lock,
} from 'lucide-react';
import {
  fetchAIStatus,
  sendAIChatMessage,
  fetchAIConversations,
  fetchAIConversationDetail,
  fetchExfiltrationInvestigations,
} from '../services/api';
import {
  AIStatusResponse,
  ChatMessageResponse,
  ConversationSessionSummary,
} from '../types/ai';
import { ExfiltrationInvestigationItem } from '../types/exfiltration';

export const AISocAnalystPage: React.FC = () => {
  const [status, setStatus] = useState<AIStatusResponse | null>(null);
  const [, setLoadingStatus] = useState<boolean>(true);

  // Conversations State
  const [sessions, setSessions] = useState<ConversationSessionSummary[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMessageResponse[]>([]);
  const [loadingMessages, setLoadingMessages] = useState<boolean>(false);

  // Input State
  const [inputMessage, setInputMessage] = useState<string>('');
  const [isSending, setIsSending] = useState<boolean>(false);

  // Context Selection (Attach investigation)
  const [investigations, setInvestigations] = useState<ExfiltrationInvestigationItem[]>([]);
  const [selectedInvestigationId, setSelectedInvestigationId] = useState<string>('');

  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Load Status and Sessions
  useEffect(() => {
    const init = async () => {
      try {
        setLoadingStatus(true);
        const [statusData, sessionsData, invData] = await Promise.all([
          fetchAIStatus(),
          fetchAIConversations(15),
          fetchExfiltrationInvestigations({ limit: 15 }),
        ]);
        setStatus(statusData);
        setSessions(sessionsData);
        setInvestigations(invData || []);

        if (sessionsData.length > 0) {
          setActiveSessionId(sessionsData[0].id);
        }
      } catch (err) {
        console.error('Failed to initialize AI analyst dashboard', err);
      } finally {
        setLoadingStatus(false);
      }
    };
    init();
  }, []);

  // Load Messages when active session changes
  useEffect(() => {
    if (!activeSessionId) {
      setMessages([]);
      return;
    }

    const loadSession = async () => {
      try {
        setLoadingMessages(true);
        const detail = await fetchAIConversationDetail(activeSessionId);
        setMessages(detail.messages || []);
        if (detail.investigation_id) {
          setSelectedInvestigationId(detail.investigation_id);
        }
      } catch (err) {
        console.error('Failed to load conversation detail', err);
      } finally {
        setLoadingMessages(false);
      }
    };
    loadSession();
  }, [activeSessionId]);

  // Scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isSending]);

  const handleSendMessage = async (customPrompt?: string) => {
    const textToSend = customPrompt || inputMessage;
    if (!textToSend.trim() || isSending) return;

    try {
      setIsSending(true);
      if (!customPrompt) {
        setInputMessage('');
      }

      // Optimistically add user message
      const tempUserMsg: ChatMessageResponse = {
        message_id: 'temp-' + Date.now(),
        session_id: activeSessionId || 'new',
        role: 'user',
        content: textToSend,
        evidence_references: [],
        tool_invocations: [],
        created_at: new Date().toISOString(),
      };
      setMessages(prev => [...prev, tempUserMsg]);

      const response = await sendAIChatMessage({
        message: textToSend,
        sessionId: activeSessionId || undefined,
        investigationId: selectedInvestigationId || undefined,
      });

      // Update session ID if newly created
      if (!activeSessionId) {
        setActiveSessionId(response.session_id);
        const updatedSessions = await fetchAIConversations(15);
        setSessions(updatedSessions);
      }

      setMessages(prev => [...prev.filter(m => !m.message_id.startsWith('temp-')), response]);
    } catch (err) {
      console.error('Failed to send AI chat message', err);
    } finally {
      setIsSending(false);
    }
  };

  const handleStartNewSession = () => {
    setActiveSessionId(null);
    setMessages([]);
    setSelectedInvestigationId('');
  };

  const selectedInv = investigations.find(i => i.id === selectedInvestigationId);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
              <Bot className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                AI SOC Analyst Assistant
                <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 font-mono font-medium">
                  Phase 9
                </span>
              </h1>
              <p className="text-sm text-slate-400 mt-0.5">
                Local, evidence-grounded AI security investigations, read-only tool orchestration, and ATT&CK mappings.
              </p>
            </div>
          </div>
        </div>

        {/* Model Status Pill */}
        <div className="flex items-center gap-3">
          <div className="p-2 px-3 rounded-lg bg-slate-900 border border-slate-800 flex items-center gap-2 text-xs">
            <div
              className={`w-2 h-2 rounded-full ${
                status?.is_healthy ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'
              }`}
            />
            <span className="text-slate-400">Provider:</span>
            <span className="font-mono text-slate-200 font-semibold uppercase">
              {status?.provider_type || 'MOCK'}
            </span>
            <span className="text-slate-600">|</span>
            <span className="font-mono text-emerald-400">
              {status?.model_id || 'mock-sentinel-v1'}
            </span>
          </div>

          <button
            onClick={handleStartNewSession}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-sm transition-colors"
          >
            <Plus className="w-4 h-4" />
            New Inquiry
          </button>
        </div>
      </div>

      {/* Main 3-Column Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Sessions & Prompt Library */}
        <div className="lg:col-span-3 space-y-4">
          {/* AI Guardrails Disclosure */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2.5 text-xs shadow-sm">
            <div className="flex items-center gap-2 text-slate-200 font-semibold">
              <Lock className="w-4 h-4 text-emerald-400" />
              Safety & Privacy Boundaries
            </div>
            <p className="text-slate-400 text-[11px] leading-relaxed">
              Operates under strictly read-only server controls. Zero disruptive actions (no file deletion or IP
              blocking). Sensitive credentials are sanitized before model ingest.
            </p>
          </div>

          {/* Prompt Quick-Start Pills */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2.5 shadow-sm">
            <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider block">
              Investigation Inquiries
            </span>
            <div className="space-y-1.5">
              {[
                'Why was this alert generated?',
                'Could this activity be a false positive?',
                'Explain threat risk score calculation.',
                'What missing evidence is needed?',
              ].map((prompt, idx) => (
                <button
                  key={idx}
                  onClick={() => handleSendMessage(prompt)}
                  disabled={isSending}
                  className="w-full text-left p-2 rounded-lg bg-slate-950 border border-slate-800 hover:border-emerald-500/40 text-[11px] text-slate-300 hover:text-emerald-300 transition-colors"
                >
                  {prompt}
                </button>
              ))}
            </div>
          </div>

          {/* Session History List */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3 shadow-sm">
            <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider block flex items-center justify-between">
              <span>Recent Sessions ({sessions.length})</span>
            </span>

            <div className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
              {sessions.length === 0 ? (
                <div className="text-slate-500 text-xs py-4 text-center">No previous sessions.</div>
              ) : (
                sessions.map(s => {
                  const isActive = activeSessionId === s.id;
                  return (
                    <div
                      key={s.id}
                      onClick={() => setActiveSessionId(s.id)}
                      className={`p-2.5 rounded-lg border text-xs cursor-pointer transition-colors ${
                        isActive
                          ? 'bg-slate-800 border-emerald-500/50 text-white font-medium'
                          : 'bg-slate-950 border-slate-800 text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
                      }`}
                    >
                      <div className="truncate mb-0.5">{s.title}</div>
                      <div className="text-[10px] text-slate-500 font-mono">
                        {new Date(s.updated_at).toLocaleTimeString([], {
                          hour: '2-digit',
                          minute: '2-digit',
                        })}
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>

        {/* Center Column: Interactive Chat Stream */}
        <div className="lg:col-span-6 bg-slate-900 border border-slate-800 rounded-xl flex flex-col h-[700px] shadow-sm overflow-hidden">
          {/* Active Context Banner */}
          <div className="p-3.5 bg-slate-950 border-b border-slate-800 flex items-center justify-between text-xs">
            <div className="flex items-center gap-2 text-slate-300">
              <Sparkles className="w-4 h-4 text-emerald-400" />
              <span>
                Active Scope:{' '}
                <strong className="text-white">
                  {selectedInv ? selectedInv.title : 'General Security Dialogue'}
                </strong>
              </span>
            </div>
            {selectedInv && (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-red-950 text-red-400 border border-red-800">
                Score: {selectedInv.risk_score}
              </span>
            )}
          </div>

          {/* Messages Stream */}
          <div className="flex-1 p-4 overflow-y-auto space-y-4">
            {messages.length === 0 && !loadingMessages ? (
              <div className="h-full flex flex-col items-center justify-center text-center p-6 text-slate-500 space-y-3">
                <Bot className="w-12 h-12 text-slate-600 opacity-40" />
                <div className="max-w-sm">
                  <h3 className="text-sm font-semibold text-slate-300">SentinelDLP AI SOC Analyst</h3>
                  <p className="text-xs text-slate-500 mt-1">
                    Ask a security question, review an alert, or select an inquiry on the left to begin evidence-grounded
                    investigation.
                  </p>
                </div>
              </div>
            ) : (
              messages.map(msg => {
                const isUser = msg.role === 'user';
                return (
                  <div
                    key={msg.message_id}
                    className={`flex flex-col ${isUser ? 'items-end' : 'items-start'} space-y-1.5`}
                  >
                    <div className="flex items-center gap-1.5 text-[11px] text-slate-500">
                      {isUser ? (
                        <span>Analyst</span>
                      ) : (
                        <span className="flex items-center gap-1 text-emerald-400 font-semibold">
                          <Bot className="w-3.5 h-3.5" />
                          AI SOC Analyst
                        </span>
                      )}
                      <span>•</span>
                      <span>
                        {new Date(msg.created_at).toLocaleTimeString([], {
                          hour: '2-digit',
                          minute: '2-digit',
                        })}
                      </span>
                    </div>

                    <div
                      className={`p-3.5 rounded-xl text-xs leading-relaxed max-w-[85%] whitespace-pre-wrap ${
                        isUser
                          ? 'bg-emerald-600 text-white rounded-tr-none'
                          : 'bg-slate-950 border border-slate-800 text-slate-200 rounded-tl-none shadow-sm'
                      }`}
                    >
                      {msg.content}
                    </div>

                    {/* Evidence References */}
                    {!isUser && msg.evidence_references && msg.evidence_references.length > 0 && (
                      <div className="flex flex-wrap items-center gap-1.5 pt-1 text-[10px]">
                        <span className="text-slate-500">Grounded Records:</span>
                        {msg.evidence_references.map((ref, idx) => (
                          <span
                            key={idx}
                            className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono border border-slate-700"
                          >
                            {ref}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })
            )}

            {isSending && (
              <div className="flex items-center gap-2 text-xs text-emerald-400 font-medium py-2">
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>AI SOC Analyst evaluating security records...</span>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Input Bar */}
          <div className="p-3 bg-slate-950 border-t border-slate-800">
            <form
              onSubmit={e => {
                e.preventDefault();
                handleSendMessage();
              }}
              className="flex items-center gap-2"
            >
              <input
                type="text"
                placeholder="Ask a security question, request alert triage, or verify evidence..."
                value={inputMessage}
                onChange={e => setInputMessage(e.target.value)}
                disabled={isSending}
                className="flex-1 px-3.5 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
              />
              <button
                type="submit"
                disabled={!inputMessage.trim() || isSending}
                className="p-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white disabled:opacity-40 transition-colors"
              >
                <Send className="w-4 h-4" />
              </button>
            </form>
          </div>
        </div>

        {/* Right Column: Investigation Context & Model Attributes */}
        <div className="lg:col-span-3 space-y-4">
          {/* Investigation Selector */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3 shadow-sm">
            <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider block">
              Attach Investigation Context
            </span>
            <select
              value={selectedInvestigationId}
              onChange={e => setSelectedInvestigationId(e.target.value)}
              className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-emerald-500"
            >
              <option value="">No Investigation (General)</option>
              {investigations.map(inv => (
                <option key={inv.id} value={inv.id}>
                  {inv.title} (Score: {inv.risk_score})
                </option>
              ))}
            </select>

            {selectedInv && (
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs space-y-2 mt-2">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Severity</span>
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-red-950 text-red-400 border border-red-800">
                    {selectedInv.severity}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Risk Score</span>
                  <span className="font-mono font-bold text-red-400">{selectedInv.risk_score} / 100</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Status</span>
                  <span className="font-mono text-cyan-400">{selectedInv.status}</span>
                </div>
                <p className="text-[11px] text-slate-400 leading-tight pt-1 border-t border-slate-900">
                  {selectedInv.description}
                </p>
              </div>
            )}
          </div>

          {/* Model Specification Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3 shadow-sm">
            <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider block">
              Local Inference Specification
            </span>
            <div className="space-y-2 text-xs">
              <div className="flex justify-between text-slate-400">
                <span>Model Engine:</span>
                <span className="font-mono text-slate-200">
                  {status?.model_id || 'mock-sentinel-v1'}
                </span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>Hardware Target:</span>
                <span className="text-slate-200">6GB RTX 2060</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>Storage Target:</span>
                <span className="font-mono text-slate-300">E:\OllamaModels</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>Tool Calling:</span>
                <span className="text-emerald-400 font-semibold">Enabled (Read-Only)</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
export default AISocAnalystPage;