import React, { useState, useRef, useEffect } from 'react';
import {
  Send,
  Trash2,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Lock,
  Cpu,
  Clock,
  AlertCircle,
  ExternalLink,
  ChevronRight,
  Bot,
  User,
  Sparkles,
  RefreshCw
} from 'lucide-react';
import { useGateway } from '../context/GatewayContext';
import { submitChat } from '../services/api';
import { Badge } from '../components/common/Badge';
import { Card } from '../components/common/Card';
import { Link } from 'react-router-dom';

export function Playground() {
  const { connectionStatus, addToast, backendUrl, loadEvents, loadMetrics } = useGateway();

  const [inputPrompt, setInputPrompt] = useState('');
  const [selectedModel, setSelectedModel] = useState('gpt-4o-security-proxy');
  const [messages, setMessages] = useState([
    {
      id: 'welcome',
      role: 'system',
      content:
        'Sentinel AI Gateway is active. Every query submitted through this playground is inspected for sensitive data egress, credential exfiltration, and prompt injections before being routed upstream.',
      timestamp: new Date().toISOString(),
    },
  ]);
  const [isSending, setIsSending] = useState(false);
  const [lastError, setLastError] = useState(null);

  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, isSending]);

  const handleSend = async (e) => {
    e?.preventDefault();
    if (!inputPrompt.trim() || isSending) return;

    if (connectionStatus !== 'connected') {
      setLastError(
        `Backend gateway is offline at ${backendUrl}. The Request Playground requires an active Sentinel AI backend server at POST /chat.`
      );
      addToast({
        title: 'Backend Offline',
        message: 'Cannot send prompt without active FastAPI gateway proxy.',
        type: 'error',
      });
      return;
    }

    const userText = inputPrompt;
    setInputPrompt('');
    setLastError(null);

    const userMsgId = `user_${Date.now()}`;
    const newMsg = {
      id: userMsgId,
      role: 'user',
      content: userText,
      timestamp: new Date().toISOString(),
      model: selectedModel,
    };

    setMessages((prev) => [...prev, newMsg]);
    setIsSending(true);

    const startTime = performance.now();

    try {
      const response = await submitChat(userText, selectedModel);
      const totalTime = Math.round(performance.now() - startTime);

      if (response.success && response.data) {
        const data = response.data;
        const assistantMsg = {
          id: `bot_${Date.now()}`,
          role: 'assistant',
          decision: data.decision || 'ALLOW', // 'ALLOW' | 'REDACT' | 'BLOCK'
          content: data.response || null,
          blockedReason: data.blocked_reason || null,
          findings: data.findings || [],
          latencyMs: data.latency_ms || totalTime,
          timestamp: data.timestamp || new Date().toISOString(),
          requestId: data.request_id || `req_${Date.now().toString(36)}`,
        };

        setMessages((prev) => [...prev, assistantMsg]);
        loadEvents();
        loadMetrics();
      } else {
        throw new Error('Invalid response structure received from POST /chat');
      }
    } catch (err) {
      setLastError(err.message || 'Failed to submit chat to gateway.');
      addToast({
        title: 'Gateway Proxy Error',
        message: err.message || 'Failed to connect to backend',
        type: 'error',
      });
    } finally {
      setIsSending(false);
    }
  };

  const handleClearHistory = () => {
    setMessages([
      {
        id: 'welcome_reset',
        role: 'system',
        content: 'Playground session cleared. Gateway inspection proxy ready for new requests.',
        timestamp: new Date().toISOString(),
      },
    ]);
    setLastError(null);
    addToast({
      title: 'Session Cleared',
      message: 'All local conversation history was cleared.',
      type: 'info',
    });
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-bold text-slate-100">Request Playground</h2>
            <Badge variant="cyan" size="sm">GATEWAY PROXY</Badge>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Simulate end-user applications communicating through the Sentinel AI security gateway.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <select
            value={selectedModel}
            onChange={(e) => setSelectedModel(e.target.value)}
            className="px-3 py-1.5 bg-[#111827] border border-[#1E293B] rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/50"
          >
            <option value="gpt-4o-security-proxy">Proxy: GPT-4o Security Enforced</option>
            <option value="claude-3-5-sonnet-proxy">Proxy: Claude 3.5 Sonnet Enforced</option>
            <option value="llama-3-70b-proxy">Proxy: Llama-3 Enterprise Enforced</option>
          </select>

          <button
            onClick={handleClearHistory}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors flex items-center gap-1.5"
            title="Clear current session"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Clear Chat</span>
          </button>
        </div>
      </div>

      {/* Backend Offline Warning Banner */}
      {connectionStatus !== 'connected' && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/60 text-rose-200 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-rose-400 flex-shrink-0 mt-0.5" />
            <div>
              <h4 className="text-sm font-semibold text-rose-300">Gateway Backend Disconnected</h4>
              <p className="text-xs text-rose-200 mt-0.5 leading-relaxed">
                The Request Playground requires a live backend gateway at{' '}
                <code className="font-mono bg-rose-900/60 px-1 py-0.5 rounded text-rose-100">{backendUrl}</code> to proxy AI responses.
                Per cybersecurity integrity standards, AI completions are never fabricated in the browser.
              </p>
            </div>
          </div>
          <Link
            to="/scanner"
            className="px-3.5 py-2 rounded-lg text-xs font-semibold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 hover:bg-cyan-500/30 transition-all flex items-center gap-1.5 flex-shrink-0 whitespace-nowrap"
          >
            <span>Open Heuristic Scanner</span>
            <ChevronRight className="w-4 h-4" />
          </Link>
        </div>
      )}

      {/* Chat Container */}
      <Card className="p-0 overflow-hidden flex flex-col h-[600px]">
        {/* Messages Scroll Area */}
        <div className="flex-1 p-4 sm:p-6 overflow-y-auto space-y-4">
          {messages.map((msg) => {
            if (msg.role === 'system') {
              return (
                <div key={msg.id} className="p-3 rounded-lg bg-slate-900/80 border border-[#1E293B] text-xs text-slate-400 flex items-start gap-3">
                  <ShieldCheck className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
                  <div className="leading-relaxed">{msg.content}</div>
                </div>
              );
            }

            if (msg.role === 'user') {
              return (
                <div key={msg.id} className="flex justify-end">
                  <div className="max-w-[85%] sm:max-w-[75%] rounded-2xl p-4 bg-[#1e293b] text-slate-100 border border-slate-700 shadow-md">
                    <div className="flex items-center justify-between gap-4 mb-1 text-[10px] font-mono text-slate-400">
                      <span className="flex items-center gap-1 font-semibold text-cyan-400">
                        <User className="w-3 h-3" /> Client Request
                      </span>
                      <span>{new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span>
                    </div>
                    <div className="font-mono text-xs whitespace-pre-wrap break-all leading-relaxed">
                      {msg.content}
                    </div>
                  </div>
                </div>
              );
            }

            // Assistant / Gateway Response
            const isBlocked = msg.decision === 'BLOCK';
            const isRedacted = msg.decision === 'REDACT';

            return (
              <div key={msg.id} className="flex justify-start">
                <div className={`max-w-[85%] sm:max-w-[75%] rounded-2xl p-4 border shadow-xl ${
                  isBlocked
                    ? 'bg-rose-950/25 border-rose-500/40 text-rose-200'
                    : isRedacted
                    ? 'bg-[#111c2e] border-amber-500/30 text-slate-200'
                    : 'bg-[#111c2e] border-[#1E293B] text-slate-200'
                }`}>
                  {/* Top Gateway Verdict Pill */}
                  <div className="flex items-center justify-between gap-3 pb-2.5 mb-2.5 border-b border-slate-700/50 text-xs">
                    <div className="flex items-center gap-2">
                      <Bot className="w-4 h-4 text-cyan-400" />
                      <span className="font-semibold text-slate-100 text-xs">Sentinel AI Gateway</span>
                      <Badge variant={msg.decision} size="xs">{msg.decision}</Badge>
                    </div>

                    <div className="flex items-center gap-2 font-mono text-[10px] text-slate-400">
                      {msg.latencyMs && (
                        <span className="flex items-center gap-1 text-emerald-400">
                          <Clock className="w-3 h-3" /> {msg.latencyMs}ms
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Body Content */}
                  {isBlocked ? (
                    <div className="space-y-2">
                      <div className="flex items-center gap-2 text-rose-300 font-semibold text-xs">
                        <ShieldX className="w-4 h-4 text-rose-400" />
                        Prompt Rejected by Security Policy
                      </div>
                      <p className="text-xs text-rose-200/90 leading-relaxed font-mono bg-rose-950/40 p-2.5 rounded-lg border border-rose-900/50">
                        {msg.blockedReason || 'High-risk security policy violation. The prompt was not forwarded to upstream LLM.'}
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {isRedacted && (
                        <div className="text-[11px] font-mono text-amber-400 flex items-center gap-1 bg-amber-500/10 px-2 py-1 rounded border border-amber-500/20 mb-2">
                          <Lock className="w-3 h-3" /> Sensitive tokens were redacted before reaching AI model.
                        </div>
                      )}
                      <div className="text-xs whitespace-pre-wrap leading-relaxed text-slate-200">
                        {msg.content}
                      </div>
                    </div>
                  )}

                  {/* Findings breakdown if any */}
                  {msg.findings && msg.findings.length > 0 && (
                    <div className="mt-3 pt-2 border-t border-slate-700/50 flex flex-wrap gap-1.5">
                      {msg.findings.map((f, i) => (
                        <span key={i} className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-cyan-300 border border-slate-700">
                          {f.category || f.type}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            );
          })}

          {isSending && (
            <div className="flex justify-start">
              <div className="p-4 rounded-2xl bg-[#111c2e] border border-[#1E293B] flex items-center gap-3 text-xs text-slate-400">
                <RefreshCw className="w-4 h-4 text-cyan-400 animate-spin" />
                <span>Sentinel AI inspecting payload & routing through security proxy...</span>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Input Bar */}
        <div className="p-4 bg-[#0d1320] border-t border-[#1E293B]">
          {lastError && (
            <div className="mb-3 p-2 text-xs text-rose-300 bg-rose-950/50 rounded border border-rose-800/40 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-rose-400 flex-shrink-0" />
              <span>{lastError}</span>
            </div>
          )}

          <form onSubmit={handleSend} className="flex items-center gap-2">
            <input
              type="text"
              value={inputPrompt}
              onChange={(e) => setInputPrompt(e.target.value)}
              placeholder={
                connectionStatus === 'connected'
                  ? 'Ask a question or test a prompt injection attack through the gateway...'
                  : 'Backend offline: Start FastAPI server to test live proxy responses...'
              }
              disabled={isSending || connectionStatus !== 'connected'}
              className="flex-1 px-4 py-2.5 bg-[#0B1020] border border-[#1E293B] rounded-xl text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 disabled:opacity-50"
            />
            <button
              type="submit"
              disabled={isSending || !inputPrompt.trim() || connectionStatus !== 'connected'}
              className="px-4 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold transition-all shadow-[0_0_12px_rgba(34,211,238,0.3)] flex items-center gap-2 disabled:opacity-40 disabled:cursor-not-allowed text-xs"
            >
              <Send className="w-3.5 h-3.5 fill-current" />
              <span className="hidden sm:inline">Send</span>
            </button>
          </form>
        </div>
      </Card>
    </div>
  );
}
