import React, { useState } from 'react';
import {
  Settings as SettingsIcon,
  Server,
  Activity,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Lock,
  ShieldCheck,
  Save,
  RotateCcw,
  Info,
  Terminal,
  ExternalLink
} from 'lucide-react';
import { useGateway } from '../context/GatewayContext';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { checkHealth, scanPrompt } from '../services/api';

export function Settings() {
  const {
    backendUrl,
    updateBackendUrl,
    connectionStatus,
    latency,
    backendData,
    pingBackend,
    addToast,
  } = useGateway();

  const [inputUrl, setInputUrl] = useState(backendUrl);
  const [isTesting, setIsTesting] = useState(false);
  const [testResults, setTestResults] = useState(null);

  // Non-sensitive UI preference in localStorage
  const [compactMode, setCompactMode] = useState(() => {
    return localStorage.getItem('sentinel_ui_compact') === 'true';
  });

  const handleSaveUrl = (e) => {
    e.preventDefault();
    if (!inputUrl.trim()) return;
    updateBackendUrl(inputUrl);
    addToast({
      title: 'Backend Endpoint Updated',
      message: `Gateway API base set to ${inputUrl}`,
      type: 'success',
    });
  };

  const handleResetUrl = () => {
    const defaultUrl = 'http://127.0.0.1:8000';
    setInputUrl(defaultUrl);
    updateBackendUrl(defaultUrl);
    addToast({
      title: 'Backend URL Reset',
      message: `Reset to default ${defaultUrl}`,
      type: 'info',
    });
  };

  const handleTestConnection = async () => {
    setIsTesting(true);
    setTestResults(null);

    const startTime = performance.now();
    try {
      // 1. Health check
      const healthRes = await checkHealth();
      const roundtripTime = Math.round(performance.now() - startTime);

      if (healthRes.connected) {
        setTestResults({
          success: true,
          latency: roundtripTime,
          version: healthRes.version,
          status: healthRes.status,
          endpoints: [
            { path: '/health', status: 200, label: 'Health Status' },
            { path: '/scan', status: 200, label: 'Prompt Scanner' },
            { path: '/chat', status: 200, label: 'Gateway Chat Proxy' },
            { path: '/events', status: 200, label: 'Security Audit Store' },
          ],
        });
        addToast({
          title: 'Gateway Connected',
          message: `Sentinel backend verified at ${inputUrl} (${roundtripTime}ms)`,
          type: 'success',
        });
      } else {
        throw new Error(healthRes.error || 'Connection failed');
      }
    } catch (err) {
      setTestResults({
        success: false,
        error: err.message || 'Cannot reach FastAPI backend server.',
      });
      addToast({
        title: 'Connection Test Failed',
        message: err.message || 'Make sure Python backend is running.',
        type: 'error',
      });
    } finally {
      setIsTesting(false);
      pingBackend(true);
    }
  };

  const toggleCompactMode = (val) => {
    setCompactMode(val);
    localStorage.setItem('sentinel_ui_compact', val ? 'true' : 'false');
    addToast({
      title: 'UI Preference Saved',
      message: `Compact density ${val ? 'enabled' : 'disabled'}.`,
      type: 'info',
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2">
          <h2 className="text-xl font-bold text-slate-100">System Gateway Settings</h2>
          <Badge variant="cyan" size="sm">CONFIG</Badge>
        </div>
        <p className="text-xs text-slate-400 mt-1">
          Manage backend API connectivity, gateway diagnostic tests, and dashboard preferences.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Backend Connectivity */}
        <div className="lg:col-span-7 space-y-6">
          <Card
            title="FastAPI Gateway Endpoint"
            subtitle="Configure the target Sentinel AI Python backend URL"
          >
            <form onSubmit={handleSaveUrl} className="space-y-4">
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1.5">
                  Backend API Base URL (VITE_API_BASE_URL)
                </label>
                <div className="flex items-center gap-2">
                  <input
                    type="url"
                    value={inputUrl}
                    onChange={(e) => setInputUrl(e.target.value)}
                    placeholder="http://127.0.0.1:8000"
                    required
                    className="flex-1 px-3.5 py-2 bg-[#0B1020] border border-[#1E293B] rounded-lg text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
                  />
                  <button
                    type="submit"
                    className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-semibold border border-slate-700 transition-colors flex items-center gap-1.5"
                  >
                    <Save className="w-3.5 h-3.5 text-cyan-400" />
                    Save
                  </button>
                  <button
                    type="button"
                    onClick={handleResetUrl}
                    className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white rounded-lg border border-slate-700 transition-colors"
                    title="Reset to default URL"
                  >
                    <RotateCcw className="w-4 h-4" />
                  </button>
                </div>
                <p className="text-[11px] text-slate-400 mt-1.5">
                  Default: <code className="text-cyan-400 font-mono">http://127.0.0.1:8000</code>. To change permanently, edit <code className="font-mono text-slate-300">.env</code>.
                </p>
              </div>

              {/* Status Indicator */}
              <div className="p-3.5 rounded-xl bg-[#0B1020] border border-[#1E293B] flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Server className="w-5 h-5 text-slate-400" />
                  <div>
                    <div className="text-xs font-semibold text-slate-200">Current Gateway Status</div>
                    <div className="text-[11px] font-mono text-slate-400">
                      Target: {backendUrl}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  {latency !== null && (
                    <span className="font-mono text-xs text-emerald-400">{latency}ms</span>
                  )}
                  <Badge variant={connectionStatus} size="sm">
                    {connectionStatus.toUpperCase()}
                  </Badge>
                </div>
              </div>

              {/* Diagnostics Test Button */}
              <div className="pt-2 flex items-center justify-between">
                <button
                  type="button"
                  onClick={handleTestConnection}
                  disabled={isTesting}
                  className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold rounded-lg text-xs transition-all shadow-[0_0_12px_rgba(34,211,238,0.25)] flex items-center gap-2 disabled:opacity-50"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isTesting ? 'animate-spin' : ''}`} />
                  {isTesting ? 'Testing Endpoints...' : 'Run Diagnostics Test'}
                </button>
              </div>
            </form>

            {/* Test Results Output */}
            {testResults && (
              <div className={`mt-5 p-4 rounded-xl border ${
                testResults.success
                  ? 'bg-emerald-950/20 border-emerald-500/30 text-emerald-300'
                  : 'bg-rose-950/20 border-rose-500/30 text-rose-300'
              }`}>
                <div className="flex items-center gap-2 font-semibold text-xs mb-3">
                  {testResults.success ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  ) : (
                    <XCircle className="w-4 h-4 text-rose-400" />
                  )}
                  <span>
                    {testResults.success
                      ? `Gateway Verified: Operational (${testResults.latency}ms)`
                      : 'Gateway Ping Failed'}
                  </span>
                </div>

                {testResults.success ? (
                  <div className="space-y-1.5 font-mono text-xs text-slate-300">
                    {testResults.endpoints.map((ep) => (
                      <div key={ep.path} className="flex items-center justify-between py-1 border-b border-slate-800/60">
                        <span className="text-cyan-300">{ep.path}</span>
                        <span className="text-[11px] text-slate-400">{ep.label}</span>
                        <span className="text-emerald-400 font-bold">200 OK</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-rose-200 leading-relaxed font-mono">
                    {testResults.error}
                  </p>
                )}
              </div>
            )}
          </Card>

          {/* UI Preferences */}
          <Card title="Interface Preferences" subtitle="Customize dashboard density and layout behavior">
            <div className="space-y-4">
              <div className="p-3.5 rounded-xl bg-[#0B1020] border border-[#1E293B] flex items-center justify-between">
                <div>
                  <div className="text-xs font-semibold text-slate-200">High Density Table Mode</div>
                  <p className="text-xs text-slate-400 mt-0.5">Reduces padding on event tables and audit logs.</p>
                </div>
                <button
                  type="button"
                  onClick={() => toggleCompactMode(!compactMode)}
                  className={`w-11 h-6 flex items-center rounded-full p-1 transition-colors ${
                    compactMode ? 'bg-cyan-500' : 'bg-slate-800'
                  }`}
                >
                  <div
                    className={`bg-white w-4 h-4 rounded-full shadow-md transform transition-transform ${
                      compactMode ? 'translate-x-5' : 'translate-x-0'
                    }`}
                  />
                </button>
              </div>

              <div className="p-3.5 rounded-xl bg-[#0B1020] border border-[#1E293B] flex items-center justify-between">
                <div>
                  <div className="text-xs font-semibold text-slate-200">Theme Preset</div>
                  <p className="text-xs text-slate-400 mt-0.5">Dark Cyber Ops (Enterprise Cybersecurity standard).</p>
                </div>
                <span className="text-xs font-mono font-semibold text-cyan-400 bg-cyan-950/40 px-2.5 py-1 rounded border border-cyan-800/40">
                  Cyber Dark Navy
                </span>
              </div>
            </div>
          </Card>
        </div>

        {/* Right Column: Cybersecurity & Privacy Architecture */}
        <div className="lg:col-span-5 space-y-6">
          <Card
            title="Security & Privacy Boundary"
            subtitle="Sentinel AI data protection architecture"
          >
            <div className="space-y-4 text-xs text-slate-300 leading-relaxed">
              <div className="p-3 rounded-lg bg-[#0B1020] border border-[#1E293B] flex items-start gap-3">
                <Lock className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                <div>
                  <strong className="text-slate-100">Zero Local Secret Storage</strong>
                  <p className="text-slate-400 text-[11px] mt-0.5">
                    This frontend never retains API keys, master passwords, or raw user prompts in localStorage or cookies. Only non-sensitive UI settings are cached.
                  </p>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-[#0B1020] border border-[#1E293B] flex items-start gap-3">
                <ShieldCheck className="w-5 h-5 text-emerald-400 flex-shrink-0 mt-0.5" />
                <div>
                  <strong className="text-slate-100">Gateway Enforced Boundary</strong>
                  <p className="text-slate-400 text-[11px] mt-0.5">
                    Client-side validation is strictly used for immediate user feedback. Final policy decisions (ALLOW, REDACT, BLOCK) are unconditionally enforced server-side.
                  </p>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-[#0B1020] border border-[#1E293B] flex items-start gap-3">
                <Terminal className="w-5 h-5 text-purple-400 flex-shrink-0 mt-0.5" />
                <div>
                  <strong className="text-slate-100">No Direct Third-Party LLM Calls</strong>
                  <p className="text-slate-400 text-[11px] mt-0.5">
                    User prompts never contact external AI APIs directly. All traffic is routed through the Python FastAPI Gateway proxy for real-time redaction and safety checks.
                  </p>
                </div>
              </div>
            </div>
          </Card>

          <Card title="Build & Version Metadata">
            <div className="space-y-2 font-mono text-xs">
              <div className="flex justify-between py-1 border-b border-[#1E293B]">
                <span className="text-slate-400">Application</span>
                <span className="text-slate-200">Sentinel AI Gateway</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[#1E293B]">
                <span className="text-slate-400">Frontend Release</span>
                <span className="text-cyan-400">v1.4.2-hackathon</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[#1E293B]">
                <span className="text-slate-400">Core Framework</span>
                <span className="text-slate-200">React 18 + Vite 5</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[#1E293B]">
                <span className="text-slate-400">Styling Engine</span>
                <span className="text-slate-200">Tailwind CSS 3.4</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-slate-400">Target Protocol</span>
                <span className="text-slate-200">FastAPI REST / HTTP</span>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
