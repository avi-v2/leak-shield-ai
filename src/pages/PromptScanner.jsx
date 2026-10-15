import React, { useState } from 'react';
import {
  Terminal,
  Zap,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  ShieldAlert,
  Lock,
  ArrowRight,
  Info,
  RefreshCw,
  Sparkles,
  HelpCircle,
  FileCode
} from 'lucide-react';
import { useGateway } from '../context/GatewayContext';
import { scanPrompt } from '../services/api';
import { SCANNER_SAMPLE_PROMPTS, simulateLocalScan } from '../services/mockData';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';

export function PromptScanner() {
  const { connectionStatus, addToast } = useGateway();

  const [promptText, setPromptText] = useState(SCANNER_SAMPLE_PROMPTS[1].prompt); // Default to API key test
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [scanError, setScanError] = useState(null);
  const [activeTab, setActiveTab] = useState('redacted'); // 'redacted' | 'raw'
  const [copied, setCopied] = useState(false);

  // Perform Scan
  const handleScan = async (forceSimulate = false) => {
    if (!promptText.trim()) {
      addToast({
        title: 'Empty Prompt',
        message: 'Please enter or select a prompt to inspect.',
        type: 'warning',
      });
      return;
    }

    setIsScanning(true);
    setScanError(null);

    // If backend is connected and not forcing simulation
    if (connectionStatus === 'connected' && !forceSimulate) {
      try {
        const response = await scanPrompt(promptText);
        if (response.success && response.data) {
          setScanResult({
            ...response.data,
            simulated: false,
          });
          addToast({
            title: 'Gateway Scan Complete',
            message: `Result: ${response.data.action || 'INSPECTED'} (Enforced by backend)`,
            type: response.data.action === 'BLOCK' ? 'error' : response.data.action === 'REDACT' ? 'warning' : 'success',
          });
        } else {
          throw new Error('Unexpected response schema from backend');
        }
      } catch (err) {
        setScanError({
          message: err.message || 'Failed to communicate with Sentinel AI backend scanner.',
          status: err.status,
        });
        setScanResult(null);
        addToast({
          title: 'Backend Scan Failed',
          message: err.message || 'Gateway connection error',
          type: 'error',
        });
      } finally {
        setIsScanning(false);
      }
    } else {
      // Backend is offline or simulation requested
      // We simulate local heuristic scan, but explicitly mark it as simulated
      setTimeout(() => {
        const result = simulateLocalScan(promptText);
        setScanResult(result);
        setIsScanning(false);
        addToast({
          title: 'Local Heuristic Analysis',
          message: 'Backend offline: performed client-side heuristic inspection.',
          type: 'info',
        });
      }, 400);
    }
  };

  const copyRedacted = () => {
    if (scanResult?.redacted_prompt) {
      navigator.clipboard.writeText(scanResult.redacted_prompt);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
      addToast({
        title: 'Copied to Clipboard',
        message: 'Sanitized prompt payload ready for upstream submission.',
        type: 'success',
      });
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2">
          <h2 className="text-xl font-bold text-slate-100">Prompt Security Scanner</h2>
          {connectionStatus === 'connected' ? (
            <Badge variant="connected" size="sm">LIVE GATEWAY</Badge>
          ) : (
            <Badge variant="offline" size="sm">LOCAL DEMO MODE</Badge>
          )}
        </div>
        <p className="text-xs text-slate-400 mt-1">
          Deep heuristic and lexical inspection to prevent credential leakage, PII exposure, and adversarial prompt injections.
        </p>
      </div>

      {/* Preset Test Prompts Quick-Picker */}
      <Card title="Quick-Test Scenarios" subtitle="Load realistic hackathon test vectors into the inspector">
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-2.5">
          {SCANNER_SAMPLE_PROMPTS.map((sample) => (
            <button
              key={sample.id}
              onClick={() => {
                setPromptText(sample.prompt);
                setScanResult(null);
                setScanError(null);
              }}
              className="p-3 rounded-lg bg-[#0B1020] hover:bg-slate-800/80 border border-[#1E293B] hover:border-cyan-500/40 text-left transition-all group flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300">
                    {sample.title}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 line-clamp-2">{sample.prompt}</p>
              </div>
              <div className="mt-2.5 flex items-center justify-between">
                <span className="text-[10px] text-slate-500 font-mono">{sample.category}</span>
                <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono font-medium ${
                  sample.tag === 'Clean' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' :
                  sample.tag === 'Redact' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                  'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                }`}>
                  {sample.tag}
                </span>
              </div>
            </button>
          ))}
        </div>
      </Card>

      {/* Main Scanner Section */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Input Textarea */}
        <div className="lg:col-span-6 space-y-4">
          <Card
            title="Inspect Prompt Payload"
            subtitle="Paste any raw LLM prompt or system directive for inspection"
            headerAction={
              <button
                onClick={() => setPromptText('')}
                className="text-xs text-slate-400 hover:text-slate-200"
              >
                Clear
              </button>
            }
          >
            <div className="space-y-3">
              <div className="relative">
                <textarea
                  value={promptText}
                  onChange={(e) => setPromptText(e.target.value)}
                  placeholder="Paste prompt text here (e.g., instructions, API keys, customer data, or potential jailbreak phrases)..."
                  rows={10}
                  className="w-full p-3.5 bg-[#0B1020] border border-[#1E293B] rounded-xl text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 resize-y leading-relaxed"
                />
              </div>

              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pt-2">
                <div className="text-xs text-slate-400 font-mono space-x-3">
                  <span>Chars: <strong className="text-slate-200">{promptText.length}</strong></span>
                  <span>Tokens (est): <strong className="text-slate-200">{Math.ceil(promptText.length / 4)}</strong></span>
                </div>

                <div className="flex items-center gap-2 w-full sm:w-auto">
                  {connectionStatus === 'offline' && (
                    <button
                      type="button"
                      onClick={() => handleScan(true)}
                      disabled={isScanning || !promptText.trim()}
                      className="px-3 py-2 text-xs font-semibold rounded-lg bg-purple-600/20 text-purple-300 border border-purple-500/30 hover:bg-purple-600/30 transition-colors flex items-center gap-1.5"
                    >
                      Simulate Local Scan
                    </button>
                  )}

                  <button
                    type="button"
                    onClick={() => handleScan(false)}
                    disabled={isScanning || !promptText.trim()}
                    className="flex-1 sm:flex-initial px-5 py-2 text-xs font-bold rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition-all shadow-[0_0_15px_rgba(34,211,238,0.35)] flex items-center justify-center gap-2 disabled:opacity-50"
                  >
                    {isScanning ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        Scanning Gateway...
                      </>
                    ) : (
                      <>
                        <Zap className="w-4 h-4 fill-current" />
                        Scan Prompt
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>
          </Card>
        </div>

        {/* Right: Results Panel */}
        <div className="lg:col-span-6 space-y-4">
          {/* Error Banner if Backend Call Failed */}
          {scanError && (
            <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/50 text-rose-300 space-y-2">
              <div className="flex items-center gap-2 font-semibold text-sm">
                <XCircle className="w-5 h-5 text-rose-400" />
                Backend Gateway Request Failed
              </div>
              <p className="text-xs text-rose-200 leading-relaxed">
                {scanError.message}
              </p>
              <div className="pt-2 flex items-center gap-3 text-xs">
                <button
                  onClick={() => handleScan(true)}
                  className="px-3 py-1.5 rounded bg-purple-600/30 hover:bg-purple-600/40 text-purple-200 border border-purple-500/40 font-medium"
                >
                  Run Local Heuristic Preview
                </button>
              </div>
            </div>
          )}

          {/* Results Card */}
          {scanResult ? (
            <Card
              title="Inspection Forensic Report"
              subtitle={
                scanResult.simulated
                  ? 'Simulated Local Analysis (Backend offline)'
                  : 'Backend Verified Security Verdict'
              }
              headerAction={
                scanResult.simulated ? (
                  <Badge variant="simulated" size="xs">SIMULATED PREVIEW</Badge>
                ) : (
                  <Badge variant="connected" size="xs">GATEWAY VERIFIED</Badge>
                )
              }
            >
              <div className="space-y-5">
                {/* Decision Header */}
                <div className={`p-4 rounded-xl border flex items-center justify-between ${
                  scanResult.action === 'BLOCK'
                    ? 'bg-rose-950/20 border-rose-500/30 text-rose-300'
                    : scanResult.action === 'REDACT'
                    ? 'bg-amber-950/20 border-amber-500/30 text-amber-300'
                    : 'bg-emerald-950/20 border-emerald-500/30 text-emerald-300'
                }`}>
                  <div className="flex items-center gap-3">
                    <div className="p-2.5 rounded-lg bg-black/40">
                      {scanResult.action === 'BLOCK' ? (
                        <ShieldAlert className="w-6 h-6 text-rose-400" />
                      ) : scanResult.action === 'REDACT' ? (
                        <Lock className="w-6 h-6 text-amber-400" />
                      ) : (
                        <CheckCircle2 className="w-6 h-6 text-emerald-400" />
                      )}
                    </div>
                    <div>
                      <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                        Gateway Decision
                      </div>
                      <div className="text-lg font-bold font-mono">
                        {scanResult.action}
                      </div>
                    </div>
                  </div>

                  <div className="text-right space-y-1">
                    <div className="text-[10px] font-mono text-slate-400">Risk Level</div>
                    <Badge variant={scanResult.risk_level || 'low'} size="sm">
                      {(scanResult.risk_level || 'LOW').toUpperCase()}
                    </Badge>
                  </div>
                </div>

                {/* Recommendation summary */}
                <div className="text-xs text-slate-300 p-3 rounded-lg bg-[#0B1020] border border-[#1E293B] leading-relaxed">
                  <strong className="text-cyan-400">Recommendation:</strong> {scanResult.recommendation}
                </div>

                {/* Detailed Findings List */}
                <div>
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2 flex items-center justify-between">
                    <span>Detected Findings ({scanResult.findings?.length || 0})</span>
                    {scanResult.prompt_injection_risk && scanResult.prompt_injection_risk !== 'none' && (
                      <span className="text-[11px] text-rose-400 font-mono">
                        Injection Risk: {scanResult.prompt_injection_risk.toUpperCase()}
                      </span>
                    )}
                  </h4>

                  {scanResult.findings && scanResult.findings.length > 0 ? (
                    <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                      {scanResult.findings.map((f, idx) => (
                        <div
                          key={idx}
                          className="p-3 rounded-lg bg-[#0B1020] border border-[#1E293B] flex items-start justify-between gap-3 text-xs"
                        >
                          <div className="space-y-1 flex-1">
                            <div className="flex items-center gap-2">
                              <span className="font-semibold text-slate-200">{f.category || f.type}</span>
                              <Badge variant={f.severity} size="xs">{f.severity}</Badge>
                            </div>
                            <p className="text-slate-400 text-[11px] leading-relaxed">{f.description}</p>
                            {f.match_preview && (
                              <div className="font-mono text-[10px] text-amber-300/90 bg-amber-950/20 px-2 py-0.5 rounded border border-amber-900/40 inline-block mt-1">
                                Pattern: {f.match_preview}
                              </div>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-4 rounded-lg bg-[#0B1020] border border-[#1E293B] text-center text-xs text-emerald-400 flex items-center justify-center gap-2">
                      <CheckCircle2 className="w-4 h-4" />
                      Zero high-risk secrets or adversarial vectors detected.
                    </div>
                  )}
                </div>

                {/* Redacted Prompt Diff View */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setActiveTab('redacted')}
                        className={`text-xs font-medium px-2.5 py-1 rounded-md transition-colors ${
                          activeTab === 'redacted'
                            ? 'bg-cyan-500/20 text-cyan-300 font-semibold border border-cyan-500/30'
                            : 'text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        Sanitized Prompt Payload
                      </button>
                      <button
                        onClick={() => setActiveTab('raw')}
                        className={`text-xs font-medium px-2.5 py-1 rounded-md transition-colors ${
                          activeTab === 'raw'
                            ? 'bg-cyan-500/20 text-cyan-300 font-semibold border border-cyan-500/30'
                            : 'text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        Original Prompt
                      </button>
                    </div>

                    {activeTab === 'redacted' && (
                      <button
                        onClick={copyRedacted}
                        className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono transition-colors"
                      >
                        {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        {copied ? 'Copied' : 'Copy Payload'}
                      </button>
                    )}
                  </div>

                  <div className="p-3.5 rounded-xl bg-[#070b14] border border-[#1E293B] font-mono text-xs text-slate-300 whitespace-pre-wrap break-all max-h-48 overflow-y-auto leading-relaxed">
                    {activeTab === 'redacted'
                      ? scanResult.redacted_prompt || promptText
                      : promptText}
                  </div>
                </div>
              </div>
            </Card>
          ) : (
            <Card className="h-full flex items-center justify-center p-12 text-center text-slate-500">
              <div className="flex flex-col items-center max-w-sm space-y-3">
                <div className="p-4 rounded-full bg-slate-900 border border-[#1E293B] text-slate-600">
                  <Terminal className="w-8 h-8" />
                </div>
                <h3 className="text-sm font-semibold text-slate-300">Awaiting Prompt Submission</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Enter a prompt or select a quick-test scenario above, then click <strong>Scan Prompt</strong> to trigger deep security analysis.
                </p>
              </div>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
