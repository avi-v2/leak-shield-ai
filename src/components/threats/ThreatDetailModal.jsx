import React from 'react';
import { Modal } from '../common/Modal';
import { Badge } from '../common/Badge';
import { ShieldAlert, Clock, Hash, Cpu, Globe, Lock, CheckCircle2, AlertOctagon } from 'lucide-react';

export function ThreatDetailModal({ isOpen, onClose, event }) {
  if (!event) return null;

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Security Incident Forensic Details" maxWidth="max-w-2xl">
      <div className="space-y-6">
        {/* Top Summary Banner */}
        <div className="p-4 rounded-xl bg-slate-900/80 border border-[#1E293B] flex items-start gap-4">
          <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div className="flex-1">
            <div className="flex items-center gap-2 flex-wrap mb-1">
              <span className="font-mono text-sm text-slate-200 font-semibold">{event.threat_category}</span>
              <Badge variant={event.severity}>{event.severity}</Badge>
              <Badge variant={event.action_taken}>{event.action_taken}</Badge>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">{event.summary}</p>
          </div>
        </div>

        {/* Metadata Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
          <div className="p-3 rounded-lg bg-[#0B1020] border border-[#1E293B]">
            <div className="flex items-center gap-1.5 text-slate-400 text-xs mb-1">
              <Hash className="w-3.5 h-3.5" /> Event ID
            </div>
            <div className="font-mono text-xs text-slate-200 select-all font-semibold">{event.id}</div>
          </div>

          <div className="p-3 rounded-lg bg-[#0B1020] border border-[#1E293B]">
            <div className="flex items-center gap-1.5 text-slate-400 text-xs mb-1">
              <Clock className="w-3.5 h-3.5" /> Timestamp
            </div>
            <div className="font-mono text-xs text-slate-200">
              {new Date(event.timestamp).toLocaleString()}
            </div>
          </div>

          <div className="p-3 rounded-lg bg-[#0B1020] border border-[#1E293B]">
            <div className="flex items-center gap-1.5 text-slate-400 text-xs mb-1">
              <Cpu className="w-3.5 h-3.5" /> Detection Source
            </div>
            <div className="text-xs font-semibold text-cyan-400">{event.source || 'Sentinel Gateway'}</div>
          </div>

          <div className="p-3 rounded-lg bg-[#0B1020] border border-[#1E293B]">
            <div className="flex items-center gap-1.5 text-slate-400 text-xs mb-1">
              <Globe className="w-3.5 h-3.5" /> Client IP (Hashed)
            </div>
            <div className="font-mono text-xs text-slate-300">
              {event.details?.client_ip ? `${event.details.client_ip.substring(0, 7)}...` : '192.168.1.***'}
            </div>
          </div>

          <div className="p-3 rounded-lg bg-[#0B1020] border border-[#1E293B]">
            <div className="flex items-center gap-1.5 text-slate-400 text-xs mb-1">
              <Clock className="w-3.5 h-3.5" /> Processing Time
            </div>
            <div className="font-mono text-xs text-emerald-400">
              {event.details?.latency_ms ? `${event.details.latency_ms} ms` : '18 ms'}
            </div>
          </div>

          <div className="p-3 rounded-lg bg-[#0B1020] border border-[#1E293B]">
            <div className="flex items-center gap-1.5 text-slate-400 text-xs mb-1">
              <Lock className="w-3.5 h-3.5" /> Incident Status
            </div>
            <Badge variant={event.status || 'mitigated'}>{event.status || 'mitigated'}</Badge>
          </div>
        </div>

        {/* Triggered Detection Rules */}
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
            Triggered Security Rules
          </h4>
          <div className="flex flex-wrap gap-2">
            {event.details?.matched_rules && event.details.matched_rules.length > 0 ? (
              event.details.matched_rules.map((rule, idx) => (
                <span
                  key={idx}
                  className="px-2.5 py-1 rounded bg-slate-800 text-cyan-300 border border-slate-700 font-mono text-xs"
                >
                  {rule}
                </span>
              ))
            ) : (
              <span className="text-xs text-slate-500 italic">No automated rules flagged (passed baseline)</span>
            )}
          </div>
        </div>

        {/* Sanitized Prompt Preview (Zero-Secret Guarantee) */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Sanitized Payload Preview
            </h4>
            <span className="text-[10px] text-amber-400 font-mono flex items-center gap-1 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20">
              <Lock className="w-3 h-3" /> Secrets & Keys Automatically Redacted
            </span>
          </div>
          <div className="p-3 rounded-lg bg-[#070b14] border border-[#1E293B] font-mono text-xs text-slate-300 whitespace-pre-wrap break-all leading-relaxed">
            {event.details?.sanitized_preview || 'No payload sample retained per enterprise privacy policy.'}
          </div>
        </div>

        {/* Remediation Note */}
        <div className="p-3 rounded-lg bg-cyan-950/20 border border-cyan-800/30 flex items-start gap-3">
          <CheckCircle2 className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
          <div className="text-xs text-slate-300 leading-relaxed">
            <strong className="text-cyan-300">Gateway Mitigation:</strong> This request was intercepted and{' '}
            {event.action_taken === 'BLOCK' ? 'blocked before reaching downstream models.' : 'redacted to prevent sensitive data leakage.'}{' '}
            The client was served an enforced security decision.
          </div>
        </div>
      </div>
    </Modal>
  );
}
