import React from 'react';

export function StatCard({ title, value, change, trend = 'up', icon: Icon, color = 'cyan', subtitle }) {
  const colorStyles = {
    cyan: {
      bg: 'bg-cyan-500/10',
      text: 'text-cyan-400',
      border: 'border-cyan-500/20',
      glow: 'shadow-[0_0_15px_-3px_rgba(34,211,238,0.15)]',
    },
    emerald: {
      bg: 'bg-emerald-500/10',
      text: 'text-emerald-400',
      border: 'border-emerald-500/20',
      glow: 'shadow-[0_0_15px_-3px_rgba(16,185,129,0.15)]',
    },
    amber: {
      bg: 'bg-amber-500/10',
      text: 'text-amber-400',
      border: 'border-amber-500/20',
      glow: 'shadow-[0_0_15px_-3px_rgba(245,158,11,0.15)]',
    },
    rose: {
      bg: 'bg-rose-500/10',
      text: 'text-rose-400',
      border: 'border-rose-500/20',
      glow: 'shadow-[0_0_15px_-3px_rgba(239,68,68,0.15)]',
    },
    purple: {
      bg: 'bg-purple-500/10',
      text: 'text-purple-400',
      border: 'border-purple-500/20',
      glow: 'shadow-[0_0_15px_-3px_rgba(168,85,247,0.15)]',
    },
  };

  const style = colorStyles[color] || colorStyles.cyan;

  return (
    <div className={`bg-[#111827] border border-[#1E293B] rounded-xl p-5 ${style.glow} hover:border-[#334155] transition-all duration-200`}>
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-medium uppercase tracking-wider text-slate-400">{title}</span>
        {Icon && (
          <div className={`p-2 rounded-lg ${style.bg} ${style.text} border ${style.border}`}>
            <Icon className="w-5 h-5" />
          </div>
        )}
      </div>

      <div className="flex items-baseline space-x-2">
        <span className="text-2xl font-bold font-mono text-slate-100">{value}</span>
        {change && (
          <span
            className={`text-xs font-semibold ${
              trend === 'up' ? 'text-emerald-400' : trend === 'down' ? 'text-rose-400' : 'text-slate-400'
            }`}
          >
            {change}
          </span>
        )}
      </div>

      {subtitle && <p className="text-xs text-slate-400 mt-1">{subtitle}</p>}
    </div>
  );
}
