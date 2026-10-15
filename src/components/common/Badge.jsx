import React from 'react';

export function Badge({ children, variant = 'neutral', size = 'md', className = '' }) {
  const baseClasses = 'inline-flex items-center font-mono font-medium rounded-full border transition-colors';
  
  const sizeClasses = {
    xs: 'px-1.5 py-0.2 text-[10px]',
    sm: 'px-2 py-0.5 text-xs',
    md: 'px-2.5 py-1 text-xs',
    lg: 'px-3 py-1.5 text-sm',
  };

  const variantClasses = {
    // Actions
    ALLOW: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    REDACT: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    BLOCK: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
    
    // Severities
    critical: 'bg-rose-600/20 text-rose-300 border-rose-500/40 font-bold',
    high: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
    medium: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    low: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
    
    // Statuses
    operational: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    mitigated: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
    flagged: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
    investigating: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
    resolved: 'bg-slate-700/50 text-slate-300 border-slate-600/30',

    // Connection
    connected: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    offline: 'bg-rose-500/15 text-rose-400 border-rose-500/30',
    checking: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    simulated: 'bg-purple-500/15 text-purple-300 border-purple-500/30',

    // Generic
    cyan: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
    neutral: 'bg-slate-800 text-slate-300 border-slate-700',
  };

  const lookupKey = typeof children === 'string' ? children.toUpperCase() : variant;
  const chosenStyle = variantClasses[variant] || variantClasses[lookupKey] || variantClasses.neutral;

  return (
    <span className={`${baseClasses} ${sizeClasses[size] || sizeClasses.md} ${chosenStyle} ${className}`}>
      {children}
    </span>
  );
}
