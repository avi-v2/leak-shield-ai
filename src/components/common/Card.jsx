import React from 'react';

export function Card({ children, className = '', title, subtitle, headerAction, footer }) {
  return (
    <div className={`bg-[#111827] border border-[#1E293B] rounded-xl shadow-lg ${className}`}>
      {(title || subtitle || headerAction) && (
        <div className="px-5 py-4 border-b border-[#1E293B] flex items-center justify-between">
          <div>
            {title && <h3 className="text-base font-semibold text-slate-100">{title}</h3>}
            {subtitle && <p className="text-xs text-slate-400 mt-0.5">{subtitle}</p>}
          </div>
          {headerAction && <div>{headerAction}</div>}
        </div>
      )}
      <div className="p-5">{children}</div>
      {footer && (
        <div className="px-5 py-3 border-t border-[#1E293B] bg-[#0d1320] rounded-b-xl text-xs text-slate-400">
          {footer}
        </div>
      )}
    </div>
  );
}
