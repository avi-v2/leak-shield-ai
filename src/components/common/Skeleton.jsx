import React from 'react';

export function Skeleton({ className = '', count = 1 }) {
  if (count === 1) {
    return <div className={`animate-pulse bg-slate-800/60 rounded ${className}`} />;
  }

  return (
    <div className="space-y-2">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className={`animate-pulse bg-slate-800/60 rounded ${className}`} />
      ))}
    </div>
  );
}

export function TableSkeleton({ rows = 5, cols = 6 }) {
  return (
    <div className="divide-y divide-[#1E293B]">
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="py-4 px-6 flex items-center justify-between gap-4">
          {Array.from({ length: cols }).map((_, c) => (
            <div
              key={c}
              className="h-4 bg-slate-800/60 rounded animate-pulse"
              style={{ width: `${Math.max(40, 100 - c * 10)}px` }}
            />
          ))}
        </div>
      ))}
    </div>
  );
}
