import React from 'react';
import { useLocation, Link } from 'react-router-dom';
import { Menu, Terminal, RefreshCw, Activity, ShieldCheck, AlertCircle } from 'lucide-react';
import { useGateway } from '../../context/GatewayContext';
import { Badge } from '../common/Badge';

export function Navbar({ onMenuClick }) {
  const { connectionStatus, latency, pingBackend } = useGateway();

  const getPageTitle = (pathname) => {
    switch (pathname) {
      case '/':
        return 'Security Overview';
      case '/threats':
        return 'Live Threat Monitor';
      case '/scanner':
        return 'Prompt Security Scanner';
      case '/playground':
        return 'Request Playground';
      case '/policies':
        return 'Security Policies';
      case '/audit':
        return 'Audit Logs';
      case '/settings':
        return 'System Settings';
      default:
        return 'Dashboard';
    }
  };

  return (
    <header className="h-16 bg-[#0d1424]/90 backdrop-blur-md border-b border-[#1E293B] sticky top-0 z-30 px-4 sm:px-6 flex items-center justify-between">
      {/* Left: Mobile hamburger & Page Title */}
      <div className="flex items-center gap-3">
        <button
          onClick={onMenuClick}
          className="lg:hidden p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          aria-label="Toggle navigation menu"
        >
          <Menu className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400 hidden sm:inline">Leak-Sheild-AI</span>
          <span className="text-slate-500 hidden sm:inline">/</span>
          <h1 className="text-sm font-semibold text-slate-100">{getPageTitle(location.pathname)}</h1>
        </div>
      </div>

      {/* Right: Gateway Status, Ping Pill, Action */}
      <div className="flex items-center gap-3">

        {/* Backend Connectivity Pill */}
        <button
          onClick={() => pingBackend()}
          title="Click to re-ping FastAPI backend gateway"
          className="flex items-center gap-2 px-2.5 py-1 rounded-lg bg-[#111827] border border-[#1E293B] hover:border-slate-700 transition-colors text-xs font-mono"
        >
          <span
            className={`w-2 h-2 rounded-full ${
              connectionStatus === 'connected'
                ? 'bg-emerald-400 shadow-[0_0_8px_rgba(16,185,129,0.8)]'
                : connectionStatus === 'checking'
                ? 'bg-amber-400 animate-pulse'
                : 'bg-rose-400 shadow-[0_0_8px_rgba(239,68,68,0.8)]'
            }`}
          />
          <span className="text-slate-300 hidden sm:inline">
            {connectionStatus === 'connected' ? 'Backend Live' : connectionStatus === 'checking' ? 'Connecting...' : 'Backend Offline'}
          </span>
          {latency !== null && (
            <span className="text-emerald-400 font-semibold">{latency}ms</span>
          )}
        </button>

        {/* Quick Scan Action Button */}
        {location.pathname !== '/scanner' && (
          <Link
            to="/scanner"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 hover:bg-cyan-500/25 transition-all shadow-[0_0_12px_-2px_rgba(34,211,238,0.2)]"
          >
            <Terminal className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Scan Prompt</span>
          </Link>
        )}
      </div>
    </header>
  );
}
