import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  ShieldAlert,
  Activity,
  Terminal,
  Play,
  Sliders,
  FileText,
  Settings,
  Shield,
  Radio,
  Cpu
} from 'lucide-react';
import { useGateway } from '../../context/GatewayContext';
import { Badge } from '../common/Badge';

export function Sidebar({ isOpen, onClose }) {
  const { connectionStatus, events } = useGateway();

  const navItems = [
    { name: 'Security Dashboard', path: '/', icon: Activity },
    { name: 'Live Threat Monitor', path: '/threats', icon: ShieldAlert, badge: events?.length ? `${events.length}` : null },
    { name: 'Prompt Security Scanner', path: '/scanner', icon: Terminal },
    { name: 'Request Playground', path: '/playground', icon: Play },
    { name: 'Security Policies', path: '/policies', icon: Sliders },
    { name: 'Audit Logs', path: '/audit', icon: FileText },
    { name: 'Settings', path: '/settings', icon: Settings },
  ];

  return (
    <>
      {/* Mobile Backdrop */}
      {isOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm lg:hidden"
          onClick={onClose}
          aria-hidden="true"
        />
      )}

      {/* Sidebar Container */}
      <aside
        className={`fixed top-0 bottom-0 left-0 z-40 w-64 bg-[#0d1424] border-r border-[#1E293B] flex flex-col transition-transform duration-200 lg:translate-x-0 ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* Brand Header */}
        <div className="h-16 flex items-center px-6 border-b border-[#1E293B] gap-3">
          <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-[0_0_15px_-3px_rgba(34,211,238,0.25)]">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="font-bold text-sm tracking-wide text-white">LEAK-SHIELD</span>
              <span className="text-xs font-mono font-bold text-cyan-400 bg-cyan-500/10 px-1 py-0.2 rounded border border-cyan-500/30">
                AI
              </span>
            </div>
            <p className="text-[10px] text-slate-400 font-medium tracking-tight">AI Security Gateway</p>
          </div>
        </div>

        {/* Navigation List */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          <div className="px-3 pb-2 text-[10px] font-bold uppercase tracking-wider text-slate-400">
            Core Modules
          </div>

          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                onClick={onClose}
                className={({ isActive }) =>
                  `flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-all group ${
                    isActive
                      ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 shadow-[0_0_12px_-2px_rgba(34,211,238,0.15)]'
                      : 'text-slate-300 hover:text-white hover:bg-slate-800/60 border border-transparent'
                  }`
                }
              >
                <div className="flex items-center gap-3">
                  <Icon className="w-4 h-4 transition-transform group-hover:scale-110" />
                  <span>{item.name}</span>
                </div>
                {item.badge && (
                  <span className="px-1.5 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/30">
                    {item.badge}
                  </span>
                )}
              </NavLink>
            );
          })}
        </nav>

        {/* System Health Status Footer */}
        <div className="p-4 border-t border-[#1E293B] bg-[#0a0f1c]">
          <div className="p-3 rounded-lg bg-[#111827] border border-[#1E293B]">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[11px] font-semibold text-slate-300 flex items-center gap-1.5">
                <Radio className={`w-3.5 h-3.5 ${connectionStatus === 'connected' ? 'text-emerald-400 animate-pulse' : 'text-rose-400'}`} />
                Gateway Engine
              </span>
              <Badge variant={connectionStatus} size="xs">
                {connectionStatus === 'connected' ? 'ACTIVE' : connectionStatus === 'checking' ? 'SYNC' : 'OFFLINE'}
              </Badge>
            </div>
            <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
              <span>Rule Engine</span>
              <span className="text-emerald-400 font-semibold">Active</span>
            </div>
          </div>
        </div>
      </aside>
    </>
  );
}
