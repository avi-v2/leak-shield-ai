import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Lock,
  Zap,
  Activity,
  AlertTriangle,
  RefreshCw,
  Info
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell
} from 'recharts';
import { useGateway } from '../context/GatewayContext';
import { StatCard } from '../components/common/StatCard';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { ThreatDetailModal } from '../components/threats/ThreatDetailModal';
import { Link } from 'react-router-dom';

export function Overview() {
  const { events, metrics, connectionStatus, loadEvents, loadMetrics, metricsLoading } = useGateway();
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    await Promise.all([loadEvents(), loadMetrics()]);
    setIsRefreshing(false);
  };

  // Compute stats from real backend metrics and persisted events
  const totalInspected = metrics.total_requests;
  const totalAllowed = metrics.allowed_requests;
  const totalBlocked = metrics.blocked_requests;
  const piiCount = metrics.sensitive_data_detections;
  const injectionCount = metrics.injection_detections;

  const trafficData = metrics.traffic_over_time || [];
  const threatData = metrics.threat_distribution || [];

  const recentEvents = events
    .filter((e) => e.action_taken === 'BLOCK' || e.action_taken === 'REDACT')
    .slice(0, 5);

  return (
    <div className="space-y-6">
      {/* Status Header Banner */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-4 rounded-xl bg-gradient-to-r from-[#111827] via-[#131D31] to-[#111827] border border-[#1E293B]">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Activity className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold text-slate-100">Gateway Threat Operations Center</h2>
              {connectionStatus === 'connected' ? (
                <Badge variant="connected" size="xs">LIVE BACKEND ENFORCED</Badge>
              ) : (
                <Badge variant="offline" size="xs">GATEWAY OFFLINE</Badge>
              )}
            </div>
            <p className="text-xs text-slate-400">
              Live inspection of LLM prompts and completions for unauthorized data egress & prompt manipulation.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 self-end sm:self-auto">
          <button
            onClick={handleRefresh}
            disabled={isRefreshing || connectionStatus !== 'connected'}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors flex items-center gap-1.5 disabled:opacity-40"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <Link
            to="/scanner"
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition-all shadow-[0_0_12px_rgba(34,211,238,0.3)] flex items-center gap-1.5"
          >
            <Zap className="w-3.5 h-3.5" />
            Launch Scanner
          </Link>
        </div>
      </div>

      {/* Top Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <StatCard
          title="Total Inspected"
          value={totalInspected.toLocaleString()}
          subtitle="All Gateway Requests"
          icon={Activity}
          color="cyan"
        />
        <StatCard
          title="Requests Allowed"
          value={totalAllowed.toLocaleString()}
          subtitle="Clean / Sanitized"
          icon={ShieldCheck}
          color="emerald"
        />
        <StatCard
          title="Requests Blocked"
          value={totalBlocked.toLocaleString()}
          subtitle="Violations Intercepted"
          icon={ShieldX}
          color="rose"
        />
        <StatCard
          title="Sensitive Data Leaks"
          value={piiCount.toLocaleString()}
          subtitle="PII & Credential Masks"
          icon={Lock}
          color="amber"
        />
        <StatCard
          title="Prompt Injections"
          value={injectionCount.toLocaleString()}
          subtitle="Jailbreak & Delimiter Injections"
          icon={ShieldAlert}
          color="purple"
        />
      </div>

      {/* Charts Section: Real Traffic over time + Threat Categories */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recharts Area Chart: Real Traffic Over Time */}
        <div className="lg:col-span-2 min-w-0">
          <Card
            title="Gateway Traffic & Threat Interceptions"
            subtitle="Hourly distribution of inspected, passed, and blocked LLM requests"
          >
            <div className="h-72 w-full min-w-0">
              {trafficData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={trafficData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                    <defs>
                      <linearGradient id="colorInspected" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#22D3EE" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#22D3EE" stopOpacity={0.0} />
                      </linearGradient>
                      <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#EF4444" stopOpacity={0.4} />
                        <stop offset="95%" stopColor="#EF4444" stopOpacity={0.0} />
                      </linearGradient>
                    </defs>
                    <XAxis
                      dataKey="time"
                      stroke="#475569"
                      tick={{ fill: '#94A3B8', fontSize: 11 }}
                      tickLine={false}
                    />
                    <YAxis
                      stroke="#475569"
                      tick={{ fill: '#94A3B8', fontSize: 11 }}
                      tickLine={false}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#111827',
                        borderColor: '#1E293B',
                        borderRadius: '8px',
                        color: '#F8FAFC',
                        fontSize: '12px',
                      }}
                    />
                    <Area
                      type="monotone"
                      dataKey="inspected"
                      name="Total Inspected"
                      stroke="#22D3EE"
                      strokeWidth={2}
                      fillOpacity={1}
                      fill="url(#colorInspected)"
                    />
                    <Area
                      type="monotone"
                      dataKey="blocked"
                      name="Blocked Violations"
                      stroke="#EF4444"
                      strokeWidth={2}
                      fillOpacity={1}
                      fill="url(#colorBlocked)"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-center p-6 border border-dashed border-[#1E293B] rounded-xl bg-[#0B1020]/40">
                  <Activity className="w-8 h-8 text-slate-600 mb-2" />
                  <p className="text-sm font-medium text-slate-400">No Traffic Recorded Yet</p>
                  <p className="text-xs text-slate-400 mt-1 max-w-sm">
                    Submit prompts through the Prompt Scanner or Gateway Chat Proxy to begin recording live telemetry.
                  </p>
                </div>
              )}
            </div>
            {trafficData.length > 0 && (
              <div className="mt-4 pt-3 border-t border-[#1E293B] flex items-center justify-between text-xs text-slate-400">
                <div className="flex items-center gap-4">
                  <span className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-sm bg-cyan-400" /> Inspected
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-sm bg-rose-500" /> Blocked
                  </span>
                </div>
              </div>
            )}
          </Card>
        </div>

        {/* Real Threat Category Distribution */}
        <div className="min-w-0">
          <Card
            title="Threat Categories"
            subtitle="Breakdown of detected security violations"
          >
            <div className="h-64 w-full min-w-0">
              {threatData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={threatData}
                      cx="50%"
                      cy="50%"
                      innerRadius={55}
                      outerRadius={85}
                      paddingAngle={3}
                      dataKey="count"
                    >
                      {threatData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#111827',
                        borderColor: '#1E293B',
                        borderRadius: '8px',
                        color: '#F8FAFC',
                        fontSize: '12px',
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-center p-6 border border-dashed border-[#1E293B] rounded-xl bg-[#0B1020]/40">
                  <ShieldCheck className="w-8 h-8 text-emerald-500/50 mb-2" />
                  <p className="text-sm font-medium text-slate-400">Zero Threat Incidents</p>
                  <p className="text-xs text-slate-400 mt-1 max-w-xs">
                    No security violations have been detected in the current audit store.
                  </p>
                </div>
              )}
            </div>
            {threatData.length > 0 && (
              <div className="space-y-1.5 mt-2 border-t border-[#1E293B] pt-3">
                {threatData.map((item) => (
                  <div key={item.name} className="flex items-center justify-between text-xs">
                    <span className="flex items-center gap-2 text-slate-300 truncate">
                      <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: item.color }} />
                      <span className="truncate">{item.name}</span>
                    </span>
                    <span className="font-mono text-slate-400 ml-2">{item.count}</span>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>

      {/* Recent Intercepted Threats Table */}
      <Card
        title="Recent Intercepted Violations"
        subtitle="Last security actions enforced by Leak-Sheild-AI"
        headerAction={
          <Link
            to="/threats"
            className="text-xs text-cyan-400 hover:text-cyan-300 font-medium transition-colors"
          >
            View Threat Monitor &rarr;
          </Link>
        }
      >
        {recentEvents.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-[#1E293B] text-slate-400">
                  <th className="py-2.5 px-3">Timestamp</th>
                  <th className="py-2.5 px-3">Threat Category</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Enforcement</th>
                  <th className="py-2.5 px-3">Summary</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1E293B]/60 text-slate-300">
                {recentEvents.map((evt) => (
                  <tr
                    key={evt.id}
                    onClick={() => setSelectedEvent(evt)}
                    className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                  >
                    <td className="py-2.5 px-3 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                      {new Date(evt.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 px-3 font-semibold text-slate-200">
                      {evt.threat_category}
                    </td>
                    <td className="py-2.5 px-3">
                      <Badge variant={evt.severity} size="xs">
                        {evt.severity?.toUpperCase()}
                      </Badge>
                    </td>
                    <td className="py-2.5 px-3">
                      <Badge variant={evt.action_taken === 'BLOCK' ? 'danger' : 'warning'} size="xs">
                        {evt.action_taken}
                      </Badge>
                    </td>
                    <td className="py-2.5 px-3 text-slate-400 truncate max-w-xs">
                      {evt.summary}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-8 text-center text-slate-400">
            <ShieldCheck className="w-8 h-8 text-emerald-500/40 mx-auto mb-2" />
            <p className="text-sm font-medium text-slate-300">No Security Incidents in Gateway Log</p>
            <p className="text-xs text-slate-400 mt-1">
              Any prompt containing exposed credentials, PII, or injection directives will appear here once intercepted.
            </p>
          </div>
        )}
      </Card>

      {/* Threat Detail Modal */}
      {selectedEvent && (
        <ThreatDetailModal
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
        />
      )}
    </div>
  );
}
