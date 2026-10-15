import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Lock,
  Zap,
  Activity,
  AlertTriangle,
  ArrowUpRight,
  ExternalLink,
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
  Cell,
  Legend
} from 'recharts';
import { useGateway } from '../context/GatewayContext';
import { StatCard } from '../components/common/StatCard';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { ThreatDetailModal } from '../components/threats/ThreatDetailModal';
import { MOCK_TRAFFIC_DATA, MOCK_THREAT_DISTRIBUTION } from '../services/mockData';
import { Link } from 'react-router-dom';

export function Overview() {
  const { events, connectionStatus, isUsingSimulatedData, latency } = useGateway();
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [timeRange, setTimeRange] = useState('24h');

  // Compute stats dynamically from events
  const totalBlocked = events.filter((e) => e.action_taken === 'BLOCK').length;
  const totalRedacted = events.filter((e) => e.action_taken === 'REDACT').length;
  const totalAllowed = events.filter((e) => e.action_taken === 'ALLOW').length;
  const totalInspected = isUsingSimulatedData ? 10420 : (events.length || 0);

  const piiCount = events.filter((e) => e.threat_category?.includes('PII') || e.threat_category?.includes('Credential') || e.threat_category?.includes('Key')).length;
  const injectionCount = events.filter((e) => e.threat_category?.includes('Injection') || e.threat_category?.includes('Jailbreak') || e.threat_category?.includes('System')).length;

  const recentBlocked = events
    .filter((e) => e.action_taken === 'BLOCK' || e.action_taken === 'REDACT')
    .slice(0, 5);

  return (
    <div className="space-y-6">
      {/* Simulation / Status Header Banner */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-4 rounded-xl bg-gradient-to-r from-[#111827] via-[#131D31] to-[#111827] border border-[#1E293B]">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Activity className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold text-slate-100">Gateway Threat Operations Center</h2>
              {isUsingSimulatedData ? (
                <Badge variant="simulated" size="xs">SIMULATED TELEMETRY</Badge>
              ) : (
                <Badge variant="connected" size="xs">BACKEND ENFORCED</Badge>
              )}
            </div>
            <p className="text-xs text-slate-400">
              Live inspection of LLM prompts and completions for unauthorized data egress & prompt manipulation.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 self-end sm:self-auto">
          <Link
            to="/scanner"
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold transition-all shadow-[0_0_12px_rgba(34,211,238,0.3)] flex items-center gap-1.5"
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
          change="+12.4%"
          trend="up"
          icon={Activity}
          color="cyan"
          subtitle="All Gateway Requests"
        />
        <StatCard
          title="Requests Allowed"
          value={isUsingSimulatedData ? '9,842' : `${totalAllowed}`}
          change="94.5%"
          trend="up"
          icon={ShieldCheck}
          color="emerald"
          subtitle="Clean / Sanitized"
        />
        <StatCard
          title="Requests Blocked"
          value={isUsingSimulatedData ? '452' : `${totalBlocked}`}
          change="+8.1%"
          trend="down"
          icon={ShieldX}
          color="rose"
          subtitle="Violations Intercepted"
        />
        <StatCard
          title="Sensitive Data Leaks"
          value={isUsingSimulatedData ? '218' : `${piiCount}`}
          change="-4.2%"
          trend="up"
          icon={Lock}
          color="amber"
          subtitle="PII & Credential Masks"
        />
        <StatCard
          title="Prompt Injections"
          value={isUsingSimulatedData ? '184' : `${injectionCount}`}
          change="+15.3%"
          trend="down"
          icon={ShieldAlert}
          color="purple"
          subtitle="Jailbreak & Delimiter Injections"
        />
      </div>

      {/* Charts Section: Traffic over time + Threat Categories */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recharts Area Chart: Traffic Over Time */}
        <div className="lg:col-span-2 min-w-0">
          <Card
            title="Gateway Traffic & Threat Interceptions"
            subtitle="Hourly distribution of inspected, passed, and blocked LLM requests"
            headerAction={
              <div className="flex items-center gap-1 bg-[#0B1020] p-1 rounded-lg border border-[#1E293B]">
                {['24h', '7d'].map((range) => (
                  <button
                    key={range}
                    onClick={() => setTimeRange(range)}
                    className={`px-2 py-0.5 text-xs font-mono rounded transition-colors ${
                      timeRange === range
                        ? 'bg-cyan-500/20 text-cyan-300 font-semibold'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {range}
                  </button>
                ))}
              </div>
            }
          >
            <div className="h-72 w-full min-w-0">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={MOCK_TRAFFIC_DATA} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
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
            </div>
            <div className="mt-4 pt-3 border-t border-[#1E293B] flex items-center justify-between text-xs text-slate-400">
              <div className="flex items-center gap-4">
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-sm bg-cyan-400" /> Inspected
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-sm bg-rose-500" /> Blocked
                </span>
              </div>
              <span className="font-mono text-[11px] text-slate-400">Peak Load: 1,680 req/hr</span>
            </div>
          </Card>
        </div>

        {/* Recharts Threat Category Distribution */}
        <div className="min-w-0">
          <Card
            title="Threat Categories"
            subtitle="Breakdown of detected security violations"
          >
            <div className="h-64 w-full min-w-0">
              <ResponsiveContainer width="100%" height="100%">

                <PieChart>
                  <Pie
                    data={MOCK_THREAT_DISTRIBUTION}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={85}
                    paddingAngle={3}
                    dataKey="count"
                  >
                    {MOCK_THREAT_DISTRIBUTION.map((entry, index) => (
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
            </div>

            <div className="space-y-2 mt-2">
              {MOCK_THREAT_DISTRIBUTION.map((cat) => (
                <div key={cat.name} className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: cat.color }} />
                    <span className="text-slate-300">{cat.name}</span>
                  </div>
                  <span className="font-mono font-semibold text-slate-400">{cat.count}</span>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>

      {/* Recent Blocked / Flagged Requests Table */}
      <Card
        title="Recent Security Events"
        subtitle="Latest high-risk queries intercepted by the gateway"
        headerAction={
          <Link
            to="/threats"
            className="text-xs font-medium text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors"
          >
            View All Threats <ArrowUpRight className="w-3.5 h-3.5" />
          </Link>
        }
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#0B1020] text-slate-400 font-mono uppercase text-[10px] border-b border-[#1E293B]">
              <tr>
                <th className="py-2.5 px-3">Event ID</th>
                <th className="py-2.5 px-3">Category</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Action</th>
                <th className="py-2.5 px-3">Summary</th>
                <th className="py-2.5 px-3 text-right">Time</th>
                <th className="py-2.5 px-3 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E293B]/60 text-slate-300">
              {recentBlocked.length > 0 ? (
                recentBlocked.map((evt) => (
                  <tr key={evt.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-3 font-mono font-medium text-slate-200">{evt.id}</td>
                    <td className="py-3 px-3 font-medium text-slate-100">{evt.threat_category}</td>
                    <td className="py-3 px-3">
                      <Badge variant={evt.severity} size="xs">{evt.severity}</Badge>
                    </td>
                    <td className="py-3 px-3">
                      <Badge variant={evt.action_taken} size="xs">{evt.action_taken}</Badge>
                    </td>
                    <td className="py-3 px-3 max-w-xs truncate text-slate-400" title={evt.summary}>
                      {evt.summary}
                    </td>
                    <td className="py-3 px-3 text-right font-mono text-slate-400">
                      {new Date(evt.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </td>
                    <td className="py-3 px-3 text-right">
                      <button
                        onClick={() => setSelectedEvent(evt)}
                        className="text-cyan-400 hover:text-cyan-300 font-medium text-[11px] hover:underline"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="py-6 text-center text-slate-500">
                    No high-risk events recorded in this time window.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Threat Detail Modal */}
      <ThreatDetailModal
        isOpen={Boolean(selectedEvent)}
        onClose={() => setSelectedEvent(null)}
        event={selectedEvent}
      />
    </div>
  );
}
