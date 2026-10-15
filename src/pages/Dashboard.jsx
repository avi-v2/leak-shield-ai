import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Activity,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Lock,
  Zap,
  RefreshCw,
  AlertTriangle,
  Search,
  Filter,
  FileText,
  Image as ImageIcon,
  Terminal,
  ExternalLink,
  ChevronRight,
  ChevronLeft,
  Info,
  Layers,
  TrendingUp,
  Cpu,
  Eye,
  Sliders,
  CheckCircle2,
  FileCheck,
  AlertOctagon
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  CartesianGrid
} from 'recharts';
import { Link } from 'react-router-dom';

import { useGateway } from '../context/GatewayContext';
import {
  getDashboardSummary,
  getDashboardTimeline,
  getThreatCategories,
  getInjectionKeywords,
  getDlpAnalytics,
  getPolicyDistribution,
  getFileImageAnalytics,
  getDashboardEvents
} from '../services/api';
import { StatCard } from '../components/common/StatCard';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { ThreatDetailModal } from '../components/threats/ThreatDetailModal';

// Color map for threat categories
const CATEGORY_PALETTE = {
  'Prompt Injection': '#EF4444',
  'Jailbreak Attempts': '#DC2626',
  'API Keys & Access Tokens': '#F59E0B',
  'Passwords & Credentials': '#D97706',
  'Email Addresses': '#3B82F6',
  'Payment Cards': '#EC4899',
  'Indian Identifiers (PAN/Aadhaar)': '#8B5CF6',
  'Phone Numbers': '#06B6D4',
  'Image Metadata & GPS': '#10B981',
  'Suspicious Document Content': '#F97316',
  'Other Sensitive Data': '#64748B',
};

export function Dashboard() {
  const { connectionStatus, latency, refreshAll } = useGateway();

  // Selected global time range
  const [timeRange, setTimeRange] = useState('24h');
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState(null);

  // Core API State
  const [summary, setSummary] = useState({
    total_scans: 0,
    threats_detected: 0,
    clean_scans: 0,
    blocked_requests: 0,
    redacted_requests: 0,
    allowed_requests: 0,
    threat_rate_pct: 0.0,
    block_rate_pct: 0.0,
    sensitive_data_findings: 0,
    injection_attempts: 0,
    prompts_scanned: 0,
    files_scanned: 0,
    images_scanned: 0,
  });

  const [timelineData, setTimelineData] = useState([]);
  const [threatCategoryData, setThreatCategoryData] = useState({ categories: [], total_findings: 0, unique_threatened_scans: 0 });
  const [injectionKeywords, setInjectionKeywords] = useState({ indicators: [], total_flagged_scans: 0, total_indicator_matches: 0 });
  const [dlpData, setDlpData] = useState({ total_sensitive_findings: 0, scans_with_sensitive_data: 0, sensitive_scan_percentage: 0, most_frequent_categories: [], safe_samples: [] });
  const [policyData, setPolicyData] = useState({ total_evaluations: 0, distribution: { ALLOW: { count: 0, percentage: 0 }, REDACT: { count: 0, percentage: 0 }, BLOCK: { count: 0, percentage: 0 } }, common_block_reasons: [], common_redact_reasons: [] });
  const [fileImageData, setFileImageData] = useState({ files_scanned: 0, images_scanned: 0, by_file_type: {}, ocr_stats: {}, metadata_findings_count: 0, gps_findings_count: 0, embedded_credential_count: 0, injection_in_files_count: 0 });

  // Events Table State
  const [eventsList, setEventsList] = useState([]);
  const [eventsTotal, setEventsTotal] = useState(0);
  const [eventsPage, setEventsPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const [searchQuery, setSearchQuery] = useState('');
  const [actionFilter, setActionFilter] = useState('ALL');
  const [mediumFilter, setMediumFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [isLoadingEvents, setIsLoadingEvents] = useState(false);

  // Load all telemetry
  const loadDashboardData = useCallback(async (range = timeRange) => {
    setIsRefreshing(true);
    try {
      const [sumRes, timeRes, catRes, injRes, dlpRes, polRes, fiRes] = await Promise.allSettled([
        getDashboardSummary(range),
        getDashboardTimeline(range),
        getThreatCategories(range),
        getInjectionKeywords(range, 10),
        getDlpAnalytics(range),
        getPolicyDistribution(range),
        getFileImageAnalytics(range),
      ]);

      if (sumRes.status === 'fulfilled' && sumRes.value?.success) {
        setSummary(sumRes.value.data);
      }
      if (timeRes.status === 'fulfilled' && timeRes.value?.success) {
        setTimelineData(timeRes.value.data || []);
      }
      if (catRes.status === 'fulfilled' && catRes.value?.success) {
        setThreatCategoryData(catRes.value.data || { categories: [] });
      }
      if (injRes.status === 'fulfilled' && injRes.value?.success) {
        setInjectionKeywords(injRes.value.data || { indicators: [] });
      }
      if (dlpRes.status === 'fulfilled' && dlpRes.value?.success) {
        setDlpData(dlpRes.value.data || { most_frequent_categories: [], safe_samples: [] });
      }
      if (polRes.status === 'fulfilled' && polRes.value?.success) {
        setPolicyData(polRes.value.data || { distribution: {} });
      }
      if (fiRes.status === 'fulfilled' && fiRes.value?.success) {
        setFileImageData(fiRes.value.data || { by_file_type: {}, ocr_stats: {} });
      }
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
    } finally {
      setIsRefreshing(false);
    }
  }, [timeRange]);

  // Load paginated security events table
  const loadEventsTable = useCallback(async () => {
    setIsLoadingEvents(true);
    try {
      const res = await getDashboardEvents({
        limit: pageSize,
        offset: eventsPage * pageSize,
        range: timeRange,
        search: searchQuery.trim() || undefined,
        action: actionFilter,
        input_type: mediumFilter,
        severity: severityFilter,
      });

      if (res.success && res.data) {
        setEventsList(res.data.events || []);
        setEventsTotal(res.data.total || 0);
      }
    } catch (err) {
      console.error('Failed to load security events:', err);
    } finally {
      setIsLoadingEvents(false);
    }
  }, [eventsPage, pageSize, timeRange, searchQuery, actionFilter, mediumFilter, severityFilter]);

  // Initial load and range changes
  useEffect(() => {
    loadDashboardData(timeRange);
    setEventsPage(0);
  }, [timeRange, loadDashboardData]);

  useEffect(() => {
    loadEventsTable();
  }, [loadEventsTable]);

  // Auto-refresh interval (15s)
  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => {
      loadDashboardData(timeRange);
      loadEventsTable();
    }, 15000);
    return () => clearInterval(interval);
  }, [autoRefresh, timeRange, loadDashboardData, loadEventsTable]);

  const handleManualRefresh = async () => {
    await Promise.all([loadDashboardData(timeRange), loadEventsTable(), refreshAll?.()]);
  };

  const totalPages = Math.ceil(eventsTotal / pageSize);

  // Policy Distribution Chart Data
  const policyChartData = useMemo(() => {
    if (!policyData?.distribution) return [];
    return [
      { name: 'ALLOWED', value: policyData.distribution.ALLOW?.count || 0, color: '#10B981' },
      { name: 'REDACTED', value: policyData.distribution.REDACT?.count || 0, color: '#F59E0B' },
      { name: 'BLOCKED', value: policyData.distribution.BLOCK?.count || 0, color: '#EF4444' },
    ].filter(item => item.value > 0);
  }, [policyData]);

  return (
    <div className="space-y-6">
      {/* 1. Dashboard Operations Header */}
      <div className="flex flex-col xl:flex-row items-start xl:items-center justify-between gap-4 p-4 rounded-xl bg-gradient-to-r from-[#111827] via-[#131D31] to-[#111827] border border-[#1E293B]">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Activity className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-base font-bold text-slate-100">AI Security Operations Center (SOC)</h1>
              {connectionStatus === 'connected' ? (
                <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  GATEWAY ACTIVE {latency ? `(${latency}ms)` : ''}
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30">
                  <span className="w-1.5 h-1.5 rounded-full bg-rose-400" />
                  BACKEND OFFLINE
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Real-time telemetry and policy enforcement monitoring for prompts, documents, and images.
            </p>
          </div>
        </div>

        {/* Global Controls: Time Range Selector & Refresh */}
        <div className="flex items-center gap-3 flex-wrap self-end xl:self-auto">
          {/* Time Range Pills */}
          <div className="inline-flex items-center p-1 rounded-lg bg-[#0B1020] border border-[#1E293B]">
            {[
              { id: '1h', label: '1 Hour' },
              { id: '24h', label: '24 Hours' },
              { id: '7d', label: '7 Days' },
              { id: '30d', label: '30 Days' },
              { id: 'all', label: 'All Time' },
            ].map((r) => (
              <button
                key={r.id}
                onClick={() => setTimeRange(r.id)}
                className={`px-2.5 py-1 text-xs font-medium rounded-md transition-all ${
                  timeRange === r.id
                    ? 'bg-cyan-500 text-slate-950 font-semibold shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {r.label}
              </button>
            ))}
          </div>

          {/* Auto Refresh Toggle */}
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`px-2.5 py-1.5 rounded-lg text-xs font-mono border transition-colors flex items-center gap-1.5 ${
              autoRefresh
                ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40'
                : 'bg-slate-900 text-slate-400 border-slate-700 hover:text-slate-300'
            }`}
            title="Auto-refresh every 15 seconds"
          >
            <span className={`w-2 h-2 rounded-full ${autoRefresh ? 'bg-emerald-400 animate-ping' : 'bg-slate-500'}`} />
            Auto-Sync
          </button>

          {/* Manual Refresh */}
          <button
            onClick={handleManualRefresh}
            disabled={isRefreshing}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors flex items-center gap-1.5 disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
            Refresh
          </button>

          <Link
            to="/scanner"
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-400 hover:to-blue-400 text-slate-950 transition-all shadow-[0_0_15px_rgba(34,211,238,0.25)] flex items-center gap-1.5"
          >
            <Zap className="w-3.5 h-3.5" />
            Scanner
          </Link>
        </div>
      </div>

      {/* 2. Top-Level KPI Cards (8 Metrics with Documented Denominators) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-8 gap-3">
        <StatCard
          title="Total Scans"
          value={summary.total_scans.toLocaleString()}
          subtitle={`${summary.prompts_scanned}p · ${summary.files_scanned}f · ${summary.images_scanned}img`}
          icon={Activity}
          color="cyan"
        />
        <StatCard
          title="Threats Detected"
          value={summary.threats_detected.toLocaleString()}
          subtitle={`Clean: ${summary.clean_scans}`}
          icon={ShieldAlert}
          color="amber"
        />
        <StatCard
          title="Blocked Requests"
          value={summary.blocked_requests.toLocaleString()}
          subtitle="Mandatory Halts"
          icon={ShieldX}
          color="rose"
        />
        <StatCard
          title="Redacted Requests"
          value={summary.redacted_requests.toLocaleString()}
          subtitle="Egress Sanitized"
          icon={ShieldCheck}
          color="emerald"
        />
        <StatCard
          title="Threat Rate"
          value={`${summary.threat_rate_pct}%`}
          subtitle="Threats / Total"
          icon={TrendingUp}
          color="amber"
        />
        <StatCard
          title="Block Rate"
          value={`${summary.block_rate_pct}%`}
          subtitle="Blocked / Total"
          icon={AlertOctagon}
          color="rose"
        />
        <StatCard
          title="Sensitive Data"
          value={summary.sensitive_data_findings.toLocaleString()}
          subtitle="PII, Keys, Passwords"
          icon={Lock}
          color="purple"
        />
        <StatCard
          title="Injections"
          value={summary.injection_attempts.toLocaleString()}
          subtitle="Adversarial Prompts"
          icon={Terminal}
          color="rose"
        />
      </div>

      {/* 3. Security Activity Over Time & Policy Verdicts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Time-series Area Chart (2 cols) */}
        <div className="lg:col-span-2 min-w-0">
          <Card
            title="Security Activity Over Time"
            subtitle={`Aggregated request volume, threat flags, blocks, and redactions (${timeRange.toUpperCase()})`}
            headerAction={
              <span className="text-xs font-mono text-slate-400">
                {timelineData.length} data point{timelineData.length === 1 ? '' : 's'}
              </span>
            }
          >
            <div className="h-72 w-full min-w-0">
              {timelineData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={timelineData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                    <defs>
                      <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#22D3EE" stopOpacity={0.25} />
                        <stop offset="95%" stopColor="#22D3EE" stopOpacity={0.0} />
                      </linearGradient>
                      <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#F59E0B" stopOpacity={0.35} />
                        <stop offset="95%" stopColor="#F59E0B" stopOpacity={0.0} />
                      </linearGradient>
                      <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#EF4444" stopOpacity={0.4} />
                        <stop offset="95%" stopColor="#EF4444" stopOpacity={0.0} />
                      </linearGradient>
                      <linearGradient id="colorRedacted" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#10B981" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#10B981" stopOpacity={0.0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" opacity={0.6} />
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
                        backgroundColor: '#0F172A',
                        borderColor: '#1E293B',
                        borderRadius: '8px',
                        color: '#F8FAFC',
                        fontSize: '12px',
                        boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.5)',
                      }}
                    />
                    <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }} />
                    <Area
                      type="monotone"
                      dataKey="inspected"
                      name="Total Scans"
                      stroke="#22D3EE"
                      strokeWidth={2}
                      fillOpacity={1}
                      fill="url(#colorTotal)"
                    />
                    <Area
                      type="monotone"
                      dataKey="threats"
                      name="Threats Detected"
                      stroke="#F59E0B"
                      strokeWidth={2}
                      fillOpacity={1}
                      fill="url(#colorThreats)"
                    />
                    <Area
                      type="monotone"
                      dataKey="blocked"
                      name="Blocked"
                      stroke="#EF4444"
                      strokeWidth={2}
                      fillOpacity={1}
                      fill="url(#colorBlocked)"
                    />
                    <Area
                      type="monotone"
                      dataKey="redacted"
                      name="Redacted"
                      stroke="#10B981"
                      strokeWidth={2}
                      fillOpacity={1}
                      fill="url(#colorRedacted)"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-center p-6 border border-dashed border-[#1E293B] rounded-xl bg-[#0B1020]/40">
                  <Activity className="w-8 h-8 text-slate-600 mb-2" />
                  <p className="text-sm font-medium text-slate-300">No Activity in Selected Window</p>
                  <p className="text-xs text-slate-500 mt-1 max-w-sm">
                    No gateway scans have been recorded in the past {timeRange}. Submit requests via the Scanner or select &quot;All Time&quot;.
                  </p>
                </div>
              )}
            </div>
          </Card>
        </div>

        {/* Policy Decisions Card (1 col) */}
        <div className="min-w-0">
          <Card
            title="Policy Verdict Distribution"
            subtitle="Autonomous gateway enforcement breakdown"
          >
            <div className="h-44 w-full flex items-center justify-center">
              {policyChartData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={policyChartData}
                      cx="50%"
                      cy="50%"
                      innerRadius={45}
                      outerRadius={68}
                      paddingAngle={4}
                      dataKey="value"
                    >
                      {policyChartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0F172A',
                        borderColor: '#1E293B',
                        borderRadius: '8px',
                        color: '#F8FAFC',
                        fontSize: '12px',
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="text-center text-xs text-slate-500">No evaluations yet</div>
              )}
            </div>

            {/* Verdict Counts and Top Block Reasons */}
            <div className="grid grid-cols-3 gap-2 text-center pt-2 border-t border-[#1E293B] mt-2">
              <div className="p-2 rounded bg-emerald-500/5 border border-emerald-500/20">
                <span className="text-[10px] uppercase font-mono text-emerald-400 block">Allow</span>
                <span className="text-sm font-bold text-slate-200">{policyData?.distribution?.ALLOW?.count || 0}</span>
                <span className="text-[10px] text-slate-400 block">{policyData?.distribution?.ALLOW?.percentage || 0}%</span>
              </div>
              <div className="p-2 rounded bg-amber-500/5 border border-amber-500/20">
                <span className="text-[10px] uppercase font-mono text-amber-400 block">Redact</span>
                <span className="text-sm font-bold text-slate-200">{policyData?.distribution?.REDACT?.count || 0}</span>
                <span className="text-[10px] text-slate-400 block">{policyData?.distribution?.REDACT?.percentage || 0}%</span>
              </div>
              <div className="p-2 rounded bg-rose-500/5 border border-rose-500/20">
                <span className="text-[10px] uppercase font-mono text-rose-400 block">Block</span>
                <span className="text-sm font-bold text-slate-200">{policyData?.distribution?.BLOCK?.count || 0}</span>
                <span className="text-[10px] text-slate-400 block">{policyData?.distribution?.BLOCK?.percentage || 0}%</span>
              </div>
            </div>

            {/* Top Block Reasons List */}
            {policyData?.common_block_reasons?.length > 0 && (
              <div className="mt-3 pt-3 border-t border-[#1E293B]">
                <span className="text-[11px] font-semibold text-slate-300 block mb-1.5">Top Block Justifications</span>
                <div className="space-y-1">
                  {policyData.common_block_reasons.slice(0, 2).map((br, i) => (
                    <div key={i} className="flex items-center justify-between text-xs bg-slate-900/60 px-2 py-1 rounded border border-slate-800">
                      <span className="truncate max-w-[190px] text-slate-400" title={br.reason}>{br.reason}</span>
                      <span className="font-mono text-rose-400 font-bold ml-1">{br.count}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </Card>
        </div>
      </div>

      {/* 4. Threat Category Breakdown & Injection Intelligence */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threat Category Breakdown Card */}
        <Card
          title="Threat Category Breakdown"
          subtitle="Distribution of security findings vs unique affected requests"
          headerAction={
            <div className="flex items-center gap-1.5 text-xs text-slate-400">
              <span>{threatCategoryData.total_findings || 0} Findings</span>
              <span>·</span>
              <span>{threatCategoryData.unique_threatened_scans || 0} Scans</span>
            </div>
          }
        >
          {threatCategoryData.categories?.length > 0 ? (
            <div className="space-y-3 max-h-96 overflow-y-auto pr-1">
              {threatCategoryData.categories.map((cat, idx) => {
                const barColor = CATEGORY_PALETTE[cat.name] || cat.color || '#64748B';
                return (
                  <div key={idx} className="p-2.5 rounded-lg bg-[#0B1020] border border-[#1E293B]">
                    <div className="flex items-center justify-between mb-1.5">
                      <div className="flex items-center gap-2">
                        <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: barColor }} />
                        <span className="text-xs font-semibold text-slate-200">{cat.name}</span>
                      </div>
                      <div className="flex items-center gap-2 text-xs">
                        <span className="font-mono font-bold text-slate-200">{cat.findings_count} findings</span>
                        <span className="text-slate-500">({cat.unique_scans_count} scans)</span>
                        <span className="font-mono text-cyan-400 text-[11px]">{cat.percentage}%</span>
                      </div>
                    </div>

                    {/* Progress Bar */}
                    <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-300"
                        style={{ width: `${Math.min(100, cat.percentage)}%`, backgroundColor: barColor }}
                      />
                    </div>

                    {/* Severity Pills */}
                    {cat.severity_breakdown && (
                      <div className="flex items-center gap-2 mt-2 text-[10px] font-mono text-slate-400">
                        {cat.severity_breakdown.critical > 0 && (
                          <span className="text-rose-400 font-bold">Crit: {cat.severity_breakdown.critical}</span>
                        )}
                        {cat.severity_breakdown.high > 0 && (
                          <span className="text-rose-300">High: {cat.severity_breakdown.high}</span>
                        )}
                        {cat.severity_breakdown.medium > 0 && (
                          <span className="text-amber-400">Med: {cat.severity_breakdown.medium}</span>
                        )}
                        {cat.severity_breakdown.low > 0 && (
                          <span className="text-cyan-400">Low: {cat.severity_breakdown.low}</span>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="h-64 flex flex-col items-center justify-center text-center p-6 border border-dashed border-[#1E293B] rounded-xl bg-[#0B1020]/40">
              <ShieldCheck className="w-8 h-8 text-emerald-500 mb-2" />
              <p className="text-sm font-medium text-slate-300">No Detected Threats</p>
              <p className="text-xs text-slate-500 mt-1 max-w-xs">
                Zero threat findings recorded in the current filter window. All traffic evaluated as safe.
              </p>
            </div>
          )}
          <div className="mt-3 pt-2 border-t border-[#1E293B] flex items-center gap-1.5 text-[11px] text-slate-500">
            <Info className="w-3.5 h-3.5 shrink-0" />
            <span>Findings count measures total detected instances; unique scans counts distinct requests.</span>
          </div>
        </Card>

        {/* Prompt Injection Intelligence Card */}
        <Card
          title="Prompt Injection Intelligence"
          subtitle="Top detected injection phrases, keywords, and rule matches"
          headerAction={
            <span className="text-xs font-mono text-rose-400 font-semibold">
              {injectionKeywords.total_flagged_scans || 0} Flagged Requests
            </span>
          }
        >
          {injectionKeywords.indicators?.length > 0 ? (
            <div className="space-y-2.5 max-h-96 overflow-y-auto pr-1">
              {injectionKeywords.indicators.map((item, idx) => (
                <div key={idx} className="p-2.5 rounded-lg bg-[#0B1020] border border-[#1E293B]">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-mono font-medium text-rose-300 bg-rose-500/10 px-2 py-0.5 rounded border border-rose-500/20 truncate max-w-[280px]">
                      &quot;{item.phrase}&quot;
                    </span>
                    <div className="flex items-center gap-2 text-xs">
                      <span className="font-mono font-bold text-slate-100">{item.count} hits</span>
                      <span className="text-slate-500">({item.percentage_of_flagged_scans}%)</span>
                    </div>
                  </div>

                  {/* Metadata line */}
                  <div className="flex items-center justify-between text-[11px] text-slate-400 mt-1.5">
                    <div className="flex items-center gap-1.5">
                      <span className="text-slate-500">Methods:</span>
                      {item.detection_methods?.map((m, mIdx) => (
                        <span key={mIdx} className="px-1.5 py-0.2 rounded bg-slate-800 text-[10px] font-mono text-cyan-400">
                          {m}
                        </span>
                      ))}
                    </div>
                    {item.is_exact_rule ? (
                      <span className="text-[10px] text-amber-400 font-mono">Exact Rule</span>
                    ) : (
                      <span className="text-[10px] text-slate-500 font-mono">Heuristic Match</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="h-64 flex flex-col items-center justify-center text-center p-6 border border-dashed border-[#1E293B] rounded-xl bg-[#0B1020]/40">
              <Terminal className="w-8 h-8 text-slate-600 mb-2" />
              <p className="text-sm font-medium text-slate-300">No Prompt Injections Flagged</p>
              <p className="text-xs text-slate-500 mt-1 max-w-xs">
                No adversarial jailbreaks or delimiter injection patterns observed in this period.
              </p>
            </div>
          )}
          <div className="mt-3 pt-2 border-t border-[#1E293B] flex items-center gap-1.5 text-[11px] text-slate-500">
            <Info className="w-3.5 h-3.5 shrink-0" />
            <span>Keyword presence alone does not constitute semantic AI evaluation; raw prompts are never exposed.</span>
          </div>
        </Card>
      </div>

      {/* 5. Sensitive Data & DLP Analytics + File & Image Security */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Sensitive Data & DLP Analytics */}
        <Card
          title="Sensitive Data & DLP Analytics"
          subtitle="PII, credential exposures, and egress masking verification"
          headerAction={
            <span className="text-xs font-mono text-purple-400">
              {dlpData.total_sensitive_findings || 0} Findings ({dlpData.sensitive_scan_percentage || 0}% of traffic)
            </span>
          }
        >
          <div className="grid grid-cols-3 gap-3 mb-4">
            <div className="p-3 rounded-lg bg-[#0B1020] border border-[#1E293B] text-center">
              <span className="text-[10px] uppercase font-mono text-slate-400 block">Total Findings</span>
              <span className="text-lg font-bold font-mono text-purple-400">{dlpData.total_sensitive_findings || 0}</span>
            </div>
            <div className="p-3 rounded-lg bg-[#0B1020] border border-[#1E293B] text-center">
              <span className="text-[10px] uppercase font-mono text-slate-400 block">Values Masked</span>
              <span className="text-lg font-bold font-mono text-emerald-400">{dlpData.values_redacted_count || 0}</span>
            </div>
            <div className="p-3 rounded-lg bg-[#0B1020] border border-[#1E293B] text-center">
              <span className="text-[10px] uppercase font-mono text-slate-400 block">Affected Scans</span>
              <span className="text-lg font-bold font-mono text-slate-200">{dlpData.scans_with_sensitive_data || 0}</span>
            </div>
          </div>

          {/* Top Sensitive Categories */}
          {dlpData.most_frequent_categories?.length > 0 && (
            <div className="mb-4">
              <span className="text-xs font-semibold text-slate-300 block mb-2">Most Frequent PII & Secret Types</span>
              <div className="space-y-1.5">
                {dlpData.most_frequent_categories.slice(0, 4).map((c, idx) => (
                  <div key={idx} className="flex items-center justify-between text-xs bg-slate-900/60 p-2 rounded border border-slate-800">
                    <span className="text-slate-300 font-medium">{c.name}</span>
                    <span className="font-mono text-purple-300 font-bold">{c.count} items ({c.percentage}%)</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Safe Redacted Preview Samples */}
          <div>
            <span className="text-xs font-semibold text-slate-300 block mb-2">Sanitized Audit Previews (Zero Raw Secrets)</span>
            {dlpData.safe_samples?.length > 0 ? (
              <div className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
                {dlpData.safe_samples.slice(0, 3).map((sample, sIdx) => (
                  <div key={sIdx} className="p-2 rounded bg-[#0B1020] border border-[#1E293B] text-xs flex items-center justify-between">
                    <div className="truncate max-w-[260px]">
                      <span className="text-slate-400 text-[10px] block">{sample.category}</span>
                      <span className="font-mono text-amber-300">{sample.preview}</span>
                    </div>
                    <Badge variant="REDACT" size="xs">Masked</Badge>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-4 text-xs text-slate-500 border border-dashed border-[#1E293B] rounded">
                Zero sensitive data leaks detected in selected window.
              </div>
            )}
          </div>
        </Card>

        {/* File and Image Security Telemetry */}
        <Card
          title="Document & Image Security Telemetry"
          subtitle="File inspections, OCR pipelines, and embedded threat detection"
          headerAction={
            <span className="text-xs font-mono text-cyan-400">
              {fileImageData.files_scanned + fileImageData.images_scanned} Media Scans
            </span>
          }
        >
          <div className="grid grid-cols-2 gap-3 mb-4">
            <div className="p-3 rounded-lg bg-[#0B1020] border border-[#1E293B] flex items-center gap-3">
              <div className="p-2 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                <FileText className="w-5 h-5" />
              </div>
              <div>
                <span className="text-[10px] uppercase font-mono text-slate-400 block">Documents Scanned</span>
                <span className="text-lg font-bold font-mono text-slate-200">{fileImageData.files_scanned}</span>
              </div>
            </div>
            <div className="p-3 rounded-lg bg-[#0B1020] border border-[#1E293B] flex items-center gap-3">
              <div className="p-2 rounded bg-purple-500/10 border border-purple-500/30 text-purple-400">
                <ImageIcon className="w-5 h-5" />
              </div>
              <div>
                <span className="text-[10px] uppercase font-mono text-slate-400 block">Images Scanned</span>
                <span className="text-lg font-bold font-mono text-slate-200">{fileImageData.images_scanned}</span>
              </div>
            </div>
          </div>

          {/* Media Threat Counters */}
          <div className="space-y-2 mb-4">
            <div className="flex items-center justify-between text-xs p-2 rounded bg-slate-900/60 border border-slate-800">
              <span className="text-slate-300">EXIF / GPS Geolocation Metadata Leaks</span>
              <span className="font-mono font-bold text-amber-400">{fileImageData.gps_findings_count || 0}</span>
            </div>
            <div className="flex items-center justify-between text-xs p-2 rounded bg-slate-900/60 border border-slate-800">
              <span className="text-slate-300">Credentials Embedded in Files / OCR Text</span>
              <span className="font-mono font-bold text-rose-400">{fileImageData.embedded_credential_count || 0}</span>
            </div>
            <div className="flex items-center justify-between text-xs p-2 rounded bg-slate-900/60 border border-slate-800">
              <span className="text-slate-300">Injections Inside Documents / Text</span>
              <span className="font-mono font-bold text-rose-400">{fileImageData.injection_in_files_count || 0}</span>
            </div>
          </div>

          {/* File Types Breakdown */}
          {Object.keys(fileImageData.by_file_type || {}).length > 0 && (
            <div>
              <span className="text-xs font-semibold text-slate-300 block mb-1.5">Processed MIME Types</span>
              <div className="flex flex-wrap gap-1.5">
                {Object.entries(fileImageData.by_file_type).map(([ft, count], i) => (
                  <span key={i} className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 font-mono text-[11px] text-slate-300">
                    {ft}: <strong className="text-cyan-400">{count}</strong>
                  </span>
                ))}
              </div>
            </div>
          )}
        </Card>
      </div>

      {/* 6. Recent Security Events Table with Multi-faceted Filtering & Pagination */}
      <Card
        title="Security Audit Events Log"
        subtitle="Chronological inspection records with live multi-attribute filtering"
        headerAction={
          <div className="text-xs font-mono text-slate-400">
            Showing {eventsList.length} of {eventsTotal} events
          </div>
        }
      >
        {/* Table Filters Bar */}
        <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 mb-4 pb-4 border-b border-[#1E293B]">
          {/* Search Input */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search by summary, rule, event ID, or payload text..."
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setEventsPage(0);
              }}
              className="w-full bg-[#0B1020] border border-[#1E293B] rounded-lg pl-9 pr-4 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Action Filter */}
          <select
            value={actionFilter}
            onChange={(e) => {
              setActionFilter(e.target.value);
              setEventsPage(0);
            }}
            className="bg-[#0B1020] border border-[#1E293B] rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Actions</option>
            <option value="ALLOW">ALLOW</option>
            <option value="REDACT">REDACT</option>
            <option value="BLOCK">BLOCK</option>
          </select>

          {/* Medium / Input Type Filter */}
          <select
            value={mediumFilter}
            onChange={(e) => {
              setMediumFilter(e.target.value);
              setEventsPage(0);
            }}
            className="bg-[#0B1020] border border-[#1E293B] rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Mediums</option>
            <option value="prompt">Prompt Text</option>
            <option value="file">Documents</option>
            <option value="image">Images</option>
          </select>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value);
              setEventsPage(0);
            }}
            className="bg-[#0B1020] border border-[#1E293B] rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        {/* Events Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-[#1E293B] text-slate-400 font-mono text-[11px] uppercase bg-slate-900/40">
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Event ID</th>
                <th className="py-2.5 px-3">Type</th>
                <th className="py-2.5 px-3">Threat Category</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Action</th>
                <th className="py-2.5 px-3">Detection</th>
                <th className="py-2.5 px-3">Preview / Summary</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E293B]/60">
              {isLoadingEvents ? (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-slate-400">
                    <RefreshCw className="w-5 h-5 animate-spin mx-auto text-cyan-400 mb-2" />
                    Loading audit events...
                  </td>
                </tr>
              ) : eventsList.length > 0 ? (
                eventsList.map((evt) => (
                  <tr
                    key={evt.id}
                    onClick={() => setSelectedEvent(evt)}
                    className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                  >
                    <td className="py-3 px-3 font-mono text-slate-400 whitespace-nowrap">
                      {new Date(evt.timestamp).toLocaleString(undefined, {
                        month: 'short',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit',
                      })}
                    </td>
                    <td className="py-3 px-3 font-mono text-cyan-400 whitespace-nowrap font-semibold">
                      {evt.id}
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap">
                      <span className="capitalize px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-[10px] text-slate-300 font-mono">
                        {evt.input_type || 'prompt'}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-medium text-slate-200">
                      {evt.threat_category}
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap">
                      <Badge variant={evt.severity} size="xs">{evt.severity}</Badge>
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap">
                      <Badge variant={evt.action_taken} size="xs">{evt.action_taken}</Badge>
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap">
                      <div className="flex gap-1 flex-wrap">
                        {evt.detection_methods?.slice(0, 2).map((dm, idx) => (
                          <span key={idx} className="text-[9px] px-1.5 py-0.2 rounded bg-slate-800 font-mono text-cyan-300">
                            {dm}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-3 px-3 max-w-xs truncate text-slate-400">
                      {evt.sanitized_preview || evt.summary}
                    </td>
                    <td className="py-3 px-3 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedEvent(evt);
                        }}
                        className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-slate-700 text-[11px] font-medium"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-slate-500">
                    No security events matching current criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Controls */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between pt-4 mt-2 border-t border-[#1E293B] text-xs">
            <span className="text-slate-400">
              Page <strong className="text-slate-200">{eventsPage + 1}</strong> of{' '}
              <strong className="text-slate-200">{totalPages}</strong>
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setEventsPage((p) => Math.max(0, p - 1))}
                disabled={eventsPage === 0}
                className="px-2.5 py-1.5 rounded bg-slate-800 border border-slate-700 text-slate-300 disabled:opacity-40 flex items-center gap-1 hover:bg-slate-700"
              >
                <ChevronLeft className="w-3.5 h-3.5" /> Previous
              </button>
              <button
                onClick={() => setEventsPage((p) => Math.min(totalPages - 1, p + 1))}
                disabled={eventsPage >= totalPages - 1}
                className="px-2.5 py-1.5 rounded bg-slate-800 border border-slate-700 text-slate-300 disabled:opacity-40 flex items-center gap-1 hover:bg-slate-700"
              >
                Next <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}
      </Card>

      {/* Forensic Event Detail Modal */}
      <ThreatDetailModal
        isOpen={Boolean(selectedEvent)}
        onClose={() => setSelectedEvent(null)}
        event={selectedEvent}
      />
    </div>
  );
}

export default Dashboard;
