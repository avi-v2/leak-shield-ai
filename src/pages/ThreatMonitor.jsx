import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  Search,
  Filter,
  RefreshCw,
  ArrowUpDown,
  SlidersHorizontal,
  ExternalLink,
  Lock,
  Download,
  AlertTriangle,
  Info
} from 'lucide-react';
import { useGateway } from '../context/GatewayContext';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { ThreatDetailModal } from '../components/threats/ThreatDetailModal';
import { TableSkeleton } from '../components/common/Skeleton';

export function ThreatMonitor() {
  const { events, eventsLoading, loadEvents, connectionStatus } = useGateway();

  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [actionFilter, setActionFilter] = useState('ALL');
  const [sortField, setSortField] = useState('timestamp');
  const [sortDirection, setSortDirection] = useState('desc');
  const [selectedEvent, setSelectedEvent] = useState(null);

  // Filter and sort events
  const filteredEvents = useMemo(() => {
    return events
      .filter((evt) => {
        // Search filter
        if (searchTerm.trim() !== '') {
          const q = searchTerm.toLowerCase();
          const matchId = evt.id?.toLowerCase().includes(q);
          const matchCategory = evt.threat_category?.toLowerCase().includes(q);
          const matchSummary = evt.summary?.toLowerCase().includes(q);
          const matchSource = evt.source?.toLowerCase().includes(q);
          if (!matchId && !matchCategory && !matchSummary && !matchSource) return false;
        }

        // Severity filter
        if (severityFilter !== 'ALL' && evt.severity?.toLowerCase() !== severityFilter.toLowerCase()) {
          return false;
        }

        // Category filter
        if (categoryFilter !== 'ALL' && !evt.threat_category?.toLowerCase().includes(categoryFilter.toLowerCase())) {
          return false;
        }

        // Action filter
        if (actionFilter !== 'ALL' && evt.action_taken !== actionFilter) {
          return false;
        }

        return true;
      })
      .sort((a, b) => {
        let valA = a[sortField];
        let valB = b[sortField];

        if (sortField === 'timestamp') {
          valA = new Date(valA).getTime();
          valB = new Date(valB).getTime();
        } else if (sortField === 'severity') {
          const rank = { critical: 4, high: 3, medium: 2, low: 1 };
          valA = rank[valA?.toLowerCase()] || 0;
          valB = rank[valB?.toLowerCase()] || 0;
        }

        if (valA < valB) return sortDirection === 'asc' ? -1 : 1;
        if (valA > valB) return sortDirection === 'asc' ? 1 : -1;
        return 0;
      });
  }, [events, searchTerm, severityFilter, categoryFilter, actionFilter, sortField, sortDirection]);

  const toggleSort = (field) => {
    if (sortField === field) {
      setSortDirection((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  };

  const categories = ['ALL', 'Credential', 'Injection', 'PII', 'Jailbreak', 'System Prompt'];

  return (
    <div className="space-y-6">
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-bold text-slate-100">Live Threat Monitor</h2>
            <Badge variant="cyan" size="sm">{filteredEvents.length} Incidents</Badge>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time feed of intercepted prompt injection attacks, credential exfiltration, and sensitive data leaks.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => loadEvents()}
            disabled={eventsLoading}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors flex items-center gap-1.5 disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${eventsLoading ? 'animate-spin text-cyan-400' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <Card>
        <div className="flex flex-col lg:flex-row gap-4 items-stretch lg:items-center justify-between">
          {/* Search Box */}
          <div className="relative flex-1 min-w-[240px]">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search by Event ID, threat category, rule, or summary..."
              className="w-full pl-9 pr-4 py-2 bg-[#0B1020] border border-[#1E293B] rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
            />
            {searchTerm && (
              <button
                onClick={() => setSearchTerm('')}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-400 hover:text-white"
              >
                Clear
              </button>
            )}
          </div>

          {/* Filters */}
          <div className="flex flex-wrap items-center gap-2">
            {/* Severity Filter */}
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-3 py-2 bg-[#0B1020] border border-[#1E293B] rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50"
            >
              <option value="ALL">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>

            {/* Action Filter */}
            <select
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              className="px-3 py-2 bg-[#0B1020] border border-[#1E293B] rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50"
            >
              <option value="ALL">All Actions</option>
              <option value="BLOCK">BLOCK</option>
              <option value="REDACT">REDACT</option>
              <option value="ALLOW">ALLOW</option>
            </select>

            {/* Category Filter */}
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="px-3 py-2 bg-[#0B1020] border border-[#1E293B] rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50"
            >
              <option value="ALL">All Threat Types</option>
              <option value="Credential">Credentials / Keys</option>
              <option value="Injection">Prompt Injection</option>
              <option value="PII">PII / Financial</option>
              <option value="Jailbreak">Jailbreak Personas</option>
              <option value="System Prompt">System Extraction</option>
            </select>
          </div>
        </div>
      </Card>

      {/* Events Table Card */}
      <Card className="p-0 overflow-hidden">
        {eventsLoading ? (
          <TableSkeleton rows={6} cols={7} />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#0B1020] text-slate-400 font-mono uppercase text-[10px] border-b border-[#1E293B]">
                <tr>
                  <th
                    className="py-3 px-4 cursor-pointer hover:text-slate-200 select-none"
                    onClick={() => toggleSort('timestamp')}
                  >
                    <div className="flex items-center gap-1.5">
                      <span>Timestamp</span>
                      <ArrowUpDown className="w-3 h-3" />
                    </div>
                  </th>
                  <th className="py-3 px-4">Event ID</th>
                  <th className="py-3 px-4">Threat Category</th>
                  <th
                    className="py-3 px-4 cursor-pointer hover:text-slate-200 select-none"
                    onClick={() => toggleSort('severity')}
                  >
                    <div className="flex items-center gap-1.5">
                      <span>Severity</span>
                      <ArrowUpDown className="w-3 h-3" />
                    </div>
                  </th>
                  <th className="py-3 px-4">Detection Source</th>
                  <th className="py-3 px-4">Action Taken</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1E293B]/60 text-slate-300">
                {filteredEvents.length > 0 ? (
                  filteredEvents.map((evt) => (
                    <tr
                      key={evt.id}
                      onClick={() => setSelectedEvent(evt)}
                      className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                    >
                      <td className="py-3.5 px-4 font-mono text-slate-400 whitespace-nowrap">
                        {new Date(evt.timestamp).toLocaleString()}
                      </td>
                      <td className="py-3.5 px-4 font-mono font-semibold text-slate-200">{evt.id}</td>
                      <td className="py-3.5 px-4">
                        <div className="font-semibold text-slate-100">{evt.threat_category}</div>
                        <div className="text-[11px] text-slate-400 truncate max-w-xs">{evt.summary}</div>
                      </td>
                      <td className="py-3.5 px-4">
                        <Badge variant={evt.severity} size="xs">{evt.severity}</Badge>
                      </td>
                      <td className="py-3.5 px-4 font-mono text-cyan-400 text-[11px]">
                        {evt.source || 'Prompt Scanner'}
                      </td>
                      <td className="py-3.5 px-4">
                        <Badge variant={evt.action_taken} size="xs">{evt.action_taken}</Badge>
                      </td>
                      <td className="py-3.5 px-4">
                        <Badge variant={evt.status || 'mitigated'} size="xs">{evt.status || 'mitigated'}</Badge>
                      </td>
                      <td className="py-3.5 px-4 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedEvent(evt);
                          }}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs font-medium border border-slate-700 transition-colors"
                        >
                          Forensics
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={8} className="py-12 text-center text-slate-400">
                      <div className="flex flex-col items-center justify-center gap-2">
                        <ShieldAlert className="w-8 h-8 text-slate-600" />
                        <span className="text-sm font-medium text-slate-300">No matching threat incidents found</span>
                        <span className="text-xs text-slate-500">
                          Try adjusting your search query or reset your filters.
                        </span>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Forensic Detail Modal */}
      <ThreatDetailModal
        isOpen={Boolean(selectedEvent)}
        onClose={() => setSelectedEvent(null)}
        event={selectedEvent}
      />
    </div>
  );
}
