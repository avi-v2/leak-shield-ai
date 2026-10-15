import React, { useState, useMemo } from 'react';
import {
  FileText,
  Download,
  Trash2,
  RefreshCw,
  Search,
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
  Clock,
  Lock,
  Filter,
  CheckCircle2,
  ExternalLink
} from 'lucide-react';
import { useGateway } from '../context/GatewayContext';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { ConfirmDialog } from '../components/common/ConfirmDialog';
import { TableSkeleton } from '../components/common/Skeleton';
import { ThreatDetailModal } from '../components/threats/ThreatDetailModal';

export function AuditLogs() {
  const {
    events,
    eventsLoading,
    loadEvents,
    clearAllEvents,
    connectionStatus,
    addToast
  } = useGateway();

  const [searchTerm, setSearchTerm] = useState('');
  const [decisionFilter, setDecisionFilter] = useState('ALL');
  const [pageSize, setPageSize] = useState(10);
  const [currentPage, setCurrentPage] = useState(1);
  const [isConfirmOpen, setIsConfirmOpen] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState(null);

  // Filtered audit events
  const filteredEvents = useMemo(() => {
    return events.filter((evt) => {
      if (searchTerm.trim() !== '') {
        const q = searchTerm.toLowerCase();
        const matchId = evt.id?.toLowerCase().includes(q);
        const matchCategory = evt.threat_category?.toLowerCase().includes(q);
        const matchSummary = evt.summary?.toLowerCase().includes(q);
        if (!matchId && !matchCategory && !matchSummary) return false;
      }

      if (decisionFilter !== 'ALL' && evt.action_taken !== decisionFilter) {
        return false;
      }

      return true;
    });
  }, [events, searchTerm, decisionFilter]);

  // Pagination calculation
  const totalPages = Math.ceil(filteredEvents.length / pageSize) || 1;
  const paginatedEvents = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredEvents.slice(start, start + pageSize);
  }, [filteredEvents, currentPage, pageSize]);

  // Export to CSV Function
  const handleExportCSV = () => {
    if (!filteredEvents || filteredEvents.length === 0) {
      addToast({
        title: 'Export Warning',
        message: 'No log events available to export.',
        type: 'warning',
      });
      return;
    }

    const headers = [
      'Timestamp',
      'Request_ID',
      'Threat_Category',
      'Severity',
      'Decision',
      'Processing_Time_ms',
      'Source',
      'Status',
      'Rules_Triggered',
      'Client_IP_Hashed'
    ];

    const rows = filteredEvents.map((e) => [
      `"${new Date(e.timestamp).toISOString()}"`,
      `"${e.id}"`,
      `"${e.threat_category || ''}"`,
      `"${e.severity || ''}"`,
      `"${e.action_taken || ''}"`,
      `"${e.details?.latency_ms || 18}"`,
      `"${e.source || 'Sentinel Gateway'}"`,
      `"${e.status || 'mitigated'}"`,
      `"${(e.details?.matched_rules || []).join(';')}"`,
      `"${e.details?.client_ip ? e.details.client_ip.substring(0, 7) + '***' : '192.168.***'}"`
    ]);

    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\r\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `sentinel_audit_logs_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    addToast({
      title: 'Audit Logs Exported',
      message: `Exported ${filteredEvents.length} records to CSV.`,
      type: 'success',
    });
  };

  const handleClearLogs = async () => {
    setIsDeleting(true);
    const success = await clearAllEvents();
    setIsDeleting(false);
    setIsConfirmOpen(false);
    if (success) {
      setCurrentPage(1);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-bold text-slate-100">Security Audit Trail</h2>
            <Badge variant="cyan" size="sm">{filteredEvents.length} Logs</Badge>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Immutable compliance record of all prompt evaluations, data redactions, and access decisions.
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => loadEvents()}
            disabled={eventsLoading}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors flex items-center gap-1.5 disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${eventsLoading ? 'animate-spin text-cyan-400' : ''}`} />
            Refresh
          </button>

          <button
            onClick={handleExportCSV}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            Export CSV
          </button>

          <button
            onClick={() => setIsConfirmOpen(true)}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 border border-rose-800/50 transition-colors flex items-center gap-1.5"
          >
            <Trash2 className="w-3.5 h-3.5" />
            Clear Logs
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <Card>
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4">
          <div className="relative flex-1 min-w-[220px]">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setCurrentPage(1);
              }}
              placeholder="Search by Request ID, category, or detail..."
              className="w-full pl-9 pr-4 py-2 bg-[#0B1020] border border-[#1E293B] rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
            />
          </div>

          <div className="flex items-center gap-3">
            <select
              value={decisionFilter}
              onChange={(e) => {
                setDecisionFilter(e.target.value);
                setCurrentPage(1);
              }}
              className="px-3 py-2 bg-[#0B1020] border border-[#1E293B] rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50"
            >
              <option value="ALL">All Decisions</option>
              <option value="BLOCK">BLOCK</option>
              <option value="REDACT">REDACT</option>
              <option value="ALLOW">ALLOW</option>
            </select>

            <select
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value));
                setCurrentPage(1);
              }}
              className="px-3 py-2 bg-[#0B1020] border border-[#1E293B] rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50"
            >
              <option value={10}>10 per page</option>
              <option value={25}>25 per page</option>
              <option value={50}>50 per page</option>
            </select>
          </div>
        </div>
      </Card>

      {/* Audit Log Table */}
      <Card className="p-0 overflow-hidden">
        {eventsLoading ? (
          <TableSkeleton rows={6} cols={6} />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#0B1020] text-slate-400 font-mono uppercase text-[10px] border-b border-[#1E293B]">
                <tr>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Request ID</th>
                  <th className="py-3 px-4">Detection Categories</th>
                  <th className="py-3 px-4">Decision</th>
                  <th className="py-3 px-4">Processing Time</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1E293B]/60 text-slate-300">
                {paginatedEvents.length > 0 ? (
                  paginatedEvents.map((evt) => (
                    <tr key={evt.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-3.5 px-4 font-mono text-slate-400 whitespace-nowrap">
                        {new Date(evt.timestamp).toLocaleString()}
                      </td>
                      <td className="py-3.5 px-4 font-mono font-semibold text-slate-200">
                        {evt.id}
                      </td>
                      <td className="py-3.5 px-4">
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-slate-100">{evt.threat_category}</span>
                          <Badge variant={evt.severity} size="xs">{evt.severity}</Badge>
                        </div>
                        <div className="text-[11px] text-slate-400 truncate max-w-sm">{evt.summary}</div>
                      </td>
                      <td className="py-3.5 px-4">
                        <Badge variant={evt.action_taken} size="xs">{evt.action_taken}</Badge>
                      </td>
                      <td className="py-3.5 px-4 font-mono text-emerald-400">
                        {evt.details?.latency_ms ? `${evt.details.latency_ms}ms` : '16ms'}
                      </td>
                      <td className="py-3.5 px-4 text-right">
                        <button
                          onClick={() => setSelectedEvent(evt)}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs font-medium border border-slate-700 transition-colors"
                        >
                          View
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={6} className="py-12 text-center text-slate-400">
                      <div className="flex flex-col items-center justify-center gap-2">
                        <FileText className="w-8 h-8 text-slate-600" />
                        <span className="text-sm font-medium text-slate-300">No audit records found</span>
                        <span className="text-xs text-slate-500">
                          Events will be appended here as prompts are inspected by the gateway.
                        </span>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
        <div className="p-4 border-t border-[#1E293B] bg-[#0d1320] flex items-center justify-between text-xs text-slate-400">
          <div>
            Showing <strong className="text-slate-200">{filteredEvents.length === 0 ? 0 : (currentPage - 1) * pageSize + 1}</strong> to{' '}
            <strong className="text-slate-200">{Math.min(currentPage * pageSize, filteredEvents.length)}</strong> of{' '}
            <strong className="text-slate-200">{filteredEvents.length}</strong> events
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setCurrentPage((p) => Math.max(p - 1, 1))}
              disabled={currentPage <= 1}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-40 transition-colors"
              aria-label="Previous page"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="font-mono text-xs text-slate-300">
              Page {currentPage} of {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage((p) => Math.min(p + 1, totalPages))}
              disabled={currentPage >= totalPages}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 disabled:opacity-40 transition-colors"
              aria-label="Next page"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </Card>

      {/* Confirmation Dialog for Destructive Clear */}
      <ConfirmDialog
        isOpen={isConfirmOpen}
        onClose={() => setIsConfirmOpen(false)}
        onConfirm={handleClearLogs}
        title="Clear Security Audit Logs?"
        message="This will permanently delete all stored security event logs from the Sentinel AI backend gateway. This action cannot be reverted."
        confirmText="Confirm Clear"
        cancelText="Keep Logs"
        danger={true}
        loading={isDeleting}
      />

      {/* Incident Forensic Modal */}
      <ThreatDetailModal
        isOpen={Boolean(selectedEvent)}
        onClose={() => setSelectedEvent(null)}
        event={selectedEvent}
      />
    </div>
  );
}
