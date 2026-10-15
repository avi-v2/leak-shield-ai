import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import {
  checkHealth,
  getEvents,
  clearEvents as apiClearEvents,
  getPolicies,
  updatePolicies as apiUpdatePolicies,
  getMetrics,
  getApiBaseUrl,
  setApiBaseUrl
} from '../services/api';

const GatewayContext = createContext(null);

export const DEFAULT_POLICIES = {
  detectApiKeys: true,
  detectCreditCards: true,
  detectSsn: true,
  detectEmails: true,
  detectPasswords: true,
  detectAadhaar: true,
  detectPan: true,
  detectPhone: true,
  blockPromptInjection: true,
  blockJailbreaks: true,
  blockSystemPromptExtraction: true,
  inspectModelOutputs: true,
  defaultAction: 'REDACT', // 'ALLOW' | 'REDACT' | 'BLOCK'
  highRiskThreshold: 'high', // 'medium' | 'high' | 'critical'
};

export function GatewayProvider({ children }) {
  const [backendUrl, setBackendUrlState] = useState(getApiBaseUrl());
  const [connectionStatus, setConnectionStatus] = useState('checking'); // 'connected' | 'offline' | 'checking'
  const [latency, setLatency] = useState(null);
  const [backendData, setBackendData] = useState(null);
  const [events, setEvents] = useState([]);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [metrics, setMetrics] = useState({
    total_requests: 0,
    allowed_requests: 0,
    blocked_requests: 0,
    redacted_requests: 0,
    sensitive_data_detections: 0,
    injection_detections: 0,
    traffic_over_time: [],
    threat_distribution: []
  });
  const [metricsLoading, setMetricsLoading] = useState(false);
  const [toasts, setToasts] = useState([]);

  // Server-synchronized policies state
  const [policies, setPolicies] = useState(DEFAULT_POLICIES);
  const [hasUnsavedPolicyChanges, setHasUnsavedPolicyChanges] = useState(false);

  // Toast dispatcher
  const addToast = useCallback((toast) => {
    const id = Date.now() + Math.random().toString(36).substring(2, 6);
    const newToast = { id, type: 'info', duration: 4000, ...toast };
    setToasts((prev) => [...prev, newToast]);

    if (newToast.duration > 0) {
      setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== id));
      }, newToast.duration);
    }
    return id;
  }, []);

  const removeToast = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  // Backend Health Ping
  const pingBackend = useCallback(async (quiet = false) => {
    if (!quiet) setConnectionStatus('checking');
    try {
      const result = await checkHealth();
      if (result.connected) {
        setConnectionStatus('connected');
        setLatency(result.latency);
        setBackendData(result.data);
        return true;
      } else {
        setConnectionStatus('offline');
        setLatency(null);
        return false;
      }
    } catch (err) {
      setConnectionStatus('offline');
      setLatency(null);
      return false;
    }
  }, []);

  // Fetch security events from real SQLite database
  const loadEvents = useCallback(async () => {
    setEventsLoading(true);
    try {
      const res = await getEvents();
      if (res.success && Array.isArray(res.data)) {
        setEvents(res.data);
      } else {
        setEvents([]);
      }
    } catch (err) {
      // Backend not connected or error, honest empty state
      setEvents([]);
    } finally {
      setEventsLoading(false);
    }
  }, []);

  // Fetch real operational metrics from backend
  const loadMetrics = useCallback(async () => {
    setMetricsLoading(true);
    try {
      const res = await getMetrics();
      if (res.success && res.data) {
        setMetrics(res.data);
      }
    } catch (err) {
      // Keep real zero state
    } finally {
      setMetricsLoading(false);
    }
  }, []);

  // Fetch server policies
  const loadServerPolicies = useCallback(async () => {
    try {
      const res = await getPolicies();
      if (res.success && res.data) {
        setPolicies(res.data);
        setHasUnsavedPolicyChanges(false);
      }
    } catch (err) {
      // Retain defaults if offline
    }
  }, []);

  // Clear events via DELETE /events
  const clearAllEvents = useCallback(async () => {
    try {
      if (connectionStatus === 'connected') {
        const res = await apiClearEvents();
        setEvents([]);
        loadMetrics();
        addToast({
          title: 'Audit Logs Cleared',
          message: res.data?.message || 'All security event logs removed from backend gateway.',
          type: 'success',
        });
        return true;
      } else {
        addToast({
          title: 'Gateway Offline',
          message: 'Cannot clear logs while gateway is offline.',
          type: 'error',
        });
        return false;
      }
    } catch (err) {
      addToast({
        title: 'Error Clearing Logs',
        message: err.message || 'Failed to clear events.',
        type: 'error',
      });
      return false;
    }
  }, [connectionStatus, addToast, loadMetrics]);

  // Update backend URL
  const updateBackendUrl = useCallback((newUrl) => {
    setApiBaseUrl(newUrl);
    setBackendUrlState(getApiBaseUrl());
    pingBackend();
  }, [pingBackend]);

  // Update local policy draft
  const updatePolicy = useCallback((key, value) => {
    setPolicies((prev) => {
      const next = { ...prev, [key]: value };
      setHasUnsavedPolicyChanges(true);
      return next;
    });
  }, []);

  // Save policies to backend
  const savePolicies = useCallback(async () => {
    try {
      const res = await apiUpdatePolicies(policies);
      if (res.success && res.data) {
        setPolicies(res.data);
        setHasUnsavedPolicyChanges(false);
        addToast({
          title: 'Policies Enforced on Server',
          message: 'Security policy successfully persisted to SQLite on the gateway backend.',
          type: 'success',
        });
      }
    } catch (err) {
      addToast({
        title: 'Policy Save Error',
        message: err.message || 'Could not persist policies to gateway backend.',
        type: 'error',
      });
    }
  }, [policies, addToast]);

  // Reset policies to default
  const resetPolicies = useCallback(async () => {
    try {
      const res = await apiUpdatePolicies(DEFAULT_POLICIES);
      if (res.success && res.data) {
        setPolicies(res.data);
        setHasUnsavedPolicyChanges(false);
        addToast({
          title: 'Policies Reset',
          message: 'Restored default Sentinel security thresholds on the server.',
          type: 'info',
        });
      }
    } catch (err) {
      setPolicies(DEFAULT_POLICIES);
      setHasUnsavedPolicyChanges(false);
    }
  }, [addToast]);

  // Initial load
  useEffect(() => {
    pingBackend().then((connected) => {
      if (connected) {
        loadEvents();
        loadMetrics();
        loadServerPolicies();
      }
    });

    const interval = setInterval(() => {
      pingBackend(true);
    }, 15000); // Poll health every 15s

    return () => clearInterval(interval);
  }, [pingBackend, loadEvents, loadMetrics, loadServerPolicies]);

  const value = {
    backendUrl,
    updateBackendUrl,
    connectionStatus,
    latency,
    backendData,
    pingBackend,
    events,
    eventsLoading,
    loadEvents,
    metrics,
    metricsLoading,
    loadMetrics,
    clearAllEvents,
    toasts,
    addToast,
    removeToast,
    policies,
    updatePolicy,
    savePolicies,
    resetPolicies,
    hasUnsavedPolicyChanges,
  };

  return (
    <GatewayContext.Provider value={value}>
      {children}
    </GatewayContext.Provider>
  );
}

export function useGateway() {
  const context = useContext(GatewayContext);
  if (!context) {
    throw new Error('useGateway must be used within a GatewayProvider');
  }
  return context;
}
