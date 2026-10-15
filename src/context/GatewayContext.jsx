import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { checkHealth, getEvents, clearEvents as apiClearEvents, getApiBaseUrl, setApiBaseUrl } from '../services/api';
import { MOCK_SECURITY_EVENTS } from '../services/mockData';

const GatewayContext = createContext(null);

export const DEFAULT_POLICIES = {
  detectApiKeys: true,
  detectCreditCards: true,
  detectSsn: true,
  detectEmails: true,
  detectPasswords: true,
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
  const [isUsingSimulatedData, setIsUsingSimulatedData] = useState(false);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [toasts, setToasts] = useState([]);

  // Local policies state
  const [policies, setPolicies] = useState(() => {
    try {
      const saved = localStorage.getItem('sentinel_local_policies');
      return saved ? JSON.parse(saved) : DEFAULT_POLICIES;
    } catch {
      return DEFAULT_POLICIES;
    }
  });
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

  // Fetch security events
  const loadEvents = useCallback(async () => {
    setEventsLoading(true);
    try {
      const res = await getEvents();
      if (res.success && Array.isArray(res.data)) {
        setEvents(res.data);
        setIsUsingSimulatedData(false);
      } else {
        // Empty or non-array, fall back
        setEvents(MOCK_SECURITY_EVENTS);
        setIsUsingSimulatedData(true);
      }
    } catch (err) {
      // Backend not connected or error, use realistic mock data
      setEvents(MOCK_SECURITY_EVENTS);
      setIsUsingSimulatedData(true);
    } finally {
      setEventsLoading(false);
    }
  }, []);

  // Clear events
  const clearAllEvents = useCallback(async () => {
    try {
      if (connectionStatus === 'connected') {
        await apiClearEvents();
        setEvents([]);
        addToast({
          title: 'Audit Logs Cleared',
          message: 'All security event logs removed from backend gateway.',
          type: 'success',
        });
      } else {
        setEvents([]);
        setIsUsingSimulatedData(false);
        addToast({
          title: 'Demo Logs Cleared',
          message: 'Cleared local simulated events cache.',
          type: 'info',
        });
      }
      return true;
    } catch (err) {
      addToast({
        title: 'Error Clearing Logs',
        message: err.message || 'Failed to clear events.',
        type: 'error',
      });
      return false;
    }
  }, [connectionStatus, addToast]);

  // Update backend URL
  const updateBackendUrl = useCallback((newUrl) => {
    setApiBaseUrl(newUrl);
    setBackendUrl(getApiBaseUrl());
    pingBackend();
  }, [pingBackend]);

  // Update policy draft
  const updatePolicy = useCallback((key, value) => {
    setPolicies((prev) => {
      const next = { ...prev, [key]: value };
      setHasUnsavedPolicyChanges(true);
      return next;
    });
  }, []);

  // Save policy draft to localStorage
  const savePolicies = useCallback(() => {
    try {
      localStorage.setItem('sentinel_local_policies', JSON.stringify(policies));
      setHasUnsavedPolicyChanges(false);
      addToast({
        title: 'Policies Saved Locally',
        message: 'Saved configuration in browser state (Note: Server rules take final precedence).',
        type: 'success',
      });
    } catch {
      addToast({
        title: 'Error Saving Policies',
        message: 'Could not write to browser storage.',
        type: 'error',
      });
    }
  }, [policies, addToast]);

  // Reset policies to default
  const resetPolicies = useCallback(() => {
    setPolicies(DEFAULT_POLICIES);
    localStorage.removeItem('sentinel_local_policies');
    setHasUnsavedPolicyChanges(false);
    addToast({
      title: 'Policies Reset',
      message: 'Restored default Sentinel security thresholds.',
      type: 'info',
    });
  }, [addToast]);

  // Initial load
  useEffect(() => {
    pingBackend().then(() => {
      loadEvents();
    });

    const interval = setInterval(() => {
      pingBackend(true);
    }, 15000); // Poll health every 15s

    return () => clearInterval(interval);
  }, [pingBackend, loadEvents]);

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
    clearAllEvents,
    isUsingSimulatedData,
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
