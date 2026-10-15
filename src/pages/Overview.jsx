/**
 * Security Overview Page — Sentinel AI / Leak-Shield-AI
 *
 * Primary landing page presenting the AI Security Operations Center (SOC) Dashboard:
 * - 8 Real-time KPI Cards (Scans, Threats, Blocked, Redacted, Rates, PII, Injections)
 * - Interactive time-series telemetry (1h, 24h, 7d, 30d, All Time)
 * - Threat category distribution & prompt injection intelligence
 * - DLP analytics, policy verdicts, file/image telemetry
 * - Live filterable security event audit log
 */

import React from 'react';
import { Dashboard } from './Dashboard';

export function Overview() {
  return <Dashboard />;
}

export default Overview;
