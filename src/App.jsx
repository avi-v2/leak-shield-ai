import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { GatewayProvider } from './context/GatewayContext';
import { AppLayout } from './components/layout/AppLayout';

import { Overview } from './pages/Overview';
import { Dashboard } from './pages/Dashboard';
import { ThreatMonitor } from './pages/ThreatMonitor';
import { PromptScanner } from './pages/PromptScanner';
import { Playground } from './pages/Playground';
import { Policies } from './pages/Policies';
import { AuditLogs } from './pages/AuditLogs';
import { Settings } from './pages/Settings';

export default function App() {
  return (
    <GatewayProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<AppLayout />}>
            <Route index element={<Overview />} />
            <Route path="dashboard" element={<Dashboard />} />
            <Route path="threats" element={<ThreatMonitor />} />
            <Route path="scanner" element={<PromptScanner />} />
            <Route path="playground" element={<Playground />} />
            <Route path="policies" element={<Policies />} />
            <Route path="audit" element={<AuditLogs />} />
            <Route path="settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </GatewayProvider>
  );
}
