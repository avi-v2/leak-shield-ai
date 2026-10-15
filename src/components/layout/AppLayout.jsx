import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Navbar } from './Navbar';
import { ToastContainer } from '../common/Toast';
import { useGateway } from '../../context/GatewayContext';
import { AlertCircle, ExternalLink } from 'lucide-react';
import { Link } from 'react-router-dom';

export function AppLayout() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const { connectionStatus, isUsingSimulatedData, backendUrl } = useGateway();

  return (
    <div className="min-h-screen bg-[#0B1020] text-slate-100 flex flex-col">
      {/* Toast Notifications */}
      <ToastContainer />

      {/* Sidebar Navigation */}
      <Sidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      {/* Main Content Area */}
      <div className="lg:pl-64 flex flex-col flex-1">
        <Navbar onMenuClick={() => setSidebarOpen(true)} />

        {/* Global Connection Warning Banner when Backend is Offline */}
        {connectionStatus === 'offline' && (
          <div className="bg-rose-950/40 border-b border-rose-800/40 px-4 py-2.5 sm:px-6 flex items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-2 text-rose-300">
              <AlertCircle className="w-4 h-4 text-rose-400 flex-shrink-0" />
              <span>
                <strong>Gateway Backend Disconnected:</strong> Cannot reach{' '}
                <code className="font-mono bg-rose-950 px-1 py-0.5 rounded text-rose-200">{backendUrl}</code>.{' '}
                Operating in simulated demo mode. Start your FastAPI server or test in Settings.
              </span>
            </div>
            <Link
              to="/settings"
              className="text-cyan-400 hover:text-cyan-300 underline font-medium flex items-center gap-1 flex-shrink-0"
            >
              Configure Connection
            </Link>
          </div>
        )}

        {/* Router Outlet for Pages */}
        <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-7xl w-full mx-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
