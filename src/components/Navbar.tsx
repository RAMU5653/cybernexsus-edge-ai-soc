/**
 * CyberNexsus Edge AI SOC - Navigation & Header Component
 */

import React from 'react';
import { 
  ShieldAlert, 
  Cpu, 
  Activity, 
  Send, 
  FileText, 
  Terminal, 
  Grid, 
  Clock, 
  Sliders, 
  Database,
  DownloadCloud,
  Layers
} from 'lucide-react';
import { HardwareTelemetry, LocalModelInfo } from '../types';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  telemetry: HardwareTelemetry;
  activeModel: LocalModelInfo;
  onOpenModelManager: () => void;
  onOpenCvssCalculator: () => void;
  onOpenTelegramConfig: () => void;
  criticalAlertCount: number;
  isLiveMode: boolean;
  onToggleLiveMode: () => void;
  onResetDemoData: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  telemetry,
  activeModel,
  onOpenModelManager,
  onOpenCvssCalculator,
  onOpenTelegramConfig,
  criticalAlertCount,
  isLiveMode,
  onToggleLiveMode,
  onResetDemoData,
}) => {
  const navTabs = [
    { id: 'alerts', label: 'Alerts & Triage', icon: ShieldAlert, badge: criticalAlertCount },
    { id: 'timeline', label: 'Threat Timeline', icon: Clock },
    { id: 'mitre', label: 'MITRE ATT&CK', icon: Grid },
    { id: 'investigation', label: 'AI Investigation', icon: Terminal },
    { id: 'normalizer', label: 'Log Normalizer', icon: Layers },
    { id: 'reports', label: 'SOC Reports', icon: FileText },
  ];

  return (
    <header className="bg-[#0b111e]/95 backdrop-blur border-b border-cyan-900/40 sticky top-0 z-40">
      {/* Top status line */}
      <div className="border-b border-slate-800/80 px-4 py-1.5 flex flex-wrap items-center justify-between text-xs font-mono">
        <div className="flex items-center space-x-3">
          <span className="flex items-center space-x-1.5 text-cyan-400">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500"></span>
            </span>
            <span className="font-semibold uppercase tracking-wider">LOCAL-FIRST EDGE SOC</span>
          </span>
          <span className="text-slate-600">|</span>
          <span className="text-slate-400 flex items-center gap-1">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-300 font-semibold">Snapdragon PC</span>: Qualcomm Hexagon NPU ({telemetry.npuTopsActive} TOPS)
          </span>
          <span className="text-slate-600">|</span>
          <span className="text-emerald-400">TDP: {telemetry.powerDrawWatts}W</span>
          <span className="text-slate-600">|</span>
          <span className="text-slate-400">Zero Cloud Egress / 100% Offline Edge</span>
        </div>

        <div className="flex items-center space-x-3 mt-1 sm:mt-0">
          {/* Live vs Demo Mode Toggle */}
          <button
            onClick={onToggleLiveMode}
            className={`flex items-center space-x-1.5 px-2.5 py-0.5 rounded font-mono font-bold transition cursor-pointer border ${
              isLiveMode
                ? 'bg-emerald-950/80 border-emerald-500 text-emerald-300'
                : 'bg-amber-950/80 border-amber-600/70 text-amber-300'
            }`}
            title="Toggle between Live Real Data and Mock Demo Data"
          >
            <span className={`w-2 h-2 rounded-full ${isLiveMode ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`}></span>
            <span>{isLiveMode ? 'LIVE REAL PC MODE' : 'DEMO THREAT MODE'}</span>
          </button>

          {isLiveMode ? (
            <button
              onClick={onResetDemoData}
              className="text-[11px] text-slate-400 hover:text-cyan-300 underline cursor-pointer"
              title="Reload Seed Threat Scenarios"
            >
              Reload Demo
            </button>
          ) : (
            <button
              onClick={onToggleLiveMode}
              className="text-[11px] text-slate-400 hover:text-emerald-300 underline cursor-pointer"
              title="Purge all mock data and start live listening"
            >
              Purge Mock
            </button>
          )}
          <button
            onClick={onOpenModelManager}
            className="flex items-center space-x-1.5 px-2.5 py-0.5 rounded bg-cyan-950/80 border border-cyan-700/60 text-cyan-300 hover:bg-cyan-900/60 transition cursor-pointer"
            title="Configure Local Model & Hardware"
          >
            <DownloadCloud className="w-3.5 h-3.5" />
            <span className="font-medium truncate max-w-[140px]">{activeModel.name.split('-')[0]} ({activeModel.quantization})</span>
          </button>

          <button
            onClick={onOpenCvssCalculator}
            className="flex items-center space-x-1 px-2.5 py-0.5 rounded bg-slate-800/90 border border-slate-700 text-slate-300 hover:text-white hover:bg-slate-700/80 transition cursor-pointer"
            title="CVSS v3.1 Calculator"
          >
            <Sliders className="w-3.5 h-3.5 text-amber-400" />
            <span>CVSS v3.1</span>
          </button>

          <button
            onClick={onOpenTelegramConfig}
            className="flex items-center space-x-1 px-2.5 py-0.5 rounded bg-sky-950/60 border border-sky-700/60 text-sky-300 hover:bg-sky-900/60 transition cursor-pointer"
            title="Telegram Alert Dispatcher"
          >
            <Send className="w-3.5 h-3.5" />
            <span>Telegram</span>
          </button>
        </div>
      </div>

      {/* Main navigation toolbar */}
      <div className="px-4 py-2.5 flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2.5">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-700 p-0.5 shadow-lg shadow-cyan-500/20 flex items-center justify-center">
              <div className="w-full h-full bg-[#090e1a] rounded-[7px] flex items-center justify-center">
                <ShieldAlert className="w-5 h-5 text-cyan-400" />
              </div>
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-lg font-extrabold tracking-wider bg-gradient-to-r from-cyan-400 via-teal-300 to-blue-400 bg-clip-text text-transparent">
                  CYBERNEXSUS
                </span>
                <span className="px-1.5 py-0.2 text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 rounded">
                  EDGE AI SOC
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-mono leading-none mt-0.5">
                On-Device Security Investigation Engine
              </p>
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex items-center space-x-1 overflow-x-auto py-1">
          {navTabs.map(tab => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center space-x-2 px-3.5 py-2 rounded-lg text-xs font-medium transition cursor-pointer whitespace-nowrap ${
                  isActive
                    ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-500/10'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span>{tab.label}</span>
                {tab.badge !== undefined && tab.badge > 0 && (
                  <span className="px-1.5 py-0.2 text-[10px] font-bold rounded-full bg-red-500 text-white animate-pulse">
                    {tab.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>
    </header>
  );
};
