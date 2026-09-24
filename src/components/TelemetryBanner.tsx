/**
 * CyberNexsus Edge AI SOC - Snapdragon PC Edge Telemetry Banner
 */

import React from 'react';
import { Cpu, Zap, Activity, Gauge, HardDrive, CheckCircle2 } from 'lucide-react';
import { HardwareTelemetry, HardwareExecutionProvider, LocalModelInfo } from '../types';

interface TelemetryBannerProps {
  telemetry: HardwareTelemetry;
  activeModel: LocalModelInfo;
  onProviderChange: (provider: HardwareExecutionProvider) => void;
  onOpenModelManager: () => void;
}

export const TelemetryBanner: React.FC<TelemetryBannerProps> = ({
  telemetry,
  activeModel,
  onProviderChange,
  onOpenModelManager,
}) => {
  return (
    <div className="bg-[#0c1322] border-b border-slate-800/80 px-4 py-2.5">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-3 text-xs">
        
        {/* Left: Execution Provider Selector */}
        <div className="flex items-center space-x-2 w-full md:w-auto">
          <span className="text-slate-400 font-mono flex items-center gap-1.5 whitespace-nowrap">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <span className="font-semibold text-slate-200">Execution Target:</span>
          </span>
          <div className="inline-flex rounded-lg bg-slate-900/90 p-1 border border-slate-700/80">
            <button
              onClick={() => onProviderChange('NPU')}
              className={`px-3 py-1 rounded text-xs font-mono font-medium transition cursor-pointer flex items-center gap-1.5 ${
                telemetry.target === 'NPU'
                  ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-sm shadow-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Zap className="w-3 h-3 text-yellow-300" />
              <span>NPU (Hexagon 45 TOPS)</span>
              {telemetry.target === 'NPU' && <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>}
            </button>
            <button
              onClick={() => onProviderChange('GPU')}
              className={`px-3 py-1 rounded text-xs font-mono font-medium transition cursor-pointer flex items-center gap-1.5 ${
                telemetry.target === 'GPU'
                  ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <span>GPU (Adreno)</span>
            </button>
            <button
              onClick={() => onProviderChange('CPU')}
              className={`px-3 py-1 rounded text-xs font-mono font-medium transition cursor-pointer flex items-center gap-1.5 ${
                telemetry.target === 'CPU'
                  ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <span>CPU (Oryon)</span>
            </button>
          </div>
        </div>

        {/* Center/Right: Live Snapdragon Telemetry Readouts */}
        <div className="flex flex-wrap items-center gap-4 text-slate-300 font-mono w-full md:w-auto justify-end">
          <div className="flex items-center space-x-1.5 bg-slate-900/80 px-2.5 py-1 rounded border border-slate-800">
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-400">Throughput:</span>
            <span className="text-cyan-300 font-bold">{telemetry.inferenceTokPerSec} tok/s</span>
          </div>

          <div className="flex items-center space-x-1.5 bg-slate-900/80 px-2.5 py-1 rounded border border-slate-800">
            <Gauge className="w-3.5 h-3.5 text-emerald-400" />
            <span className="text-slate-400">Latency:</span>
            <span className="text-emerald-300 font-bold">{telemetry.inferenceLatencyMs} ms</span>
          </div>

          <div className="flex items-center space-x-1.5 bg-slate-900/80 px-2.5 py-1 rounded border border-slate-800">
            <Zap className="w-3.5 h-3.5 text-amber-400" />
            <span className="text-slate-400">Power:</span>
            <span className="text-amber-300 font-bold">{telemetry.powerDrawWatts} W</span>
          </div>

          <div className="flex items-center space-x-1.5 bg-slate-900/80 px-2.5 py-1 rounded border border-slate-800">
            <HardDrive className="w-3.5 h-3.5 text-indigo-400" />
            <span className="text-slate-400">VRAM:</span>
            <span className="text-indigo-300 font-bold">{(telemetry.ramUsageMB / 1024).toFixed(1)} GB / 16 GB</span>
          </div>

          <button
            onClick={onOpenModelManager}
            className="flex items-center space-x-1.5 bg-cyan-950/60 hover:bg-cyan-900/70 border border-cyan-800/80 text-cyan-300 px-2.5 py-1 rounded transition cursor-pointer"
          >
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            <span className="truncate max-w-[130px] font-semibold">{activeModel.name}</span>
          </button>
        </div>

      </div>
    </div>
  );
};
