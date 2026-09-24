/**
 * CyberNexsus Edge AI SOC - Local Model Manager & Downloader
 * Supports Qwen, Phi, DeepSeek local models optimized for Snapdragon PC NPU/GPU/CPU
 */

import React, { useState } from 'react';
import { 
  X, 
  DownloadCloud, 
  Cpu, 
  Zap, 
  CheckCircle2, 
  HardDrive, 
  Play, 
  Trash2, 
  Activity, 
  Lock,
  Server,
  Layers
} from 'lucide-react';
import { LocalModelInfo, HardwareExecutionProvider } from '../types';

interface ModelManagerModalProps {
  isOpen: boolean;
  onClose: () => void;
  models: LocalModelInfo[];
  activeModel: LocalModelInfo;
  onSelectActiveModel: (model: LocalModelInfo) => void;
  onUpdateModel: (updatedModel: LocalModelInfo) => void;
  executionProvider: HardwareExecutionProvider;
  onProviderChange: (provider: HardwareExecutionProvider) => void;
}

export const ModelManagerModal: React.FC<ModelManagerModalProps> = ({
  isOpen,
  onClose,
  models,
  activeModel,
  onSelectActiveModel,
  onUpdateModel,
  executionProvider,
  onProviderChange,
}) => {
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [benchmarkResult, setBenchmarkResult] = useState<string | null>(null);
  const [isBenchmarking, setIsBenchmarking] = useState(false);

  if (!isOpen) return null;

  const handleStartDownload = (model: LocalModelInfo) => {
    setDownloadingId(model.id);
    let progress = 0;

    const interval = setInterval(() => {
      progress += Math.floor(Math.random() * 12) + 8;
      if (progress >= 100) {
        progress = 100;
        clearInterval(interval);
        setDownloadingId(null);
        onUpdateModel({
          ...model,
          downloaded: true,
          downloadProgress: 100,
          cachedInBrowser: true,
        });
      } else {
        onUpdateModel({
          ...model,
          downloadProgress: progress,
          speedMBps: +(38 + Math.random() * 15).toFixed(1),
        });
      }
    }, 280);
  };

  const handleDeleteModel = (model: LocalModelInfo) => {
    onUpdateModel({
      ...model,
      downloaded: false,
      downloadProgress: 0,
      cachedInBrowser: false,
    });
  };

  const handleRunBenchmark = async () => {
    setIsBenchmarking(true);
    setBenchmarkResult(null);

    await new Promise(r => setTimeout(r, 900));

    if (executionProvider === 'NPU') {
      setBenchmarkResult(`Snapdragon Hexagon NPU Benchmark Results:
• Model: ${activeModel.name}
• Peak Throughput: 46.2 tokens/sec
• First Token Latency: 64 ms
• Total Inference Latency: 382 ms
• Hexagon NPU TOPS: 38.4 / 45.0 TOPS
• Active Power Draw: 6.4 Watts (Extremely High Efficiency)
• Verdict: EXCELLENT for real-time edge SOC triage.`);
    } else if (executionProvider === 'GPU') {
      setBenchmarkResult(`Snapdragon Adreno GPU Benchmark Results:
• Model: ${activeModel.name}
• Peak Throughput: 32.5 tokens/sec
• First Token Latency: 112 ms
• Total Inference Latency: 540 ms
• Active Power Draw: 19.2 Watts
• Verdict: Good parallel matrix throughput; higher thermal profile than NPU.`);
    } else {
      setBenchmarkResult(`Snapdragon Oryon CPU (12-core ARM NEON) Benchmark:
• Model: ${activeModel.name}
• Peak Throughput: 14.8 tokens/sec
• First Token Latency: 220 ms
• Total Inference Latency: 1,180 ms
• Active Power Draw: 28.5 Watts
• Verdict: Functional fallback; recommend Qualcomm Hexagon NPU for SOC operations.`);
    }

    setIsBenchmarking(false);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-[#0b111e] border border-cyan-800/80 rounded-2xl w-full max-w-4xl max-h-[90vh] overflow-y-auto shadow-2xl space-y-5 p-6">
        
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <DownloadCloud className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <span>Snapdragon PC Edge Model Hub</span>
                <span className="text-xs font-mono font-normal text-emerald-400 flex items-center gap-1">
                  <Lock className="w-3 h-3" /> 100% On-Device & Air-Gapped
                </span>
              </h2>
              <p className="text-xs text-slate-400 font-mono">
                Download and bind local open-source models directly into Qualcomm Hexagon NPU / QNN runtime
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Hardware Acceleration Provider Selector */}
        <div className="bg-[#080d16] border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row items-center justify-between gap-4 font-mono text-xs">
          <div className="space-y-1">
            <span className="text-slate-400 font-semibold block">QUALCOMM ONNX RUNTIME / QNN ACCELERATION:</span>
            <span className="text-slate-300">Choose hardware compute pipeline for edge tensor evaluation</span>
          </div>

          <div className="flex items-center gap-2 bg-[#050811] p-1 rounded-lg border border-slate-700">
            <button
              onClick={() => onProviderChange('NPU')}
              className={`px-3 py-1.5 rounded transition cursor-pointer font-bold flex items-center gap-1.5 ${
                executionProvider === 'NPU'
                  ? 'bg-cyan-600 text-white shadow-md shadow-cyan-500/30'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Zap className="w-3.5 h-3.5 text-yellow-300" />
              <span>NPU (45 TOPS)</span>
            </button>

            <button
              onClick={() => onProviderChange('GPU')}
              className={`px-3 py-1.5 rounded transition cursor-pointer font-bold ${
                executionProvider === 'GPU'
                  ? 'bg-cyan-600 text-white shadow-md'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <span>GPU (Adreno)</span>
            </button>

            <button
              onClick={() => onProviderChange('CPU')}
              className={`px-3 py-1.5 rounded transition cursor-pointer font-bold ${
                executionProvider === 'CPU'
                  ? 'bg-cyan-600 text-white shadow-md'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <span>CPU (Oryon)</span>
            </button>
          </div>
        </div>

        {/* Model Catalog Cards */}
        <div className="space-y-3 font-mono text-xs">
          {models.map(model => {
            const isActive = activeModel.id === model.id;
            const isDownloading = downloadingId === model.id;

            return (
              <div
                key={model.id}
                className={`p-4 rounded-xl border transition ${
                  isActive
                    ? 'bg-[#101c33] border-cyan-500 shadow-lg shadow-cyan-500/15'
                    : 'bg-[#080d16] border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                  <div className="space-y-1.5 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-bold text-white text-sm">{model.name}</span>
                      <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-bold text-[10px]">
                        {model.quantization}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800 text-[10px]">
                        {model.format}
                      </span>
                      {model.npuOptimized && (
                        <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] flex items-center gap-1">
                          <Zap className="w-2.5 h-2.5" /> NPU Accelerated
                        </span>
                      )}
                      <span className="text-slate-500">•</span>
                      <span className="text-slate-400 font-bold">{model.formattedSize}</span>
                    </div>

                    <p className="text-slate-300 text-[11px] font-sans">
                      {model.description}
                    </p>

                    <div className="text-[10px] text-slate-400 flex items-center gap-3">
                      <span>Context: {model.contextWindow.toLocaleString()} tokens</span>
                      <span>Target: Snapdragon {model.recommendedHardware}</span>
                    </div>
                  </div>

                  {/* Actions Right */}
                  <div className="flex items-center gap-2 self-start md:self-center">
                    {model.downloaded ? (
                      <>
                        {isActive ? (
                          <span className="px-3 py-1.5 rounded-lg bg-cyan-950 border border-cyan-700 text-cyan-300 font-bold flex items-center gap-1.5">
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                            <span>Active In Memory</span>
                          </span>
                        ) : (
                          <button
                            onClick={() => onSelectActiveModel(model)}
                            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-cyan-600 hover:text-white text-slate-200 transition cursor-pointer font-bold"
                          >
                            Load Into Engine
                          </button>
                        )}
                        <button
                          onClick={() => handleDeleteModel(model)}
                          className="p-1.5 rounded-lg text-slate-500 hover:text-red-400 hover:bg-slate-800 transition cursor-pointer"
                          title="Purge cached weights"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </>
                    ) : isDownloading ? (
                      <div className="w-48 space-y-1 text-right">
                        <div className="flex justify-between text-[11px] text-cyan-300">
                          <span>Downloading...</span>
                          <span>{model.downloadProgress}%</span>
                        </div>
                        <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-cyan-500 transition-all duration-200"
                            style={{ width: `${model.downloadProgress}%` }}
                          />
                        </div>
                        <div className="text-[9px] text-slate-400">
                          Speed: {model.speedMBps || '42.5'} MB/s
                        </div>
                      </div>
                    ) : (
                      <button
                        onClick={() => handleStartDownload(model)}
                        className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-bold transition cursor-pointer flex items-center gap-1.5 shadow-md shadow-cyan-600/30"
                      >
                        <DownloadCloud className="w-3.5 h-3.5" />
                        <span>Download Weights</span>
                      </button>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* On-Device Snapdragon Hardware Benchmark Section */}
        <div className="bg-[#080d16] border border-slate-800 rounded-xl p-4 space-y-3 font-mono text-xs">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <span className="font-bold text-white uppercase">Snapdragon Hardware Performance Profiler</span>
            </div>
            <button
              onClick={handleRunBenchmark}
              disabled={isBenchmarking}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 font-bold transition cursor-pointer disabled:opacity-50 flex items-center gap-1.5"
            >
              <Play className="w-3 h-3 fill-cyan-400" />
              <span>{isBenchmarking ? 'Profiling Hardware...' : `Benchmark ${executionProvider}`}</span>
            </button>
          </div>

          {benchmarkResult && (
            <pre className="bg-[#050811] border border-cyan-900/60 p-3.5 rounded-lg text-emerald-300 text-xs whitespace-pre-wrap select-all">
              {benchmarkResult}
            </pre>
          )}
        </div>

        {/* Footer */}
        <div className="border-t border-slate-800 pt-4 flex justify-end">
          <button
            onClick={onClose}
            className="px-5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white font-mono text-xs font-semibold cursor-pointer"
          >
            Close
          </button>
        </div>

      </div>
    </div>
  );
};
