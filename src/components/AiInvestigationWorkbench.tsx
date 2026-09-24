/**
 * CyberNexsus Edge AI SOC - AI Investigation Workbench
 * Local-First AI Security Investigation powered by Snapdragon PC NPU/GPU/CPU
 */

import React, { useState } from 'react';
import { 
  Terminal, 
  Cpu, 
  Zap, 
  Sparkles, 
  ShieldCheck, 
  AlertTriangle, 
  CheckCircle2, 
  Layers, 
  Activity, 
  Copy, 
  Send, 
  FileText, 
  ArrowRight,
  Database,
  Search,
  Lock,
  Flame
} from 'lucide-react';
import { 
  SecurityAlert, 
  LocalModelInfo, 
  HardwareExecutionProvider, 
  HardwareTelemetry,
  AiInvestigationResult 
} from '../types';
import { LocalAiEngine } from '../services/localAiEngine';

interface AiInvestigationWorkbenchProps {
  alerts: SecurityAlert[];
  selectedAlert: SecurityAlert | null;
  onSelectAlert: (alert: SecurityAlert) => void;
  activeModel: LocalModelInfo;
  models: LocalModelInfo[];
  onSelectModel: (model: LocalModelInfo) => void;
  telemetry: HardwareTelemetry;
  executionProvider: HardwareExecutionProvider;
  onProviderChange: (provider: HardwareExecutionProvider) => void;
  onSaveInvestigationResult: (alertId: string, result: AiInvestigationResult) => void;
  onGenerateReport: (alert: SecurityAlert) => void;
}

export const AiInvestigationWorkbench: React.FC<AiInvestigationWorkbenchProps> = ({
  alerts,
  selectedAlert,
  onSelectAlert,
  activeModel,
  models,
  onSelectModel,
  telemetry,
  executionProvider,
  onProviderChange,
  onSaveInvestigationResult,
  onGenerateReport,
}) => {
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisStage, setAnalysisStage] = useState('');
  const [analysisProgress, setAnalysisProgress] = useState(0);
  const [activeTab, setActiveTab] = useState<'hypothesis' | 'iocs' | 'correlation' | 'mitre' | 'explanation' | 'recommendations' | 'chat'>('hypothesis');
  
  // Interactive Chat State
  const [chatMessages, setChatMessages] = useState<Array<{ sender: 'user' | 'ai'; text: string; time: string }>>([
    {
      sender: 'ai',
      text: `CyberNexsus Edge AI copilot initialized on Qualcomm Hexagon NPU. Model: ${activeModel.name}. Ask me for containment commands, YARA rules, or killchain clarification.`,
      time: new Date().toLocaleTimeString(),
    }
  ]);
  const [chatInput, setChatInput] = useState('');
  const [isChatThinking, setIsChatThinking] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

  const currentAlert = selectedAlert || alerts[0];
  const investigation = currentAlert?.investigationResult;

  const handleRunInvestigation = async () => {
    if (!currentAlert) return;
    setIsAnalyzing(true);
    setAnalysisProgress(5);
    setAnalysisStage('Loading model weights into Snapdragon memory...');

    try {
      const result = await LocalAiEngine.runInvestigation(
        currentAlert,
        activeModel,
        executionProvider,
        (stage, prog) => {
          setAnalysisStage(stage);
          setAnalysisProgress(prog);
        }
      );
      onSaveInvestigationResult(currentAlert.id, result);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleSendChat = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!chatInput.trim() || isChatThinking) return;

    const userText = chatInput.trim();
    setChatInput('');
    const now = new Date().toLocaleTimeString();

    setChatMessages(prev => [...prev, { sender: 'user', text: userText, time: now }]);
    setIsChatThinking(true);

    try {
      const aiReply = await LocalAiEngine.queryAnalystAssistant(
        userText,
        currentAlert,
        activeModel,
        executionProvider
      );
      setChatMessages(prev => [...prev, { sender: 'ai', text: aiReply, time: new Date().toLocaleTimeString() }]);
    } finally {
      setIsChatThinking(false);
    }
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(id);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Top Banner: Local Edge Architecture HUD */}
      <div className="bg-gradient-to-r from-[#0c1626] via-[#09101d] to-[#070b14] border border-cyan-800/60 rounded-xl p-5 shadow-xl relative overflow-hidden">
        <div className="absolute right-0 top-0 w-96 h-full pointer-events-none opacity-10 bg-[radial-gradient(circle_at_center,_var(--tw-gradient-stops))] from-cyan-400 to-transparent"></div>
        
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded bg-cyan-500/20 border border-cyan-400/40 text-cyan-300 font-mono text-xs font-bold flex items-center gap-1.5">
                <Cpu className="w-3.5 h-3.5" />
                SNAPDRAGON PC EDGE ENGINE
              </span>
              <span className="text-xs font-mono text-slate-400">|</span>
              <span className="text-xs font-mono text-emerald-400 flex items-center gap-1">
                <Lock className="w-3 h-3" /> Zero Cloud Egress • Air-Gapped Privacy
              </span>
            </div>
            <h1 className="text-2xl font-black tracking-tight text-white flex items-center gap-2">
              <Terminal className="w-6 h-6 text-cyan-400" />
              <span>Edge AI Security Investigation Workbench</span>
            </h1>
            <p className="text-xs font-mono text-slate-400">
              Autonomous threat hypothesis, IOC extraction, MITRE mapping & remediation generation
            </p>
          </div>

          {/* Model & Target Selector */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="bg-[#050811] border border-slate-700 rounded-lg p-1.5 flex items-center gap-2 text-xs font-mono">
              <span className="text-slate-400 pl-1.5">Active Model:</span>
              <select
                value={activeModel.id}
                onChange={e => {
                  const m = models.find(mod => mod.id === e.target.value);
                  if (m) onSelectModel(m);
                }}
                className="bg-slate-900 border border-slate-700 rounded px-2.5 py-1 text-cyan-300 font-semibold focus:outline-none focus:border-cyan-500 cursor-pointer"
              >
                {models.map(m => (
                  <option key={m.id} value={m.id}>
                    {m.name} ({m.quantization})
                  </option>
                ))}
              </select>
            </div>

            <div className="bg-[#050811] border border-slate-700 rounded-lg p-1.5 flex items-center gap-2 text-xs font-mono">
              <span className="text-slate-400 pl-1.5">Hardware Target:</span>
              <select
                value={executionProvider}
                onChange={e => onProviderChange(e.target.value as HardwareExecutionProvider)}
                className="bg-slate-900 border border-slate-700 rounded px-2.5 py-1 text-amber-300 font-semibold focus:outline-none focus:border-cyan-500 cursor-pointer"
              >
                <option value="NPU">Snapdragon NPU (Hexagon 45 TOPS)</option>
                <option value="GPU">Snapdragon GPU (Adreno)</option>
                <option value="CPU">Snapdragon CPU (Oryon ARM)</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Main Grid: Incident Selector on Left, AI Investigation Panel on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Incident Queue Left Bar (4 cols) */}
        <div className="lg:col-span-4 space-y-4">
          <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2 font-mono text-xs">
              <span className="text-slate-300 font-bold">SELECT INCIDENT</span>
              <span className="text-slate-500">{alerts.length} Incidents</span>
            </div>

            <div className="space-y-2.5 max-h-[600px] overflow-y-auto pr-1">
              {alerts.map(alert => {
                const isSelected = currentAlert?.id === alert.id;
                return (
                  <div
                    key={alert.id}
                    onClick={() => onSelectAlert(alert)}
                    className={`p-3.5 rounded-lg border transition cursor-pointer select-none ${
                      isSelected
                        ? 'bg-[#101c33] border-cyan-500 shadow-md shadow-cyan-500/15'
                        : 'bg-[#080d16] border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between text-xs font-mono mb-1.5">
                      <span className="font-bold text-cyan-400">{alert.id}</span>
                      <div className="flex items-center gap-1.5">
                        <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                          alert.severity === 'CRITICAL' ? 'bg-red-950 text-red-300 border border-red-800' : 'bg-amber-950 text-amber-300 border border-amber-800'
                        }`}>
                          {alert.severity}
                        </span>
                        <span className="text-slate-400 font-bold">Risk: {alert.riskScore}/100</span>
                      </div>
                    </div>

                    <h4 className="text-xs font-semibold text-white truncate mb-1">
                      {alert.title}
                    </h4>

                    <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                      <span>{alert.affectedHost}</span>
                      {alert.investigationResult ? (
                        <span className="text-emerald-400 flex items-center gap-1">
                          <CheckCircle2 className="w-3 h-3" /> Investigated
                        </span>
                      ) : (
                        <span className="text-yellow-500">Pending AI</span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Run Investigation Action Trigger */}
            <div className="pt-2 border-t border-slate-800">
              <button
                onClick={handleRunInvestigation}
                disabled={isAnalyzing}
                className="w-full py-2.5 rounded-lg bg-gradient-to-r from-cyan-600 via-teal-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-mono text-xs font-bold transition flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20 disabled:opacity-50 cursor-pointer"
              >
                {isAnalyzing ? (
                  <>
                    <Activity className="w-4 h-4 animate-spin text-cyan-200" />
                    <span>Analyzing on Snapdragon {executionProvider}...</span>
                  </>
                ) : (
                  <>
                    <Sparkles className="w-4 h-4 text-cyan-200" />
                    <span>Execute Edge AI Investigation</span>
                  </>
                )}
              </button>
            </div>

          </div>
        </div>

        {/* Investigation Output Center/Right (8 cols) */}
        <div className="lg:col-span-8 space-y-4">
          
          {/* Progress Indicator if analyzing */}
          {isAnalyzing && (
            <div className="bg-[#0c1322] border border-cyan-500/50 rounded-xl p-5 space-y-3 cyber-glow-cyan animate-pulse">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-cyan-300 font-bold flex items-center gap-2">
                  <Activity className="w-4 h-4 animate-spin" />
                  {analysisStage}
                </span>
                <span className="text-cyan-400 font-bold">{analysisProgress}%</span>
              </div>
              <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                <div 
                  className="h-full bg-gradient-to-r from-cyan-500 via-teal-400 to-blue-500 transition-all duration-300"
                  style={{ width: `${analysisProgress}%` }}
                />
              </div>
              <div className="text-[11px] font-mono text-slate-400 flex items-center justify-between">
                <span>Active Target: Snapdragon Hexagon NPU ({telemetry.npuTopsActive} TOPS)</span>
                <span>Thermal/Power: {telemetry.powerDrawWatts}W</span>
              </div>
            </div>
          )}

          {investigation ? (
            <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5 space-y-5">
              
              {/* Investigation Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center gap-2 font-mono text-xs">
                    <span className="text-cyan-400 font-bold">CYBERNEXSUS INVESTIGATION REPORT</span>
                    <span className="text-slate-600">•</span>
                    <span className="text-slate-400">{investigation.id}</span>
                  </div>
                  <h2 className="text-lg font-bold text-white mt-0.5">
                    {currentAlert.title}
                  </h2>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => onGenerateReport(currentAlert)}
                    className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 transition flex items-center gap-1.5 cursor-pointer"
                  >
                    <FileText className="w-3.5 h-3.5 text-amber-400" />
                    <span>Full PDF/Doc Report</span>
                  </button>
                </div>
              </div>

              {/* Hardware Execution Metadata Banner */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 bg-[#080d16] p-3 rounded-lg border border-slate-800 font-mono text-xs">
                <div>
                  <span className="text-slate-500 block text-[10px]">INFERENCE ENGINE</span>
                  <span className="text-cyan-300 font-semibold">{investigation.modelUsed.split(' ')[0]}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">HARDWARE ACCELERATION</span>
                  <span className="text-emerald-400 font-semibold">Snapdragon {investigation.executionProvider}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">THROUGHPUT / SPEED</span>
                  <span className="text-amber-300 font-semibold">{investigation.tokensPerSec} tok/s ({investigation.inferenceDurationMs}ms)</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">CONFIDENCE RATING</span>
                  <span className="text-purple-300 font-semibold">{investigation.confidenceScore}% (High Assurance)</span>
                </div>
              </div>

              {/* Investigation Tabs Navigation */}
              <div className="flex items-center space-x-1 border-b border-slate-800 overflow-x-auto pb-1 text-xs font-mono">
                {[
                  { id: 'hypothesis', label: 'Attack Hypothesis' },
                  { id: 'iocs', label: `Extracted IOCs (${investigation.iocExtraction.length})` },
                  { id: 'correlation', label: 'Correlation Narrative' },
                  { id: 'mitre', label: 'MITRE Mapping' },
                  { id: 'explanation', label: 'Root Cause & Blast Radius' },
                  { id: 'recommendations', label: 'Recommendations & Playbooks' },
                  { id: 'chat', label: 'Analyst Copilot' },
                ].map(tab => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id as any)}
                    className={`px-3 py-1.5 rounded-t font-medium transition cursor-pointer whitespace-nowrap ${
                      activeTab === tab.id
                        ? 'bg-slate-800 text-cyan-300 border-b-2 border-cyan-400 font-bold'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              {/* Tab Content Display */}
              <div className="min-h-[300px]">
                
                {/* 1. Attack Hypothesis Tab */}
                {activeTab === 'hypothesis' && (
                  <div className="space-y-4">
                    <div className="bg-[#080d16] border border-cyan-900/50 p-4 rounded-xl space-y-2">
                      <div className="text-xs font-mono font-bold text-cyan-400 flex items-center gap-1.5">
                        <Sparkles className="w-4 h-4" />
                        SYNTHESIZED ATTACK HYPOTHESIS
                      </div>
                      <p className="text-sm text-slate-200 leading-relaxed font-sans">
                        {investigation.attackHypothesis}
                      </p>
                    </div>

                    {/* Local RAG Sources Retrieved */}
                    <div className="bg-[#080d16] border border-slate-800 p-4 rounded-xl space-y-2.5">
                      <div className="text-xs font-mono font-bold text-slate-400 flex items-center gap-1.5">
                        <Database className="w-4 h-4 text-cyan-400" />
                        LOCAL SECURITY RAG SOURCES RETRIEVED (ON-DEVICE VECTOR INDEX)
                      </div>
                      <div className="space-y-1.5">
                        {investigation.ragSourcesRetrieved.map((src, i) => (
                          <div key={i} className="flex items-center justify-between text-xs font-mono p-2 rounded bg-slate-900/70 border border-slate-800">
                            <span className="text-slate-300">{src.title}</span>
                            <span className="text-cyan-400 font-bold">Similarity: {(src.relevanceScore * 100).toFixed(0)}%</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}

                {/* 2. IOC Extraction Tab */}
                {activeTab === 'iocs' && (
                  <div className="space-y-3">
                    <div className="border border-slate-800 rounded-xl overflow-hidden">
                      <table className="w-full text-left font-mono text-xs">
                        <thead className="bg-[#080d16] text-slate-400 border-b border-slate-800">
                          <tr>
                            <th className="p-3">Indicator / Entity</th>
                            <th className="p-3">Type</th>
                            <th className="p-3">Likelihood</th>
                            <th className="p-3">Remediation Action</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800 bg-[#0c1322]">
                          {investigation.iocExtraction.map((ioc, idx) => (
                            <tr key={idx} className="hover:bg-slate-900/60">
                              <td className="p-3 font-bold text-cyan-300 select-all">{ioc.indicator}</td>
                              <td className="p-3 text-slate-300">{ioc.type}</td>
                              <td className="p-3">
                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                  ioc.maliciousLikelihood === 'CRITICAL' ? 'bg-red-950 text-red-300 border border-red-800' : 'bg-amber-950 text-amber-300 border border-amber-800'
                                }`}>
                                  {ioc.maliciousLikelihood}
                                </span>
                              </td>
                              <td className="p-3 text-slate-300">{ioc.action}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* 3. Event Correlation Narrative Tab */}
                {activeTab === 'correlation' && (
                  <div className="space-y-4">
                    <div className="bg-[#080d16] border border-slate-800 p-4 rounded-xl space-y-3">
                      <div className="text-xs font-mono font-bold text-slate-400">
                        TEMPORAL & ENTITY CHAINING ANALYSIS
                      </div>
                      <p className="text-sm text-slate-200 leading-relaxed font-mono">
                        {investigation.eventCorrelationNarrative}
                      </p>
                    </div>

                    <div className="border border-slate-800 rounded-xl p-4 bg-[#080d16] space-y-3">
                      <div className="text-xs font-mono text-slate-400 font-bold">
                        CORRELATED TELEMETRY CHAIN ({currentAlert.chainedEvents.length} RAW LOG EVENTS)
                      </div>
                      <div className="space-y-2 max-h-60 overflow-y-auto">
                        {currentAlert.chainedEvents.map((evt, i) => (
                          <div key={i} className="p-2.5 rounded bg-slate-900/80 border border-slate-800 text-xs font-mono flex items-center justify-between">
                            <div className="space-y-0.5">
                              <div className="text-cyan-300 font-semibold">{evt.message}</div>
                              <div className="text-slate-500 text-[10px]">{evt.timestamp} • {evt.sourceType.toUpperCase()}</div>
                            </div>
                            <span className="text-slate-400 font-bold">#{i + 1}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}

                {/* 4. MITRE Mapping Tab */}
                {activeTab === 'mitre' && (
                  <div className="space-y-3">
                    {investigation.mitreMappingAnalysis.map((item, idx) => (
                      <div key={idx} className="bg-[#080d16] border border-slate-800 p-4 rounded-xl space-y-1.5">
                        <div className="flex items-center justify-between font-mono text-xs">
                          <span className="text-cyan-400 font-bold">{item.techniqueId}: {item.techniqueName}</span>
                          <span className="text-slate-400 px-2 py-0.5 rounded bg-slate-800">{item.tactic}</span>
                        </div>
                        <p className="text-xs font-mono text-emerald-300 pt-1">
                          Evidence Found: {item.evidenceFound}
                        </p>
                      </div>
                    ))}
                  </div>
                )}

                {/* 5. Root Cause & Explanation Tab */}
                {activeTab === 'explanation' && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="bg-[#080d16] border border-slate-800 p-4 rounded-xl space-y-2">
                      <div className="text-xs font-mono font-bold text-red-400 uppercase">
                        Identified Root Cause
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed font-mono">
                        {investigation.explanation.rootCause}
                      </p>
                    </div>

                    <div className="bg-[#080d16] border border-slate-800 p-4 rounded-xl space-y-2">
                      <div className="text-xs font-mono font-bold text-amber-400 uppercase">
                        Initial Attack Vector
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed font-mono">
                        {investigation.explanation.attackVector}
                      </p>
                    </div>

                    <div className="bg-[#080d16] border border-slate-800 p-4 rounded-xl space-y-2">
                      <div className="text-xs font-mono font-bold text-purple-400 uppercase">
                        Potential Blast Radius
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed font-mono">
                        {investigation.explanation.potentialBlastRadius}
                      </p>
                    </div>

                    <div className="bg-[#080d16] border border-slate-800 p-4 rounded-xl space-y-2">
                      <div className="text-xs font-mono font-bold text-cyan-400 uppercase">
                        Assessed Attacker Goal
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed font-mono">
                        {investigation.explanation.attackerGoal}
                      </p>
                    </div>
                  </div>
                )}

                {/* 6. Recommendations & Playbooks Tab */}
                {activeTab === 'recommendations' && (
                  <div className="space-y-4">
                    {investigation.recommendations.map((rec, idx) => (
                      <div key={idx} className="bg-[#080d16] border border-slate-800 rounded-xl p-4 space-y-2.5">
                        <div className="flex items-center justify-between font-mono text-xs">
                          <div className="flex items-center gap-2">
                            <span className={`px-2 py-0.5 rounded font-bold ${
                              rec.priority === 'IMMEDIATE' ? 'bg-red-950 text-red-300 border border-red-800' : 'bg-amber-950 text-amber-300 border border-amber-800'
                            }`}>
                              {rec.priority}
                            </span>
                            <span className="font-bold text-white">{rec.action}</span>
                          </div>
                          <span className="text-slate-400 text-[10px]">{rec.type}</span>
                        </div>

                        {rec.commandSnippet && (
                          <div className="relative">
                            <pre className="bg-[#04060d] border border-slate-800 p-3 rounded-lg text-xs font-mono text-emerald-300 overflow-x-auto whitespace-pre-wrap select-all">
                              {rec.commandSnippet}
                            </pre>
                            <button
                              onClick={() => handleCopy(rec.commandSnippet!, `rec-${idx}`)}
                              className="absolute top-2 right-2 p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition cursor-pointer"
                              title="Copy Command"
                            >
                              {copiedCmd === `rec-${idx}` ? (
                                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" />
                              )}
                            </button>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                {/* 7. Analyst Copilot Interactive Chat */}
                {activeTab === 'chat' && (
                  <div className="space-y-4">
                    <div className="bg-[#080d16] border border-slate-800 rounded-xl p-4 h-80 overflow-y-auto space-y-3 font-mono text-xs">
                      {chatMessages.map((msg, i) => (
                        <div
                          key={i}
                          className={`p-3 rounded-lg ${
                            msg.sender === 'user'
                              ? 'bg-cyan-950/60 border border-cyan-800 ml-8 text-cyan-200'
                              : 'bg-slate-900 border border-slate-800 mr-8 text-slate-200'
                          }`}
                        >
                          <div className="flex items-center justify-between text-[10px] text-slate-500 mb-1">
                            <span className="font-bold uppercase text-slate-400">
                              {msg.sender === 'user' ? 'SOC Analyst' : `${activeModel.name} (Snapdragon ${executionProvider})`}
                            </span>
                            <span>{msg.time}</span>
                          </div>
                          <div className="whitespace-pre-wrap leading-relaxed">
                            {msg.text}
                          </div>
                        </div>
                      ))}
                      {isChatThinking && (
                        <div className="text-cyan-400 flex items-center gap-2 text-xs font-mono italic">
                          <Activity className="w-3.5 h-3.5 animate-spin" />
                          <span>Generating local response via Snapdragon NPU...</span>
                        </div>
                      )}
                    </div>

                    <form onSubmit={handleSendChat} className="flex gap-2">
                      <input
                        type="text"
                        placeholder="Ask edge model to draft iptables rule, explain base64 payload, or suggest containment..."
                        value={chatInput}
                        onChange={e => setChatInput(e.target.value)}
                        className="flex-1 bg-[#080d16] border border-slate-800 rounded-lg px-4 py-2 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                      />
                      <button
                        type="submit"
                        disabled={!chatInput.trim() || isChatThinking}
                        className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-bold transition disabled:opacity-50 cursor-pointer flex items-center gap-1.5"
                      >
                        <Send className="w-3.5 h-3.5" />
                        <span>Send</span>
                      </button>
                    </form>
                  </div>
                )}

              </div>

            </div>
          ) : (
            <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-12 text-center space-y-4">
              <div className="w-12 h-12 rounded-full bg-cyan-950/80 border border-cyan-700 flex items-center justify-center mx-auto text-cyan-400">
                <Terminal className="w-6 h-6" />
              </div>
              <div className="space-y-1">
                <h3 className="text-base font-bold text-white">No AI Investigation Executed Yet</h3>
                <p className="text-xs text-slate-400 font-mono max-w-md mx-auto">
                  Click below to launch an on-device edge investigation utilizing {activeModel.name} on the Qualcomm Hexagon NPU.
                </p>
              </div>
              <button
                onClick={handleRunInvestigation}
                className="px-5 py-2.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-mono text-xs font-bold transition inline-flex items-center gap-2 shadow-lg shadow-cyan-500/25 cursor-pointer"
              >
                <Sparkles className="w-4 h-4 text-cyan-200" />
                <span>Investigate Incident {currentAlert?.id} Now</span>
              </button>
            </div>
          )}

        </div>

      </div>
    </div>
  );
};
