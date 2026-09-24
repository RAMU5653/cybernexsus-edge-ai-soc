/**
 * CyberNexsus Edge AI SOC - MITRE ATT&CK Enterprise Matrix Navigator
 */

import React, { useState } from 'react';
import { Grid, Shield, AlertTriangle, CheckCircle2, ChevronRight, ExternalLink, Search } from 'lucide-react';
import { MitreTechniqueRef, SecurityAlert } from '../types';
import { MITRE_KNOWLEDGE_BASE } from '../data/mockData';

interface MitreAttackViewProps {
  alerts: SecurityAlert[];
  onSelectAlert: (alert: SecurityAlert) => void;
}

const TACTICS_ORDER = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
] as const;

export const MitreAttackView: React.FC<MitreAttackViewProps> = ({ alerts, onSelectAlert }) => {
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechniqueRef | null>(
    MITRE_KNOWLEDGE_BASE[0]
  );
  const [filterSearch, setFilterSearch] = useState('');

  // Collect all technique IDs that are active in current alerts
  const activeTechniqueIds = new Set<string>();
  alerts.forEach(a => {
    a.mitreTechniques.forEach(t => activeTechniqueIds.add(t.id));
  });

  // Group techniques by tactic
  const techniquesByTactic = TACTICS_ORDER.map(tactic => {
    const list = MITRE_KNOWLEDGE_BASE.filter(t => t.tactic === tactic);
    return { tactic, list };
  });

  const matchedAlertsForSelected = alerts.filter(a =>
    selectedTechnique ? a.mitreTechniques.some(t => t.id === selectedTechnique.id) : false
  );

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Grid className="w-7 h-7 text-cyan-400" />
            <span>MITRE ATT&CK Enterprise Navigator</span>
          </h1>
          <p className="text-sm text-slate-400 font-mono mt-1">
            Tactics, techniques, and procedures (TTPs) mapped to real-time endpoint & network telemetry
          </p>
        </div>

        {/* Search */}
        <div className="flex items-center gap-2 bg-[#0c1322] border border-slate-800 rounded-lg px-3 py-1.5 font-mono text-xs w-full md:w-72">
          <Search className="w-4 h-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search technique (e.g. T1110, Sudo)..."
            value={filterSearch}
            onChange={e => setFilterSearch(e.target.value)}
            className="bg-transparent text-white focus:outline-none w-full"
          />
        </div>
      </div>

      {/* Main Grid: Enterprise Matrix */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Matrix Columns (8 cols) */}
        <div className="lg:col-span-8 bg-[#0c1322] border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3 font-mono text-xs">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-red-400 animate-ping"></span>
              <span className="text-white font-bold">ACTIVE ENTERPRISE COVERAGE</span>
            </div>
            <div className="flex items-center gap-3 text-slate-400">
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded bg-red-500/80"></span>
                <span>Active Threat Observed</span>
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded bg-slate-700"></span>
                <span>Baseline Mitigated</span>
              </span>
            </div>
          </div>

          {/* Tactics Scroll Container */}
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-3">
            {techniquesByTactic.map(({ tactic, list }) => {
              const hasActiveInTactic = list.some(t => activeTechniqueIds.has(t.id));
              return (
                <div key={tactic} className="bg-[#080d16] rounded-lg border border-slate-800 p-2.5 space-y-2">
                  <div className="border-b border-slate-800 pb-1.5 flex items-center justify-between">
                    <span className="text-[11px] font-mono font-bold text-cyan-300 truncate" title={tactic}>
                      {tactic}
                    </span>
                    {hasActiveInTactic && (
                      <span className="w-2 h-2 rounded-full bg-red-400"></span>
                    )}
                  </div>

                  <div className="space-y-1.5 min-h-[90px]">
                    {list.length === 0 ? (
                      <div className="text-[10px] font-mono text-slate-600 italic py-2">
                        No active detections
                      </div>
                    ) : (
                      list
                        .filter(t => !filterSearch || t.id.toLowerCase().includes(filterSearch.toLowerCase()) || t.name.toLowerCase().includes(filterSearch.toLowerCase()))
                        .map(tech => {
                          const isActive = activeTechniqueIds.has(tech.id);
                          const isSelected = selectedTechnique?.id === tech.id;
                          return (
                            <button
                              key={tech.id}
                              onClick={() => setSelectedTechnique(tech)}
                              className={`w-full text-left px-2 py-1.5 rounded text-[11px] font-mono transition cursor-pointer border flex flex-col ${
                                isSelected
                                  ? 'bg-cyan-950 border-cyan-400 text-white shadow-md shadow-cyan-500/20'
                                  : isActive
                                    ? 'bg-red-950/60 border-red-700/80 text-red-200 hover:border-red-500'
                                    : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
                              }`}
                            >
                              <div className="flex items-center justify-between">
                                <span className="font-bold">{tech.id}</span>
                                {isActive && <span className="text-[9px] px-1 rounded bg-red-900 text-red-100 font-bold">ALERT</span>}
                              </div>
                              <span className="truncate text-[10px] opacity-90">{tech.name}</span>
                            </button>
                          );
                        })
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Details Drawer (4 cols) */}
        <div className="lg:col-span-4 space-y-4">
          {selectedTechnique ? (
            <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5 space-y-4 sticky top-24">
              
              <div className="border-b border-slate-800 pb-3">
                <div className="flex items-center justify-between text-xs font-mono text-cyan-400 mb-1">
                  <span>{selectedTechnique.tactic}</span>
                  <span className="bg-cyan-950 border border-cyan-800 px-2 py-0.5 rounded font-bold text-cyan-300">
                    {selectedTechnique.id}
                  </span>
                </div>
                <h3 className="text-base font-bold text-white">
                  {selectedTechnique.name}
                </h3>
              </div>

              {/* Technical Description */}
              <div>
                <h4 className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider mb-1">
                  Adversary Behavior
                </h4>
                <p className="text-xs text-slate-300 leading-relaxed bg-[#080d16] p-3 rounded-lg border border-slate-800">
                  {selectedTechnique.description}
                </p>
              </div>

              {/* Detection Methodology */}
              <div>
                <h4 className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider mb-1">
                  Detection Telemetry & Indicators
                </h4>
                <p className="text-xs text-emerald-300 font-mono leading-relaxed bg-[#080d16] p-3 rounded-lg border border-slate-800">
                  {selectedTechnique.detection}
                </p>
              </div>

              {/* Correlated Active Incidents */}
              <div>
                <h4 className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Correlated Incidents ({matchedAlertsForSelected.length})
                </h4>

                {matchedAlertsForSelected.length === 0 ? (
                  <div className="text-xs font-mono text-slate-500 italic bg-[#080d16] p-3 rounded-lg border border-slate-800">
                    No active unhandled incidents currently map to this technique.
                  </div>
                ) : (
                  <div className="space-y-2">
                    {matchedAlertsForSelected.map(alert => (
                      <div
                        key={alert.id}
                        onClick={() => onSelectAlert(alert)}
                        className="bg-[#080d16] hover:bg-[#101b30] border border-slate-800 hover:border-cyan-600 rounded-lg p-3 transition cursor-pointer"
                      >
                        <div className="flex items-center justify-between text-xs font-mono mb-1">
                          <span className="font-bold text-cyan-400">{alert.id}</span>
                          <span className="text-red-400 font-bold">Risk: {alert.riskScore}/100</span>
                        </div>
                        <div className="text-xs font-semibold text-white truncate">
                          {alert.title}
                        </div>
                        <div className="text-[11px] font-mono text-slate-400 mt-1">
                          Host: {alert.affectedHost}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

            </div>
          ) : (
            <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-12 text-center text-slate-400 font-mono text-xs">
              Select a MITRE technique tile to inspect behavioral descriptions and active incident correlation.
            </div>
          )}
        </div>

      </div>
    </div>
  );
};
