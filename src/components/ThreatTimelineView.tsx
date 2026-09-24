/**
 * CyberNexsus Edge AI SOC - Interactive Threat Timeline View
 */

import React, { useState } from 'react';
import { 
  Clock, 
  Filter, 
  Terminal, 
  CheckCircle, 
  Copy, 
  ShieldAlert, 
  Server, 
  User, 
  Network, 
  HardDrive,
  FileCode,
  ArrowDown
} from 'lucide-react';
import { NormalizedSecurityEvent, SecurityAlert, LogSourceType } from '../types';

interface ThreatTimelineViewProps {
  events: NormalizedSecurityEvent[];
  alerts: SecurityAlert[];
  selectedAlert: SecurityAlert | null;
  onSelectAlert: (alert: SecurityAlert) => void;
  onInvestigateAlert: (alert: SecurityAlert) => void;
}

export const ThreatTimelineView: React.FC<ThreatTimelineViewProps> = ({
  events,
  alerts,
  selectedAlert,
  onSelectAlert,
  onInvestigateAlert,
}) => {
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>(
    selectedAlert ? selectedAlert.incidentId : 'ALL'
  );
  const [activeEvent, setActiveEvent] = useState<NormalizedSecurityEvent | null>(events[0] || null);
  const [copiedRaw, setCopiedRaw] = useState(false);

  // Filter events based on selected incident
  const displayedEvents = selectedIncidentId === 'ALL'
    ? [...events].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
    : events
        .filter(e => e.correlationId === selectedIncidentId)
        .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

  const getSourceTypeBadge = (source: LogSourceType) => {
    switch (source) {
      case 'sysmon':
        return 'bg-purple-950/80 text-purple-300 border-purple-800';
      case 'windows_event':
        return 'bg-blue-950/80 text-blue-300 border-blue-800';
      case 'linux_auth':
      case 'linux_syslog':
        return 'bg-amber-950/80 text-amber-300 border-amber-800';
      case 'zeek':
        return 'bg-teal-950/80 text-teal-300 border-teal-800';
      case 'suricata':
        return 'bg-red-950/80 text-red-300 border-red-800';
      case 'splunk':
        return 'bg-emerald-950/80 text-emerald-300 border-emerald-800';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const getSeverityColor = (sev: NormalizedSecurityEvent['severity']) => {
    switch (sev) {
      case 'CRITICAL': return 'text-red-400 border-red-500 bg-red-950/40';
      case 'HIGH': return 'text-amber-400 border-amber-500 bg-amber-950/40';
      case 'MEDIUM': return 'text-yellow-400 border-yellow-500 bg-yellow-950/40';
      default: return 'text-cyan-400 border-cyan-500 bg-cyan-950/40';
    }
  };

  const handleCopyRaw = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedRaw(true);
    setTimeout(() => setCopiedRaw(false), 2000);
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header & Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Clock className="w-7 h-7 text-cyan-400" />
            <span>Threat Chronology & Multi-Source Killchain</span>
          </h1>
          <p className="text-sm text-slate-400 font-mono mt-1">
            Normalized chronological event stream correlated across Windows, Sysmon, Linux, Zeek & Suricata
          </p>
        </div>

        {/* Incident selector */}
        <div className="flex items-center gap-2 bg-[#0c1322] border border-slate-800 rounded-lg p-1.5 font-mono text-xs">
          <Filter className="w-4 h-4 text-slate-400 ml-2" />
          <span className="text-slate-400">Incident Scope:</span>
          <select
            value={selectedIncidentId}
            onChange={e => {
              setSelectedIncidentId(e.target.value);
              const foundAlert = alerts.find(a => a.incidentId === e.target.value);
              if (foundAlert) onSelectAlert(foundAlert);
            }}
            className="bg-[#070b12] border border-slate-700 rounded px-2.5 py-1 text-slate-200 focus:outline-none focus:border-cyan-500 cursor-pointer"
          >
            <option value="ALL">All Correlated Feeds ({events.length} events)</option>
            {alerts.map(a => (
              <option key={a.id} value={a.incidentId}>
                {a.id}: {a.title.substring(0, 38)}...
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Grid: Left Timeline Stream, Right Event Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left Column: Interactive Timeline (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4 font-mono text-xs text-slate-400">
              <span className="font-bold text-slate-200">CHRONOLOGICAL EVENT CHAIN</span>
              <span>{displayedEvents.length} Sequential Events</span>
            </div>

            <div className="relative pl-6 space-y-6 before:absolute before:left-2.5 before:top-3 before:bottom-3 before:w-0.5 before:bg-gradient-to-b before:from-cyan-500 before:via-blue-500 before:to-red-500">
              {displayedEvents.map((evt, idx) => {
                const isSelected = activeEvent?.id === evt.id;
                return (
                  <div
                    key={evt.id}
                    onClick={() => setActiveEvent(evt)}
                    className={`relative cursor-pointer transition rounded-xl p-4 border select-none ${
                      isSelected
                        ? 'bg-[#101b30] border-cyan-500/80 shadow-lg shadow-cyan-500/10'
                        : 'bg-[#080d16] border-slate-800/90 hover:border-slate-700 hover:bg-[#0c1322]'
                    }`}
                  >
                    {/* Node Dot on line */}
                    <div className={`absolute -left-[27px] top-4 w-3.5 h-3.5 rounded-full border-2 transition ${
                      isSelected 
                        ? 'bg-cyan-400 border-white ring-4 ring-cyan-500/30' 
                        : 'bg-slate-900 border-slate-500'
                    }`} />

                    {/* Event Content Header */}
                    <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono mb-2">
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded font-semibold border ${getSourceTypeBadge(evt.sourceType)}`}>
                          {evt.sourceType.toUpperCase()}
                        </span>
                        <span className={`px-2 py-0.5 rounded text-[11px] font-bold border ${getSeverityColor(evt.severity)}`}>
                          {evt.severity}
                        </span>
                        <span className="text-slate-500">#{idx + 1}</span>
                      </div>
                      <span className="text-slate-400 flex items-center gap-1">
                        <Clock className="w-3 h-3 text-slate-500" />
                        {new Date(evt.timestamp).toLocaleTimeString()} UTC
                      </span>
                    </div>

                    <h3 className="text-sm font-semibold text-white mb-2 line-clamp-2">
                      {evt.message}
                    </h3>

                    {/* Quick Metadata Tokens */}
                    <div className="flex flex-wrap items-center gap-3 text-xs font-mono text-slate-400">
                      <span className="flex items-center gap-1 text-slate-300">
                        <Server className="w-3 h-3 text-cyan-400" />
                        {evt.hostname}
                      </span>
                      {evt.username && (
                        <span className="flex items-center gap-1 text-indigo-300">
                          <User className="w-3 h-3 text-indigo-400" />
                          {evt.username}
                        </span>
                      )}
                      {evt.dstIp && (
                        <span className="flex items-center gap-1 text-amber-300">
                          <Network className="w-3 h-3 text-amber-400" />
                          → {evt.dstIp}{evt.dstPort ? `:${evt.dstPort}` : ''}
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Right Column: Event Detail & Raw Log Inspector (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          {activeEvent ? (
            <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-5 space-y-5 sticky top-24">
              
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="font-mono">
                  <div className="text-xs text-slate-400 uppercase tracking-wider">Inspecting Normalized Event</div>
                  <div className="text-sm font-bold text-cyan-300">{activeEvent.id}</div>
                </div>
                <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold border ${getSeverityColor(activeEvent.severity)}`}>
                  {activeEvent.severity}
                </span>
              </div>

              {/* Key Metadata Table */}
              <div className="bg-[#080d16] rounded-lg border border-slate-800 p-3.5 space-y-2.5 font-mono text-xs">
                <div className="flex justify-between border-b border-slate-800/60 pb-1.5">
                  <span className="text-slate-400">Source Parser:</span>
                  <span className="text-slate-200 font-semibold uppercase">{activeEvent.sourceType}</span>
                </div>
                <div className="flex justify-between border-b border-slate-800/60 pb-1.5">
                  <span className="text-slate-400">Timestamp:</span>
                  <span className="text-cyan-300">{activeEvent.timestamp}</span>
                </div>
                <div className="flex justify-between border-b border-slate-800/60 pb-1.5">
                  <span className="text-slate-400">Target Host:</span>
                  <span className="text-slate-200 font-bold">{activeEvent.hostname}</span>
                </div>
                {activeEvent.username && (
                  <div className="flex justify-between border-b border-slate-800/60 pb-1.5">
                    <span className="text-slate-400">User Identity:</span>
                    <span className="text-indigo-300 font-bold">{activeEvent.username}</span>
                  </div>
                )}
                {activeEvent.srcIp && (
                  <div className="flex justify-between border-b border-slate-800/60 pb-1.5">
                    <span className="text-slate-400">Source IP / Port:</span>
                    <span className="text-slate-200">{activeEvent.srcIp}:{activeEvent.srcPort || 'N/A'}</span>
                  </div>
                )}
                {activeEvent.dstIp && (
                  <div className="flex justify-between border-b border-slate-800/60 pb-1.5">
                    <span className="text-slate-400">Destination IP:</span>
                    <span className="text-amber-300 font-bold">{activeEvent.dstIp}:{activeEvent.dstPort || 'N/A'}</span>
                  </div>
                )}
                {activeEvent.processName && (
                  <div className="flex justify-between border-b border-slate-800/60 pb-1.5">
                    <span className="text-slate-400">Binary Image:</span>
                    <span className="text-emerald-300">{activeEvent.processName}</span>
                  </div>
                )}
                <div className="flex justify-between">
                  <span className="text-slate-400">Category:</span>
                  <span className="text-cyan-400">{activeEvent.eventCategory}</span>
                </div>
              </div>

              {/* Command Line / Execution Details if available */}
              {activeEvent.commandLine && (
                <div>
                  <div className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider mb-1.5 flex items-center gap-1.5">
                    <FileCode className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Command Line Execution</span>
                  </div>
                  <pre className="bg-[#050811] border border-slate-800 p-3 rounded-lg text-xs font-mono text-emerald-300 overflow-x-auto whitespace-pre-wrap break-all select-all">
                    {activeEvent.commandLine}
                  </pre>
                </div>
              )}

              {/* Raw Ingest Log Display */}
              <div>
                <div className="flex items-center justify-between text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                  <span className="flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-slate-400" />
                    <span>Raw Unparsed Security Log</span>
                  </span>
                  <button
                    onClick={() => handleCopyRaw(activeEvent.rawLog)}
                    className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 text-[11px] cursor-pointer"
                  >
                    {copiedRaw ? <CheckCircle className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedRaw ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <div className="bg-[#050811] border border-slate-800 p-3 rounded-lg text-[11px] font-mono text-slate-300 max-h-48 overflow-y-auto whitespace-pre-wrap break-all select-all">
                  {activeEvent.rawLog}
                </div>
              </div>

              {/* Chained Incident Link */}
              {selectedAlert && (
                <div className="pt-2 border-t border-slate-800">
                  <button
                    onClick={() => onInvestigateAlert(selectedAlert)}
                    className="w-full py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-xs font-mono text-white font-bold transition flex items-center justify-center gap-2 cursor-pointer shadow-md"
                  >
                    <Terminal className="w-4 h-4" />
                    <span>Launch AI Investigation for Incident {selectedAlert.id}</span>
                  </button>
                </div>
              )}

            </div>
          ) : (
            <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-12 text-center text-slate-400 font-mono text-xs">
              Select an event from the timeline to view normalized parameters and raw payload.
            </div>
          )}
        </div>

      </div>
    </div>
  );
};
