/**
 * CyberNexsus Edge AI SOC - Alerts & Incident Triage View
 */

import React, { useState } from 'react';
import { 
  ShieldAlert, 
  Search, 
  Filter, 
  ArrowRight, 
  Terminal, 
  Clock, 
  Send, 
  Sliders, 
  CheckCircle, 
  AlertTriangle,
  Server,
  User,
  ExternalLink,
  ChevronDown,
  Sparkles,
  FileText
} from 'lucide-react';
import { SecurityAlert, SeverityLevel } from '../types';

interface AlertsViewProps {
  alerts: SecurityAlert[];
  onSelectAlertForInvestigation: (alert: SecurityAlert) => void;
  onViewTimeline: (alert: SecurityAlert) => void;
  onOpenCvssForAlert: (alert: SecurityAlert) => void;
  onDispatchTelegram: (alert: SecurityAlert) => void;
  onGenerateReport: (alert: SecurityAlert) => void;
  onUpdateAlertStatus: (alertId: string, status: SecurityAlert['status']) => void;
}

export const AlertsView: React.FC<AlertsViewProps> = ({
  alerts,
  onSelectAlertForInvestigation,
  onViewTimeline,
  onOpenCvssForAlert,
  onDispatchTelegram,
  onGenerateReport,
  onUpdateAlertStatus,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [expandedAlertId, setExpandedAlertId] = useState<string | null>(alerts[0]?.id || null);

  const filteredAlerts = alerts.filter(alert => {
    const matchesSearch = 
      alert.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.affectedHost.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.affectedUser.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.mitreTechniques.some(t => t.id.toLowerCase().includes(searchTerm.toLowerCase()) || t.name.toLowerCase().includes(searchTerm.toLowerCase())) ||
      alert.id.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesSeverity = severityFilter === 'ALL' || alert.severity === severityFilter;
    const matchesStatus = statusFilter === 'ALL' || alert.status === statusFilter;

    return matchesSearch && matchesSeverity && matchesStatus;
  });

  const getSeverityBadgeClass = (sev: SeverityLevel) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-500/20 text-red-300 border-red-500/50 cyber-glow-red';
      case 'HIGH':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/50 cyber-glow-amber';
      case 'MEDIUM':
        return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/50';
      case 'LOW':
        return 'bg-blue-500/20 text-blue-300 border-blue-500/50';
      default:
        return 'bg-slate-700/40 text-slate-300 border-slate-600';
    }
  };

  const getStatusBadgeClass = (status: SecurityAlert['status']) => {
    switch (status) {
      case 'NEW':
        return 'bg-rose-950 text-rose-300 border border-rose-800';
      case 'INVESTIGATING':
        return 'bg-cyan-950 text-cyan-300 border border-cyan-700 animate-pulse';
      case 'CONTAINED':
        return 'bg-amber-950 text-amber-300 border border-amber-700';
      case 'RESOLVED':
        return 'bg-emerald-950 text-emerald-300 border border-emerald-700';
      default:
        return 'bg-slate-800 text-slate-400 border border-slate-700';
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      
      {/* Top Header & Stats Overview */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <ShieldAlert className="w-7 h-7 text-cyan-400" />
            <span>Active Security Incident Queue</span>
          </h1>
          <p className="text-sm text-slate-400 font-mono mt-1">
            Real-time multi-source event correlation & edge AI threat triage
          </p>
        </div>

        {/* Quick Metric Chips */}
        <div className="flex flex-wrap items-center gap-2.5 font-mono text-xs">
          <div className="bg-[#0f172a] border border-slate-800 rounded-lg px-3.5 py-2 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-red-400"></span>
            <span className="text-slate-400">Critical:</span>
            <span className="text-white font-bold">{alerts.filter(a => a.severity === 'CRITICAL').length}</span>
          </div>
          <div className="bg-[#0f172a] border border-slate-800 rounded-lg px-3.5 py-2 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-amber-400"></span>
            <span className="text-slate-400">High:</span>
            <span className="text-white font-bold">{alerts.filter(a => a.severity === 'HIGH').length}</span>
          </div>
          <div className="bg-[#0f172a] border border-slate-800 rounded-lg px-3.5 py-2 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
            <span className="text-slate-400">AI Investigated:</span>
            <span className="text-cyan-300 font-bold">{alerts.filter(a => a.investigationResult).length}</span>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row items-center gap-3">
        <div className="relative flex-1 w-full">
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search alerts by host, user, MITRE technique (e.g. T1110), IOC..."
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            className="w-full bg-[#070b12] border border-slate-800 rounded-lg pl-10 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto">
          <div className="flex items-center gap-1.5 bg-[#070b12] border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 font-mono">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <select
              value={severityFilter}
              onChange={e => setSeverityFilter(e.target.value)}
              className="bg-transparent focus:outline-none cursor-pointer text-slate-200"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          <div className="flex items-center gap-1.5 bg-[#070b12] border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 font-mono">
            <select
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value)}
              className="bg-transparent focus:outline-none cursor-pointer text-slate-200"
            >
              <option value="ALL">All Statuses</option>
              <option value="NEW">New</option>
              <option value="INVESTIGATING">Investigating</option>
              <option value="CONTAINED">Contained</option>
              <option value="RESOLVED">Resolved</option>
            </select>
          </div>
        </div>
      </div>

      {/* Incident Alert Cards List */}
      <div className="space-y-4">
        {filteredAlerts.length === 0 ? (
          <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-12 text-center text-slate-400 font-mono">
            No incidents found matching your query criteria.
          </div>
        ) : (
          filteredAlerts.map(alert => {
            const isExpanded = expandedAlertId === alert.id;
            return (
              <div 
                key={alert.id}
                className="bg-[#0c1322] border border-slate-800/90 hover:border-slate-700 rounded-xl overflow-hidden transition shadow-lg"
              >
                {/* Main Card Header Bar */}
                <div 
                  className="p-5 flex flex-col lg:flex-row lg:items-center justify-between gap-4 cursor-pointer select-none"
                  onClick={() => setExpandedAlertId(isExpanded ? null : alert.id)}
                >
                  <div className="space-y-2 flex-1">
                    <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
                      <span className="font-bold text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800">
                        {alert.id}
                      </span>
                      <span className={`px-2 py-0.5 rounded font-bold border ${getSeverityBadgeClass(alert.severity)}`}>
                        {alert.severity}
                      </span>
                      <span className={`px-2 py-0.5 rounded font-medium ${getStatusBadgeClass(alert.status)}`}>
                        {alert.status}
                      </span>
                      <span className="text-slate-500">•</span>
                      <span className="text-slate-400 flex items-center gap-1">
                        <Clock className="w-3.5 h-3.5" />
                        {new Date(alert.createdAt).toLocaleString()}
                      </span>
                    </div>

                    <h2 className="text-lg font-bold text-white group-hover:text-cyan-300 transition">
                      {alert.title}
                    </h2>

                    <div className="flex flex-wrap items-center gap-4 text-xs font-mono text-slate-400">
                      <span className="flex items-center gap-1 text-slate-300">
                        <Server className="w-3.5 h-3.5 text-cyan-400" />
                        Host: <span className="text-cyan-300 font-medium">{alert.affectedHost}</span>
                      </span>
                      <span className="flex items-center gap-1 text-slate-300">
                        <User className="w-3.5 h-3.5 text-indigo-400" />
                        User: <span className="text-indigo-300 font-medium">{alert.affectedUser}</span>
                      </span>
                      <span className="text-slate-500">•</span>
                      <span>{alert.chainedEvents.length} Chained Logs</span>
                      <span>{alert.iocs.length} Extracted IOCs</span>
                    </div>
                  </div>

                  {/* Right Score Badges & Quick Action */}
                  <div className="flex items-center space-x-4 lg:self-center">
                    
                    {/* CVSS v3.1 Score Box */}
                    <div 
                      onClick={(e) => { e.stopPropagation(); onOpenCvssForAlert(alert); }}
                      className="bg-[#070b14] border border-slate-800 hover:border-cyan-500/50 rounded-lg p-2.5 text-center min-w-[90px] transition cursor-pointer group"
                      title="Click to view full CVSS v3.1 breakdown"
                    >
                      <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider group-hover:text-cyan-400">
                        CVSS v3.1
                      </div>
                      <div className="text-xl font-extrabold font-mono text-amber-400">
                        {alert.cvss.baseScore}
                      </div>
                      <div className="text-[10px] font-mono text-slate-500">
                        {alert.cvss.severity}
                      </div>
                    </div>

                    {/* SOC Risk Score Gauge */}
                    <div className="bg-[#070b14] border border-slate-800 rounded-lg p-2.5 text-center min-w-[90px]">
                      <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">
                        Risk Score
                      </div>
                      <div className="text-xl font-extrabold font-mono text-red-400">
                        {alert.riskScore}<span className="text-xs text-slate-500 font-normal">/100</span>
                      </div>
                      <div className="text-[10px] font-mono text-slate-500">
                        Criticality
                      </div>
                    </div>

                    <ChevronDown className={`w-5 h-5 text-slate-400 transition-transform ${isExpanded ? 'rotate-180 text-cyan-400' : ''}`} />
                  </div>
                </div>

                {/* Expanded Details Section */}
                {isExpanded && (
                  <div className="border-t border-slate-800 bg-[#080d18] p-5 space-y-4">
                    
                    {/* Summary */}
                    <div>
                      <h4 className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider mb-1">
                        Incident Synopsis
                      </h4>
                      <p className="text-sm text-slate-200 leading-relaxed">
                        {alert.summary}
                      </p>
                    </div>

                    {/* MITRE ATT&CK Mapping Badges */}
                    <div>
                      <h4 className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider mb-2">
                        MITRE ATT&CK Enterprise Techniques
                      </h4>
                      <div className="flex flex-wrap gap-2">
                        {alert.mitreTechniques.map(tech => (
                          <div
                            key={tech.id}
                            className="bg-cyan-950/40 border border-cyan-800/80 rounded-md px-2.5 py-1 text-xs font-mono text-cyan-300 flex items-center gap-1.5"
                          >
                            <span className="font-bold text-cyan-200">{tech.id}</span>
                            <span className="text-slate-400">|</span>
                            <span>{tech.name}</span>
                            <span className="text-[10px] px-1 rounded bg-cyan-900/60 text-slate-300">
                              {tech.tactic}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* CVSS Vector String */}
                    <div className="bg-[#050811] p-3 rounded-lg border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2 font-mono text-xs">
                      <div className="flex items-center gap-2">
                        <Sliders className="w-4 h-4 text-amber-400" />
                        <span className="text-slate-400 font-semibold">CVSS v3.1 Vector:</span>
                        <code className="text-amber-300 select-all">{alert.cvss.vectorString}</code>
                      </div>
                      <button
                        onClick={() => onOpenCvssForAlert(alert)}
                        className="text-cyan-400 hover:text-cyan-300 hover:underline flex items-center gap-1 text-[11px] cursor-pointer"
                      >
                        Adjust Metrics <ExternalLink className="w-3 h-3" />
                      </button>
                    </div>

                    {/* AI Investigation Status Banner */}
                    {alert.investigationResult ? (
                      <div className="bg-gradient-to-r from-cyan-950/40 to-blue-950/30 border border-cyan-800/60 rounded-lg p-3.5 space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2 text-xs font-mono text-cyan-300 font-bold">
                            <Sparkles className="w-4 h-4 text-cyan-400" />
                            <span>AI Edge Investigation Completed ({alert.investigationResult.modelUsed})</span>
                          </div>
                          <span className="text-[11px] font-mono text-emerald-400">
                            Confidence: {alert.investigationResult.confidenceScore}%
                          </span>
                        </div>
                        <p className="text-xs text-slate-300 italic font-mono line-clamp-2">
                          "{alert.investigationResult.attackHypothesis}"
                        </p>
                      </div>
                    ) : null}

                    {/* Action Bar */}
                    <div className="pt-2 flex flex-wrap items-center justify-between gap-3 border-t border-slate-800/80">
                      
                      {/* Status select */}
                      <div className="flex items-center gap-2 text-xs font-mono">
                        <span className="text-slate-400">Triage Status:</span>
                        <select
                          value={alert.status}
                          onChange={e => onUpdateAlertStatus(alert.id, e.target.value as any)}
                          className="bg-[#070b14] border border-slate-700 rounded px-2.5 py-1 text-slate-200 focus:outline-none focus:border-cyan-500 cursor-pointer"
                        >
                          <option value="NEW">NEW</option>
                          <option value="INVESTIGATING">INVESTIGATING</option>
                          <option value="CONTAINED">CONTAINED</option>
                          <option value="RESOLVED">RESOLVED</option>
                        </select>
                      </div>

                      {/* Primary Buttons */}
                      <div className="flex flex-wrap items-center gap-2">
                        <button
                          onClick={() => onViewTimeline(alert)}
                          className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 transition flex items-center gap-1.5 cursor-pointer"
                        >
                          <Clock className="w-3.5 h-3.5 text-cyan-400" />
                          <span>Threat Timeline</span>
                        </button>

                        <button
                          onClick={() => onGenerateReport(alert)}
                          className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 transition flex items-center gap-1.5 cursor-pointer"
                        >
                          <FileText className="w-3.5 h-3.5 text-amber-400" />
                          <span>SOC Report</span>
                        </button>

                        <button
                          onClick={() => onDispatchTelegram(alert)}
                          className="px-3 py-1.5 rounded-lg bg-sky-950/80 hover:bg-sky-900 border border-sky-700 text-xs font-mono text-sky-300 transition flex items-center gap-1.5 cursor-pointer"
                        >
                          <Send className="w-3.5 h-3.5" />
                          <span>Dispatch to Telegram</span>
                        </button>

                        <button
                          onClick={() => onSelectAlertForInvestigation(alert)}
                          className="px-4 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-xs font-mono text-white font-bold transition flex items-center gap-1.5 shadow-md shadow-cyan-600/30 cursor-pointer"
                        >
                          <Terminal className="w-3.5 h-3.5" />
                          <span>Launch AI Investigation</span>
                          <ArrowRight className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>

                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

    </div>
  );
};
