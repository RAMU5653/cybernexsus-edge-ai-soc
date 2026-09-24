/**
 * CyberNexsus Edge AI SOC - Reports View
 * Formal Security Incident Investigation Report with CVSS v3.1 and Evidence Breakdown
 */

import React, { useState } from 'react';
import { 
  FileText, 
  Download, 
  Printer, 
  ShieldAlert, 
  Sliders, 
  Clock, 
  CheckCircle2, 
  ExternalLink, 
  Copy, 
  Terminal,
  Cpu,
  Layers
} from 'lucide-react';
import { SecurityAlert } from '../types';

interface ReportsViewProps {
  alerts: SecurityAlert[];
  selectedAlert: SecurityAlert | null;
  onSelectAlert: (alert: SecurityAlert) => void;
}

export const ReportsView: React.FC<ReportsViewProps> = ({
  alerts,
  selectedAlert,
  onSelectAlert,
}) => {
  const currentAlert = selectedAlert || alerts[0];
  const [copiedMd, setCopiedMd] = useState(false);

  const generateMarkdownReport = (alert: SecurityAlert) => {
    const mitreStr = alert.mitreTechniques.map(t => `- **${t.id}**: ${t.name} (${t.tactic})`).join('\n');
    const iocStr = alert.iocs.map(i => `- **${i.type}**: \`${i.value}\` (Confidence: ${i.confidence}%, Actor: ${i.threatActor || 'Unknown'})`).join('\n');
    const eventsStr = alert.chainedEvents.map(e => `1. **[${e.timestamp}]** \`${e.sourceType.toUpperCase()}\`: ${e.message}`).join('\n');
    const recStr = alert.investigationResult?.recommendations.map(r => `### [${r.priority}] ${r.action}\n\`\`\`bash\n${r.commandSnippet || '# No script provided'}\n\`\`\``).join('\n\n') || 'Pending recommendations';

    return `# CYBERNEXSUS EDGE AI SOC INCIDENT REPORT
**Incident ID:** ${alert.id} (${alert.incidentId})  
**Classification Date:** ${new Date(alert.createdAt).toUTCString()}  
**Risk Score:** ${alert.riskScore}/100 | **Severity:** ${alert.severity}  
**Target Host:** \`${alert.affectedHost}\` | **Account:** \`${alert.affectedUser}\`  

---

## 1. Executive Summary
${alert.summary}

## 2. CVSS v3.1 Vulnerability & Threat Assessment
- **Base Score:** ${alert.cvss.baseScore} (${alert.cvss.severity})
- **Vector String:** \`${alert.cvss.vectorString}\`
- **Exploitability Sub-Score:** ${alert.cvss.exploitabilityScore}
- **Impact Sub-Score:** ${alert.cvss.impactScore}

## 3. MITRE ATT&CK Mapping
${mitreStr}

## 4. Local Edge AI Investigation (Snapdragon ${alert.investigationResult?.executionProvider || 'NPU'})
**Model:** ${alert.investigationResult?.modelUsed || 'Qwen2.5-Coder-1.5B (ONNX INT4)'}  
**Attack Hypothesis:**  
${alert.investigationResult?.attackHypothesis || 'Pending execution'}

### Root Cause & Attack Vector
- **Root Cause:** ${alert.investigationResult?.explanation.rootCause || 'N/A'}
- **Attack Vector:** ${alert.investigationResult?.explanation.attackVector || 'N/A'}
- **Potential Blast Radius:** ${alert.investigationResult?.explanation.potentialBlastRadius || 'N/A'}
- **Attacker Goal:** ${alert.investigationResult?.explanation.attackerGoal || 'N/A'}

## 5. Correlated Telemetry & Evidence Chain
${eventsStr}

## 6. Extracted Indicators of Compromise (IOCs)
${iocStr}

## 7. Containment & Remediation Playbooks
${recStr}

---
*Report generated locally on Snapdragon PC (Qualcomm Hexagon NPU). Zero telemetry leaked.*
`;
  };

  const handleDownloadMarkdown = () => {
    if (!currentAlert) return;
    const md = generateMarkdownReport(currentAlert);
    const blob = new Blob([md], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `CyberNexsus_Report_${currentAlert.id}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadJSON = () => {
    if (!currentAlert) return;
    const jsonStr = JSON.stringify(currentAlert, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `CyberNexsus_Report_${currentAlert.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopyMarkdown = () => {
    if (!currentAlert) return;
    const md = generateMarkdownReport(currentAlert);
    navigator.clipboard.writeText(md);
    setCopiedMd(true);
    setTimeout(() => setCopiedMd(false), 2000);
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <FileText className="w-7 h-7 text-cyan-400" />
            <span>CyberNexsus SOC Incident Reports</span>
          </h1>
          <p className="text-sm text-slate-400 font-mono mt-1">
            Standardized incident reporting with CVSS v3.1, MITRE ATT&CK, evidence, and AI remediation
          </p>
        </div>

        {/* Action buttons */}
        <div className="flex flex-wrap items-center gap-2.5 font-mono text-xs">
          <button
            onClick={handleCopyMarkdown}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 transition cursor-pointer flex items-center gap-1.5"
          >
            {copiedMd ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedMd ? 'Copied' : 'Copy MD'}</span>
          </button>

          <button
            onClick={handleDownloadMarkdown}
            className="px-3 py-1.5 rounded-lg bg-cyan-950 hover:bg-cyan-900 border border-cyan-800 text-cyan-300 transition cursor-pointer flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Markdown</span>
          </button>

          <button
            onClick={handleDownloadJSON}
            className="px-3 py-1.5 rounded-lg bg-indigo-950 hover:bg-indigo-900 border border-indigo-800 text-indigo-300 transition cursor-pointer flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </button>

          <button
            onClick={() => window.print()}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 transition cursor-pointer flex items-center gap-1.5"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print Report</span>
          </button>
        </div>
      </div>

      {/* Incident Switcher */}
      <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-3 flex items-center gap-3 font-mono text-xs">
        <span className="text-slate-400 pl-2">Select Report Incident:</span>
        <select
          value={currentAlert?.id}
          onChange={e => {
            const found = alerts.find(a => a.id === e.target.value);
            if (found) onSelectAlert(found);
          }}
          className="bg-[#080d16] border border-slate-700 rounded px-3 py-1 text-cyan-300 font-semibold focus:outline-none focus:border-cyan-500 cursor-pointer flex-1"
        >
          {alerts.map(a => (
            <option key={a.id} value={a.id}>
              {a.id}: {a.title} (Risk: {a.riskScore}/100 - {a.severity})
            </option>
          ))}
        </select>
      </div>

      {/* Main Formatted Report Document */}
      {currentAlert ? (
        <div className="bg-[#0c1322] border border-slate-800 rounded-2xl p-8 space-y-8 shadow-2xl print:bg-white print:text-black print:border-none">
          
          {/* Document Header */}
          <div className="border-b border-slate-800 pb-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 font-mono text-xs text-cyan-400 font-bold mb-1">
                <ShieldAlert className="w-4 h-4" />
                <span>CYBERNEXSUS EDGE SOC INCIDENT BRIEFING</span>
              </div>
              <h2 className="text-2xl font-black text-white">
                {currentAlert.title}
              </h2>
              <div className="text-xs font-mono text-slate-400 mt-1 flex flex-wrap items-center gap-3">
                <span>Incident Reference: <b>{currentAlert.incidentId}</b></span>
                <span>•</span>
                <span>Detected: {new Date(currentAlert.createdAt).toUTCString()}</span>
                <span>•</span>
                <span>Assigned: {currentAlert.assignedAnalyst || 'SOC Tier-2 Lead'}</span>
              </div>
            </div>

            {/* Score Pill in header */}
            <div className="flex items-center gap-3 self-start md:self-center">
              <div className="bg-[#080d16] border border-red-900/60 rounded-xl p-3 text-center min-w-[110px]">
                <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Risk Rating</div>
                <div className="text-2xl font-black font-mono text-red-400">{currentAlert.riskScore}<span className="text-xs text-slate-500">/100</span></div>
                <div className="text-[10px] font-mono font-bold text-red-300">{currentAlert.severity}</div>
              </div>

              <div className="bg-[#080d16] border border-cyan-900/60 rounded-xl p-3 text-center min-w-[110px]">
                <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">CVSS v3.1</div>
                <div className="text-2xl font-black font-mono text-amber-400">{currentAlert.cvss.baseScore}</div>
                <div className="text-[10px] font-mono text-amber-300">{currentAlert.cvss.severity}</div>
              </div>
            </div>
          </div>

          {/* Key Metrics & CVSS v3.1 Specification Details */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
            <div className="bg-[#080d16] p-4 rounded-xl border border-slate-800 space-y-1.5">
              <span className="text-slate-400 text-[11px]">AFFECTED INFRASTRUCTURE</span>
              <div className="text-sm font-bold text-white">{currentAlert.affectedHost}</div>
              <div className="text-slate-400">Account: <span className="text-indigo-300">{currentAlert.affectedUser}</span></div>
            </div>

            <div className="bg-[#080d16] p-4 rounded-xl border border-slate-800 space-y-1.5">
              <span className="text-slate-400 text-[11px]">CVSS 3.1 BASE VECTOR</span>
              <div className="text-xs font-mono text-amber-300 select-all truncate">{currentAlert.cvss.vectorString}</div>
              <div className="text-slate-400">Exploitability: {currentAlert.cvss.exploitabilityScore} | Impact: {currentAlert.cvss.impactScore}</div>
            </div>

            <div className="bg-[#080d16] p-4 rounded-xl border border-slate-800 space-y-1.5">
              <span className="text-slate-400 text-[11px]">PRIMARY MITRE TECHNIQUES</span>
              <div className="text-xs font-bold text-cyan-300 flex flex-wrap gap-1">
                {currentAlert.mitreTechniques.map(t => (
                  <span key={t.id} className="bg-cyan-950 px-1.5 py-0.5 rounded border border-cyan-800">
                    {t.id} ({t.name})
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Section 1: Synopsis */}
          <div className="space-y-2">
            <h3 className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider">
              1. Incident Synopsis & Triage Context
            </h3>
            <p className="text-sm text-slate-300 leading-relaxed font-sans bg-[#080d16] p-4 rounded-xl border border-slate-800">
              {currentAlert.summary}
            </p>
          </div>

          {/* Section 2: AI Investigation & Hypothesis */}
          {currentAlert.investigationResult && (
            <div className="space-y-4">
              <h3 className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider flex items-center justify-between">
                <span>2. Local AI Threat Investigation (Snapdragon {currentAlert.investigationResult.executionProvider} Engine)</span>
                <span className="text-slate-500 font-normal">{currentAlert.investigationResult.modelUsed}</span>
              </h3>

              <div className="bg-[#080d16] border border-cyan-950 p-5 rounded-xl space-y-3">
                <div className="text-xs font-mono font-semibold text-slate-400 uppercase">
                  Attack Hypothesis:
                </div>
                <p className="text-sm text-slate-200 leading-relaxed font-sans italic">
                  "{currentAlert.investigationResult.attackHypothesis}"
                </p>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-3 border-t border-slate-800 text-xs font-mono">
                  <div>
                    <span className="text-red-400 font-bold block mb-1">Identified Root Cause:</span>
                    <span className="text-slate-300">{currentAlert.investigationResult.explanation.rootCause}</span>
                  </div>
                  <div>
                    <span className="text-amber-400 font-bold block mb-1">Adversary Attack Vector:</span>
                    <span className="text-slate-300">{currentAlert.investigationResult.explanation.attackVector}</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Section 3: Evidence & Chained Events */}
          <div className="space-y-3">
            <h3 className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider">
              3. Chronological Forensic Evidence Table ({currentAlert.chainedEvents.length} Events)
            </h3>

            <div className="border border-slate-800 rounded-xl overflow-hidden font-mono text-xs">
              <table className="w-full text-left">
                <thead className="bg-[#080d16] text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="p-3">Timestamp (UTC)</th>
                    <th className="p-3">Source Parser</th>
                    <th className="p-3">Category</th>
                    <th className="p-3">Correlated Message / Process</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 bg-[#0c1322]">
                  {currentAlert.chainedEvents.map((evt, idx) => (
                    <tr key={idx} className="hover:bg-slate-900/60">
                      <td className="p-3 text-slate-400 whitespace-nowrap">{evt.timestamp}</td>
                      <td className="p-3 font-semibold uppercase text-cyan-300">{evt.sourceType}</td>
                      <td className="p-3 text-slate-300">{evt.eventCategory}</td>
                      <td className="p-3 text-slate-200">{evt.message}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Section 4: Extracted IOCs */}
          <div className="space-y-3">
            <h3 className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider">
              4. Extracted Threat Indicators (IOCs)
            </h3>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono text-xs">
              {currentAlert.iocs.map((ioc, idx) => (
                <div key={idx} className="bg-[#080d16] border border-slate-800 rounded-xl p-3.5 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400 text-[10px]">{ioc.type}</span>
                    <span className="text-cyan-400 font-bold">{ioc.confidence}% Confidence</span>
                  </div>
                  <div className="text-sm font-bold text-cyan-300 select-all">{ioc.value}</div>
                  <div className="text-[11px] text-slate-400">{ioc.context}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Section 5: Remediation Playbooks */}
          {currentAlert.investigationResult?.recommendations && (
            <div className="space-y-3">
              <h3 className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider">
                5. Remediation Playbooks & DFIR Containment Actions
              </h3>

              <div className="space-y-3 font-mono text-xs">
                {currentAlert.investigationResult.recommendations.map((rec, idx) => (
                  <div key={idx} className="bg-[#080d16] border border-slate-800 rounded-xl p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-red-400 font-bold">[{rec.priority}] {rec.action}</span>
                      <span className="text-slate-400 text-[10px]">{rec.type}</span>
                    </div>
                    {rec.commandSnippet && (
                      <pre className="bg-[#04060c] p-3 rounded-lg text-emerald-300 border border-slate-800 overflow-x-auto whitespace-pre-wrap select-all">
                        {rec.commandSnippet}
                      </pre>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Footer signature */}
          <div className="border-t border-slate-800 pt-6 text-xs font-mono text-slate-500 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <span>CyberNexsus Edge AI SOC • Snapdragon PC Qualcomm Hexagon NPU</span>
            <span>Security Operations Center • Air-Gapped Confidential</span>
          </div>

        </div>
      ) : null}

    </div>
  );
};
