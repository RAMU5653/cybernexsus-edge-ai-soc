/**
 * CyberNexsus Edge AI SOC - Telegram Configuration & Dispatch Log Modal
 */

import React, { useState } from 'react';
import { X, Send, CheckCircle2, AlertTriangle, MessageSquare, ShieldAlert, History, Copy } from 'lucide-react';
import { TelegramConfig, TelegramDispatchLog, SecurityAlert } from '../types';
import { TelegramService } from '../services/telegramService';

interface TelegramConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  alerts: SecurityAlert[];
  targetAlert: SecurityAlert | null;
}

export const TelegramConfigModal: React.FC<TelegramConfigModalProps> = ({
  isOpen,
  onClose,
  alerts,
  targetAlert,
}) => {
  const [config, setConfig] = useState<TelegramConfig>(TelegramService.getConfig());
  const [logs, setLogs] = useState<TelegramDispatchLog[]>(TelegramService.getDispatchLogs());
  const [dispatchStatus, setDispatchStatus] = useState<string | null>(null);
  const [isSending, setIsSending] = useState(false);
  const [activeTab, setActiveTab] = useState<'config' | 'logs'>('config');

  if (!isOpen) return null;

  const currentAlert = targetAlert || alerts[0];

  const handleSaveConfig = () => {
    TelegramService.saveConfig(config);
    setDispatchStatus('Configuration successfully saved to local encrypted vault.');
    setTimeout(() => setDispatchStatus(null), 3000);
  };

  const handleTestDispatch = async () => {
    if (!currentAlert) return;
    setIsSending(true);
    setDispatchStatus(null);

    try {
      const res = await TelegramService.dispatchAlert(currentAlert, config);
      setDispatchStatus(res.message);
      setLogs(TelegramService.getDispatchLogs());
    } finally {
      setIsSending(false);
    }
  };

  const previewPayload = currentAlert ? TelegramService.formatAlertMessage(currentAlert, config) : '';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-[#0b111e] border border-cyan-800/80 rounded-2xl w-full max-w-3xl max-h-[90vh] overflow-y-auto shadow-2xl space-y-5 p-6">
        
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-sky-500/10 border border-sky-500/30 text-sky-400">
              <Send className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <span>Telegram SOC Alert Dispatcher</span>
                <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-sky-950 text-sky-300 border border-sky-800">
                  REAL-TIME DISPATCH
                </span>
              </h2>
              <p className="text-xs text-slate-400 font-mono">
                Forward high-severity incidents, CVSS v3.1 metrics, and local AI hypotheses to Telegram
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

        {/* Tab switcher */}
        <div className="flex items-center space-x-2 border-b border-slate-800 pb-2 font-mono text-xs">
          <button
            onClick={() => setActiveTab('config')}
            className={`px-3 py-1.5 rounded-lg font-bold transition cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'config'
                ? 'bg-sky-600 text-white'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <MessageSquare className="w-3.5 h-3.5" />
            <span>Bot Configuration & Preview</span>
          </button>

          <button
            onClick={() => setActiveTab('logs')}
            className={`px-3 py-1.5 rounded-lg font-bold transition cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'logs'
                ? 'bg-sky-600 text-white'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <History className="w-3.5 h-3.5" />
            <span>Dispatch Log History ({logs.length})</span>
          </button>
        </div>

        {activeTab === 'config' ? (
          <div className="space-y-4 font-mono text-xs">
            
            {/* Bot credentials */}
            <div className="bg-[#080d16] border border-slate-800 p-4 rounded-xl space-y-3">
              <div className="font-bold text-white uppercase tracking-wider text-xs">
                Telegram Bot API Credentials
              </div>
              <p className="text-slate-400 text-[11px] font-sans">
                Enter your Telegram Bot Token and Chat ID to send real alerts directly to your channel. If left blank, CyberNexsus operates in high-fidelity on-device simulation mode.
              </p>

              <div className="space-y-2">
                <div>
                  <label className="text-slate-400 block mb-1">Bot Token (from @BotFather):</label>
                  <input
                    type="password"
                    placeholder="e.g. 7192837482:AAHdk28dks..."
                    value={config.botToken}
                    onChange={e => setConfig({ ...config, botToken: e.target.value })}
                    className="w-full bg-[#050811] border border-slate-800 rounded px-3 py-2 text-white font-mono text-xs focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="text-slate-400 block mb-1">Chat ID or Channel Handle:</label>
                  <input
                    type="text"
                    placeholder="e.g. -10019283749 or @MySecurityChannel"
                    value={config.chatId}
                    onChange={e => setConfig({ ...config, chatId: e.target.value })}
                    className="w-full bg-[#050811] border border-slate-800 rounded px-3 py-2 text-white font-mono text-xs focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              {/* Toggles */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-2 border-t border-slate-800">
                <label className="flex items-center space-x-2 text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={config.includeCvssDetails}
                    onChange={e => setConfig({ ...config, includeCvssDetails: e.target.checked })}
                    className="rounded bg-slate-900 border-slate-700 text-cyan-500"
                  />
                  <span>Include CVSS v3.1 vector & scores</span>
                </label>

                <label className="flex items-center space-x-2 text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={config.includeMitreTags}
                    onChange={e => setConfig({ ...config, includeMitreTags: e.target.checked })}
                    className="rounded bg-slate-900 border-slate-700 text-cyan-500"
                  />
                  <span>Include MITRE ATT&CK technique tags</span>
                </label>
              </div>
            </div>

            {/* Live Message Payload Preview */}
            <div className="space-y-2">
              <div className="flex items-center justify-between text-slate-400">
                <span className="font-bold text-white uppercase">Live Payload Preview for {currentAlert?.id}</span>
                <span className="text-[10px]">HTML Formatted</span>
              </div>
              <pre className="bg-[#050811] border border-slate-800 p-3.5 rounded-xl text-sky-200 text-xs max-h-48 overflow-y-auto whitespace-pre-wrap select-all">
                {previewPayload}
              </pre>
            </div>

            {/* Status alert */}
            {dispatchStatus && (
              <div className="p-3 rounded-lg bg-emerald-950/80 border border-emerald-700 text-emerald-300 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 shrink-0" />
                <span>{dispatchStatus}</span>
              </div>
            )}

            {/* Action Bar */}
            <div className="flex items-center justify-between pt-3 border-t border-slate-800">
              <button
                onClick={handleSaveConfig}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white font-bold transition cursor-pointer"
              >
                Save Settings
              </button>

              <button
                onClick={handleTestDispatch}
                disabled={isSending}
                className="px-5 py-2 rounded-lg bg-gradient-to-r from-sky-600 to-blue-600 hover:from-sky-500 hover:to-blue-500 text-white font-bold transition cursor-pointer flex items-center gap-2 disabled:opacity-50 shadow-md shadow-sky-500/25"
              >
                <Send className="w-3.5 h-3.5" />
                <span>{isSending ? 'Dispatching...' : `Dispatch Alert (${currentAlert?.id})`}</span>
              </button>
            </div>

          </div>
        ) : (
          /* Logs Tab */
          <div className="space-y-3 font-mono text-xs">
            {logs.length === 0 ? (
              <div className="bg-[#080d16] p-12 text-center text-slate-500 rounded-xl border border-slate-800">
                No Telegram dispatches recorded yet. Use the "Dispatch Alert" button to initiate.
              </div>
            ) : (
              <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
                {logs.map(log => (
                  <div key={log.id} className="bg-[#080d16] border border-slate-800 p-3.5 rounded-xl space-y-1.5">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-cyan-400">{log.alertId}</span>
                        <span className={`px-2 py-0.2 rounded text-[10px] font-bold ${
                          log.status === 'SUCCESS' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' :
                          log.status === 'SIMULATED' ? 'bg-sky-950 text-sky-300 border border-sky-800' :
                          'bg-red-950 text-red-300 border border-red-800'
                        }`}>
                          {log.status}
                        </span>
                      </div>
                      <span className="text-[10px] text-slate-500">{new Date(log.sentAt).toLocaleString()}</span>
                    </div>

                    <div className="text-white font-semibold">{log.alertTitle}</div>
                    <div className="text-[11px] text-slate-400">Recipient: <code className="text-sky-300">{log.recipientChatId}</code></div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

      </div>
    </div>
  );
};
