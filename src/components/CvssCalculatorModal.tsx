/**
 * CyberNexsus Edge AI SOC - CVSS v3.1 Calculator Modal
 * Implements the FIRST.org CVSS v3.1 specification
 */

import React, { useState, useEffect } from 'react';
import { X, Sliders, CheckCircle2, Copy, ShieldAlert, Sparkles, RefreshCw } from 'lucide-react';
import { Cvss31Metrics, Cvss31Result, SecurityAlert } from '../types';
import { calculateCvss31, parseCvssVectorString, CVSS_METRIC_WEIGHTS, DEFAULT_HIGH_SEVERITY_METRICS } from '../utils/cvss31';

interface CvssCalculatorModalProps {
  isOpen: boolean;
  onClose: () => void;
  targetAlert: SecurityAlert | null;
  onApplyCvssToAlert?: (alertId: string, result: Cvss31Result) => void;
}

export const CvssCalculatorModal: React.FC<CvssCalculatorModalProps> = ({
  isOpen,
  onClose,
  targetAlert,
  onApplyCvssToAlert,
}) => {
  const [metrics, setMetrics] = useState<Cvss31Metrics>(
    targetAlert ? (parseCvssVectorString(targetAlert.cvss.vectorString) || DEFAULT_HIGH_SEVERITY_METRICS) : DEFAULT_HIGH_SEVERITY_METRICS
  );
  const [rawVectorInput, setRawVectorInput] = useState('');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (targetAlert) {
      const parsed = parseCvssVectorString(targetAlert.cvss.vectorString);
      if (parsed) setMetrics(parsed);
    }
  }, [targetAlert]);

  if (!isOpen) return null;

  const result = calculateCvss31(metrics);

  const handleApplyVector = () => {
    const parsed = parseCvssVectorString(rawVectorInput.trim());
    if (parsed) {
      setMetrics(parsed);
      setRawVectorInput('');
    }
  };

  const handleCopyVector = () => {
    navigator.clipboard.writeText(result.vectorString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleApplyToAlert = () => {
    if (targetAlert && onApplyCvssToAlert) {
      onApplyCvssToAlert(targetAlert.id, result);
      onClose();
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-[#0b111e] border border-cyan-800/80 rounded-2xl w-full max-w-4xl max-h-[90vh] overflow-y-auto shadow-2xl space-y-5 p-6">
        
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400">
              <Sliders className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <span>CVSS v3.1 Standards Calculator</span>
                <span className="text-xs font-mono font-normal text-slate-400">FIRST.org Spec</span>
              </h2>
              <p className="text-xs text-slate-400 font-mono">
                {targetAlert ? `Calibrating metrics for incident: ${targetAlert.id} (${targetAlert.title})` : 'Standalone metric evaluation'}
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

        {/* Live Score Summary Banner */}
        <div className="bg-gradient-to-r from-[#070b14] to-[#0f172a] border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="text-center bg-[#070b14] border border-cyan-800/80 rounded-xl px-5 py-3">
              <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">CVSS Base Score</div>
              <div className="text-3xl font-black font-mono text-amber-400">{result.baseScore}</div>
              <div className="text-xs font-mono font-bold text-amber-300">{result.severity}</div>
            </div>

            <div className="space-y-1 font-mono text-xs">
              <div className="text-slate-300">
                Exploitability Sub-Score: <b className="text-cyan-300">{result.exploitabilityScore}</b>
              </div>
              <div className="text-slate-300">
                Impact Sub-Score: <b className="text-purple-300">{result.impactScore}</b>
              </div>
              <div className="text-slate-300">
                SOC Operational Risk: <b className="text-red-400">{result.riskScore}/100</b>
              </div>
            </div>
          </div>

          {/* Vector String copy & load */}
          <div className="w-full md:w-auto space-y-2 font-mono text-xs">
            <div className="flex items-center gap-2 bg-[#050811] p-2.5 rounded-lg border border-slate-800">
              <code className="text-amber-300 text-[11px] select-all">{result.vectorString}</code>
              <button
                onClick={handleCopyVector}
                className="text-cyan-400 hover:text-cyan-300 ml-auto cursor-pointer"
                title="Copy Vector String"
              >
                {copied ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>

            <div className="flex items-center gap-1.5">
              <input
                type="text"
                placeholder="Paste CVSS:3.1/AV:N/AC:L/..."
                value={rawVectorInput}
                onChange={e => setRawVectorInput(e.target.value)}
                className="flex-1 bg-[#050811] border border-slate-800 rounded px-2.5 py-1 text-[11px] text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500"
              />
              <button
                onClick={handleApplyVector}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] cursor-pointer"
              >
                Load
              </button>
            </div>
          </div>
        </div>

        {/* Metrics Form */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 font-mono text-xs">
          
          {/* Exploitability Metrics Group */}
          <div className="bg-[#080d16] p-4 rounded-xl border border-slate-800 space-y-4">
            <h3 className="font-bold text-cyan-300 uppercase tracking-wider text-xs border-b border-slate-800 pb-2">
              Exploitability Metrics
            </h3>

            {/* Attack Vector */}
            <div className="space-y-1.5">
              <div className="flex justify-between text-slate-300">
                <span>Attack Vector (AV)</span>
                <span className="text-cyan-400 font-bold">{metrics.attackVector}</span>
              </div>
              <div className="grid grid-cols-4 gap-1.5">
                {(['N', 'A', 'L', 'P'] as const).map(val => (
                  <button
                    key={val}
                    onClick={() => setMetrics(m => ({ ...m, attackVector: val }))}
                    className={`py-1.5 rounded text-center transition cursor-pointer border ${
                      metrics.attackVector === val
                        ? 'bg-cyan-600 text-white border-cyan-400 font-bold'
                        : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {val === 'N' ? 'Net (N)' : val === 'A' ? 'Adj (A)' : val === 'L' ? 'Loc (L)' : 'Phys (P)'}
                  </button>
                ))}
              </div>
            </div>

            {/* Attack Complexity */}
            <div className="space-y-1.5">
              <div className="flex justify-between text-slate-300">
                <span>Attack Complexity (AC)</span>
                <span className="text-cyan-400 font-bold">{metrics.attackComplexity}</span>
              </div>
              <div className="grid grid-cols-2 gap-2">
                {(['L', 'H'] as const).map(val => (
                  <button
                    key={val}
                    onClick={() => setMetrics(m => ({ ...m, attackComplexity: val }))}
                    className={`py-1.5 rounded text-center transition cursor-pointer border ${
                      metrics.attackComplexity === val
                        ? 'bg-cyan-600 text-white border-cyan-400 font-bold'
                        : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {val === 'L' ? 'Low (L)' : 'High (H)'}
                  </button>
                ))}
              </div>
            </div>

            {/* Privileges Required */}
            <div className="space-y-1.5">
              <div className="flex justify-between text-slate-300">
                <span>Privileges Required (PR)</span>
                <span className="text-cyan-400 font-bold">{metrics.privilegesRequired}</span>
              </div>
              <div className="grid grid-cols-3 gap-1.5">
                {(['N', 'L', 'H'] as const).map(val => (
                  <button
                    key={val}
                    onClick={() => setMetrics(m => ({ ...m, privilegesRequired: val }))}
                    className={`py-1.5 rounded text-center transition cursor-pointer border ${
                      metrics.privilegesRequired === val
                        ? 'bg-cyan-600 text-white border-cyan-400 font-bold'
                        : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {val === 'N' ? 'None (N)' : val === 'L' ? 'Low (L)' : 'High (H)'}
                  </button>
                ))}
              </div>
            </div>

            {/* User Interaction */}
            <div className="space-y-1.5">
              <div className="flex justify-between text-slate-300">
                <span>User Interaction (UI)</span>
                <span className="text-cyan-400 font-bold">{metrics.userInteraction}</span>
              </div>
              <div className="grid grid-cols-2 gap-2">
                {(['N', 'R'] as const).map(val => (
                  <button
                    key={val}
                    onClick={() => setMetrics(m => ({ ...m, userInteraction: val }))}
                    className={`py-1.5 rounded text-center transition cursor-pointer border ${
                      metrics.userInteraction === val
                        ? 'bg-cyan-600 text-white border-cyan-400 font-bold'
                        : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {val === 'N' ? 'None (N)' : 'Required (R)'}
                  </button>
                ))}
              </div>
            </div>

            {/* Scope */}
            <div className="space-y-1.5">
              <div className="flex justify-between text-slate-300">
                <span>Scope (S)</span>
                <span className="text-amber-400 font-bold">{metrics.scope}</span>
              </div>
              <div className="grid grid-cols-2 gap-2">
                {(['U', 'C'] as const).map(val => (
                  <button
                    key={val}
                    onClick={() => setMetrics(m => ({ ...m, scope: val }))}
                    className={`py-1.5 rounded text-center transition cursor-pointer border ${
                      metrics.scope === val
                        ? 'bg-amber-600 text-white border-amber-400 font-bold'
                        : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {val === 'U' ? 'Unchanged (U)' : 'Changed (C)'}
                  </button>
                ))}
              </div>
            </div>

          </div>

          {/* Impact Metrics Group */}
          <div className="bg-[#080d16] p-4 rounded-xl border border-slate-800 space-y-4">
            <h3 className="font-bold text-purple-300 uppercase tracking-wider text-xs border-b border-slate-800 pb-2">
              Impact Metrics
            </h3>

            {/* Confidentiality */}
            <div className="space-y-1.5">
              <div className="flex justify-between text-slate-300">
                <span>Confidentiality (C)</span>
                <span className="text-purple-400 font-bold">{metrics.confidentiality}</span>
              </div>
              <div className="grid grid-cols-3 gap-1.5">
                {(['N', 'L', 'H'] as const).map(val => (
                  <button
                    key={val}
                    onClick={() => setMetrics(m => ({ ...m, confidentiality: val }))}
                    className={`py-1.5 rounded text-center transition cursor-pointer border ${
                      metrics.confidentiality === val
                        ? 'bg-purple-600 text-white border-purple-400 font-bold'
                        : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {val === 'N' ? 'None (N)' : val === 'L' ? 'Low (L)' : 'High (H)'}
                  </button>
                ))}
              </div>
            </div>

            {/* Integrity */}
            <div className="space-y-1.5">
              <div className="flex justify-between text-slate-300">
                <span>Integrity (I)</span>
                <span className="text-purple-400 font-bold">{metrics.integrity}</span>
              </div>
              <div className="grid grid-cols-3 gap-1.5">
                {(['N', 'L', 'H'] as const).map(val => (
                  <button
                    key={val}
                    onClick={() => setMetrics(m => ({ ...m, integrity: val }))}
                    className={`py-1.5 rounded text-center transition cursor-pointer border ${
                      metrics.integrity === val
                        ? 'bg-purple-600 text-white border-purple-400 font-bold'
                        : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {val === 'N' ? 'None (N)' : val === 'L' ? 'Low (L)' : 'High (H)'}
                  </button>
                ))}
              </div>
            </div>

            {/* Availability */}
            <div className="space-y-1.5">
              <div className="flex justify-between text-slate-300">
                <span>Availability (A)</span>
                <span className="text-purple-400 font-bold">{metrics.availability}</span>
              </div>
              <div className="grid grid-cols-3 gap-1.5">
                {(['N', 'L', 'H'] as const).map(val => (
                  <button
                    key={val}
                    onClick={() => setMetrics(m => ({ ...m, availability: val }))}
                    className={`py-1.5 rounded text-center transition cursor-pointer border ${
                      metrics.availability === val
                        ? 'bg-purple-600 text-white border-purple-400 font-bold'
                        : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {val === 'N' ? 'None (N)' : val === 'L' ? 'Low (L)' : 'High (H)'}
                  </button>
                ))}
              </div>
            </div>

            {/* Preset quick buttons */}
            <div className="pt-4 border-t border-slate-800">
              <div className="text-[11px] text-slate-400 mb-2">Predefined Threat Profiles:</div>
              <div className="flex flex-wrap gap-2">
                <button
                  onClick={() => setMetrics({ attackVector: 'N', attackComplexity: 'L', privilegesRequired: 'N', userInteraction: 'N', scope: 'U', confidentiality: 'H', integrity: 'H', availability: 'H' })}
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-[10px] text-slate-300 cursor-pointer"
                >
                  Remote Root Takeover (9.8)
                </button>
                <button
                  onClick={() => setMetrics({ attackVector: 'L', attackComplexity: 'L', privilegesRequired: 'L', userInteraction: 'N', scope: 'C', confidentiality: 'H', integrity: 'H', availability: 'H' })}
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-[10px] text-slate-300 cursor-pointer"
                >
                  Ransomware Staging (8.8)
                </button>
              </div>
            </div>

          </div>

        </div>

        {/* Modal Actions */}
        <div className="border-t border-slate-800 pt-4 flex items-center justify-between font-mono text-xs">
          <button
            onClick={() => setMetrics(DEFAULT_HIGH_SEVERITY_METRICS)}
            className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition cursor-pointer flex items-center gap-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Reset to High Baseline</span>
          </button>

          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 transition cursor-pointer"
            >
              Close
            </button>
            {targetAlert && (
              <button
                onClick={handleApplyToAlert}
                className="px-5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-bold transition cursor-pointer shadow-md shadow-cyan-600/30"
              >
                Apply Score ({result.baseScore}) to {targetAlert.id}
              </button>
            )}
          </div>
        </div>

      </div>
    </div>
  );
};
