/**
 * CyberNexsus Edge AI SOC - Main Application Entrypoint
 * Local-First AI Security Investigation Platform
 * Architecture: Snapdragon PC NPU/GPU/CPU + ONNX Runtime/QNN + CVSS v3.1 + MITRE ATT&CK
 */

import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { TelemetryBanner } from './components/TelemetryBanner';
import { AlertsView } from './components/AlertsView';
import { ThreatTimelineView } from './components/ThreatTimelineView';
import { MitreAttackView } from './components/MitreAttackView';
import { AiInvestigationWorkbench } from './components/AiInvestigationWorkbench';
import { EventNormalizerView } from './components/EventNormalizerView';
import { ReportsView } from './components/ReportsView';
import { CvssCalculatorModal } from './components/CvssCalculatorModal';
import { ModelManagerModal } from './components/ModelManagerModal';
import { TelegramConfigModal } from './components/TelegramConfigModal';

import { 
  SecurityAlert, 
  NormalizedSecurityEvent, 
  LocalModelInfo, 
  HardwareExecutionProvider, 
  HardwareTelemetry,
  Cvss31Result,
  AiInvestigationResult 
} from './types';
import { INITIAL_ALERTS, INITIAL_EVENTS, LOCAL_MODELS_CATALOG, INITIAL_IOCS } from './data/mockData';
import { LocalAiEngine } from './services/localAiEngine';

export default function App() {
  // Navigation
  const [activeTab, setActiveTab] = useState<string>('alerts');

  // Core Data State
  const [isLiveMode, setIsLiveMode] = useState<boolean>(false);
  const [alerts, setAlerts] = useState<SecurityAlert[]>(INITIAL_ALERTS);
  const [events, setEvents] = useState<NormalizedSecurityEvent[]>(INITIAL_EVENTS);
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(INITIAL_ALERTS[0]);

  const handleToggleLiveMode = () => {
    if (!isLiveMode) {
      // Switching to LIVE REAL PC MODE -> Purge mock data
      setAlerts([]);
      setEvents([]);
      setSelectedAlert(null);
      setIsLiveMode(true);
    } else {
      // Switching back to demo mode -> Load demo threats
      setAlerts(INITIAL_ALERTS);
      setEvents(INITIAL_EVENTS);
      setSelectedAlert(INITIAL_ALERTS[0]);
      setIsLiveMode(false);
    }
  };

  const handleResetDemoData = () => {
    setAlerts(INITIAL_ALERTS);
    setEvents(INITIAL_EVENTS);
    setSelectedAlert(INITIAL_ALERTS[0]);
    setIsLiveMode(false);
  };

  // Edge Hardware & Model State
  const [models, setModels] = useState<LocalModelInfo[]>(LOCAL_MODELS_CATALOG);
  const [activeModel, setActiveModel] = useState<LocalModelInfo>(LOCAL_MODELS_CATALOG[0]);
  const [executionProvider, setExecutionProvider] = useState<HardwareExecutionProvider>('NPU');
  const [telemetry, setTelemetry] = useState<HardwareTelemetry>(LocalAiEngine.getTelemetry('NPU'));

  // Modals
  const [isCvssModalOpen, setIsCvssModalOpen] = useState(false);
  const [isModelManagerOpen, setIsModelManagerOpen] = useState(false);
  const [isTelegramModalOpen, setIsTelegramModalOpen] = useState(false);
  const [cvssTargetAlert, setCvssTargetAlert] = useState<SecurityAlert | null>(null);

  // Periodic telemetry update to reflect realistic edge activity
  useEffect(() => {
    const timer = setInterval(() => {
      setTelemetry(LocalAiEngine.getTelemetry(executionProvider));
    }, 4000);
    return () => clearInterval(timer);
  }, [executionProvider]);

  const handleProviderChange = (provider: HardwareExecutionProvider) => {
    setExecutionProvider(provider);
    setTelemetry(LocalAiEngine.getTelemetry(provider));
  };

  const handleSelectAlertForInvestigation = (alert: SecurityAlert) => {
    setSelectedAlert(alert);
    setActiveTab('investigation');
  };

  const handleViewTimeline = (alert: SecurityAlert) => {
    setSelectedAlert(alert);
    setActiveTab('timeline');
  };

  const handleOpenCvssForAlert = (alert: SecurityAlert) => {
    setCvssTargetAlert(alert);
    setIsCvssModalOpen(true);
  };

  const handleDispatchTelegram = (alert: SecurityAlert) => {
    setSelectedAlert(alert);
    setIsTelegramModalOpen(true);
  };

  const handleGenerateReport = (alert: SecurityAlert) => {
    setSelectedAlert(alert);
    setActiveTab('reports');
  };

  const handleUpdateAlertStatus = (alertId: string, status: SecurityAlert['status']) => {
    setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, status } : a));
    if (selectedAlert?.id === alertId) {
      setSelectedAlert(prev => prev ? { ...prev, status } : null);
    }
  };

  const handleApplyCvssToAlert = (alertId: string, result: Cvss31Result) => {
    setAlerts(prev => prev.map(a => {
      if (a.id === alertId) {
        return {
          ...a,
          cvss: result,
          severity: result.severity,
          riskScore: result.riskScore,
        };
      }
      return a;
    }));

    if (selectedAlert?.id === alertId) {
      setSelectedAlert(prev => prev ? {
        ...prev,
        cvss: result,
        severity: result.severity,
        riskScore: result.riskScore,
      } : null);
    }
  };

  const handleSaveInvestigationResult = (alertId: string, result: AiInvestigationResult) => {
    setAlerts(prev => prev.map(a => {
      if (a.id === alertId) {
        return {
          ...a,
          investigationResult: result,
          status: 'INVESTIGATING',
        };
      }
      return a;
    }));

    if (selectedAlert?.id === alertId) {
      setSelectedAlert(prev => prev ? {
        ...prev,
        investigationResult: result,
        status: 'INVESTIGATING',
      } : null);
    }
  };

  const handleIngestNewEvents = (newEvents: NormalizedSecurityEvent[], newAlerts: SecurityAlert[]) => {
    setEvents(prev => [...newEvents, ...prev]);
    if (newAlerts.length > 0) {
      // Merge unique alerts
      setAlerts(prev => {
        const existingIds = new Set(prev.map(a => a.id));
        const toAdd = newAlerts.filter(a => !existingIds.has(a.id));
        return [...toAdd, ...prev];
      });
    }
  };

  const handleUpdateModel = (updatedModel: LocalModelInfo) => {
    setModels(prev => prev.map(m => m.id === updatedModel.id ? updatedModel : m));
    if (activeModel.id === updatedModel.id) {
      setActiveModel(updatedModel);
    }
  };

  const criticalCount = alerts.filter(a => a.severity === 'CRITICAL').length;

  return (
    <div className="min-h-screen bg-[#080c14] text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      
      {/* Top Main Navigation Header */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        telemetry={telemetry}
        activeModel={activeModel}
        onOpenModelManager={() => setIsModelManagerOpen(true)}
        onOpenCvssCalculator={() => {
          setCvssTargetAlert(selectedAlert || alerts[0] || null);
          setIsCvssModalOpen(true);
        }}
        onOpenTelegramConfig={() => setIsTelegramModalOpen(true)}
        criticalAlertCount={criticalCount}
        isLiveMode={isLiveMode}
        onToggleLiveMode={handleToggleLiveMode}
        onResetDemoData={handleResetDemoData}
      />

      {/* Real-time Edge Hardware Telemetry Banner */}
      <TelemetryBanner
        telemetry={telemetry}
        activeModel={activeModel}
        onProviderChange={handleProviderChange}
        onOpenModelManager={() => setIsModelManagerOpen(true)}
      />

      {/* Main Tabbed Views */}
      <main className="flex-1 pb-16">
        {activeTab === 'alerts' && (
          <AlertsView
            alerts={alerts}
            onSelectAlertForInvestigation={handleSelectAlertForInvestigation}
            onViewTimeline={handleViewTimeline}
            onOpenCvssForAlert={handleOpenCvssForAlert}
            onDispatchTelegram={handleDispatchTelegram}
            onGenerateReport={handleGenerateReport}
            onUpdateAlertStatus={handleUpdateAlertStatus}
          />
        )}

        {activeTab === 'timeline' && (
          <ThreatTimelineView
            events={events}
            alerts={alerts}
            selectedAlert={selectedAlert}
            onSelectAlert={setSelectedAlert}
            onInvestigateAlert={handleSelectAlertForInvestigation}
          />
        )}

        {activeTab === 'mitre' && (
          <MitreAttackView
            alerts={alerts}
            onSelectAlert={handleSelectAlertForInvestigation}
          />
        )}

        {activeTab === 'investigation' && (
          <AiInvestigationWorkbench
            alerts={alerts}
            selectedAlert={selectedAlert}
            onSelectAlert={setSelectedAlert}
            activeModel={activeModel}
            models={models}
            onSelectModel={setActiveModel}
            telemetry={telemetry}
            executionProvider={executionProvider}
            onProviderChange={handleProviderChange}
            onSaveInvestigationResult={handleSaveInvestigationResult}
            onGenerateReport={handleGenerateReport}
          />
        )}

        {activeTab === 'normalizer' && (
          <EventNormalizerView
            events={events}
            onIngestNewEvents={handleIngestNewEvents}
            iocs={INITIAL_IOCS}
          />
        )}

        {activeTab === 'reports' && (
          <ReportsView
            alerts={alerts}
            selectedAlert={selectedAlert}
            onSelectAlert={setSelectedAlert}
          />
        )}
      </main>

      {/* Modal Dialogs */}
      <CvssCalculatorModal
        isOpen={isCvssModalOpen}
        onClose={() => setIsCvssModalOpen(false)}
        targetAlert={cvssTargetAlert}
        onApplyCvssToAlert={handleApplyCvssToAlert}
      />

      <ModelManagerModal
        isOpen={isModelManagerOpen}
        onClose={() => setIsModelManagerOpen(false)}
        models={models}
        activeModel={activeModel}
        onSelectActiveModel={setActiveModel}
        onUpdateModel={handleUpdateModel}
        executionProvider={executionProvider}
        onProviderChange={handleProviderChange}
      />

      <TelegramConfigModal
        isOpen={isTelegramModalOpen}
        onClose={() => setIsTelegramModalOpen(false)}
        alerts={alerts}
        targetAlert={selectedAlert}
      />

    </div>
  );
}
