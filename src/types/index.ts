/**
 * CyberNexsus Edge AI SOC - Type Definitions
 * Architecture: Snapdragon PC Local-First AI Security Platform
 */

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

export type LogSourceType = 
  | 'windows_event' 
  | 'sysmon' 
  | 'linux_auth' 
  | 'linux_syslog' 
  | 'zeek' 
  | 'suricata' 
  | 'splunk';

export interface NormalizedSecurityEvent {
  id: string;
  timestamp: string;
  sourceType: LogSourceType;
  rawLog: string;
  hostname: string;
  username?: string;
  srcIp?: string;
  srcPort?: number;
  dstIp?: string;
  dstPort?: number;
  processName?: string;
  processId?: number;
  parentProcessName?: string;
  commandLine?: string;
  hashes?: {
    md5?: string;
    sha256?: string;
  };
  eventCategory: 'AUTHENTICATION' | 'PROCESS_EXECUTION' | 'NETWORK_CONNECTION' | 'PRIVILEGE_ESCALATION' | 'PERSISTENCE' | 'DEFENSE_EVASION' | 'EXFILTRATION';
  eventId?: number | string;
  message: string;
  severity: SeverityLevel;
  tags: string[];
  dedupHash: string;
  correlationId?: string;
}

// CVSS v3.1 Metric Values according to FIRST.org Standard
export interface Cvss31Metrics {
  // Exploitability Metrics
  attackVector: 'N' | 'A' | 'L' | 'P'; // Network, Adjacent, Local, Physical
  attackComplexity: 'L' | 'H'; // Low, High
  privilegesRequired: 'N' | 'L' | 'H'; // None, Low, High
  userInteraction: 'N' | 'R'; // None, Required
  scope: 'U' | 'C'; // Unchanged, Changed
  
  // Impact Metrics
  confidentiality: 'N' | 'L' | 'H'; // None, Low, High
  integrity: 'N' | 'L' | 'H'; // None, Low, High
  availability: 'N' | 'L' | 'H'; // None, Low, High
}

export interface Cvss31Result {
  baseScore: number;
  severity: SeverityLevel;
  vectorString: string;
  exploitabilityScore: number;
  impactScore: number;
  riskScore: number; // 0 - 100 SOC operational risk
}

export interface MitreTechniqueRef {
  id: string; // e.g. T1110, T1059.001
  name: string;
  tactic: 'Initial Access' | 'Execution' | 'Persistence' | 'Privilege Escalation' | 'Defense Evasion' | 'Credential Access' | 'Discovery' | 'Lateral Movement' | 'Collection' | 'Command and Control' | 'Exfiltration' | 'Impact';
  description: string;
  detection: string;
}

export interface SecurityIOC {
  type: 'IP' | 'DOMAIN' | 'HASH_SHA256' | 'HASH_MD5' | 'FILE_PATH' | 'MUTEX' | 'COMMAND_PATTERN';
  value: string;
  threatActor?: string;
  malwareFamily?: string;
  confidence: number; // 0 - 100
  firstSeen: string;
  context: string;
}

export interface SecurityAlert {
  id: string;
  title: string;
  incidentId: string;
  severity: SeverityLevel;
  riskScore: number; // 0 - 100
  cvss: Cvss31Result;
  status: 'NEW' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'FALSE_POSITIVE';
  createdAt: string;
  affectedHost: string;
  affectedUser: string;
  mitreTactics: string[];
  mitreTechniques: MitreTechniqueRef[];
  matchedRules: string[];
  chainedEvents: NormalizedSecurityEvent[];
  iocs: SecurityIOC[];
  summary: string;
  investigationResult?: AiInvestigationResult;
  assignedAnalyst?: string;
}

// Local Snapdragon Edge AI Types
export type HardwareExecutionProvider = 'NPU' | 'GPU' | 'CPU';

export interface LocalModelInfo {
  id: string;
  name: string;
  family: 'Qwen' | 'Phi' | 'DeepSeek' | 'Mistral';
  version: string;
  sizeBytes: number;
  formattedSize: string;
  quantization: 'INT4' | 'INT8' | 'FP16';
  format: 'ONNX/QNN' | 'GGUF' | 'WebGPU';
  contextWindow: number;
  downloaded: boolean;
  downloadProgress: number; // 0 - 100
  speedMBps?: number;
  cachedInBrowser: boolean;
  description: string;
  recommendedHardware: HardwareExecutionProvider;
  npuOptimized: boolean;
}

export interface HardwareTelemetry {
  target: HardwareExecutionProvider;
  npuModel: string; // Snapdragon Hexagon NPU (45 TOPS)
  npuUtilizationPercent: number;
  npuTopsActive: number;
  gpuUtilizationPercent: number;
  cpuUtilizationPercent: number;
  temperatureCelsius: number;
  powerDrawWatts: number; // Snapdragon 15W TDP profile
  ramUsageMB: number;
  ramTotalMB: number;
  inferenceTokPerSec: number;
  inferenceLatencyMs: number;
}

export interface AiInvestigationResult {
  id: string;
  alertId: string;
  modelUsed: string;
  executionProvider: HardwareExecutionProvider;
  generatedAt: string;
  inferenceDurationMs: number;
  tokensGenerated: number;
  tokensPerSec: number;
  confidenceScore: number; // 0 - 100
  
  // Investigation sections
  attackHypothesis: string;
  iocExtraction: {
    indicator: string;
    type: string;
    maliciousLikelihood: 'CRITICAL' | 'HIGH' | 'SUSPICIOUS' | 'BENIGN';
    action: string;
  }[];
  eventCorrelationNarrative: string;
  mitreMappingAnalysis: {
    techniqueId: string;
    techniqueName: string;
    tactic: string;
    evidenceFound: string;
  }[];
  explanation: {
    rootCause: string;
    attackVector: string;
    potentialBlastRadius: string;
    attackerGoal: string;
  };
  recommendations: {
    priority: 'IMMEDIATE' | 'HIGH' | 'MEDIUM';
    action: string;
    type: 'HOST_ISOLATION' | 'FIREWALL_BLOCK' | 'CREDENTIAL_REVOCATION' | 'FORENSIC_COLLECTION';
    commandSnippet?: string;
  }[];
  ragSourcesRetrieved: {
    source: string;
    title: string;
    relevanceScore: number;
  }[];
}

export interface TelegramConfig {
  enabled: boolean;
  botToken: string;
  chatId: string;
  autoDispatchCritical: boolean;
  autoDispatchHigh: boolean;
  includeCvssDetails: boolean;
  includeMitreTags: boolean;
}

export interface TelegramDispatchLog {
  id: string;
  alertId: string;
  alertTitle: string;
  severity: SeverityLevel;
  sentAt: string;
  status: 'SUCCESS' | 'FAILED' | 'SIMULATED';
  recipientChatId: string;
  payloadText: string;
}
