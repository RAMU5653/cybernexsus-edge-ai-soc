/**
 * CyberNexsus Edge AI SOC - Detection Engine
 * Evaluates Sigma rules, correlates IOCs, and calculates CVSS v3.1 scores.
 */

import { NormalizedSecurityEvent, SecurityAlert, SecurityIOC, MitreTechniqueRef, Cvss31Metrics } from '../types';
import { calculateCvss31 } from '../utils/cvss31';
import { MITRE_KNOWLEDGE_BASE } from '../data/mockData';

export interface SigmaRule {
  id: string;
  title: string;
  mitreTechnique: MitreTechniqueRef;
  cvssMetrics: Cvss31Metrics;
  condition: (event: NormalizedSecurityEvent, contextEvents: NormalizedSecurityEvent[]) => boolean;
}

export const SIGMA_RULES: SigmaRule[] = [
  {
    id: 'SIGMA-SSH-BRUTEFORCE-SUCCESS',
    title: 'SSH Brute Force Followed by Successful Logon',
    mitreTechnique: MITRE_KNOWLEDGE_BASE[0], // T1110
    cvssMetrics: {
      attackVector: 'N',
      attackComplexity: 'L',
      privilegesRequired: 'N',
      userInteraction: 'N',
      scope: 'U',
      confidentiality: 'H',
      integrity: 'H',
      availability: 'H',
    },
    condition: (evt, all) => {
      if (evt.eventId === 'SSH_AUTH_SUCCESS') {
        const priorFails = all.filter(
          e => e.eventId === 'SSH_AUTH_FAIL' && (e.srcIp === evt.srcIp || e.hostname === evt.hostname)
        );
        return priorFails.length >= 1;
      }
      return false;
    },
  },
  {
    id: 'SIGMA-SUDO-PIPE-TO-SHELL',
    title: 'Abuse of Sudo with Pipe-to-Shell Remote Payload',
    mitreTechnique: MITRE_KNOWLEDGE_BASE[5], // T1548.003
    cvssMetrics: {
      attackVector: 'L',
      attackComplexity: 'L',
      privilegesRequired: 'L',
      userInteraction: 'N',
      scope: 'C',
      confidentiality: 'H',
      integrity: 'H',
      availability: 'H',
    },
    condition: evt => {
      const cmd = (evt.commandLine || '').toLowerCase();
      return evt.eventCategory === 'PRIVILEGE_ESCALATION' && (cmd.includes('| sh') || cmd.includes('| bash') || cmd.includes('curl') || cmd.includes('wget'));
    },
  },
  {
    id: 'SIGMA-POWERSHELL-HIDDEN-ENCODED',
    title: 'Obfuscated PowerShell Execution with Hidden Window',
    mitreTechnique: MITRE_KNOWLEDGE_BASE[1], // T1059.001
    cvssMetrics: {
      attackVector: 'L',
      attackComplexity: 'L',
      privilegesRequired: 'L',
      userInteraction: 'R',
      scope: 'U',
      confidentiality: 'H',
      integrity: 'H',
      availability: 'H',
    },
    condition: evt => {
      const cmd = (evt.commandLine || '').toLowerCase();
      return (evt.processName?.includes('powershell') || cmd.includes('powershell')) && 
        (cmd.includes('-enc') || cmd.includes('-w hidden') || cmd.includes('downloadstring'));
    },
  },
  {
    id: 'SIGMA-LSASS-CREDENTIAL-DUMP',
    title: 'LSASS Memory Process Access Injection (Mimikatz Pattern)',
    mitreTechnique: MITRE_KNOWLEDGE_BASE[2], // T1003.001
    cvssMetrics: {
      attackVector: 'L',
      attackComplexity: 'L',
      privilegesRequired: 'H',
      userInteraction: 'N',
      scope: 'C',
      confidentiality: 'H',
      integrity: 'H',
      availability: 'H',
    },
    condition: evt => {
      const raw = evt.rawLog.toLowerCase();
      return evt.eventId === 10 || raw.includes('lsass.exe') || raw.includes('0x1010') || raw.includes('mimikatz');
    },
  },
  {
    id: 'SIGMA-VSSADMIN-DELETE-SHADOWS',
    title: 'Inhibit System Recovery via Volume Shadow Copy Deletion',
    mitreTechnique: MITRE_KNOWLEDGE_BASE[3], // T1490
    cvssMetrics: {
      attackVector: 'L',
      attackComplexity: 'L',
      privilegesRequired: 'H',
      userInteraction: 'N',
      scope: 'C',
      confidentiality: 'N',
      integrity: 'H',
      availability: 'H',
    },
    condition: evt => {
      const cmd = (evt.commandLine || '').toLowerCase();
      return cmd.includes('vssadmin') && (cmd.includes('delete') || cmd.includes('shadows'));
    },
  },
  {
    id: 'SIGMA-C2-COBALT-STRIKE-BEACON',
    title: 'Cobalt Strike C2 Beaconing Response Activity Observed',
    mitreTechnique: MITRE_KNOWLEDGE_BASE[4], // T1071.001
    cvssMetrics: {
      attackVector: 'N',
      attackComplexity: 'L',
      privilegesRequired: 'N',
      userInteraction: 'N',
      scope: 'C',
      confidentiality: 'H',
      integrity: 'H',
      availability: 'H',
    },
    condition: evt => {
      const raw = evt.rawLog.toLowerCase();
      return raw.includes('cobalt strike') || raw.includes('2028912') || (evt.dstPort === 8443 && evt.sourceType === 'suricata');
    },
  },
];

export class DetectionEngine {
  /**
   * Scan normalized events and produce correlated security alerts
   */
  static runDetection(events: NormalizedSecurityEvent[], iocDatabase: SecurityIOC[]): SecurityAlert[] {
    const alerts: SecurityAlert[] = [];
    const matchedRulesByCorrelation = new Map<string, { rules: SigmaRule[]; events: NormalizedSecurityEvent[] }>();

    for (const event of events) {
      const corrId = event.correlationId || event.hostname || 'corr-default';

      for (const rule of SIGMA_RULES) {
        if (rule.condition(event, events)) {
          const group = matchedRulesByCorrelation.get(corrId) || { rules: [], events: [] };
          if (!group.rules.some(r => r.id === rule.id)) {
            group.rules.push(rule);
          }
          if (!group.events.some(e => e.id === event.id)) {
            group.events.push(event);
          }
          matchedRulesByCorrelation.set(corrId, group);
        }
      }
    }

    // Convert rule matches to SecurityAlert objects
    for (const [corrId, matchGroup] of matchedRulesByCorrelation.entries()) {
      if (matchGroup.rules.length === 0) continue;

      // Primary rule dictates initial CVSS
      const primaryRule = matchGroup.rules[0];
      const cvss = calculateCvss31(primaryRule.cvssMetrics);

      // Find matched IOCs
      const matchedIocs = iocDatabase.filter(ioc => {
        return matchGroup.events.some(e => {
          return (
            (ioc.type === 'IP' && (e.srcIp === ioc.value || e.dstIp === ioc.value)) ||
            (ioc.type === 'HASH_SHA256' && e.hashes?.sha256 === ioc.value) ||
            (ioc.type === 'COMMAND_PATTERN' && e.commandLine?.includes(ioc.value))
          );
        });
      });

      const primaryEvt = matchGroup.events[0];
      const title = matchGroup.rules.length > 1
        ? `Multi-Stage Attack: ${matchGroup.rules.map(r => r.mitreTechnique.name).join(' → ')}`
        : primaryRule.title;

      alerts.push({
        id: `ALT-${Math.floor(1000 + Math.random() * 9000)}`,
        title,
        incidentId: corrId,
        severity: cvss.severity,
        riskScore: cvss.riskScore,
        cvss,
        status: 'NEW',
        createdAt: primaryEvt.timestamp,
        affectedHost: primaryEvt.hostname,
        affectedUser: primaryEvt.username || 'unknown',
        mitreTactics: Array.from(new Set(matchGroup.rules.map(r => r.mitreTechnique.tactic))),
        mitreTechniques: matchGroup.rules.map(r => r.mitreTechnique),
        matchedRules: matchGroup.rules.map(r => r.id),
        chainedEvents: matchGroup.events,
        iocs: matchedIocs,
        summary: `Chained threat activity detected on ${primaryEvt.hostname}. ${matchGroup.rules.length} Sigma rule detections correlated with ${matchedIocs.length} verified IOC matches.`,
      });
    }

    return alerts;
  }
}
