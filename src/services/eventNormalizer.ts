/**
 * CyberNexsus Edge AI SOC - Event Normalizer Engine
 * Responsible for Parsing, Normalizing, Deduplicating, and Correlating multi-source security feeds.
 * Sources: Windows Event Logs, Sysmon, Linux auth.log / syslog, Zeek, Suricata, Splunk
 */

import { NormalizedSecurityEvent, LogSourceType, SeverityLevel } from '../types';

export class EventNormalizer {
  /**
   * Auto-detect log format from raw content
   */
  static detectLogType(rawLog: string): LogSourceType {
    const trimmed = rawLog.trim();
    if (trimmed.startsWith('{') && trimmed.includes('"event_type"') && trimmed.includes('"alert"')) {
      return 'suricata';
    }
    if (trimmed.startsWith('{') && (trimmed.includes('"id.orig_h"') || trimmed.includes('"uid"'))) {
      return 'zeek';
    }
    if (trimmed.startsWith('{') && (trimmed.includes('"sourcetype"') || trimmed.includes('"EventCode"'))) {
      return 'splunk';
    }
    if (trimmed.includes('Microsoft-Windows-Sysmon') || trimmed.includes('<EventID>1</EventID>') || trimmed.includes('Sysmon')) {
      return 'sysmon';
    }
    if (trimmed.includes('Microsoft-Windows-Security') || trimmed.includes('EventID>4624') || trimmed.includes('EventID>4625') || trimmed.includes('EventID>4688')) {
      return 'windows_event';
    }
    if (trimmed.includes('sshd[') || trimmed.includes('sudo:') || trimmed.includes('authentication failure')) {
      return 'linux_auth';
    }
    return 'linux_syslog';
  }

  /**
   * Parse a single raw log entry into the unified NormalizedSecurityEvent schema
   */
  static parseAndNormalize(raw: string, forcedType?: LogSourceType): NormalizedSecurityEvent {
    const logType = forcedType || this.detectLogType(raw);
    const now = new Date().toISOString();
    const id = `evt-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;

    switch (logType) {
      case 'suricata': {
        try {
          const json = JSON.parse(raw);
          const alert = json.alert || {};
          const sev: SeverityLevel = alert.severity === 1 ? 'CRITICAL' : alert.severity === 2 ? 'HIGH' : 'MEDIUM';
          return {
            id,
            timestamp: json.timestamp || now,
            sourceType: 'suricata',
            rawLog: raw,
            hostname: json.host || 'sensor-suricata-01',
            srcIp: json.src_ip,
            srcPort: json.src_port,
            dstIp: json.dest_ip,
            dstPort: json.dest_port,
            eventCategory: 'NETWORK_CONNECTION',
            eventId: alert.signature_id ? String(alert.signature_id) : 'SURICATA_ALERT',
            message: alert.signature || 'Suricata Network Threat Signature Triggered',
            severity: sev,
            tags: ['suricata', 'ids', alert.category ? alert.category.toLowerCase().replace(/\s+/g, '-') : 'network-alert'],
            dedupHash: `suricata-${json.src_ip}-${json.dest_ip}-${alert.signature_id}`,
          };
        } catch {
          // Fallback if not valid JSON
          break;
        }
      }

      case 'zeek': {
        try {
          const json = JSON.parse(raw);
          return {
            id,
            timestamp: json.ts ? new Date(json.ts * 1000).toISOString() : now,
            sourceType: 'zeek',
            rawLog: raw,
            hostname: 'zeek-sensor-tap',
            srcIp: json['id.orig_h'],
            srcPort: json['id.orig_p'],
            dstIp: json['id.resp_h'],
            dstPort: json['id.resp_p'],
            eventCategory: 'NETWORK_CONNECTION',
            eventId: json.service || 'ZEEK_FLOW',
            message: `Zeek ${json.service || 'TCP'} connection flow: ${json['id.orig_h']}:${json['id.orig_p']} -> ${json['id.resp_h']}:${json['id.resp_p']} (${json.orig_bytes || 0} bytes out, ${json.resp_bytes || 0} bytes in)`,
            severity: (json['id.resp_p'] === 4444 || json['id.resp_p'] === 8443) ? 'HIGH' : 'LOW',
            tags: ['zeek', 'network-flow', json.service || 'tcp'],
            dedupHash: `zeek-${json['id.orig_h']}-${json['id.resp_h']}-${json['id.resp_p']}`,
          };
        } catch {
          break;
        }
      }

      case 'splunk': {
        try {
          const json = JSON.parse(raw);
          return {
            id,
            timestamp: json.time || now,
            sourceType: 'splunk',
            rawLog: raw,
            hostname: json.host || 'unknown-host',
            username: json.user || json.SubjectUserName || 'SYSTEM',
            processName: json.ImagePath ? json.ImagePath.split('\\').pop() : json.ServiceName,
            commandLine: json.CommandLine || json.ImagePath,
            eventCategory: json.EventCode === 7045 ? 'PERSISTENCE' : 'PROCESS_EXECUTION',
            eventId: json.EventCode ? String(json.EventCode) : 'SPLUNK_EVENT',
            message: `Splunk Ingest [${json.sourcetype || 'Security'}]: EventCode ${json.EventCode || 'N/A'} - ${json.ServiceName || json.Message || 'System event'}`,
            severity: json.EventCode === 7045 ? 'HIGH' : 'MEDIUM',
            tags: ['splunk', 'cim-normalized', `event-${json.EventCode || 'audit'}`],
            dedupHash: `splunk-${json.host}-${json.EventCode}-${json.ServiceName}`,
          };
        } catch {
          break;
        }
      }

      case 'sysmon': {
        const imageMatch = raw.match(/<Data Name="(?:Image|SourceImage)">(.*?)<\/Data>/i);
        const cmdMatch = raw.match(/<Data Name="CommandLine">(.*?)<\/Data>/i);
        const userMatch = raw.match(/<Data Name="User">(.*?)<\/Data>/i);
        const hostMatch = raw.match(/<Computer>(.*?)<\/Computer>/i);
        const idMatch = raw.match(/<EventID>(.*?)<\/EventID>/i);
        const hashMatch = raw.match(/SHA256=([a-fA-F0-9]{64})/i);

        const eventId = idMatch ? parseInt(idMatch[1], 10) : 1;
        const img = imageMatch ? imageMatch[1] : 'unknown.exe';
        const cmd = cmdMatch ? cmdMatch[1] : img;
        const user = userMatch ? userMatch[1] : 'CORP\\SYSTEM';
        const host = hostMatch ? hostMatch[1] : 'WKSTN-WIN';

        let category: NormalizedSecurityEvent['eventCategory'] = 'PROCESS_EXECUTION';
        let severity: SeverityLevel = 'MEDIUM';
        let msg = `Sysmon Event ID ${eventId}: ${img}`;

        if (eventId === 1) {
          category = 'PROCESS_EXECUTION';
          if (cmd.toLowerCase().includes('-enc') || cmd.toLowerCase().includes('hidden') || cmd.toLowerCase().includes('downloadstring')) {
            severity = 'CRITICAL';
            msg = `Sysmon Event ID 1: Suspicious Obfuscated PowerShell execution`;
          }
        } else if (eventId === 10) {
          category = 'PRIVILEGE_ESCALATION';
          severity = 'CRITICAL';
          msg = `Sysmon Event ID 10: LSASS Memory Access Injection`;
        }

        return {
          id,
          timestamp: now,
          sourceType: 'sysmon',
          rawLog: raw,
          hostname: host,
          username: user,
          processName: img.split('\\').pop(),
          commandLine: cmd,
          hashes: hashMatch ? { sha256: hashMatch[1] } : undefined,
          eventCategory: category,
          eventId,
          message: msg,
          severity,
          tags: ['sysmon', `eventid-${eventId}`, 'endpoint-telemetry'],
          dedupHash: `sysmon-${host}-${eventId}-${img}-${cmd.substring(0, 30)}`,
        };
      }

      case 'windows_event': {
        const idMatch = raw.match(/<EventID>(.*?)<\/EventID>/i) || raw.match(/EventCode[=:]\s*(\d+)/i);
        const eventId = idMatch ? parseInt(idMatch[1], 10) : 4688;
        const hostMatch = raw.match(/<Computer>(.*?)<\/Computer>/i);
        const procMatch = raw.match(/<Data Name="NewProcessName">(.*?)<\/Data>/i);
        const cmdMatch = raw.match(/<Data Name="CommandLine">(.*?)<\/Data>/i);
        const userMatch = raw.match(/<Data Name="SubjectUserName">(.*?)<\/Data>/i);

        const host = hostMatch ? hostMatch[1] : 'WIN-SRV-01';
        const cmd = cmdMatch ? cmdMatch[1] : (procMatch ? procMatch[1] : '');
        let sev: SeverityLevel = 'MEDIUM';

        if (cmd.includes('vssadmin') && cmd.includes('delete shadows')) {
          sev = 'CRITICAL';
        }

        return {
          id,
          timestamp: now,
          sourceType: 'windows_event',
          rawLog: raw,
          hostname: host,
          username: userMatch ? userMatch[1] : 'SYSTEM',
          processName: procMatch ? procMatch[1].split('\\').pop() : 'process.exe',
          commandLine: cmd,
          eventCategory: cmd.includes('vssadmin') ? 'DEFENSE_EVASION' : 'PROCESS_EXECUTION',
          eventId,
          message: `Windows Security Audit Event ${eventId}: ${cmd || 'Process created'}`,
          severity: sev,
          tags: ['windows-event', `id-${eventId}`, 'security-auditing'],
          dedupHash: `win-${host}-${eventId}-${cmd}`,
        };
      }

      case 'linux_auth':
      case 'linux_syslog':
      default: {
        // Regex parser for Linux auth.log lines
        const isFailed = raw.toLowerCase().includes('failed password') || raw.toLowerCase().includes('authentication failure');
        const isAccepted = raw.toLowerCase().includes('accepted password') || raw.toLowerCase().includes('session opened');
        const isSudo = raw.toLowerCase().includes('sudo:');

        const ipMatch = raw.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
        const userMatch = raw.match(/(?:for|user|COMMAND=)\s+([a-zA-Z0-9_\-]+)/);
        const hostMatch = raw.match(/^([a-zA-Z]{3}\s+\d+\s+\d+:\d+:\d+)\s+([a-zA-Z0-9.\-]+)/);

        let sev: SeverityLevel = 'LOW';
        let category: NormalizedSecurityEvent['eventCategory'] = 'AUTHENTICATION';

        if (isSudo) {
          category = 'PRIVILEGE_ESCALATION';
          sev = raw.includes('sh') || raw.includes('curl') || raw.includes('python') ? 'CRITICAL' : 'HIGH';
        } else if (isFailed) {
          sev = 'MEDIUM';
        } else if (isAccepted && ipMatch) {
          sev = 'HIGH';
        }

        return {
          id,
          timestamp: now,
          sourceType: logType,
          rawLog: raw,
          hostname: hostMatch ? hostMatch[2] : 'linux-node-01',
          username: userMatch ? userMatch[1] : 'root',
          srcIp: ipMatch ? ipMatch[0] : undefined,
          eventCategory: category,
          eventId: isSudo ? 'SUDO_EXEC' : (isFailed ? 'AUTH_FAIL' : 'AUTH_SUCCESS'),
          message: raw.length > 120 ? raw.substring(0, 117) + '...' : raw,
          severity: sev,
          tags: ['linux', isSudo ? 'sudo' : 'auth', 'syslog'],
          dedupHash: `linux-${hostMatch ? hostMatch[2] : 'node'}-${raw.substring(15, 60)}`,
        };
      }
    }

    // Generic fallback
    return {
      id,
      timestamp: now,
      sourceType: logType,
      rawLog: raw,
      hostname: 'edge-endpoint',
      eventCategory: 'PROCESS_EXECUTION',
      message: raw.substring(0, 100),
      severity: 'INFORMATIONAL',
      tags: ['generic', logType],
      dedupHash: `generic-${raw.substring(0, 40)}`,
    };
  }

  /**
   * Deduplicate an array of normalized events based on semantic signature
   */
  static deduplicateEvents(events: NormalizedSecurityEvent[]): {
    uniqueEvents: NormalizedSecurityEvent[];
    duplicateCount: number;
  } {
    const seen = new Set<string>();
    const unique: NormalizedSecurityEvent[] = [];
    let dups = 0;

    for (const evt of events) {
      if (seen.has(evt.dedupHash)) {
        dups++;
      } else {
        seen.add(evt.dedupHash);
        unique.push(evt);
      }
    }

    return { uniqueEvents: unique, duplicateCount: dups };
  }

  /**
   * Correlate events into chained attack incident clusters
   */
  static correlateEvents(events: NormalizedSecurityEvent[]): Map<string, NormalizedSecurityEvent[]> {
    const clusters = new Map<string, NormalizedSecurityEvent[]>();

    for (const evt of events) {
      const key = evt.correlationId || evt.hostname || 'cluster-default';
      const list = clusters.get(key) || [];
      list.push(evt);
      clusters.set(key, list);
    }

    return clusters;
  }
}
