/**
 * CyberNexsus Edge AI SOC - CVSS v3.1 Engine
 * Implements the FIRST.org Common Vulnerability Scoring System v3.1 specification
 * Standard URL: https://www.first.org/cvss/v3.1/specification-document
 */

import { Cvss31Metrics, Cvss31Result, SeverityLevel } from '../types';

export const CVSS_METRIC_WEIGHTS = {
  attackVector: {
    N: { value: 0.85, label: 'Network (N)', description: 'Vulnerable component is bound to network stack' },
    A: { value: 0.62, label: 'Adjacent (A)', description: 'Requires access to local network or bluetooth' },
    L: { value: 0.55, label: 'Local (L)', description: 'Requires local access or shell' },
    P: { value: 0.20, label: 'Physical (P)', description: 'Requires physical interaction with hardware' },
  },
  attackComplexity: {
    L: { value: 0.77, label: 'Low (L)', description: 'Specialized access condition or extenuating circumstances do not exist' },
    H: { value: 0.44, label: 'High (H)', description: 'Successful attack depends on conditions beyond attacker control' },
  },
  privilegesRequired: {
    unchanged: {
      N: { value: 0.85, label: 'None (N)', description: 'No authentication needed' },
      L: { value: 0.62, label: 'Low (L)', description: 'Requires basic user privileges' },
      H: { value: 0.27, label: 'High (H)', description: 'Requires administrative / root privileges' },
    },
    changed: {
      N: { value: 0.85, label: 'None (N)', description: 'No authentication needed' },
      L: { value: 0.68, label: 'Low (L)', description: 'Requires basic user privileges (Scope Changed)' },
      H: { value: 0.50, label: 'High (H)', description: 'Requires administrative privileges (Scope Changed)' },
    },
  },
  userInteraction: {
    N: { value: 0.85, label: 'None (N)', description: 'Vulnerability can be exploited without user intervention' },
    R: { value: 0.62, label: 'Required (R)', description: 'Successful attack requires user to take action' },
  },
  scope: {
    U: { label: 'Unchanged (U)', description: 'Compromised component is the only impacted entity' },
    C: { label: 'Changed (C)', description: 'Compromised component impacts resources beyond its security authority' },
  },
  impact: {
    N: { value: 0.00, label: 'None (N)', description: 'No impact' },
    L: { value: 0.22, label: 'Low (L)', description: 'Considerable access or partial loss' },
    H: { value: 0.56, label: 'High (H)', description: 'Total loss or complete compromise' },
  },
};

/**
 * CVSS v3.1 Official Roundup function
 * The smallest number, specified to one decimal place, that is equal to or higher than its input.
 */
export function cvssRoundup(input: number): number {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) {
    return intInput / 100000;
  }
  return (Math.floor(intInput / 10000) + 1) / 10;
}

/**
 * Calculate CVSS v3.1 Base Score and sub-scores from metrics
 */
export function calculateCvss31(metrics: Cvss31Metrics): Cvss31Result {
  const av = CVSS_METRIC_WEIGHTS.attackVector[metrics.attackVector].value;
  const ac = CVSS_METRIC_WEIGHTS.attackComplexity[metrics.attackComplexity].value;
  
  const prWeights = metrics.scope === 'U' 
    ? CVSS_METRIC_WEIGHTS.privilegesRequired.unchanged 
    : CVSS_METRIC_WEIGHTS.privilegesRequired.changed;
  const pr = prWeights[metrics.privilegesRequired].value;
  
  const ui = CVSS_METRIC_WEIGHTS.userInteraction[metrics.userInteraction].value;
  
  const c = CVSS_METRIC_WEIGHTS.impact[metrics.confidentiality].value;
  const i = CVSS_METRIC_WEIGHTS.impact[metrics.integrity].value;
  const a = CVSS_METRIC_WEIGHTS.impact[metrics.availability].value;

  // 1. Calculate Exploitability sub-score
  const exploitabilityScore = cvssRoundup(8.22 * av * ac * pr * ui);

  // 2. Calculate Impact Sub Score (ISS)
  const iss = 1 - ((1 - c) * (1 - i) * (1 - a));

  // 3. Calculate Impact depending on Scope
  let impactScore = 0;
  if (metrics.scope === 'U') {
    impactScore = cvssRoundup(6.42 * iss);
  } else {
    impactScore = cvssRoundup(7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15));
  }

  // 4. Calculate Base Score
  let baseScore = 0;
  if (impactScore <= 0) {
    baseScore = 0.0;
  } else if (metrics.scope === 'U') {
    baseScore = cvssRoundup(Math.min(impactScore + exploitabilityScore, 10.0));
  } else {
    baseScore = cvssRoundup(Math.min(1.08 * (impactScore + exploitabilityScore), 10.0));
  }

  // 5. Derive Severity Level
  const severity = getCvssSeverity(baseScore);

  // 6. Generate Vector String
  const vectorString = generateCvssVectorString(metrics);

  // 7. Calculate SOC operational Risk Score (0 - 100)
  const riskScore = Math.min(100, Math.round(baseScore * 10));

  return {
    baseScore,
    severity,
    vectorString,
    exploitabilityScore,
    impactScore,
    riskScore,
  };
}

export function getCvssSeverity(score: number): SeverityLevel {
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  if (score >= 0.1) return 'LOW';
  return 'INFORMATIONAL';
}

export function generateCvssVectorString(m: Cvss31Metrics): string {
  return `CVSS:3.1/AV:${m.attackVector}/AC:${m.attackComplexity}/PR:${m.privilegesRequired}/UI:${m.userInteraction}/S:${m.scope}/C:${m.confidentiality}/I:${m.integrity}/A:${m.availability}`;
}

export function parseCvssVectorString(vector: string): Cvss31Metrics | null {
  try {
    const parts = vector.replace(/^CVSS:3\.1\//, '').split('/');
    const metrics: Partial<Cvss31Metrics> = {};

    for (const part of parts) {
      const [key, val] = part.split(':');
      switch (key) {
        case 'AV': metrics.attackVector = val as any; break;
        case 'AC': metrics.attackComplexity = val as any; break;
        case 'PR': metrics.privilegesRequired = val as any; break;
        case 'UI': metrics.userInteraction = val as any; break;
        case 'S': metrics.scope = val as any; break;
        case 'C': metrics.confidentiality = val as any; break;
        case 'I': metrics.integrity = val as any; break;
        case 'A': metrics.availability = val as any; break;
      }
    }

    if (
      metrics.attackVector && metrics.attackComplexity && metrics.privilegesRequired &&
      metrics.userInteraction && metrics.scope && metrics.confidentiality &&
      metrics.integrity && metrics.availability
    ) {
      return metrics as Cvss31Metrics;
    }
    return null;
  } catch {
    return null;
  }
}

export const DEFAULT_HIGH_SEVERITY_METRICS: Cvss31Metrics = {
  attackVector: 'N',
  attackComplexity: 'L',
  privilegesRequired: 'N',
  userInteraction: 'N',
  scope: 'U',
  confidentiality: 'H',
  integrity: 'H',
  availability: 'H',
};
