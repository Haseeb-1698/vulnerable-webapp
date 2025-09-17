export interface CVSSMetrics {
  // Base Metrics
  attackVector: 'N' | 'A' | 'L' | 'P'; // Network, Adjacent, Local, Physical
  attackComplexity: 'L' | 'H'; // Low, High
  privilegesRequired: 'N' | 'L' | 'H'; // None, Low, High
  userInteraction: 'N' | 'R'; // None, Required
  scope: 'U' | 'C'; // Unchanged, Changed
  confidentialityImpact: 'N' | 'L' | 'H'; // None, Low, High
  integrityImpact: 'N' | 'L' | 'H'; // None, Low, High
  availabilityImpact: 'N' | 'L' | 'H'; // None, Low, High
}

export interface CVSSScore {
  baseScore: number;
  baseSeverity: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  vector: string;
  exploitabilityScore: number;
  impactScore: number;
}

export class CVSSCalculator {
  private static readonly ATTACK_VECTOR_VALUES = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
  private static readonly ATTACK_COMPLEXITY_VALUES = { L: 0.77, H: 0.44 };
  private static readonly PRIVILEGES_REQUIRED_VALUES = { N: 0.85, L: 0.62, H: 0.27 };
  private static readonly PRIVILEGES_REQUIRED_CHANGED_VALUES = { N: 0.85, L: 0.68, H: 0.5 };
  private static readonly USER_INTERACTION_VALUES = { N: 0.85, R: 0.62 };
  private static readonly IMPACT_VALUES = { N: 0, L: 0.22, H: 0.56 };

  static calculate(metrics: CVSSMetrics): CVSSScore {
    // Calculate Impact Sub-Score
    const confidentialityImpact = this.IMPACT_VALUES[metrics.confidentialityImpact];
    const integrityImpact = this.IMPACT_VALUES[metrics.integrityImpact];
    const availabilityImpact = this.IMPACT_VALUES[metrics.availabilityImpact];

    const impactSubScore = 1 - ((1 - confidentialityImpact) * (1 - integrityImpact) * (1 - availabilityImpact));

    let impactScore: number;
    if (metrics.scope === 'U') {
      impactScore = 6.42 * impactSubScore;
    } else {
      impactScore = 7.52 * (impactSubScore - 0.029) - 3.25 * Math.pow(impactSubScore - 0.02, 15);
    }

    // Calculate Exploitability Sub-Score
    const attackVector = this.ATTACK_VECTOR_VALUES[metrics.attackVector];
    const attackComplexity = this.ATTACK_COMPLEXITY_VALUES[metrics.attackComplexity];
    const privilegesRequired = metrics.scope === 'C' 
      ? this.PRIVILEGES_REQUIRED_CHANGED_VALUES[metrics.privilegesRequired]
      : this.PRIVILEGES_REQUIRED_VALUES[metrics.privilegesRequired];
    const userInteraction = this.USER_INTERACTION_VALUES[metrics.userInteraction];

    const exploitabilityScore = 8.22 * attackVector * attackComplexity * privilegesRequired * userInteraction;

    // Calculate Base Score
    let baseScore: number;
    if (impactScore <= 0) {
      baseScore = 0;
    } else if (metrics.scope === 'U') {
      baseScore = Math.min(impactScore + exploitabilityScore, 10);
    } else {
      baseScore = Math.min(1.08 * (impactScore + exploitabilityScore), 10);
    }

    // Round to one decimal place
    baseScore = Math.ceil(baseScore * 10) / 10;

    // Determine severity
    let baseSeverity: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    if (baseScore === 0) baseSeverity = 'NONE';
    else if (baseScore >= 0.1 && baseScore <= 3.9) baseSeverity = 'LOW';
    else if (baseScore >= 4.0 && baseScore <= 6.9) baseSeverity = 'MEDIUM';
    else if (baseScore >= 7.0 && baseScore <= 8.9) baseSeverity = 'HIGH';
    else baseSeverity = 'CRITICAL';

    // Generate CVSS vector string
    const vector = `CVSS:3.1/AV:${metrics.attackVector}/AC:${metrics.attackComplexity}/PR:${metrics.privilegesRequired}/UI:${metrics.userInteraction}/S:${metrics.scope}/C:${metrics.confidentialityImpact}/I:${metrics.integrityImpact}/A:${metrics.availabilityImpact}`;

    return {
      baseScore,
      baseSeverity,
      vector,
      exploitabilityScore: Math.round(exploitabilityScore * 10) / 10,
      impactScore: Math.round(impactScore * 10) / 10
    };
  }

  static getVulnerabilityMetrics(vulnerabilityType: string): CVSSMetrics {
    const predefinedMetrics: { [key: string]: CVSSMetrics } = {
      'SQL Injection': {
        attackVector: 'N',
        attackComplexity: 'L',
        privilegesRequired: 'L',
        userInteraction: 'N',
        scope: 'C',
        confidentialityImpact: 'H',
        integrityImpact: 'H',
        availabilityImpact: 'H'
      },
      'Cross-Site Scripting': {
        attackVector: 'N',
        attackComplexity: 'L',
        privilegesRequired: 'N',
        userInteraction: 'R',
        scope: 'C',
        confidentialityImpact: 'L',
        integrityImpact: 'L',
        availabilityImpact: 'N'
      },
      'IDOR': {
        attackVector: 'N',
        attackComplexity: 'L',
        privilegesRequired: 'L',
        userInteraction: 'N',
        scope: 'U',
        confidentialityImpact: 'H',
        integrityImpact: 'H',
        availabilityImpact: 'N'
      },
      'SSRF': {
        attackVector: 'N',
        attackComplexity: 'L',
        privilegesRequired: 'L',
        userInteraction: 'N',
        scope: 'C',
        confidentialityImpact: 'H',
        integrityImpact: 'L',
        availabilityImpact: 'L'
      },
      'Session Management': {
        attackVector: 'N',
        attackComplexity: 'L',
        privilegesRequired: 'N',
        userInteraction: 'N',
        scope: 'U',
        confidentialityImpact: 'H',
        integrityImpact: 'L',
        availabilityImpact: 'N'
      },
      'Authentication Bypass': {
        attackVector: 'N',
        attackComplexity: 'L',
        privilegesRequired: 'N',
        userInteraction: 'N',
        scope: 'C',
        confidentialityImpact: 'H',
        integrityImpact: 'H',
        availabilityImpact: 'H'
      },
      'Information Disclosure': {
        attackVector: 'N',
        attackComplexity: 'L',
        privilegesRequired: 'L',
        userInteraction: 'N',
        scope: 'U',
        confidentialityImpact: 'L',
        integrityImpact: 'N',
        availabilityImpact: 'N'
      },
      'Missing Security Headers': {
        attackVector: 'N',
        attackComplexity: 'H',
        privilegesRequired: 'N',
        userInteraction: 'R',
        scope: 'U',
        confidentialityImpact: 'L',
        integrityImpact: 'L',
        availabilityImpact: 'N'
      }
    };

    return predefinedMetrics[vulnerabilityType] || {
      attackVector: 'N',
      attackComplexity: 'L',
      privilegesRequired: 'L',
      userInteraction: 'N',
      scope: 'U',
      confidentialityImpact: 'L',
      integrityImpact: 'L',
      availabilityImpact: 'L'
    };
  }

  static calculateForVulnerability(vulnerabilityType: string): CVSSScore {
    const metrics = this.getVulnerabilityMetrics(vulnerabilityType);
    return this.calculate(metrics);
  }
}