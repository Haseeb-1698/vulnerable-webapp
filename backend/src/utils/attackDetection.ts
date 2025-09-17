import { logger, SecurityEventType } from './logger';

// Attack pattern definitions
interface AttackPattern {
  name: string;
  pattern: RegExp;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
}

// Rate limiting for attack detection
interface RateLimitEntry {
  count: number;
  firstSeen: number;
  lastSeen: number;
}

class AttackDetectionSystem {
  private attackPatterns: Map<SecurityEventType, AttackPattern[]>;
  private rateLimits: Map<string, RateLimitEntry>;
  private alertThresholds: Map<SecurityEventType, number>;
  private alertCooldowns: Map<string, number>;

  constructor() {
    this.attackPatterns = new Map();
    this.rateLimits = new Map();
    this.alertThresholds = new Map();
    this.alertCooldowns = new Map();
    
    this.initializePatterns();
    this.initializeThresholds();
    
    // Clean up old entries every 5 minutes
    setInterval(() => this.cleanup(), 5 * 60 * 1000);
  }

  private initializePatterns(): void {
    // SQL Injection patterns
    this.attackPatterns.set(SecurityEventType.SQL_INJECTION_ATTEMPT, [
      {
        name: 'Union-based SQL Injection',
        pattern: /\b(UNION\s+(ALL\s+)?SELECT)\b/i,
        severity: 'critical',
        description: 'Attempt to use UNION SELECT for data extraction'
      },
      {
        name: 'Boolean-based SQL Injection',
        pattern: /(\bOR\b\s+\d+\s*=\s*\d+|\bAND\b\s+\d+\s*=\s*\d+)/i,
        severity: 'high',
        description: 'Boolean-based blind SQL injection attempt'
      },
      {
        name: 'Time-based SQL Injection',
        pattern: /(SLEEP\s*\(|WAITFOR\s+DELAY|pg_sleep\s*\()/i,
        severity: 'high',
        description: 'Time-based blind SQL injection attempt'
      },
      {
        name: 'Comment-based SQL Injection',
        pattern: /(--|\#|\/\*.*\*\/)/,
        severity: 'medium',
        description: 'SQL comment injection attempt'
      },
      {
        name: 'Information Schema Access',
        pattern: /\b(INFORMATION_SCHEMA|SYSOBJECTS|SYSCOLUMNS|pg_tables)\b/i,
        severity: 'critical',
        description: 'Attempt to access database metadata'
      }
    ]);

    // XSS patterns
    this.attackPatterns.set(SecurityEventType.XSS_ATTEMPT, [
      {
        name: 'Script Tag Injection',
        pattern: /<script[^>]*>.*?<\/script>/i,
        severity: 'critical',
        description: 'Direct script tag injection'
      },
      {
        name: 'Event Handler Injection',
        pattern: /on\w+\s*=\s*['"]/i,
        severity: 'high',
        description: 'HTML event handler injection'
      },
      {
        name: 'JavaScript Protocol',
        pattern: /javascript\s*:/i,
        severity: 'high',
        description: 'JavaScript protocol injection'
      },
      {
        name: 'DOM Manipulation',
        pattern: /(document\.|window\.|eval\s*\()/i,
        severity: 'high',
        description: 'DOM manipulation attempt'
      },
      {
        name: 'Cookie Theft',
        pattern: /document\.cookie/i,
        severity: 'critical',
        description: 'Cookie theft attempt'
      }
    ]);

    // SSRF patterns
    this.attackPatterns.set(SecurityEventType.SSRF_ATTEMPT, [
      {
        name: 'Localhost Access',
        pattern: /^https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0)/i,
        severity: 'critical',
        description: 'Attempt to access localhost services'
      },
      {
        name: 'Private Network Access',
        pattern: /^https?:\/\/(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)/i,
        severity: 'high',
        description: 'Attempt to access private network ranges'
      },
      {
        name: 'Cloud Metadata Access',
        pattern: /^https?:\/\/(169\.254\.169\.254|metadata\.google\.internal)/i,
        severity: 'critical',
        description: 'Attempt to access cloud metadata services'
      },
      {
        name: 'File Protocol',
        pattern: /^file:\/\//i,
        severity: 'critical',
        description: 'File protocol access attempt'
      }
    ]);

    // LFI patterns
    this.attackPatterns.set(SecurityEventType.LFI_ATTEMPT, [
      {
        name: 'Directory Traversal',
        pattern: /\.\.\//,
        severity: 'high',
        description: 'Directory traversal attempt'
      },
      {
        name: 'System File Access',
        pattern: /\/(etc\/passwd|etc\/shadow|proc\/version|windows\/system32)/i,
        severity: 'critical',
        description: 'System file access attempt'
      },
      {
        name: 'URL Encoded Traversal',
        pattern: /%2e%2e%2f/i,
        severity: 'high',
        description: 'URL encoded directory traversal'
      }
    ]);
  }

  private initializeThresholds(): void {
    // Set alert thresholds (number of attempts before alerting)
    this.alertThresholds.set(SecurityEventType.SQL_INJECTION_ATTEMPT, 3);
    this.alertThresholds.set(SecurityEventType.XSS_ATTEMPT, 3);
    this.alertThresholds.set(SecurityEventType.SSRF_ATTEMPT, 2);
    this.alertThresholds.set(SecurityEventType.LFI_ATTEMPT, 2);
    this.alertThresholds.set(SecurityEventType.BRUTE_FORCE_ATTEMPT, 5);
    this.alertThresholds.set(SecurityEventType.IDOR_ATTEMPT, 3);
  }

  // Analyze input for attack patterns
  analyzeInput(
    input: string,
    eventType: SecurityEventType,
    context: {
      ip?: string;
      userId?: number;
      endpoint?: string;
      userAgent?: string;
    }
  ): {
    isAttack: boolean;
    patterns: AttackPattern[];
    severity: 'low' | 'medium' | 'high' | 'critical';
  } {
    const patterns = this.attackPatterns.get(eventType) || [];
    const matchedPatterns: AttackPattern[] = [];
    let maxSeverity: 'low' | 'medium' | 'high' | 'critical' = 'low';

    for (const pattern of patterns) {
      if (pattern.pattern.test(input)) {
        matchedPatterns.push(pattern);
        
        // Update max severity
        const severityLevels = { low: 1, medium: 2, high: 3, critical: 4 };
        if (severityLevels[pattern.severity] > severityLevels[maxSeverity]) {
          maxSeverity = pattern.severity;
        }
      }
    }

    const isAttack = matchedPatterns.length > 0;

    if (isAttack) {
      this.recordAttack(eventType, input, maxSeverity, context, matchedPatterns);
    }

    return {
      isAttack,
      patterns: matchedPatterns,
      severity: maxSeverity
    };
  }

  // Record attack attempt and check for alerting
  private recordAttack(
    eventType: SecurityEventType,
    payload: string,
    severity: 'low' | 'medium' | 'high' | 'critical',
    context: any,
    patterns: AttackPattern[]
  ): void {
    const key = `${context.ip || 'unknown'}_${eventType}`;
    const now = Date.now();

    // Update rate limiting
    const existing = this.rateLimits.get(key);
    if (existing) {
      existing.count++;
      existing.lastSeen = now;
    } else {
      this.rateLimits.set(key, {
        count: 1,
        firstSeen: now,
        lastSeen: now
      });
    }

    // Log the attack
    logger.attack(eventType, payload, severity, {
      ...context,
      patterns: patterns.map(p => p.name),
      patternCount: patterns.length
    });

    // Check if we should send an alert
    this.checkForAlert(eventType, key, context);
  }

  // Check if alert threshold is reached
  private checkForAlert(eventType: SecurityEventType, key: string, context: any): void {
    const threshold = this.alertThresholds.get(eventType) || 5;
    const rateLimitEntry = this.rateLimits.get(key);
    
    if (!rateLimitEntry || rateLimitEntry.count < threshold) {
      return;
    }

    // Check cooldown to prevent spam
    const cooldownKey = `${key}_alert`;
    const lastAlert = this.alertCooldowns.get(cooldownKey) || 0;
    const cooldownPeriod = 10 * 60 * 1000; // 10 minutes

    if (Date.now() - lastAlert < cooldownPeriod) {
      return;
    }

    // Send alert
    this.sendAlert(eventType, rateLimitEntry, context);
    this.alertCooldowns.set(cooldownKey, Date.now());
  }

  // Send security alert
  private sendAlert(
    eventType: SecurityEventType,
    rateLimitEntry: RateLimitEntry,
    context: any
  ): void {
    const alertMessage = `SECURITY ALERT: Multiple ${eventType} attempts detected`;
    const alertDetails = {
      eventType,
      attemptCount: rateLimitEntry.count,
      timeWindow: `${Math.round((rateLimitEntry.lastSeen - rateLimitEntry.firstSeen) / 1000)}s`,
      sourceIP: context.ip,
      userAgent: context.userAgent,
      endpoint: context.endpoint,
      firstSeen: new Date(rateLimitEntry.firstSeen).toISOString(),
      lastSeen: new Date(rateLimitEntry.lastSeen).toISOString()
    };

    logger.security(
      SecurityEventType.SUSPICIOUS_ACTIVITY,
      alertMessage,
      alertDetails,
      {
        severity: 'critical',
        ...context
      }
    );

    // In a real system, you would also:
    // - Send email/SMS notifications
    // - Update SIEM systems
    // - Trigger automated responses
    console.error(`🚨 ${alertMessage}`, alertDetails);
  }

  // Get attack statistics
  getAttackStats(): any {
    const stats = {
      totalAttacks: 0,
      attacksByType: {} as any,
      attacksByIP: {} as any,
      recentAttacks: [] as any[]
    };

    for (const [key, entry] of this.rateLimits.entries()) {
      const [ip, eventType] = key.split('_');
      
      stats.totalAttacks += entry.count;
      
      if (!stats.attacksByType[eventType]) {
        stats.attacksByType[eventType] = 0;
      }
      stats.attacksByType[eventType] += entry.count;
      
      if (!stats.attacksByIP[ip]) {
        stats.attacksByIP[ip] = 0;
      }
      stats.attacksByIP[ip] += entry.count;
      
      // Recent attacks (last hour)
      if (Date.now() - entry.lastSeen < 60 * 60 * 1000) {
        stats.recentAttacks.push({
          ip,
          eventType,
          count: entry.count,
          lastSeen: new Date(entry.lastSeen).toISOString()
        });
      }
    }

    return stats;
  }

  // Clean up old entries
  private cleanup(): void {
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours

    for (const [key, entry] of this.rateLimits.entries()) {
      if (now - entry.lastSeen > maxAge) {
        this.rateLimits.delete(key);
      }
    }

    for (const [key, timestamp] of this.alertCooldowns.entries()) {
      if (now - timestamp > maxAge) {
        this.alertCooldowns.delete(key);
      }
    }
  }

  // Manual alert for specific events
  triggerAlert(
    eventType: SecurityEventType,
    message: string,
    severity: 'low' | 'medium' | 'high' | 'critical',
    context: any
  ): void {
    logger.security(eventType, message, context, { severity });
    
    if (severity === 'critical' || severity === 'high') {
      console.error(`🚨 MANUAL ALERT: ${message}`, context);
    }
  }
}

// Singleton instance
export const attackDetection = new AttackDetectionSystem();
export default attackDetection;