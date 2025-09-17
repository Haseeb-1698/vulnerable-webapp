import fs from 'fs';
import path from 'path';
import { logger, SecurityEventType } from './logger';

// Audit event types
export enum AuditEventType {
  VULNERABILITY_TOGGLE = 'vulnerability_toggle',
  SECURITY_CONFIG_CHANGE = 'security_config_change',
  USER_ACTION = 'user_action',
  SYSTEM_EVENT = 'system_event',
  DATA_ACCESS = 'data_access',
  AUTHENTICATION_EVENT = 'authentication_event',
  AUTHORIZATION_EVENT = 'authorization_event',
  CONFIGURATION_CHANGE = 'configuration_change'
}

// Audit entry interface
export interface AuditEntry {
  id: string;
  timestamp: string;
  eventType: AuditEventType;
  action: string;
  description: string;
  userId?: number;
  userEmail?: string;
  ip?: string;
  userAgent?: string;
  resource?: string;
  resourceId?: string;
  oldValue?: any;
  newValue?: any;
  metadata?: any;
  severity: 'low' | 'medium' | 'high' | 'critical';
  success: boolean;
  errorMessage?: string;
}

// Vulnerability toggle specific audit
export interface VulnerabilityToggleAudit {
  vulnerabilityType: string;
  enabled: boolean;
  previousState: boolean;
  toggledBy: number;
  toggledAt: string;
  reason?: string;
  affectedEndpoints: string[];
  securityImpact: string;
}

class AuditTrailSystem {
  private auditLogFile: string;
  private vulnerabilityAuditFile: string;
  private auditDirectory: string;
  private auditEntries: AuditEntry[];
  private maxEntriesInMemory: number;

  constructor() {
    this.auditDirectory = path.join(process.cwd(), 'logs', 'audit');
    this.auditLogFile = path.join(this.auditDirectory, 'audit.log');
    this.vulnerabilityAuditFile = path.join(this.auditDirectory, 'vulnerability-toggles.log');
    this.auditEntries = [];
    this.maxEntriesInMemory = 1000;
    
    this.ensureAuditDirectory();
    this.loadRecentAuditEntries();
  }

  private ensureAuditDirectory(): void {
    if (!fs.existsSync(this.auditDirectory)) {
      fs.mkdirSync(this.auditDirectory, { recursive: true });
    }
  }

  private loadRecentAuditEntries(): void {
    try {
      if (fs.existsSync(this.auditLogFile)) {
        const content = fs.readFileSync(this.auditLogFile, 'utf8');
        const lines = content.split('\n').filter(line => line.trim());
        
        // Load last 1000 entries
        const recentLines = lines.slice(-this.maxEntriesInMemory);
        this.auditEntries = recentLines.map(line => {
          try {
            return JSON.parse(line);
          } catch {
            return null;
          }
        }).filter(entry => entry !== null);
      }
    } catch (error) {
      logger.error('Failed to load audit entries', { error: error.message });
    }
  }

  private generateAuditId(): string {
    return `audit_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private writeAuditEntry(entry: AuditEntry): void {
    try {
      const logLine = JSON.stringify(entry) + '\n';
      fs.appendFileSync(this.auditLogFile, logLine);
      
      // Add to in-memory cache
      this.auditEntries.push(entry);
      
      // Keep only recent entries in memory
      if (this.auditEntries.length > this.maxEntriesInMemory) {
        this.auditEntries = this.auditEntries.slice(-this.maxEntriesInMemory);
      }
    } catch (error) {
      logger.error('Failed to write audit entry', { error: error.message });
    }
  }

  // Record general audit event
  recordEvent(
    eventType: AuditEventType,
    action: string,
    description: string,
    context: {
      userId?: number;
      userEmail?: string;
      ip?: string;
      userAgent?: string;
      resource?: string;
      resourceId?: string;
      oldValue?: any;
      newValue?: any;
      metadata?: any;
      severity?: 'low' | 'medium' | 'high' | 'critical';
      success?: boolean;
      errorMessage?: string;
    } = {}
  ): string {
    const auditId = this.generateAuditId();
    
    const entry: AuditEntry = {
      id: auditId,
      timestamp: new Date().toISOString(),
      eventType,
      action,
      description,
      userId: context.userId,
      userEmail: context.userEmail,
      ip: context.ip,
      userAgent: context.userAgent,
      resource: context.resource,
      resourceId: context.resourceId,
      oldValue: context.oldValue,
      newValue: context.newValue,
      metadata: context.metadata,
      severity: context.severity || 'medium',
      success: context.success !== false,
      errorMessage: context.errorMessage
    };

    this.writeAuditEntry(entry);
    
    // Log to security log if high severity
    if (entry.severity === 'high' || entry.severity === 'critical') {
      logger.security(
        SecurityEventType.SUSPICIOUS_ACTIVITY,
        `High severity audit event: ${action}`,
        entry
      );
    }

    return auditId;
  }

  // Record vulnerability toggle event
  recordVulnerabilityToggle(
    vulnerabilityType: string,
    enabled: boolean,
    previousState: boolean,
    context: {
      userId: number;
      userEmail?: string;
      ip?: string;
      userAgent?: string;
      reason?: string;
      affectedEndpoints?: string[];
    }
  ): string {
    const toggleAudit: VulnerabilityToggleAudit = {
      vulnerabilityType,
      enabled,
      previousState,
      toggledBy: context.userId,
      toggledAt: new Date().toISOString(),
      reason: context.reason,
      affectedEndpoints: context.affectedEndpoints || [],
      securityImpact: this.getSecurityImpact(vulnerabilityType, enabled)
    };

    // Write to vulnerability-specific log
    try {
      const logLine = JSON.stringify(toggleAudit) + '\n';
      fs.appendFileSync(this.vulnerabilityAuditFile, logLine);
    } catch (error) {
      logger.error('Failed to write vulnerability audit entry', { error: error.message });
    }

    // Record in general audit trail
    const auditId = this.recordEvent(
      AuditEventType.VULNERABILITY_TOGGLE,
      `toggle_${vulnerabilityType}`,
      `Vulnerability ${vulnerabilityType} ${enabled ? 'enabled' : 'disabled'}`,
      {
        userId: context.userId,
        userEmail: context.userEmail,
        ip: context.ip,
        userAgent: context.userAgent,
        resource: 'vulnerability_configuration',
        resourceId: vulnerabilityType,
        oldValue: { enabled: previousState },
        newValue: { enabled },
        metadata: toggleAudit,
        severity: enabled ? 'high' : 'medium',
        success: true
      }
    );

    // Log vulnerability toggle to security log
    logger.vulnerabilityToggle(
      vulnerabilityType,
      enabled,
      context.userId,
      {
        ip: context.ip,
        userAgent: context.userAgent,
        reason: context.reason,
        auditId
      }
    );

    return auditId;
  }

  private getSecurityImpact(vulnerabilityType: string, enabled: boolean): string {
    const impacts = {
      sql_injection: enabled 
        ? 'Database queries vulnerable to injection attacks'
        : 'Database queries protected with parameterized queries',
      xss: enabled
        ? 'User input rendered without sanitization, allowing script execution'
        : 'User input properly sanitized and encoded',
      idor: enabled
        ? 'Direct object references without authorization checks'
        : 'Proper authorization checks implemented for resource access',
      ssrf: enabled
        ? 'Server-side requests without URL validation'
        : 'URL validation and whitelisting implemented',
      lfi: enabled
        ? 'File access without path validation'
        : 'Path traversal protection implemented',
      session_management: enabled
        ? 'Weak session management with insecure token handling'
        : 'Secure session management with proper token handling'
    };

    return impacts[vulnerabilityType] || 'Unknown security impact';
  }

  // Record user authentication events
  recordAuthenticationEvent(
    action: 'login' | 'logout' | 'login_failed' | 'password_change' | 'account_locked',
    userId?: number,
    context: {
      userEmail?: string;
      ip?: string;
      userAgent?: string;
      reason?: string;
      success?: boolean;
    } = {}
  ): string {
    return this.recordEvent(
      AuditEventType.AUTHENTICATION_EVENT,
      action,
      `User authentication: ${action}`,
      {
        userId,
        userEmail: context.userEmail,
        ip: context.ip,
        userAgent: context.userAgent,
        resource: 'user_authentication',
        resourceId: userId?.toString(),
        metadata: { reason: context.reason },
        severity: action === 'login_failed' ? 'medium' : 'low',
        success: context.success !== false
      }
    );
  }

  // Record data access events
  recordDataAccess(
    action: 'read' | 'create' | 'update' | 'delete',
    resource: string,
    resourceId: string,
    context: {
      userId?: number;
      userEmail?: string;
      ip?: string;
      userAgent?: string;
      oldValue?: any;
      newValue?: any;
      success?: boolean;
      errorMessage?: string;
    } = {}
  ): string {
    return this.recordEvent(
      AuditEventType.DATA_ACCESS,
      `${action}_${resource}`,
      `Data ${action} on ${resource}`,
      {
        userId: context.userId,
        userEmail: context.userEmail,
        ip: context.ip,
        userAgent: context.userAgent,
        resource,
        resourceId,
        oldValue: context.oldValue,
        newValue: context.newValue,
        severity: action === 'delete' ? 'high' : 'low',
        success: context.success !== false,
        errorMessage: context.errorMessage
      }
    );
  }

  // Get audit trail for specific user
  getUserAuditTrail(userId: number, limit: number = 100): AuditEntry[] {
    return this.auditEntries
      .filter(entry => entry.userId === userId)
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, limit);
  }

  // Get audit trail for specific resource
  getResourceAuditTrail(resource: string, resourceId?: string, limit: number = 100): AuditEntry[] {
    return this.auditEntries
      .filter(entry => {
        if (resourceId) {
          return entry.resource === resource && entry.resourceId === resourceId;
        }
        return entry.resource === resource;
      })
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, limit);
  }

  // Get vulnerability toggle history
  getVulnerabilityToggleHistory(vulnerabilityType?: string): VulnerabilityToggleAudit[] {
    try {
      if (!fs.existsSync(this.vulnerabilityAuditFile)) {
        return [];
      }

      const content = fs.readFileSync(this.vulnerabilityAuditFile, 'utf8');
      const lines = content.split('\n').filter(line => line.trim());
      
      const toggles = lines.map(line => {
        try {
          return JSON.parse(line) as VulnerabilityToggleAudit;
        } catch {
          return null;
        }
      }).filter(toggle => toggle !== null);

      if (vulnerabilityType) {
        return toggles.filter(toggle => toggle.vulnerabilityType === vulnerabilityType);
      }

      return toggles.sort((a, b) => new Date(b.toggledAt).getTime() - new Date(a.toggledAt).getTime());
    } catch (error) {
      logger.error('Failed to read vulnerability toggle history', { error: error.message });
      return [];
    }
  }

  // Get audit statistics
  getAuditStatistics(timeWindow: number = 24 * 60 * 60 * 1000): any {
    const now = Date.now();
    const windowStart = now - timeWindow;
    
    const recentEntries = this.auditEntries.filter(
      entry => new Date(entry.timestamp).getTime() > windowStart
    );

    const stats = {
      totalEvents: recentEntries.length,
      eventsByType: {} as any,
      eventsBySeverity: {} as any,
      successRate: 0,
      topUsers: {} as any,
      topResources: {} as any,
      vulnerabilityToggles: 0
    };

    let successCount = 0;

    recentEntries.forEach(entry => {
      // Count by type
      stats.eventsByType[entry.eventType] = (stats.eventsByType[entry.eventType] || 0) + 1;
      
      // Count by severity
      stats.eventsBySeverity[entry.severity] = (stats.eventsBySeverity[entry.severity] || 0) + 1;
      
      // Count successes
      if (entry.success) {
        successCount++;
      }
      
      // Count by user
      if (entry.userId) {
        stats.topUsers[entry.userId] = (stats.topUsers[entry.userId] || 0) + 1;
      }
      
      // Count by resource
      if (entry.resource) {
        stats.topResources[entry.resource] = (stats.topResources[entry.resource] || 0) + 1;
      }
      
      // Count vulnerability toggles
      if (entry.eventType === AuditEventType.VULNERABILITY_TOGGLE) {
        stats.vulnerabilityToggles++;
      }
    });

    stats.successRate = recentEntries.length > 0 
      ? Math.round((successCount / recentEntries.length) * 100 * 100) / 100
      : 100;

    return stats;
  }

  // Search audit trail
  searchAuditTrail(
    query: {
      eventType?: AuditEventType;
      userId?: number;
      resource?: string;
      severity?: string;
      startDate?: Date;
      endDate?: Date;
      action?: string;
    },
    limit: number = 100
  ): AuditEntry[] {
    let results = this.auditEntries;

    if (query.eventType) {
      results = results.filter(entry => entry.eventType === query.eventType);
    }

    if (query.userId) {
      results = results.filter(entry => entry.userId === query.userId);
    }

    if (query.resource) {
      results = results.filter(entry => entry.resource === query.resource);
    }

    if (query.severity) {
      results = results.filter(entry => entry.severity === query.severity);
    }

    if (query.startDate) {
      results = results.filter(entry => 
        new Date(entry.timestamp) >= query.startDate!
      );
    }

    if (query.endDate) {
      results = results.filter(entry => 
        new Date(entry.timestamp) <= query.endDate!
      );
    }

    if (query.action) {
      results = results.filter(entry => 
        entry.action.toLowerCase().includes(query.action!.toLowerCase())
      );
    }

    return results
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, limit);
  }
}

// Singleton instance
export const auditTrail = new AuditTrailSystem();
export default auditTrail;