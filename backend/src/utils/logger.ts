import fs from 'fs';
import path from 'path';

// Log levels
export enum LogLevel {
  ERROR = 0,
  WARN = 1,
  INFO = 2,
  DEBUG = 3,
  SECURITY = 4
}

// Log entry interface
export interface LogEntry {
  timestamp: string;
  level: string;
  message: string;
  metadata?: any;
  userId?: number;
  ip?: string;
  userAgent?: string;
  endpoint?: string;
  method?: string;
  statusCode?: number;
  responseTime?: number;
  vulnerabilityType?: string;
  attackVector?: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
}

// Security event types
export enum SecurityEventType {
  SQL_INJECTION_ATTEMPT = 'sql_injection_attempt',
  XSS_ATTEMPT = 'xss_attempt',
  IDOR_ATTEMPT = 'idor_attempt',
  SSRF_ATTEMPT = 'ssrf_attempt',
  LFI_ATTEMPT = 'lfi_attempt',
  BRUTE_FORCE_ATTEMPT = 'brute_force_attempt',
  UNAUTHORIZED_ACCESS = 'unauthorized_access',
  VULNERABILITY_TOGGLE = 'vulnerability_toggle',
  SUSPICIOUS_ACTIVITY = 'suspicious_activity',
  AUTHENTICATION_FAILURE = 'authentication_failure',
  PRIVILEGE_ESCALATION = 'privilege_escalation'
}

class Logger {
  private logLevel: LogLevel;
  private logDirectory: string;
  private securityLogFile: string;
  private applicationLogFile: string;
  private attackLogFile: string;

  constructor() {
    this.logLevel = this.getLogLevel();
    this.logDirectory = path.join(process.cwd(), 'logs');
    this.securityLogFile = path.join(this.logDirectory, 'security.log');
    this.applicationLogFile = path.join(this.logDirectory, 'application.log');
    this.attackLogFile = path.join(this.logDirectory, 'attacks.log');
    
    this.ensureLogDirectory();
  }

  private getLogLevel(): LogLevel {
    const level = process.env.LOG_LEVEL?.toLowerCase() || 'info';
    switch (level) {
      case 'error': return LogLevel.ERROR;
      case 'warn': return LogLevel.WARN;
      case 'info': return LogLevel.INFO;
      case 'debug': return LogLevel.DEBUG;
      case 'security': return LogLevel.SECURITY;
      default: return LogLevel.INFO;
    }
  }

  private ensureLogDirectory(): void {
    if (!fs.existsSync(this.logDirectory)) {
      fs.mkdirSync(this.logDirectory, { recursive: true });
    }
  }

  private formatLogEntry(entry: LogEntry): string {
    return JSON.stringify(entry) + '\n';
  }

  private writeToFile(filePath: string, entry: LogEntry): void {
    try {
      const logLine = this.formatLogEntry(entry);
      fs.appendFileSync(filePath, logLine);
    } catch (error) {
      console.error('Failed to write to log file:', error);
    }
  }

  private createLogEntry(
    level: string,
    message: string,
    metadata?: any,
    additionalFields?: Partial<LogEntry>
  ): LogEntry {
    return {
      timestamp: new Date().toISOString(),
      level,
      message,
      metadata,
      ...additionalFields
    };
  }

  // Standard logging methods
  error(message: string, metadata?: any, additionalFields?: Partial<LogEntry>): void {
    if (this.logLevel >= LogLevel.ERROR) {
      const entry = this.createLogEntry('ERROR', message, metadata, additionalFields);
      console.error(`[ERROR] ${message}`, metadata);
      this.writeToFile(this.applicationLogFile, entry);
    }
  }

  warn(message: string, metadata?: any, additionalFields?: Partial<LogEntry>): void {
    if (this.logLevel >= LogLevel.WARN) {
      const entry = this.createLogEntry('WARN', message, metadata, additionalFields);
      console.warn(`[WARN] ${message}`, metadata);
      this.writeToFile(this.applicationLogFile, entry);
    }
  }

  info(message: string, metadata?: any, additionalFields?: Partial<LogEntry>): void {
    if (this.logLevel >= LogLevel.INFO) {
      const entry = this.createLogEntry('INFO', message, metadata, additionalFields);
      console.info(`[INFO] ${message}`, metadata);
      this.writeToFile(this.applicationLogFile, entry);
    }
  }

  debug(message: string, metadata?: any, additionalFields?: Partial<LogEntry>): void {
    if (this.logLevel >= LogLevel.DEBUG) {
      const entry = this.createLogEntry('DEBUG', message, metadata, additionalFields);
      console.debug(`[DEBUG] ${message}`, metadata);
      this.writeToFile(this.applicationLogFile, entry);
    }
  }

  // Security-specific logging
  security(
    eventType: SecurityEventType,
    message: string,
    metadata?: any,
    additionalFields?: Partial<LogEntry>
  ): void {
    const entry = this.createLogEntry('SECURITY', message, {
      eventType,
      ...metadata
    }, additionalFields);
    
    console.warn(`[SECURITY] ${eventType}: ${message}`, metadata);
    this.writeToFile(this.securityLogFile, entry);
    
    // Also log to attack log if it's an attack attempt
    if (this.isAttackEvent(eventType)) {
      this.writeToFile(this.attackLogFile, entry);
    }
  }

  // Attack detection logging
  attack(
    attackType: SecurityEventType,
    payload: string,
    severity: 'low' | 'medium' | 'high' | 'critical',
    additionalFields?: Partial<LogEntry>
  ): void {
    const entry = this.createLogEntry('ATTACK', `Attack detected: ${attackType}`, {
      attackType,
      payload,
      severity
    }, {
      severity,
      vulnerabilityType: attackType,
      attackVector: payload,
      ...additionalFields
    });
    
    console.error(`[ATTACK] ${attackType} - Severity: ${severity}`, { payload });
    this.writeToFile(this.attackLogFile, entry);
    this.writeToFile(this.securityLogFile, entry);
  }

  // Vulnerability toggle logging
  vulnerabilityToggle(
    vulnerabilityType: string,
    enabled: boolean,
    userId?: number,
    additionalFields?: Partial<LogEntry>
  ): void {
    this.security(
      SecurityEventType.VULNERABILITY_TOGGLE,
      `Vulnerability ${vulnerabilityType} ${enabled ? 'enabled' : 'disabled'}`,
      {
        vulnerabilityType,
        enabled,
        userId
      },
      additionalFields
    );
  }

  // HTTP request logging
  httpRequest(
    method: string,
    endpoint: string,
    statusCode: number,
    responseTime: number,
    userId?: number,
    ip?: string,
    userAgent?: string
  ): void {
    const entry = this.createLogEntry('HTTP', `${method} ${endpoint} - ${statusCode}`, {
      method,
      endpoint,
      statusCode,
      responseTime,
      userId,
      ip,
      userAgent
    }, {
      method,
      endpoint,
      statusCode,
      responseTime,
      userId,
      ip,
      userAgent
    });
    
    this.writeToFile(this.applicationLogFile, entry);
  }

  // Performance monitoring
  performance(
    operation: string,
    duration: number,
    metadata?: any
  ): void {
    this.info(`Performance: ${operation} took ${duration}ms`, {
      operation,
      duration,
      ...metadata
    });
  }

  private isAttackEvent(eventType: SecurityEventType): boolean {
    const attackEvents = [
      SecurityEventType.SQL_INJECTION_ATTEMPT,
      SecurityEventType.XSS_ATTEMPT,
      SecurityEventType.IDOR_ATTEMPT,
      SecurityEventType.SSRF_ATTEMPT,
      SecurityEventType.LFI_ATTEMPT,
      SecurityEventType.BRUTE_FORCE_ATTEMPT,
      SecurityEventType.UNAUTHORIZED_ACCESS,
      SecurityEventType.PRIVILEGE_ESCALATION
    ];
    
    return attackEvents.includes(eventType);
  }

  // Log rotation (simple implementation)
  rotateLog(filePath: string, maxSize: number = 10 * 1024 * 1024): void {
    try {
      if (fs.existsSync(filePath)) {
        const stats = fs.statSync(filePath);
        if (stats.size > maxSize) {
          const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
          const rotatedPath = `${filePath}.${timestamp}`;
          fs.renameSync(filePath, rotatedPath);
        }
      }
    } catch (error) {
      console.error('Failed to rotate log file:', error);
    }
  }

  // Get log statistics
  getLogStats(): any {
    const stats = {
      security: this.getFileStats(this.securityLogFile),
      application: this.getFileStats(this.applicationLogFile),
      attacks: this.getFileStats(this.attackLogFile)
    };
    
    return stats;
  }

  private getFileStats(filePath: string): any {
    try {
      if (fs.existsSync(filePath)) {
        const stats = fs.statSync(filePath);
        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split('\n').filter(line => line.trim());
        
        return {
          size: stats.size,
          lines: lines.length,
          lastModified: stats.mtime,
          exists: true
        };
      }
      return { exists: false };
    } catch (error) {
      return { exists: false, error: error.message };
    }
  }
}

// Singleton instance
export const logger = new Logger();

export default logger;