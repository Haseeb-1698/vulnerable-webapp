import { Request, Response, NextFunction } from 'express';
import { logger, SecurityEventType } from '../utils/logger';

// Extend Request interface to include timing
declare global {
  namespace Express {
    interface Request {
      startTime?: number;
      userId?: number;
    }
  }
}

// Request logging middleware
export const requestLogger = (req: Request, res: Response, next: NextFunction) => {
  req.startTime = Date.now();
  
  // Log the incoming request
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const userAgent = req.get('User-Agent') || 'unknown';
  
  // Override res.end to capture response details
  const originalEnd = res.end;
  res.end = function(chunk?: any, encoding?: any) {
    const responseTime = Date.now() - (req.startTime || Date.now());
    
    // Log the completed request
    logger.httpRequest(
      req.method,
      req.originalUrl,
      res.statusCode,
      responseTime,
      req.userId,
      ip,
      userAgent
    );
    
    // Call original end method
    originalEnd.call(this, chunk, encoding);
  };
  
  next();
};

// Security event logging middleware
export const securityLogger = (req: Request, res: Response, next: NextFunction) => {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const userAgent = req.get('User-Agent') || 'unknown';
  
  // Check for potential SQL injection in query parameters
  const queryString = JSON.stringify(req.query);
  if (containsSQLInjection(queryString)) {
    logger.attack(
      SecurityEventType.SQL_INJECTION_ATTEMPT,
      queryString,
      'high',
      {
        ip,
        userAgent,
        endpoint: req.originalUrl,
        method: req.method,
        userId: req.userId
      }
    );
  }
  
  // Check for XSS attempts in request body
  if (req.body && typeof req.body === 'object') {
    const bodyString = JSON.stringify(req.body);
    if (containsXSS(bodyString)) {
      logger.attack(
        SecurityEventType.XSS_ATTEMPT,
        bodyString,
        'high',
        {
          ip,
          userAgent,
          endpoint: req.originalUrl,
          method: req.method,
          userId: req.userId
        }
      );
    }
  }
  
  // Check for SSRF attempts
  if (req.body && (req.body.imageUrl || req.body.importUrl)) {
    const url = req.body.imageUrl || req.body.importUrl;
    if (containsSSRF(url)) {
      logger.attack(
        SecurityEventType.SSRF_ATTEMPT,
        url,
        'critical',
        {
          ip,
          userAgent,
          endpoint: req.originalUrl,
          method: req.method,
          userId: req.userId
        }
      );
    }
  }
  
  // Check for LFI attempts in file paths
  if (req.params.filename && containsLFI(req.params.filename)) {
    logger.attack(
      SecurityEventType.LFI_ATTEMPT,
      req.params.filename,
      'high',
      {
        ip,
        userAgent,
        endpoint: req.originalUrl,
        method: req.method,
        userId: req.userId
      }
    );
  }
  
  next();
};

// Authentication failure logging
export const authFailureLogger = (req: Request, res: Response, next: NextFunction) => {
  const originalJson = res.json;
  
  res.json = function(body: any) {
    if (res.statusCode === 401 || res.statusCode === 403) {
      const ip = req.ip || req.connection.remoteAddress || 'unknown';
      const userAgent = req.get('User-Agent') || 'unknown';
      
      logger.security(
        SecurityEventType.AUTHENTICATION_FAILURE,
        `Authentication failed for ${req.originalUrl}`,
        {
          statusCode: res.statusCode,
          body: body,
          credentials: req.body?.email ? { email: req.body.email } : undefined
        },
        {
          ip,
          userAgent,
          endpoint: req.originalUrl,
          method: req.method,
          statusCode: res.statusCode
        }
      );
    }
    
    return originalJson.call(this, body);
  };
  
  next();
};

// IDOR attempt detection
export const idorDetectionLogger = (req: Request, res: Response, next: NextFunction) => {
  // Store original user ID for comparison
  const originalUserId = req.userId;
  
  // Override res.json to detect unauthorized access
  const originalJson = res.json;
  res.json = function(body: any) {
    // Check if response contains data that doesn't belong to the user
    if (res.statusCode === 200 && body && originalUserId) {
      if (body.userId && body.userId !== originalUserId) {
        const ip = req.ip || req.connection.remoteAddress || 'unknown';
        const userAgent = req.get('User-Agent') || 'unknown';
        
        logger.attack(
          SecurityEventType.IDOR_ATTEMPT,
          `User ${originalUserId} accessed resource belonging to user ${body.userId}`,
          'critical',
          {
            ip,
            userAgent,
            endpoint: req.originalUrl,
            method: req.method,
            userId: originalUserId,
            targetUserId: body.userId
          }
        );
      }
    }
    
    return originalJson.call(this, body);
  };
  
  next();
};

// Performance monitoring middleware
export const performanceLogger = (req: Request, res: Response, next: NextFunction) => {
  const startTime = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    
    // Log slow requests (> 1 second)
    if (duration > 1000) {
      logger.performance(
        `Slow request: ${req.method} ${req.originalUrl}`,
        duration,
        {
          statusCode: res.statusCode,
          userId: req.userId
        }
      );
    }
  });
  
  next();
};

// Helper functions for attack detection
function containsSQLInjection(input: string): boolean {
  const sqlPatterns = [
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)/i,
    /(--|#|\/\*|\*\/)/,
    /(\bOR\b.*=.*\bOR\b|\bAND\b.*=.*\bAND\b)/i,
    /('.*'|".*")\s*(=|<|>|\bLIKE\b)/i,
    /\b(UNION\s+SELECT|UNION\s+ALL\s+SELECT)\b/i,
    /\b(INFORMATION_SCHEMA|SYSOBJECTS|SYSCOLUMNS)\b/i
  ];
  
  return sqlPatterns.some(pattern => pattern.test(input));
}

function containsXSS(input: string): boolean {
  const xssPatterns = [
    /<script[^>]*>.*?<\/script>/i,
    /<iframe[^>]*>.*?<\/iframe>/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /<img[^>]*onerror[^>]*>/i,
    /<svg[^>]*onload[^>]*>/i,
    /eval\s*\(/i,
    /document\.cookie/i,
    /window\.location/i
  ];
  
  return xssPatterns.some(pattern => pattern.test(input));
}

function containsSSRF(url: string): boolean {
  if (!url || typeof url !== 'string') return false;
  
  const ssrfPatterns = [
    /^https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0)/i,
    /^https?:\/\/10\./i,
    /^https?:\/\/172\.(1[6-9]|2[0-9]|3[0-1])\./i,
    /^https?:\/\/192\.168\./i,
    /^https?:\/\/169\.254\.169\.254/i, // AWS metadata
    /^https?:\/\/metadata\.google\.internal/i, // GCP metadata
    /^file:\/\//i,
    /^ftp:\/\//i,
    /^gopher:\/\//i
  ];
  
  return ssrfPatterns.some(pattern => pattern.test(url));
}

function containsLFI(filename: string): boolean {
  if (!filename || typeof filename !== 'string') return false;
  
  const lfiPatterns = [
    /\.\.\//,
    /\.\.\\/, 
    /%2e%2e%2f/i,
    /%2e%2e%5c/i,
    /\/etc\/passwd/i,
    /\/etc\/shadow/i,
    /\/proc\/version/i,
    /\/windows\/system32/i,
    /\.\.\/\.\.\/\.\.\//
  ];
  
  return lfiPatterns.some(pattern => pattern.test(filename));
}

export {
  containsSQLInjection,
  containsXSS,
  containsSSRF,
  containsLFI
};