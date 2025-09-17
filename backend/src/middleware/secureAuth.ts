import { Request, Response, NextFunction } from 'express';
import { PrismaClient } from '@prisma/client';
import {
  extractTokenFromRequest,
  verifyAccessToken,
  validateSession,
  setSecurityHeaders,
  checkRateLimit
} from '../utils/secureSession.js';

const prisma = new PrismaClient();

/**
 * Secure Authentication Middleware
 * 
 * This middleware provides secure authentication with:
 * 1. Proper token validation and session management
 * 2. Rate limiting to prevent brute force attacks
 * 3. Security headers for additional protection
 * 4. Comprehensive error handling
 */

// Extend Request interface to include user
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: number;
        email: string;
        firstName: string;
        lastName: string;
        sessionId: string;
      };
    }
  }
}

/**
 * Secure authentication middleware
 */
export const secureAuthenticateUser = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    // Set security headers
    setSecurityHeaders(res);
    
    // Rate limiting based on IP address
    const clientIp = req.ip || req.connection.remoteAddress || 'unknown';
    const rateLimit = checkRateLimit(`auth:${clientIp}`, 100, 15 * 60 * 1000); // 100 requests per 15 minutes
    
    if (!rateLimit.allowed) {
      res.status(429).json({
        success: false,
        error: 'Too many requests',
        message: 'Rate limit exceeded. Please try again later.',
        retryAfter: Math.ceil((rateLimit.resetTime - Date.now()) / 1000)
      });
      return;
    }
    
    // Extract token from request
    const token = extractTokenFromRequest(req);
    
    if (!token) {
      res.status(401).json({
        success: false,
        error: 'Authentication required',
        message: 'Access token is required'
      });
      return;
    }
    
    // Verify token
    const decoded = verifyAccessToken(token);
    
    if (!decoded) {
      res.status(401).json({
        success: false,
        error: 'Invalid token',
        message: 'Access token is invalid or expired'
      });
      return;
    }
    
    // Validate session
    if (!validateSession(decoded.sessionId)) {
      res.status(401).json({
        success: false,
        error: 'Session expired',
        message: 'Session is no longer valid'
      });
      return;
    }
    
    // Verify user exists and is active
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        emailVerified: true
      }
    });
    
    if (!user) {
      res.status(401).json({
        success: false,
        error: 'User not found',
        message: 'User account no longer exists'
      });
      return;
    }
    
    // Optional: Check if email is verified
    if (!user.emailVerified) {
      res.status(403).json({
        success: false,
        error: 'Email not verified',
        message: 'Please verify your email address to continue'
      });
      return;
    }
    
    // Attach user to request
    req.user = {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      sessionId: decoded.sessionId
    };
    
    // Add rate limit headers
    res.set({
      'X-RateLimit-Limit': '100',
      'X-RateLimit-Remaining': rateLimit.remaining.toString(),
      'X-RateLimit-Reset': new Date(rateLimit.resetTime).toISOString()
    });
    
    next();
    
  } catch (error) {
    console.error('Secure authentication error:', error);
    res.status(500).json({
      success: false,
      error: 'Authentication error',
      message: 'An error occurred during authentication'
    });
  }
};

/**
 * Optional authentication middleware (doesn't require authentication)
 */
export const secureOptionalAuth = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    // Set security headers
    setSecurityHeaders(res);
    
    // Extract token from request
    const token = extractTokenFromRequest(req);
    
    if (token) {
      // Verify token if present
      const decoded = verifyAccessToken(token);
      
      if (decoded && validateSession(decoded.sessionId)) {
        // Get user if token is valid
        const user = await prisma.user.findUnique({
          where: { id: decoded.userId },
          select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            emailVerified: true
          }
        });
        
        if (user && user.emailVerified) {
          req.user = {
            id: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            sessionId: decoded.sessionId
          };
        }
      }
    }
    
    next();
    
  } catch (error) {
    console.error('Optional authentication error:', error);
    // Don't fail the request for optional auth
    next();
  }
};

/**
 * Admin authentication middleware
 */
export const secureRequireAdmin = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  // First run regular authentication
  await secureAuthenticateUser(req, res, () => {
    // Check if user is admin (you would need to add an isAdmin field to User model)
    // For now, we'll check if user ID is 1 (first user)
    if (req.user && req.user.id === 1) {
      next();
    } else {
      res.status(403).json({
        success: false,
        error: 'Admin access required',
        message: 'This endpoint requires administrator privileges'
      });
    }
  });
};

/**
 * Resource ownership verification middleware factory
 */
export const verifyResourceOwnership = (
  resourceType: 'task' | 'comment',
  paramName: string = 'id'
) => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          error: 'Authentication required',
          message: 'User must be authenticated'
        });
        return;
      }
      
      const resourceId = parseInt(req.params[paramName]);
      
      if (isNaN(resourceId) || resourceId <= 0) {
        res.status(400).json({
          success: false,
          error: 'Invalid resource ID',
          message: `${resourceType} ID must be a positive integer`
        });
        return;
      }
      
      let hasAccess = false;
      
      if (resourceType === 'task') {
        const task = await prisma.task.findFirst({
          where: {
            id: resourceId,
            userId: req.user.id
          },
          select: { id: true }
        });
        hasAccess = !!task;
      } else if (resourceType === 'comment') {
        const comment = await prisma.comment.findFirst({
          where: {
            id: resourceId,
            OR: [
              { userId: req.user.id }, // User owns the comment
              { task: { userId: req.user.id } } // User owns the task
            ]
          },
          select: { id: true }
        });
        hasAccess = !!comment;
      }
      
      if (!hasAccess) {
        res.status(403).json({
          success: false,
          error: 'Access denied',
          message: `You don't have permission to access this ${resourceType}`
        });
        return;
      }
      
      next();
      
    } catch (error) {
      console.error('Resource ownership verification error:', error);
      res.status(500).json({
        success: false,
        error: 'Authorization error',
        message: 'An error occurred during authorization'
      });
    }
  };
};

/**
 * CSRF protection middleware
 */
export const csrfProtection = (req: Request, res: Response, next: NextFunction): void => {
  // Skip CSRF for GET, HEAD, OPTIONS requests
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    next();
    return;
  }
  
  // Check for CSRF token in header
  const csrfToken = req.get('X-CSRF-Token') || req.body._csrf;
  const sessionToken = req.cookies?.csrfToken;
  
  if (!csrfToken || !sessionToken || csrfToken !== sessionToken) {
    res.status(403).json({
      success: false,
      error: 'CSRF token mismatch',
      message: 'Invalid or missing CSRF token'
    });
    return;
  }
  
  next();
};

/**
 * Input sanitization middleware
 */
export const sanitizeInput = (req: Request, res: Response, next: NextFunction): void => {
  // Recursively sanitize object properties
  const sanitizeObject = (obj: any): any => {
    if (typeof obj === 'string') {
      // Basic HTML entity encoding
      return obj
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .trim();
    }
    
    if (Array.isArray(obj)) {
      return obj.map(sanitizeObject);
    }
    
    if (obj && typeof obj === 'object') {
      const sanitized: any = {};
      for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
          sanitized[key] = sanitizeObject(obj[key]);
        }
      }
      return sanitized;
    }
    
    return obj;
  };
  
  // Sanitize request body
  if (req.body) {
    req.body = sanitizeObject(req.body);
  }
  
  // Sanitize query parameters
  if (req.query) {
    req.query = sanitizeObject(req.query);
  }
  
  next();
};

/**
 * Request logging middleware for security monitoring
 */
export const securityLogger = (req: Request, res: Response, next: NextFunction): void => {
  const startTime = Date.now();
  
  // Log request details
  const logData = {
    timestamp: new Date().toISOString(),
    method: req.method,
    url: req.url,
    ip: req.ip || req.connection.remoteAddress,
    userAgent: req.get('User-Agent'),
    userId: req.user?.id,
    sessionId: req.user?.sessionId
  };
  
  // Log suspicious patterns
  const suspiciousPatterns = [
    /script/i,
    /javascript:/i,
    /vbscript:/i,
    /onload/i,
    /onerror/i,
    /union.*select/i,
    /drop.*table/i,
    /\.\.\/\.\.\//,
    /%2e%2e%2f/i
  ];
  
  const requestString = JSON.stringify(req.body) + req.url + JSON.stringify(req.query);
  const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(requestString));
  
  if (isSuspicious) {
    console.warn('🚨 SUSPICIOUS REQUEST DETECTED:', logData);
  }
  
  // Override res.json to log response
  const originalJson = res.json;
  res.json = function(body: any) {
    const responseTime = Date.now() - startTime;
    
    if (isSuspicious || res.statusCode >= 400) {
      console.log('📊 SECURITY LOG:', {
        ...logData,
        statusCode: res.statusCode,
        responseTime,
        suspicious: isSuspicious
      });
    }
    
    return originalJson.call(this, body);
  };
  
  next();
};

export default {
  secureAuthenticateUser,
  secureOptionalAuth,
  secureRequireAdmin,
  verifyResourceOwnership,
  csrfProtection,
  sanitizeInput,
  securityLogger
};