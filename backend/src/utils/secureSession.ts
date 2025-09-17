import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

/**
 * Secure Session Management Utilities
 * 
 * This module provides secure session management with:
 * 1. Strong JWT secrets and proper token handling
 * 2. HttpOnly cookie-based session storage
 * 3. Token refresh mechanism and secure logout
 * 4. Proper ownership verification for all resources
 * 5. Session security best practices
 */

// Generate a strong secret key (should be stored in environment variables)
const generateStrongSecret = (): string => {
  return crypto.randomBytes(64).toString('hex');
};

// Get JWT secret from environment or generate a strong one
const JWT_SECRET = process.env.JWT_SECRET || generateStrongSecret();
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || generateStrongSecret();

// Token expiration times
const ACCESS_TOKEN_EXPIRY = '15m'; // Short-lived access token
const REFRESH_TOKEN_EXPIRY = '7d'; // Longer-lived refresh token
const REMEMBER_ME_EXPIRY = '30d'; // Extended expiry for "remember me"

// Cookie configuration
const COOKIE_CONFIG = {
  httpOnly: true, // Prevent XSS attacks
  secure: process.env.NODE_ENV === 'production', // HTTPS only in production
  sameSite: 'strict' as const, // CSRF protection
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
  path: '/'
};

const REFRESH_COOKIE_CONFIG = {
  ...COOKIE_CONFIG,
  maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
};

/**
 * Token payload interface
 */
interface TokenPayload {
  userId: number;
  email: string;
  sessionId: string;
  tokenType: 'access' | 'refresh';
  iat?: number;
  exp?: number;
}

/**
 * Session data interface
 */
interface SessionData {
  id: string;
  userId: number;
  createdAt: Date;
  lastAccessedAt: Date;
  ipAddress?: string;
  userAgent?: string;
  isActive: boolean;
}

// In-memory session store (in production, use Redis or database)
const sessionStore = new Map<string, SessionData>();

/**
 * Generate a secure session ID
 */
const generateSessionId = (): string => {
  return crypto.randomBytes(32).toString('hex');
};

/**
 * Create access token
 */
export const createAccessToken = (userId: number, email: string, sessionId: string): string => {
  const payload: TokenPayload = {
    userId,
    email,
    sessionId,
    tokenType: 'access'
  };
  
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRY,
    issuer: 'vulnerable-webapp',
    audience: 'vulnerable-webapp-users'
  });
};

/**
 * Create refresh token
 */
export const createRefreshToken = (userId: number, email: string, sessionId: string): string => {
  const payload: TokenPayload = {
    userId,
    email,
    sessionId,
    tokenType: 'refresh'
  };
  
  return jwt.sign(payload, JWT_REFRESH_SECRET, {
    expiresIn: REFRESH_TOKEN_EXPIRY,
    issuer: 'vulnerable-webapp',
    audience: 'vulnerable-webapp-users'
  });
};

/**
 * Verify access token
 */
export const verifyAccessToken = (token: string): TokenPayload | null => {
  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      issuer: 'vulnerable-webapp',
      audience: 'vulnerable-webapp-users'
    }) as TokenPayload;
    
    if (decoded.tokenType !== 'access') {
      return null;
    }
    
    return decoded;
  } catch (error) {
    return null;
  }
};

/**
 * Verify refresh token
 */
export const verifyRefreshToken = (token: string): TokenPayload | null => {
  try {
    const decoded = jwt.verify(token, JWT_REFRESH_SECRET, {
      issuer: 'vulnerable-webapp',
      audience: 'vulnerable-webapp-users'
    }) as TokenPayload;
    
    if (decoded.tokenType !== 'refresh') {
      return null;
    }
    
    return decoded;
  } catch (error) {
    return null;
  }
};

/**
 * Create a new session
 */
export const createSession = async (
  userId: number, 
  email: string, 
  req: Request, 
  rememberMe: boolean = false
): Promise<{ accessToken: string; refreshToken: string; sessionId: string }> => {
  const sessionId = generateSessionId();
  
  // Store session data
  const sessionData: SessionData = {
    id: sessionId,
    userId,
    createdAt: new Date(),
    lastAccessedAt: new Date(),
    ipAddress: req.ip || req.connection.remoteAddress,
    userAgent: req.get('User-Agent'),
    isActive: true
  };
  
  sessionStore.set(sessionId, sessionData);
  
  // Create tokens
  const accessToken = createAccessToken(userId, email, sessionId);
  const refreshToken = createRefreshToken(userId, email, sessionId);
  
  // Update user's last login
  await prisma.user.update({
    where: { id: userId },
    data: { 
      updatedAt: new Date()
      // Could add lastLoginAt field to track login times
    }
  });
  
  return { accessToken, refreshToken, sessionId };
};

/**
 * Set secure cookies for tokens
 */
export const setSecureCookies = (
  res: Response, 
  accessToken: string, 
  refreshToken: string, 
  rememberMe: boolean = false
): void => {
  const accessCookieConfig = {
    ...COOKIE_CONFIG,
    maxAge: rememberMe ? 30 * 24 * 60 * 60 * 1000 : COOKIE_CONFIG.maxAge
  };
  
  const refreshCookieConfig = {
    ...REFRESH_COOKIE_CONFIG,
    maxAge: rememberMe ? 30 * 24 * 60 * 60 * 1000 : REFRESH_COOKIE_CONFIG.maxAge
  };
  
  // Set httpOnly cookies
  res.cookie('accessToken', accessToken, accessCookieConfig);
  res.cookie('refreshToken', refreshToken, refreshCookieConfig);
};

/**
 * Clear authentication cookies
 */
export const clearAuthCookies = (res: Response): void => {
  res.clearCookie('accessToken', { path: '/' });
  res.clearCookie('refreshToken', { path: '/' });
};

/**
 * Validate session
 */
export const validateSession = (sessionId: string): boolean => {
  const session = sessionStore.get(sessionId);
  
  if (!session || !session.isActive) {
    return false;
  }
  
  // Update last accessed time
  session.lastAccessedAt = new Date();
  sessionStore.set(sessionId, session);
  
  return true;
};

/**
 * Invalidate session
 */
export const invalidateSession = (sessionId: string): void => {
  const session = sessionStore.get(sessionId);
  if (session) {
    session.isActive = false;
    sessionStore.set(sessionId, session);
  }
};

/**
 * Invalidate all user sessions
 */
export const invalidateAllUserSessions = (userId: number): void => {
  for (const [sessionId, session] of sessionStore.entries()) {
    if (session.userId === userId) {
      session.isActive = false;
      sessionStore.set(sessionId, session);
    }
  }
};

/**
 * Get user sessions
 */
export const getUserSessions = (userId: number): SessionData[] => {
  const userSessions: SessionData[] = [];
  
  for (const session of sessionStore.values()) {
    if (session.userId === userId && session.isActive) {
      userSessions.push(session);
    }
  }
  
  return userSessions;
};

/**
 * Clean up expired sessions
 */
export const cleanupExpiredSessions = (): void => {
  const now = new Date();
  const expiredSessions: string[] = [];
  
  for (const [sessionId, session] of sessionStore.entries()) {
    // Consider sessions older than 7 days as expired
    const sessionAge = now.getTime() - session.lastAccessedAt.getTime();
    const maxAge = 7 * 24 * 60 * 60 * 1000; // 7 days
    
    if (sessionAge > maxAge) {
      expiredSessions.push(sessionId);
    }
  }
  
  // Remove expired sessions
  expiredSessions.forEach(sessionId => {
    sessionStore.delete(sessionId);
  });
  
  console.log(`Cleaned up ${expiredSessions.length} expired sessions`);
};

/**
 * Refresh access token using refresh token
 */
export const refreshAccessToken = async (
  refreshToken: string, 
  req: Request
): Promise<{ accessToken: string; refreshToken: string } | null> => {
  // Verify refresh token
  const decoded = verifyRefreshToken(refreshToken);
  if (!decoded) {
    return null;
  }
  
  // Validate session
  if (!validateSession(decoded.sessionId)) {
    return null;
  }
  
  // Verify user still exists
  const user = await prisma.user.findUnique({
    where: { id: decoded.userId },
    select: { id: true, email: true }
  });
  
  if (!user) {
    return null;
  }
  
  // Create new tokens
  const newAccessToken = createAccessToken(user.id, user.email, decoded.sessionId);
  const newRefreshToken = createRefreshToken(user.id, user.email, decoded.sessionId);
  
  return {
    accessToken: newAccessToken,
    refreshToken: newRefreshToken
  };
};

/**
 * Secure logout
 */
export const secureLogout = (sessionId: string, res: Response): void => {
  // Invalidate session
  invalidateSession(sessionId);
  
  // Clear cookies
  clearAuthCookies(res);
};

/**
 * Extract token from request (cookies or Authorization header)
 */
export const extractTokenFromRequest = (req: Request): string | null => {
  // First, try to get token from httpOnly cookie (preferred)
  if (req.cookies && req.cookies.accessToken) {
    return req.cookies.accessToken;
  }
  
  // Fallback to Authorization header (for API clients)
  const authHeader = req.get('Authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }
  
  return null;
};

/**
 * Extract refresh token from request
 */
export const extractRefreshTokenFromRequest = (req: Request): string | null => {
  // Try to get refresh token from httpOnly cookie
  if (req.cookies && req.cookies.refreshToken) {
    return req.cookies.refreshToken;
  }
  
  // Fallback to request body (for refresh endpoint)
  if (req.body && req.body.refreshToken) {
    return req.body.refreshToken;
  }
  
  return null;
};

/**
 * Ownership verification utilities
 */
export const verifyTaskOwnership = async (taskId: number, userId: number): Promise<boolean> => {
  try {
    const task = await prisma.task.findFirst({
      where: {
        id: taskId,
        userId: userId
      },
      select: { id: true }
    });
    
    return !!task;
  } catch (error) {
    return false;
  }
};

export const verifyCommentOwnership = async (commentId: number, userId: number): Promise<boolean> => {
  try {
    const comment = await prisma.comment.findFirst({
      where: {
        id: commentId,
        OR: [
          { userId: userId }, // User owns the comment
          { task: { userId: userId } } // User owns the task
        ]
      },
      select: { id: true }
    });
    
    return !!comment;
  } catch (error) {
    return false;
  }
};

/**
 * Rate limiting utilities
 */
const rateLimitStore = new Map<string, { count: number; resetTime: number }>();

export const checkRateLimit = (
  identifier: string, 
  maxRequests: number = 100, 
  windowMs: number = 15 * 60 * 1000 // 15 minutes
): { allowed: boolean; remaining: number; resetTime: number } => {
  const now = Date.now();
  const record = rateLimitStore.get(identifier);
  
  if (!record || now > record.resetTime) {
    // Create new record or reset expired one
    const newRecord = {
      count: 1,
      resetTime: now + windowMs
    };
    rateLimitStore.set(identifier, newRecord);
    
    return {
      allowed: true,
      remaining: maxRequests - 1,
      resetTime: newRecord.resetTime
    };
  }
  
  if (record.count >= maxRequests) {
    return {
      allowed: false,
      remaining: 0,
      resetTime: record.resetTime
    };
  }
  
  record.count++;
  rateLimitStore.set(identifier, record);
  
  return {
    allowed: true,
    remaining: maxRequests - record.count,
    resetTime: record.resetTime
  };
};

/**
 * Security headers utility
 */
export const setSecurityHeaders = (res: Response): void => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
  });
};

// Start session cleanup interval
setInterval(cleanupExpiredSessions, 60 * 60 * 1000); // Run every hour