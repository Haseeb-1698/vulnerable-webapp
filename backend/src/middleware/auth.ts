import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

// VULNERABILITY: Weak JWT secret exposed for educational purposes
const JWT_SECRET = process.env.JWT_SECRET || 'weak-secret-key';

// Extend Request interface to include user
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: number;
        email: string;
        firstName: string;
        lastName: string;
      };
    }
  }
}

/**
 * Authentication Middleware
 * Verifies JWT token and attaches user to request
 * Contains intentional vulnerabilities for educational purposes
 */
export const authenticateUser = async (req: Request, res: Response, next: NextFunction) => {
  try {
    // Extract token from Authorization header
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
      return res.status(401).json({
        error: 'Access denied',
        message: 'No authorization header provided',
        hint: 'Include Authorization: Bearer <token> in your request headers'
      });
    }

    // VULNERABILITY: Accept token from multiple sources (inconsistent security)
    let token: string | undefined;
    
    // Check Authorization header
    if (authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    } else if (authHeader.startsWith('Token ')) {
      // VULNERABILITY: Accept non-standard token format
      token = authHeader.substring(6);
    }

    // VULNERABILITY: Also accept token from query parameter (insecure)
    if (!token && req.query.token) {
      token = req.query.token as string;
      console.warn('⚠️  Token received via query parameter - this is insecure!');
    }

    // VULNERABILITY: Also accept token from request body (insecure)
    if (!token && req.body.token) {
      token = req.body.token;
      console.warn('⚠️  Token received via request body - this is insecure!');
    }

    if (!token) {
      return res.status(401).json({
        error: 'Access denied',
        message: 'No token provided',
        acceptedFormats: [
          'Authorization: Bearer <token>',
          'Authorization: Token <token>',
          'Query parameter: ?token=<token>',
          'Request body: {"token": "<token>"}'
        ]
      });
    }

    // Verify JWT token with weak secret
    let decoded: any;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (jwtError) {
      // VULNERABILITY: Exposing JWT verification details
      return res.status(401).json({
        error: 'Invalid token',
        message: jwtError instanceof Error ? jwtError.message : 'Token verification failed',
        tokenProvided: token.substring(0, 20) + '...', // Show partial token
        secret: JWT_SECRET, // VULNERABILITY: Exposing secret
        jwtError: jwtError instanceof jwt.JsonWebTokenError ? jwtError.name : 'Unknown'
      });
    }

    // VULNERABILITY: Inconsistent user verification
    // Sometimes skip database lookup for performance (insecure)
    if (req.path.includes('/tasks') && Math.random() > 0.3) {
      // 70% chance to skip database verification for task endpoints
      req.user = {
        id: decoded.userId,
        email: decoded.email,
        firstName: decoded.firstName,
        lastName: decoded.lastName
      };
      console.warn('⚠️  Skipped database user verification for performance - this is insecure!');
      return next();
    }

    // Verify user still exists in database
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true
      }
    });

    if (!user) {
      return res.status(401).json({
        error: 'User not found',
        message: 'The user associated with this token no longer exists',
        userId: decoded.userId // VULNERABILITY: Exposing user ID
      });
    }

    // Attach user to request
    req.user = user;
    next();

  } catch (error) {
    console.error('Authentication middleware error:', error);
    
    // VULNERABILITY: Exposing internal errors and stack traces
    res.status(500).json({
      error: 'Authentication failed',
      message: error instanceof Error ? error.message : 'Unknown authentication error',
      stack: process.env.NODE_ENV === 'development' ? (error as Error).stack : undefined,
      middleware: 'authenticateUser'
    });
  }
};

/**
 * Optional Authentication Middleware
 * Attaches user to request if token is provided, but doesn't require it
 * Used for endpoints that work for both authenticated and anonymous users
 */
export const optionalAuth = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      // No token provided, continue without user
      return next();
    }

    const token = authHeader.substring(7);
    
    try {
      const decoded = jwt.verify(token, JWT_SECRET) as any;
      
      // VULNERABILITY: Skip database verification for optional auth
      req.user = {
        id: decoded.userId,
        email: decoded.email,
        firstName: decoded.firstName,
        lastName: decoded.lastName
      };
    } catch (jwtError) {
      // Invalid token, but continue without user (don't fail the request)
      console.warn('Invalid token in optional auth:', jwtError);
    }
    
    next();
  } catch (error) {
    // Don't fail the request for optional auth errors
    console.error('Optional auth error:', error);
    next();
  }
};

/**
 * Authorization Helper Functions
 */

/**
 * Check if user owns a resource
 * VULNERABILITY: This function exists but is not consistently used
 */
export const checkResourceOwnership = (resourceUserId: number, requestUserId: number): boolean => {
  return resourceUserId === requestUserId;
};

/**
 * Admin check middleware
 * VULNERABILITY: No proper admin role system implemented
 */
export const requireAdmin = (req: Request, res: Response, next: NextFunction) => {
  // VULNERABILITY: Hardcoded admin check based on user ID
  if (!req.user || req.user.id !== 1) {
    return res.status(403).json({
      error: 'Admin access required',
      message: 'This endpoint requires administrator privileges',
      hint: 'Only user ID 1 is considered admin in this vulnerable implementation'
    });
  }
  next();
};

export default {
  authenticateUser,
  optionalAuth,
  checkResourceOwnership,
  requireAdmin
};