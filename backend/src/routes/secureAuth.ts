import express from 'express';
import bcrypt from 'bcrypt';
import { body, validationResult } from 'express-validator';
import { PrismaClient } from '@prisma/client';
import {
  createSession,
  setSecureCookies,
  clearAuthCookies,
  refreshAccessToken,
  secureLogout,
  extractRefreshTokenFromRequest,
  invalidateAllUserSessions,
  getUserSessions,
  checkRateLimit,
  setSecurityHeaders
} from '../utils/secureSession.js';
import { secureAuthenticateUser } from '../middleware/secureAuth.js';

const router = express.Router();
const prisma = new PrismaClient();

/**
 * Secure Authentication Routes
 * 
 * This module provides secure authentication with:
 * 1. Strong password hashing and validation
 * 2. HttpOnly cookie-based session storage
 * 3. Token refresh mechanism and secure logout
 * 4. Rate limiting and brute force protection
 * 5. Comprehensive security measures
 */

/**
 * SECURE User Registration
 * POST /api/secure-auth/register
 */
router.post('/register', [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
  body('firstName')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('First name is required and must be less than 50 characters')
    .escape(),
  body('lastName')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Last name is required and must be less than 50 characters')
    .escape(),
  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Password confirmation does not match password');
      }
      return true;
    })
], async (req, res) => {
  try {
    // Set security headers
    setSecurityHeaders(res);
    
    // Rate limiting for registration
    const clientIp = req.ip || req.connection.remoteAddress || 'unknown';
    const rateLimit = checkRateLimit(`register:${clientIp}`, 5, 60 * 60 * 1000); // 5 registrations per hour
    
    if (!rateLimit.allowed) {
      return res.status(429).json({
        success: false,
        error: 'Too many registration attempts',
        message: 'Please wait before attempting to register again',
        retryAfter: Math.ceil((rateLimit.resetTime - Date.now()) / 1000)
      });
    }
    
    // Check validation results
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        details: errors.array()
      });
    }
    
    const { email, password, firstName, lastName } = req.body;
    
    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email },
      select: { id: true }
    });
    
    if (existingUser) {
      return res.status(409).json({
        success: false,
        error: 'User already exists',
        message: 'An account with this email already exists'
      });
    }
    
    // Hash password with strong salt rounds
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);
    
    // Create user
    const newUser = await prisma.user.create({
      data: {
        email,
        passwordHash,
        firstName,
        lastName,
        emailVerified: false // Require email verification
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        emailVerified: true
      }
    });
    
    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      user: {
        id: newUser.id,
        email: newUser.email,
        firstName: newUser.firstName,
        lastName: newUser.lastName,
        emailVerified: newUser.emailVerified
      },
      nextStep: 'Please verify your email address to complete registration'
    });
    
  } catch (error) {
    console.error('Secure registration error:', error);
    res.status(500).json({
      success: false,
      error: 'Registration failed',
      message: 'An error occurred during registration'
    });
  }
});

/**
 * SECURE User Login
 * POST /api/secure-auth/login
 */
router.post('/login', [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required'),
  body('password')
    .isLength({ min: 1 })
    .withMessage('Password is required'),
  body('rememberMe')
    .optional()
    .isBoolean()
    .withMessage('Remember me must be a boolean')
], async (req, res) => {
  try {
    // Set security headers
    setSecurityHeaders(res);
    
    // Rate limiting for login attempts
    const clientIp = req.ip || req.connection.remoteAddress || 'unknown';
    const { email, password, rememberMe = false } = req.body;
    
    // Rate limit by IP and email
    const ipRateLimit = checkRateLimit(`login:ip:${clientIp}`, 10, 15 * 60 * 1000); // 10 attempts per 15 minutes per IP
    const emailRateLimit = checkRateLimit(`login:email:${email}`, 5, 15 * 60 * 1000); // 5 attempts per 15 minutes per email
    
    if (!ipRateLimit.allowed || !emailRateLimit.allowed) {
      return res.status(429).json({
        success: false,
        error: 'Too many login attempts',
        message: 'Please wait before attempting to login again',
        retryAfter: Math.ceil(Math.max(ipRateLimit.resetTime, emailRateLimit.resetTime - Date.now()) / 1000)
      });
    }
    
    // Check validation results
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        details: errors.array()
      });
    }
    
    // Find user
    const user = await prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        email: true,
        passwordHash: true,
        firstName: true,
        lastName: true,
        emailVerified: true
      }
    });
    
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials',
        message: 'Email or password is incorrect'
      });
    }
    
    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.passwordHash);
    
    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials',
        message: 'Email or password is incorrect'
      });
    }
    
    // Check if email is verified
    if (!user.emailVerified) {
      return res.status(403).json({
        success: false,
        error: 'Email not verified',
        message: 'Please verify your email address before logging in'
      });
    }
    
    // Create session and tokens
    const { accessToken, refreshToken, sessionId } = await createSession(
      user.id,
      user.email,
      req,
      rememberMe
    );
    
    // Set secure cookies
    setSecureCookies(res, accessToken, refreshToken, rememberMe);
    
    res.json({
      success: true,
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        emailVerified: user.emailVerified
      },
      session: {
        sessionId,
        expiresAt: new Date(Date.now() + (rememberMe ? 30 * 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000))
      }
    });
    
  } catch (error) {
    console.error('Secure login error:', error);
    res.status(500).json({
      success: false,
      error: 'Login failed',
      message: 'An error occurred during login'
    });
  }
});

/**
 * SECURE Token Refresh
 * POST /api/secure-auth/refresh
 */
router.post('/refresh', async (req, res) => {
  try {
    // Set security headers
    setSecurityHeaders(res);
    
    // Extract refresh token
    const refreshToken = extractRefreshTokenFromRequest(req);
    
    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        error: 'Refresh token required',
        message: 'Refresh token is missing'
      });
    }
    
    // Refresh tokens
    const tokens = await refreshAccessToken(refreshToken, req);
    
    if (!tokens) {
      return res.status(401).json({
        success: false,
        error: 'Invalid refresh token',
        message: 'Refresh token is invalid or expired'
      });
    }
    
    // Set new secure cookies
    setSecureCookies(res, tokens.accessToken, tokens.refreshToken);
    
    res.json({
      success: true,
      message: 'Tokens refreshed successfully',
      expiresAt: new Date(Date.now() + 15 * 60 * 1000) // 15 minutes
    });
    
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({
      success: false,
      error: 'Token refresh failed',
      message: 'An error occurred during token refresh'
    });
  }
});

/**
 * SECURE Logout
 * POST /api/secure-auth/logout
 */
router.post('/logout', secureAuthenticateUser, async (req, res) => {
  try {
    // Secure logout
    secureLogout(req.user!.sessionId, res);
    
    res.json({
      success: true,
      message: 'Logout successful'
    });
    
  } catch (error) {
    console.error('Secure logout error:', error);
    res.status(500).json({
      success: false,
      error: 'Logout failed',
      message: 'An error occurred during logout'
    });
  }
});

/**
 * SECURE Logout All Sessions
 * POST /api/secure-auth/logout-all
 */
router.post('/logout-all', secureAuthenticateUser, async (req, res) => {
  try {
    // Invalidate all user sessions
    invalidateAllUserSessions(req.user!.id);
    
    // Clear cookies
    clearAuthCookies(res);
    
    res.json({
      success: true,
      message: 'All sessions logged out successfully'
    });
    
  } catch (error) {
    console.error('Logout all sessions error:', error);
    res.status(500).json({
      success: false,
      error: 'Logout failed',
      message: 'An error occurred during logout'
    });
  }
});

/**
 * Get Current User
 * GET /api/secure-auth/me
 */
router.get('/me', secureAuthenticateUser, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user!.id },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        emailVerified: true,
        createdAt: true,
        updatedAt: true
      }
    });
    
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
        message: 'User account no longer exists'
      });
    }
    
    res.json({
      success: true,
      user
    });
    
  } catch (error) {
    console.error('Get current user error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get user',
      message: 'An error occurred while retrieving user information'
    });
  }
});

/**
 * Get User Sessions
 * GET /api/secure-auth/sessions
 */
router.get('/sessions', secureAuthenticateUser, async (req, res) => {
  try {
    const sessions = getUserSessions(req.user!.id);
    
    // Remove sensitive information
    const safeSessions = sessions.map(session => ({
      id: session.id,
      createdAt: session.createdAt,
      lastAccessedAt: session.lastAccessedAt,
      ipAddress: session.ipAddress,
      userAgent: session.userAgent,
      isActive: session.isActive,
      isCurrent: session.id === req.user!.sessionId
    }));
    
    res.json({
      success: true,
      sessions: safeSessions,
      count: safeSessions.length
    });
    
  } catch (error) {
    console.error('Get user sessions error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get sessions',
      message: 'An error occurred while retrieving sessions'
    });
  }
});

/**
 * Change Password
 * POST /api/secure-auth/change-password
 */
router.post('/change-password', secureAuthenticateUser, [
  body('currentPassword')
    .isLength({ min: 1 })
    .withMessage('Current password is required'),
  body('newPassword')
    .isLength({ min: 8 })
    .withMessage('New password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('New password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.newPassword) {
        throw new Error('Password confirmation does not match new password');
      }
      return true;
    })
], async (req, res) => {
  try {
    // Check validation results
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        details: errors.array()
      });
    }
    
    const { currentPassword, newPassword } = req.body;
    
    // Get user with password hash
    const user = await prisma.user.findUnique({
      where: { id: req.user!.id },
      select: { passwordHash: true }
    });
    
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
        message: 'User account no longer exists'
      });
    }
    
    // Verify current password
    const isValidPassword = await bcrypt.compare(currentPassword, user.passwordHash);
    
    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        error: 'Invalid current password',
        message: 'Current password is incorrect'
      });
    }
    
    // Hash new password
    const saltRounds = 12;
    const newPasswordHash = await bcrypt.hash(newPassword, saltRounds);
    
    // Update password
    await prisma.user.update({
      where: { id: req.user!.id },
      data: { passwordHash: newPasswordHash }
    });
    
    // Invalidate all other sessions (force re-login on other devices)
    invalidateAllUserSessions(req.user!.id);
    
    res.json({
      success: true,
      message: 'Password changed successfully',
      note: 'All other sessions have been logged out for security'
    });
    
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({
      success: false,
      error: 'Password change failed',
      message: 'An error occurred while changing password'
    });
  }
});

export default router;