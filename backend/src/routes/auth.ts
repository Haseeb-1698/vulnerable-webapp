import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { body, validationResult } from 'express-validator';
import { PrismaClient } from '@prisma/client';

const router = express.Router();
const prisma = new PrismaClient();

// VULNERABILITY: Weak JWT secret for educational purposes
const JWT_SECRET = process.env.JWT_SECRET || 'weak-secret-key'; // Should be strong, random secret from env
const JWT_EXPIRES_IN = '30d'; // Overly long expiration

/**
 * User Registration Endpoint
 * POST /api/auth/register
 */
router.post('/register', [
  // Basic input validation with express-validator
  body('email')
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long'),
  body('firstName')
    .trim()
    .isLength({ min: 1 })
    .withMessage('First name is required'),
  body('lastName')
    .trim()
    .isLength({ min: 1 })
    .withMessage('Last name is required'),
], async (req, res) => {
  try {
    // Check validation results
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { email, password, firstName, lastName } = req.body;

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email }
    });

    if (existingUser) {
      // VULNERABILITY: User enumeration through different error messages
      return res.status(409).json({
        error: 'User already exists',
        message: 'An account with this email address already exists'
      });
    }

    // Hash password with bcrypt
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Create new user
    const newUser = await prisma.user.create({
      data: {
        email,
        passwordHash,
        firstName,
        lastName,
        emailVerified: false // Email verification not implemented for simplicity
      }
    });

    // Generate JWT token with weak secret
    const token = jwt.sign(
      { 
        userId: newUser.id, 
        email: newUser.email,
        firstName: newUser.firstName,
        lastName: newUser.lastName
      },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    // Return user data and token (excluding password hash)
    const { passwordHash: _, ...userWithoutPassword } = newUser;
    
    res.status(201).json({
      message: 'User registered successfully',
      user: userWithoutPassword,
      token,
      // VULNERABILITY: Exposing token details for educational purposes
      tokenInfo: {
        secret: JWT_SECRET,
        expiresIn: JWT_EXPIRES_IN,
        algorithm: 'HS256'
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    
    // VULNERABILITY: Exposing internal database errors
    res.status(500).json({
      error: 'Registration failed',
      details: error instanceof Error ? error.message : 'Unknown error',
      stack: process.env.NODE_ENV === 'development' ? (error as Error).stack : undefined
    });
  }
});

/**
 * User Login Endpoint
 * POST /api/auth/login
 */
router.post('/login', [
  body('email')
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail(),
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
], async (req, res) => {
  try {
    // Check validation results
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { email, password } = req.body;

    // Find user by email
    const user = await prisma.user.findUnique({
      where: { email }
    });

    if (!user) {
      // VULNERABILITY: User enumeration through different error messages
      return res.status(401).json({ 
        error: 'User not found',
        message: 'No account found with this email address'
      });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.passwordHash);

    if (!isValidPassword) {
      // VULNERABILITY: Different error message reveals valid emails
      return res.status(401).json({ 
        error: 'Invalid password',
        message: 'The password you entered is incorrect'
      });
    }

    // Generate JWT token with weak secret and long expiration
    const token = jwt.sign(
      { 
        userId: user.id, 
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName
      },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    // Update last login timestamp (optional)
    await prisma.user.update({
      where: { id: user.id },
      data: { updatedAt: new Date() }
    });

    // Return user data and token (excluding password hash)
    const { passwordHash: _, ...userWithoutPassword } = user;
    
    res.json({
      message: 'Login successful',
      user: userWithoutPassword,
      token,
      // VULNERABILITY: Exposing token details for educational purposes
      tokenInfo: {
        secret: JWT_SECRET,
        expiresIn: JWT_EXPIRES_IN,
        algorithm: 'HS256',
        warning: 'This token uses a weak secret and long expiration for educational purposes'
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    
    // VULNERABILITY: Exposing internal database errors
    res.status(500).json({
      error: 'Login failed',
      details: error instanceof Error ? error.message : 'Unknown error',
      stack: process.env.NODE_ENV === 'development' ? (error as Error).stack : undefined
    });
  }
});

/**
 * Get Current User Profile
 * GET /api/auth/me
 * Requires authentication
 */
router.get('/me', async (req, res) => {
  try {
    // Extract token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'Access denied',
        message: 'No token provided or invalid format'
      });
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    // Verify JWT token
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    
    // Get user from database
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        avatarUrl: true,
        createdAt: true,
        updatedAt: true,
        emailVerified: true
      }
    });

    if (!user) {
      return res.status(404).json({
        error: 'User not found',
        message: 'The user associated with this token no longer exists'
      });
    }

    res.json({
      user,
      tokenInfo: decoded
    });

  } catch (error) {
    console.error('Get user error:', error);
    
    if (error instanceof jwt.JsonWebTokenError) {
      return res.status(401).json({
        error: 'Invalid token',
        message: error.message,
        // VULNERABILITY: Exposing JWT error details
        tokenError: error.name
      });
    }

    // VULNERABILITY: Exposing internal errors
    res.status(500).json({
      error: 'Failed to get user profile',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * User Logout Endpoint
 * POST /api/auth/logout
 * VULNERABILITY: No proper token invalidation - tokens remain valid until expiration
 */
router.post('/logout', async (req, res) => {
  try {
    // Extract token for logging purposes
    const authHeader = req.headers.authorization;
    let token = null;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    }

    // VULNERABILITY: No token blacklisting or invalidation
    // In a secure implementation, we would:
    // 1. Add token to a blacklist/revocation list
    // 2. Store revoked tokens in Redis or database
    // 3. Check blacklist in authentication middleware
    
    // For educational purposes, we just log the logout attempt
    if (token) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET) as any;
        console.log(`User ${decoded.userId} (${decoded.email}) logged out, but token remains valid until expiration`);
        
        // VULNERABILITY: Return token details showing it's still valid
        res.json({
          message: 'Logout successful',
          warning: 'Token has not been invalidated and remains valid until expiration',
          tokenInfo: {
            userId: decoded.userId,
            email: decoded.email,
            expiresAt: new Date(decoded.exp * 1000).toISOString(),
            stillValid: true,
            vulnerability: 'No token revocation mechanism implemented'
          }
        });
      } catch (jwtError) {
        // Token was already invalid
        res.json({
          message: 'Logout successful',
          note: 'Token was already invalid'
        });
      }
    } else {
      res.json({
        message: 'Logout successful',
        note: 'No token was provided'
      });
    }

  } catch (error) {
    console.error('Logout error:', error);
    
    // Even logout errors expose internal details
    res.status(500).json({
      error: 'Logout failed',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Token Refresh Endpoint
 * POST /api/auth/refresh
 * VULNERABILITY: No proper refresh token mechanism - just issues new token with same expiration
 */
router.post('/refresh', async (req, res) => {
  try {
    // Extract current token
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'Access denied',
        message: 'No token provided for refresh'
      });
    }

    const currentToken = authHeader.substring(7);
    
    // VULNERABILITY: Accept expired tokens for refresh (insecure)
    let decoded: any;
    try {
      decoded = jwt.verify(currentToken, JWT_SECRET);
    } catch (jwtError) {
      if (jwtError instanceof jwt.TokenExpiredError) {
        // VULNERABILITY: Allow refresh of expired tokens
        decoded = jwt.decode(currentToken) as any;
        console.warn('⚠️  Refreshing expired token - this is insecure!');
      } else {
        return res.status(401).json({
          error: 'Invalid token',
          message: 'Cannot refresh invalid token',
          jwtError: jwtError instanceof Error ? jwtError.message : 'Unknown JWT error'
        });
      }
    }

    if (!decoded || !decoded.userId) {
      return res.status(401).json({
        error: 'Invalid token',
        message: 'Token does not contain valid user information'
      });
    }

    // Verify user still exists
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
      return res.status(404).json({
        error: 'User not found',
        message: 'Cannot refresh token for non-existent user'
      });
    }

    // VULNERABILITY: Issue new token with same long expiration
    const newToken = jwt.sign(
      { 
        userId: user.id, 
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        refreshedAt: new Date().toISOString()
      },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    res.json({
      message: 'Token refreshed successfully',
      token: newToken,
      user,
      // VULNERABILITY: Exposing refresh details
      refreshInfo: {
        oldTokenExpired: decoded.exp < Date.now() / 1000,
        newTokenExpiresIn: JWT_EXPIRES_IN,
        refreshedAt: new Date().toISOString(),
        vulnerability: 'Old token was not invalidated and new token has same long expiration'
      }
    });

  } catch (error) {
    console.error('Token refresh error:', error);
    
    res.status(500).json({
      error: 'Token refresh failed',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Validate Token Endpoint
 * POST /api/auth/validate
 * VULNERABILITY: Exposes detailed token information
 */
router.post('/validate', async (req, res) => {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({
        error: 'Token required',
        message: 'Please provide a token to validate'
      });
    }

    try {
      const decoded = jwt.verify(token, JWT_SECRET) as any;
      
      // VULNERABILITY: Expose all token details
      res.json({
        valid: true,
        decoded,
        tokenDetails: {
          algorithm: 'HS256',
          secret: JWT_SECRET, // VULNERABILITY: Exposing secret
          issuedAt: new Date(decoded.iat * 1000).toISOString(),
          expiresAt: new Date(decoded.exp * 1000).toISOString(),
          timeUntilExpiry: decoded.exp - Math.floor(Date.now() / 1000),
          payload: decoded
        }
      });
      
    } catch (jwtError) {
      // VULNERABILITY: Detailed error information
      res.status(401).json({
        valid: false,
        error: jwtError instanceof Error ? jwtError.message : 'Token validation failed',
        errorType: jwtError instanceof jwt.JsonWebTokenError ? jwtError.name : 'Unknown',
        tokenProvided: token.substring(0, 50) + '...', // Show partial token
        secret: JWT_SECRET, // VULNERABILITY: Still expose secret even on error
        hint: 'Check if token is properly formatted and not expired'
      });
    }

  } catch (error) {
    console.error('Token validation error:', error);
    
    res.status(500).json({
      error: 'Validation failed',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Session Management Info Endpoint
 * GET /api/auth/session-info
 * VULNERABILITY: Exposes session management internals
 */
router.get('/session-info', (req, res) => {
  // VULNERABILITY: No authentication required to view session configuration
  res.json({
    message: 'Session Management Configuration',
    jwtConfig: {
      secret: JWT_SECRET, // VULNERABILITY: Exposing secret
      algorithm: 'HS256',
      expiresIn: JWT_EXPIRES_IN,
      issuer: 'vulnerable-webapp'
    },
    vulnerabilities: {
      weakSecret: 'Using hardcoded weak secret',
      longExpiration: '30 day expiration is too long',
      noTokenRevocation: 'No proper token blacklist implementation',
      localStorage: 'Frontend stores tokens in localStorage instead of httpOnly cookies',
      inconsistentAuth: 'Authentication middleware has inconsistent checks',
      exposedInternals: 'This endpoint exposes internal configuration'
    },
    securityIssues: [
      'JWT secret is weak and hardcoded',
      'Token expiration is too long (30 days)',
      'No refresh token mechanism',
      'Logout does not invalidate tokens',
      'Tokens stored in localStorage (XSS vulnerable)',
      'Authentication middleware skips database checks randomly',
      'Error messages expose internal details',
      'No rate limiting on auth endpoints'
    ],
    recommendations: [
      'Use strong, random JWT secret from environment',
      'Implement shorter token expiration (15-30 minutes)',
      'Add proper refresh token mechanism',
      'Implement token blacklist with Redis',
      'Store tokens in httpOnly cookies',
      'Add consistent authorization checks',
      'Implement proper error handling',
      'Add rate limiting and brute force protection'
    ]
  });
});

export default router;