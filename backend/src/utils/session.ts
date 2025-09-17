import jwt from 'jsonwebtoken';

// VULNERABILITY: Weak JWT configuration exposed
export const JWT_CONFIG = {
  secret: 'weak-secret-key', // Should be strong, random, from environment
  algorithm: 'HS256' as const,
  expiresIn: '30d', // Overly long expiration
  issuer: 'vulnerable-webapp',
  audience: 'webapp-users'
};

// VULNERABILITY: No token blacklist implementation
// In a secure app, this would be a Redis store or database table
export const tokenBlacklist = new Set<string>();

/**
 * Generate JWT Token with Vulnerabilities
 */
export const generateToken = (user: {
  id: number;
  email: string;
  firstName: string;
  lastName: string;
}) => {
  const payload = {
    userId: user.id,
    email: user.email,
    firstName: user.firstName,
    lastName: user.lastName,
    // VULNERABILITY: Include sensitive information in token
    role: user.id === 1 ? 'admin' : 'user', // Hardcoded admin logic
    permissions: ['read', 'write'], // No proper permission system
    sessionId: Math.random().toString(36), // Weak session ID generation
    loginTime: new Date().toISOString()
  };

  return jwt.sign(payload, JWT_CONFIG.secret, {
    expiresIn: JWT_CONFIG.expiresIn,
    algorithm: JWT_CONFIG.algorithm,
    issuer: JWT_CONFIG.issuer,
    audience: JWT_CONFIG.audience
  });
};

/**
 * Verify JWT Token with Vulnerabilities
 */
export const verifyToken = (token: string) => {
  try {
    // VULNERABILITY: No blacklist checking
    if (tokenBlacklist.has(token)) {
      throw new Error('Token has been revoked');
    }

    const decoded = jwt.verify(token, JWT_CONFIG.secret, {
      algorithms: [JWT_CONFIG.algorithm],
      issuer: JWT_CONFIG.issuer,
      audience: JWT_CONFIG.audience
    });

    return { valid: true, decoded };
  } catch (error) {
    return { 
      valid: false, 
      error: error instanceof Error ? error.message : 'Unknown error',
      // VULNERABILITY: Expose error details
      errorType: error instanceof jwt.JsonWebTokenError ? error.constructor.name : 'Unknown'
    };
  }
};

/**
 * Decode Token Without Verification (Vulnerable)
 */
export const decodeTokenUnsafe = (token: string) => {
  // VULNERABILITY: Decode without verification
  try {
    const decoded = jwt.decode(token, { complete: true });
    return {
      header: decoded?.header,
      payload: decoded?.payload,
      signature: decoded?.signature,
      warning: 'Token decoded without signature verification - this is insecure!'
    };
  } catch (error) {
    return {
      error: 'Failed to decode token',
      details: error instanceof Error ? error.message : 'Unknown error'
    };
  }
};

/**
 * Revoke Token (Incomplete Implementation)
 */
export const revokeToken = (token: string) => {
  // VULNERABILITY: Simple in-memory blacklist that doesn't persist
  tokenBlacklist.add(token);
  
  // In a real app, this would:
  // 1. Store in Redis with TTL matching token expiration
  // 2. Store in database with cleanup job
  // 3. Use proper distributed token revocation
  
  console.log(`Token revoked (in-memory only): ${token.substring(0, 20)}...`);
  return {
    revoked: true,
    method: 'in-memory-blacklist',
    warning: 'Token revocation is not persistent and will be lost on server restart',
    blacklistSize: tokenBlacklist.size
  };
};

/**
 * Get Token Information (Vulnerable)
 */
export const getTokenInfo = (token: string) => {
  const decoded = jwt.decode(token, { complete: true });
  
  if (!decoded) {
    return { error: 'Invalid token format' };
  }

  // VULNERABILITY: Expose all token internals
  return {
    header: decoded.header,
    payload: decoded.payload,
    signature: decoded.signature,
    // VULNERABILITY: Expose secret and configuration
    verificationDetails: {
      secret: JWT_CONFIG.secret,
      algorithm: JWT_CONFIG.algorithm,
      expectedIssuer: JWT_CONFIG.issuer,
      expectedAudience: JWT_CONFIG.audience
    },
    securityWarnings: [
      'Weak secret key used',
      'Long expiration time (30 days)',
      'No token rotation implemented',
      'No proper revocation mechanism',
      'Sensitive data included in payload'
    ]
  };
};

/**
 * Session Management Statistics (Vulnerable)
 */
export const getSessionStats = () => {
  return {
    configuration: JWT_CONFIG,
    blacklistedTokens: tokenBlacklist.size,
    // VULNERABILITY: Expose internal configuration
    vulnerabilities: {
      weakSecret: JWT_CONFIG.secret,
      longExpiration: JWT_CONFIG.expiresIn,
      noTokenRotation: true,
      inMemoryBlacklist: true,
      noRateLimiting: true,
      exposedInternals: true
    },
    recommendations: [
      'Use strong, random secret from environment variables',
      'Implement shorter token expiration (15-30 minutes)',
      'Add refresh token mechanism',
      'Use persistent token blacklist (Redis/Database)',
      'Implement proper session management',
      'Add rate limiting for auth endpoints',
      'Remove sensitive data from token payload'
    ]
  };
};

export default {
  JWT_CONFIG,
  generateToken,
  verifyToken,
  decodeTokenUnsafe,
  revokeToken,
  getTokenInfo,
  getSessionStats,
  tokenBlacklist
};