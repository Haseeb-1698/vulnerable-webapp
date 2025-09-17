# Insecure Session Management (CWE-384)

## Overview

Insecure Session Management vulnerabilities occur when web applications fail to properly protect session identifiers and manage user sessions securely. These vulnerabilities can lead to session hijacking, session fixation, and unauthorized access to user accounts.

**OWASP Top 10 2021 Ranking**: #7 - Identification and Authentication Failures
**CVSS Base Score**: 5.3 - 8.1 (Medium to High)
**Common Attack Vector**: Session Tokens, Cookies, Authentication Mechanisms

## Technical Details

### How Session Management Works

Session management involves:
1. **Session Creation**: Generating unique session identifiers upon authentication
2. **Session Storage**: Storing session data securely on server and client
3. **Session Validation**: Verifying session validity on each request
4. **Session Termination**: Properly destroying sessions on logout or timeout

### Common Session Management Vulnerabilities

1. **Weak Session Token Generation**: Predictable or easily guessable session IDs
2. **Insecure Token Storage**: Storing tokens in localStorage instead of secure cookies
3. **Missing Token Expiration**: Long-lived or non-expiring tokens
4. **Insufficient Session Validation**: Weak or missing session verification
5. **Session Fixation**: Accepting user-provided session identifiers
6. **Cross-Site Session Management**: Inadequate protection against CSRF attacks

### Vulnerability Implementation in Our Application

**Location**: Authentication system and JWT token management

```javascript
// VULNERABLE CODE - JWT Token Generation
const jwt = require('jsonwebtoken');

const generateToken = (user) => {
  // VULNERABILITY: Weak secret key
  const secret = 'weak-secret-key'; // Should be strong, random secret
  
  // VULNERABILITY: Overly long expiration
  return jwt.sign(
    { 
      userId: user.id, 
      email: user.email,
      role: user.role 
    },
    secret,
    { expiresIn: '30d' } // 30 days is too long
  );
};

// VULNERABLE CODE - Login Implementation
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const user = await prisma.user.findUnique({ where: { email } });
    
    if (!user || !await bcrypt.compare(password, user.passwordHash)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // VULNERABILITY: Generate token without additional security measures
    const token = generateToken(user);
    
    // VULNERABILITY: Send token in response body instead of secure cookie
    res.json({
      message: 'Login successful',
      token: token, // Exposed in response
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
      }
    }
  }
}
```
> Prepared by haseeb