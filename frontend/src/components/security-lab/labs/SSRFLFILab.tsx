import React from 'react';
import { VulnerabilityConfig, TestResult } from '../SecurityLabDashboard';
import { VulnerabilityLabTemplate } from './VulnerabilityLabTemplate';

interface SSRFLFILabProps {
  config: VulnerabilityConfig;
  enabled: boolean;
  onToggle: () => void;
  onTest: (vulnType: string, payload: string, target?: string) => Promise<TestResult>;
  testResults: TestResult[];
}

export const SSRFLFILab: React.FC<SSRFLFILabProps> = ({
  config,
  enabled,
  onToggle,
  onTest,
  testResults
}) => {
  const vulnerableCode = `// VULNERABLE CODE - No URL Validation
app.post('/api/users/avatar', authenticateUser, async (req, res) => {
  const { imageUrl, fetchFromUrl } = req.body;
  
  if (fetchFromUrl && imageUrl) {
    try {
      // DANGER: No URL validation - allows SSRF attacks
      const response = await axios.get(imageUrl, {
        timeout: 10000,
        maxRedirects: 5
      });
      
      // DANGER: Allows fetching internal services and files
      if (imageUrl.startsWith('file://')) {
        const filePath = imageUrl.replace('file://', '');
        const fileContent = fs.readFileSync(filePath, 'utf8');
        return res.json({ 
          success: true, 
          content: fileContent
        });
      }
      
      res.json({ success: true, data: response.data });
      
    } catch (error) {
      // DANGER: Error messages leak internal information
      res.status(500).json({ 
        error: 'Failed to fetch image',
        details: error.message,
        requestedUrl: imageUrl,
        internalError: error.code
      });
    }
  }
});

// VULNERABLE: Path traversal in file serving
app.get('/api/files/:filename', (req, res) => {
  const { filename } = req.params;
  
  // DANGER: Path traversal - no input sanitization
  const filePath = path.join('./uploads', filename);
  
  try {
    const fileContent = fs.readFileSync(filePath);
    res.send(fileContent);
  } catch (error) {
    res.status(404).json({ 
      error: 'File not found', 
      path: filePath // Exposes internal paths
    });
  }
});`;

  const secureCode = `// SECURE CODE - URL Validation and Restrictions
const ALLOWED_DOMAINS = ['example.com', 'trusted-cdn.com'];
const BLOCKED_IPS = ['127.0.0.1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];

app.post('/api/users/avatar', authenticateUser, async (req, res) => {
  const { imageUrl, fetchFromUrl } = req.body;
  
  if (fetchFromUrl && imageUrl) {
    try {
      // Safe: Validate URL and domain
      const url = new URL(imageUrl);
      
      if (!ALLOWED_DOMAINS.includes(url.hostname)) {
        return res.status(400).json({ error: 'Domain not allowed' });
      }
      
      if (url.protocol === 'file:') {
        return res.status(400).json({ error: 'File protocol not allowed' });
      }
      
      // Safe: Check for private IP ranges
      const ip = await dns.lookup(url.hostname);
      if (isPrivateIP(ip.address)) {
        return res.status(400).json({ error: 'Private IP not allowed' });
      }
      
      // Safe: Restricted HTTP client
      const response = await axios.get(imageUrl, {
        timeout: 5000,
        maxRedirects: 2,
        maxContentLength: 1024 * 1024 // 1MB limit
      });
      
      res.json({ success: true, message: 'Image processed' });
      
    } catch (error) {
      // Safe: Generic error message
      res.status(500).json({ error: 'Failed to process image' });
    }
  }
});

// SECURE: Safe file serving with validation
app.get('/api/files/:filename', (req, res) => {
  const { filename } = req.params;
  
  // Safe: Validate filename
  if (!/^[a-zA-Z0-9._-]+$/.test(filename)) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  
  // Safe: Resolve and validate path
  const uploadsDir = path.resolve('./uploads');
  const filePath = path.resolve(uploadsDir, filename);
  
  // Safe: Ensure file is within uploads directory
  if (!filePath.startsWith(uploadsDir)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  try {
    const fileContent = fs.readFileSync(filePath);
    res.send(fileContent);
  } catch (error) {
    res.status(404).json({ error: 'File not found' });
  }
});`;

  const testPayloads = [
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost:22",
    "http://127.0.0.1:6379/info",
    "file:///etc/passwd",
    "file:///proc/version",
    "../../../etc/hosts",
    "....//....//....//etc/passwd",
    "http://internal-service:8080/admin"
  ];

  const ssrfTargets = [
    {
      target: "Cloud Metadata Services",
      description: "Access cloud provider metadata endpoints",
      examples: [
        "AWS: http://169.254.169.254/latest/meta-data/",
        "GCP: http://metadata.google.internal/computeMetadata/v1/",
        "Azure: http://169.254.169.254/metadata/instance"
      ],
      impact: "Access to cloud credentials, instance information, and configuration"
    },
    {
      target: "Internal Network Services",
      description: "Scan and access internal network resources",
      examples: [
        "Redis: http://localhost:6379/info",
        "Elasticsearch: http://localhost:9200/_cluster/health",
        "Admin panels: http://internal-admin:8080/admin"
      ],
      impact: "Access to internal services, databases, and administrative interfaces"
    },
    {
      target: "Local File System",
      description: "Read local files using file:// protocol",
      examples: [
        "System files: file:///etc/passwd",
        "Application config: file:///app/.env",
        "SSH keys: file:///home/user/.ssh/id_rsa"
      ],
      impact: "Access to sensitive files, configuration, and credentials"
    },
    {
      target: "Port Scanning",
      description: "Enumerate open ports on internal hosts",
      examples: [
        "SSH: http://192.168.1.1:22",
        "Database: http://db-server:3306",
        "Web services: http://internal-host:8080"
      ],
      impact: "Network reconnaissance and service discovery"
    }
  ];

  const lfiTechniques = [
    {
      technique: "Basic Path Traversal",
      description: "Use ../ sequences to navigate directory structure",
      payload: "../../../etc/passwd",
      explanation: "Navigate up three directories to reach system root"
    },
    {
      technique: "URL Encoding",
      description: "Encode path traversal sequences to bypass filters",
      payload: "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
      explanation: "URL-encoded version of ../../../etc/passwd"
    },
    {
      technique: "Double Encoding",
      description: "Double-encode to bypass multiple layers of filtering",
      payload: "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
      explanation: "Double URL-encoded path traversal"
    },
    {
      technique: "Null Byte Injection",
      description: "Use null bytes to truncate file extensions",
      payload: "../../../etc/passwd%00.jpg",
      explanation: "Null byte truncates .jpg extension (legacy vulnerability)"
    },
    {
      technique: "Absolute Path",
      description: "Use absolute paths when relative paths are filtered",
      payload: "/etc/passwd",
      explanation: "Direct absolute path to sensitive file"
    }
  ];

  return (
    <VulnerabilityLabTemplate
      title="SSRF & Local File Inclusion Laboratory (CWE-918, CWE-22)"
      description="Learn about Server-Side Request Forgery and Local File Inclusion vulnerabilities and their prevention."
      vulnerableCode={vulnerableCode}
      secureCode={secureCode}
      enabled={enabled}
      onToggle={onToggle}
      testPayloads={testPayloads}
      onTest={onTest}
      testResults={testResults}
      vulnerabilityType="ssrfLfi"
      additionalContent={
        <div className="space-y-6">
          {/* SSRF Attack Targets */}
          <div className="bg-red-50 border border-red-200 rounded-lg p-4">
            <h4 className="font-semibold text-red-900 mb-3">🎯 SSRF Attack Targets</h4>
            <div className="space-y-4">
              {ssrfTargets.map((target, index) => (
                <div key={index} className="border-l-4 border-red-400 pl-4">
                  <h5 className="font-medium text-red-900">{target.target}</h5>
                  <p className="text-sm text-red-700 mb-2">{target.description}</p>
                  <div className="space-y-1 mb-2">
                    {target.examples.map((example, exampleIndex) => (
                      <code key={exampleIndex} className="block bg-red-100 p-2 rounded text-xs font-mono text-red-800">
                        {example}
                      </code>
                    ))}
                  </div>
                  <p className="text-xs text-red-600 italic">{target.impact}</p>
                </div>
              ))}
            </div>
          </div>

          {/* LFI Techniques */}
          <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
            <h4 className="font-semibold text-orange-900 mb-3">📁 Local File Inclusion Techniques</h4>
            <div className="space-y-4">
              {lfiTechniques.map((technique, index) => (
                <div key={index} className="bg-white border border-orange-200 rounded p-3">
                  <h5 className="font-medium text-orange-800 mb-1">{technique.technique}</h5>
                  <p className="text-sm text-orange-700 mb-2">{technique.description}</p>
                  <code className="block bg-orange-100 p-2 rounded text-xs font-mono text-orange-800 mb-2">
                    {technique.payload}
                  </code>
                  <p className="text-xs text-orange-600 italic">{technique.explanation}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Cloud Metadata Exploitation */}
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <h4 className="font-semibold text-blue-900 mb-3">☁️ Cloud Metadata Exploitation</h4>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-white border border-blue-200 rounded p-3">
                <h5 className="font-medium text-blue-800 mb-2">AWS EC2</h5>
                <div className="space-y-1 text-xs">
                  <code className="block bg-blue-100 p-1 rounded text-blue-800">
                    /latest/meta-data/iam/security-credentials/
                  </code>
                  <code className="block bg-blue-100 p-1 rounded text-blue-800">
                    /latest/user-data
                  </code>
                  <code className="block bg-blue-100 p-1 rounded text-blue-800">
                    /latest/meta-data/instance-id
                  </code>
                </div>
              </div>
              <div className="bg-white border border-blue-200 rounded p-3">
                <h5 className="font-medium text-blue-800 mb-2">Google Cloud</h5>
                <div className="space-y-1 text-xs">
                  <code className="block bg-blue-100 p-1 rounded text-blue-800">
                    /computeMetadata/v1/instance/service-accounts/
                  </code>
                  <code className="block bg-blue-100 p-1 rounded text-blue-800">
                    /computeMetadata/v1/project/
                  </code>
                </div>
              </div>
              <div className="bg-white border border-blue-200 rounded p-3">
                <h5 className="font-medium text-blue-800 mb-2">Azure</h5>
                <div className="space-y-1 text-xs">
                  <code className="block bg-blue-100 p-1 rounded text-blue-800">
                    /metadata/instance/compute/
                  </code>
                  <code className="block bg-blue-100 p-1 rounded text-blue-800">
                    /metadata/identity/oauth2/token
                  </code>
                </div>
              </div>
            </div>
          </div>

          {/* Common Target Files */}
          <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
            <h4 className="font-semibold text-purple-900 mb-3">📋 Common Target Files (LFI)</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <h5 className="font-medium text-purple-800 mb-2">System Files</h5>
                <div className="space-y-1 text-xs">
                  <code className="block bg-purple-100 p-1 rounded text-purple-800">/etc/passwd</code>
                  <code className="block bg-purple-100 p-1 rounded text-purple-800">/etc/shadow</code>
                  <code className="block bg-purple-100 p-1 rounded text-purple-800">/etc/hosts</code>
                  <code className="block bg-purple-100 p-1 rounded text-purple-800">/proc/version</code>
                  <code className="block bg-purple-100 p-1 rounded text-purple-800">/proc/self/environ</code>
                </div>
              </div>
              <div>
                <h5 className="font-medium text-purple-800 mb-2">Application Files</h5>
                <div className="space-y-1 text-xs">
                  <code className="block bg-purple-100 p-1 rounded text-purple-800">.env</code>
                  <code className="block bg-purple-100 p-1 rounded text-purple-800">config.php</code>
                  <code className="block bg-purple-100 p-1 rounded text-purple-800">wp-config.php</code>
                  <code className="block bg-purple-100 p-1 rounded text-purple-800">~/.ssh/id_rsa</code>
                  <code className="block bg-purple-100 p-1 rounded text-purple-800">~/.bash_history</code>
                </div>
              </div>
            </div>
          </div>

          {/* Prevention Strategies */}
          <div className="bg-green-50 border border-green-200 rounded-lg p-4">
            <h4 className="font-semibold text-green-900 mb-3">🛡️ Prevention Strategies</h4>
            <div className="space-y-4">
              <div>
                <h5 className="font-medium text-green-800">1. URL Validation and Whitelisting</h5>
                <p className="text-sm text-green-700 mb-2">Only allow requests to trusted domains</p>
                <code className="block bg-green-100 p-2 rounded text-xs font-mono text-green-800">
                  {`const ALLOWED_DOMAINS = ['api.example.com', 'cdn.trusted.com'];`}
                </code>
              </div>
              
              <div>
                <h5 className="font-medium text-green-800">2. Network Segmentation</h5>
                <p className="text-sm text-green-700 mb-2">Isolate application servers from internal networks</p>
                <code className="block bg-green-100 p-2 rounded text-xs font-mono text-green-800">
                  {`// Block private IP ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16`}
                </code>
              </div>
              
              <div>
                <h5 className="font-medium text-green-800">3. Input Sanitization</h5>
                <p className="text-sm text-green-700 mb-2">Validate and sanitize all file paths</p>
                <code className="block bg-green-100 p-2 rounded text-xs font-mono text-green-800">
                  {`path.resolve(baseDir, userInput).startsWith(baseDir)`}
                </code>
              </div>
              
              <div>
                <h5 className="font-medium text-green-800">4. Disable Dangerous Protocols</h5>
                <p className="text-sm text-green-700 mb-2">Block file://, gopher://, and other protocols</p>
                <code className="block bg-green-100 p-2 rounded text-xs font-mono text-green-800">
                  {`if (url.protocol !== 'http:' && url.protocol !== 'https:') reject();`}
                </code>
              </div>
            </div>
          </div>

          {/* Detection and Monitoring */}
          <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
            <h4 className="font-semibold text-yellow-900 mb-3">🔍 Detection and Monitoring</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <h5 className="font-medium text-yellow-800 mb-2">Log Monitoring</h5>
                <ul className="text-sm text-yellow-700 space-y-1">
                  <li>• Monitor for metadata service requests</li>
                  <li>• Log file access attempts</li>
                  <li>• Track unusual network connections</li>
                  <li>• Alert on path traversal patterns</li>
                </ul>
              </div>
              <div>
                <h5 className="font-medium text-yellow-800 mb-2">Network Monitoring</h5>
                <ul className="text-sm text-yellow-700 space-y-1">
                  <li>• Monitor outbound connections</li>
                  <li>• Detect internal network scanning</li>
                  <li>• Track DNS resolution patterns</li>
                  <li>• Alert on cloud metadata access</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      }
    />
  );
};