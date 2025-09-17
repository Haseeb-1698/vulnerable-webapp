import request from 'supertest';
import { app } from '../../src/server';
import { setupTestDatabase, testUsers } from '../setup';
import jwt from 'jsonwebtoken';
import * as fs from 'fs';
import * as path from 'path';

describe('OWASP ZAP Integration Tests', () => {
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

  describe('ZAP Baseline Scan Configuration', () => {
    test('should generate ZAP baseline scan configuration', async () => {
      const zapConfig = {
        target: baseUrl,
        format: 'json',
        outputFile: 'zap-baseline-report.json',
        rules: {
          // Enable all vulnerability checks
          '10021': 'WARN', // X-Content-Type-Options Missing
          '10020': 'WARN', // X-Frame-Options Missing
          '10016': 'WARN', // Web Browser XSS Protection Not Enabled
          '10017': 'WARN', // Cross-Domain Misconfiguration
          '10019': 'WARN', // Content-Type Header Missing
          '10054': 'WARN', // Cookie Without SameSite Attribute
          '10055': 'WARN', // CSP Scanner
          '40012': 'WARN', // Cross Site Scripting (Reflected)
          '40014': 'WARN', // Cross Site Scripting (Persistent)
          '40018': 'WARN', // SQL Injection
          '40019': 'WARN', // SQL Injection - MySQL
          '40020': 'WARN', // SQL Injection - Hypersonic SQL
          '40021': 'WARN', // SQL Injection - Oracle
          '40022': 'WARN', // SQL Injection - PostgreSQL
          '90019': 'WARN', // Server Side Code Injection
          '90020': 'WARN', // Remote OS Command Injection
          '90021': 'WARN', // XPath Injection
          '90022': 'WARN', // Application Error Disclosure
          '90023': 'WARN', // XML External Entity Attack
          '90024': 'WARN', // Generic Padding Oracle
          '90025': 'WARN', // Expression Language Injection
          '90026': 'WARN', // SOAP Action Spoofing
          '90027': 'WARN', // Cookie Slack Detector
          '90028': 'WARN', // Insecure JSF ViewState
          '90029': 'WARN', // LDAP Injection
          '90030': 'WARN'  // WSDL File Detection
        },
        authentication: {
          method: 'bearer',
          token: user1Token
        },
        context: {
          name: 'VulnerableWebApp',
          includePaths: [
            `${baseUrl}/api/.*`,
            `${baseUrl}/.*`
          ],
          excludePaths: [
            `${baseUrl}/api/auth/logout`,
            `${baseUrl}/static/.*`
          ]
        }
      };

      // Write ZAP configuration file
      const configPath = path.join(__dirname, '../reports/zap-config.json');
      fs.mkdirSync(path.dirname(configPath), { recursive: true });
      fs.writeFileSync(configPath, JSON.stringify(zapConfig, null, 2));

      expect(fs.existsSync(configPath)).toBe(true);
      
      const savedConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      expect(savedConfig.target).toBe(baseUrl);
      expect(savedConfig.authentication.token).toBe(user1Token);
    });

    test('should create ZAP Docker Compose configuration', async () => {
      const zapDockerCompose = `
version: '3.8'
services:
  zap:
    image: owasp/zap2docker-stable
    command: >
      zap-baseline.py 
      -t ${baseUrl}
      -J /zap/wrk/zap-baseline-report.json
      -r /zap/wrk/zap-baseline-report.html
      -x /zap/wrk/zap-baseline-report.xml
      -I
      -z "-config api.addrs.addr.name=0.0.0.0 -config api.addrs.addr.regex=true"
    volumes:
      - ./reports:/zap/wrk
    networks:
      - test-network
    depends_on:
      - vulnerable-app

  zap-full-scan:
    image: owasp/zap2docker-stable
    command: >
      zap-full-scan.py 
      -t ${baseUrl}
      -J /zap/wrk/zap-full-report.json
      -r /zap/wrk/zap-full-report.html
      -x /zap/wrk/zap-full-report.xml
      -I
    volumes:
      - ./reports:/zap/wrk
    networks:
      - test-network
    depends_on:
      - vulnerable-app
    profiles:
      - full-scan

  vulnerable-app:
    build: ../../
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=test
      - DATABASE_URL=postgresql://postgres:password@db:5432/vulnerable_webapp_test
    networks:
      - test-network
    depends_on:
      - db

  db:
    image: postgres:14
    environment:
      - POSTGRES_DB=vulnerable_webapp_test
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    networks:
      - test-network

networks:
  test-network:
    driver: bridge
`;

      const dockerComposePath = path.join(__dirname, '../docker/docker-compose.zap.yml');
      fs.mkdirSync(path.dirname(dockerComposePath), { recursive: true });
      fs.writeFileSync(dockerComposePath, zapDockerCompose);

      expect(fs.existsSync(dockerComposePath)).toBe(true);
    });
  });

  describe('ZAP API Integration', () => {
    test('should create ZAP API test script', async () => {
      const zapApiScript = `#!/usr/bin/env node

const axios = require('axios');
const fs = require('fs');

class ZAPIntegration {
  constructor(zapUrl = 'http://localhost:8080') {
    this.zapUrl = zapUrl;
    this.apiKey = process.env.ZAP_API_KEY || '';
  }

  async startZAP() {
    try {
      const response = await axios.get(\`\${this.zapUrl}/JSON/core/view/version/\`);
      console.log('ZAP is running, version:', response.data.version);
      return true;
    } catch (error) {
      console.error('ZAP is not running:', error.message);
      return false;
    }
  }

  async createContext(contextName, targetUrl) {
    const params = {
      contextName,
      apikey: this.apiKey
    };

    try {
      const response = await axios.get(\`\${this.zapUrl}/JSON/context/action/newContext/\`, { params });
      console.log('Context created:', response.data);
      
      // Include target URL in context
      await axios.get(\`\${this.zapUrl}/JSON/context/action/includeInContext/\`, {
        params: {
          contextName,
          regex: \`\${targetUrl}.*\`,
          apikey: this.apiKey
        }
      });

      return response.data.contextId;
    } catch (error) {
      console.error('Failed to create context:', error.message);
      throw error;
    }
  }

  async setAuthentication(contextId, token) {
    try {
      // Set authentication method to bearer token
      await axios.get(\`\${this.zapUrl}/JSON/authentication/action/setAuthenticationMethod/\`, {
        params: {
          contextId,
          authMethodName: 'httpAuthentication',
          authMethodConfigParams: \`hostname=localhost&port=3000&realm=&username=Bearer \${token}\`,
          apikey: this.apiKey
        }
      });

      console.log('Authentication configured');
    } catch (error) {
      console.error('Failed to set authentication:', error.message);
    }
  }

  async spiderScan(targetUrl, contextId) {
    try {
      const response = await axios.get(\`\${this.zapUrl}/JSON/spider/action/scan/\`, {
        params: {
          url: targetUrl,
          contextId,
          apikey: this.apiKey
        }
      });

      const scanId = response.data.scan;
      console.log('Spider scan started, ID:', scanId);

      // Wait for spider scan to complete
      let progress = 0;
      while (progress < 100) {
        await new Promise(resolve => setTimeout(resolve, 2000));
        const statusResponse = await axios.get(\`\${this.zapUrl}/JSON/spider/view/status/\`, {
          params: { scanId, apikey: this.apiKey }
        });
        progress = parseInt(statusResponse.data.status);
        console.log(\`Spider scan progress: \${progress}%\`);
      }

      return scanId;
    } catch (error) {
      console.error('Spider scan failed:', error.message);
      throw error;
    }
  }

  async activeScan(targetUrl, contextId) {
    try {
      const response = await axios.get(\`\${this.zapUrl}/JSON/ascan/action/scan/\`, {
        params: {
          url: targetUrl,
          contextId,
          apikey: this.apiKey
        }
      });

      const scanId = response.data.scan;
      console.log('Active scan started, ID:', scanId);

      // Wait for active scan to complete
      let progress = 0;
      while (progress < 100) {
        await new Promise(resolve => setTimeout(resolve, 5000));
        const statusResponse = await axios.get(\`\${this.zapUrl}/JSON/ascan/view/status/\`, {
          params: { scanId, apikey: this.apiKey }
        });
        progress = parseInt(statusResponse.data.status);
        console.log(\`Active scan progress: \${progress}%\`);
      }

      return scanId;
    } catch (error) {
      console.error('Active scan failed:', error.message);
      throw error;
    }
  }

  async generateReport(format = 'json') {
    try {
      const response = await axios.get(\`\${this.zapUrl}/OTHER/core/other/\${format}report/\`, {
        params: { apikey: this.apiKey }
      });

      const reportPath = \`./reports/zap-report.\${format}\`;
      fs.writeFileSync(reportPath, typeof response.data === 'string' ? response.data : JSON.stringify(response.data, null, 2));
      console.log(\`Report saved to \${reportPath}\`);

      return reportPath;
    } catch (error) {
      console.error('Failed to generate report:', error.message);
      throw error;
    }
  }

  async runFullScan(targetUrl, token) {
    console.log('Starting ZAP full scan...');
    
    if (!await this.startZAP()) {
      throw new Error('ZAP is not running');
    }

    const contextId = await this.createContext('VulnerableWebApp', targetUrl);
    await this.setAuthentication(contextId, token);
    
    console.log('Running spider scan...');
    await this.spiderScan(targetUrl, contextId);
    
    console.log('Running active scan...');
    await this.activeScan(targetUrl, contextId);
    
    console.log('Generating reports...');
    await this.generateReport('json');
    await this.generateReport('html');
    
    console.log('ZAP scan completed successfully');
  }
}

// CLI usage
if (require.main === module) {
  const targetUrl = process.argv[2] || '${baseUrl}';
  const token = process.argv[3] || '${user1Token}';
  
  const zap = new ZAPIntegration();
  zap.runFullScan(targetUrl, token)
    .then(() => process.exit(0))
    .catch(error => {
      console.error('Scan failed:', error.message);
      process.exit(1);
    });
}

module.exports = ZAPIntegration;
`;

      const scriptPath = path.join(__dirname, '../scripts/zap-integration.js');
      fs.mkdirSync(path.dirname(scriptPath), { recursive: true });
      fs.writeFileSync(scriptPath, zapApiScript);
      fs.chmodSync(scriptPath, '755');

      expect(fs.existsSync(scriptPath)).toBe(true);
    });
  });

  describe('ZAP Test Execution', () => {
    test('should validate ZAP scan endpoints', async () => {
      // Test endpoints that ZAP will scan
      const endpoints = [
        '/api/auth/login',
        '/api/tasks',
        '/api/tasks/search',
        '/api/comments/task/1',
        '/api/users/avatar',
        '/api/tasks/import'
      ];

      for (const endpoint of endpoints) {
        const response = await request(app)
          .get(endpoint)
          .set('Authorization', `Bearer ${user1Token}`);

        // Endpoints should be accessible for ZAP scanning
        expect([200, 400, 401, 404, 500].includes(response.status)).toBe(true);
      }
    });

    test('should create ZAP scan targets file', async () => {
      const scanTargets = {
        baseUrl,
        endpoints: [
          {
            path: '/api/auth/login',
            method: 'POST',
            description: 'Authentication endpoint - test for auth bypass',
            vulnerabilities: ['Authentication', 'Brute Force', 'SQL Injection']
          },
          {
            path: '/api/tasks/search',
            method: 'GET',
            description: 'Search endpoint - test for SQL injection',
            vulnerabilities: ['SQL Injection', 'Information Disclosure'],
            parameters: ['query']
          },
          {
            path: '/api/comments/task/{id}',
            method: 'POST',
            description: 'Comment creation - test for XSS',
            vulnerabilities: ['XSS', 'IDOR'],
            authentication: 'required'
          },
          {
            path: '/api/tasks/{id}',
            method: 'GET',
            description: 'Task retrieval - test for IDOR',
            vulnerabilities: ['IDOR', 'Information Disclosure'],
            authentication: 'required'
          },
          {
            path: '/api/users/avatar',
            method: 'POST',
            description: 'Avatar upload - test for SSRF/LFI',
            vulnerabilities: ['SSRF', 'LFI', 'File Upload'],
            authentication: 'required'
          },
          {
            path: '/api/tasks/import',
            method: 'POST',
            description: 'Task import - test for SSRF',
            vulnerabilities: ['SSRF', 'XXE'],
            authentication: 'required'
          }
        ],
        authentication: {
          type: 'bearer',
          token: user1Token,
          header: 'Authorization'
        },
        testUsers: [
          {
            username: testUsers.user1.email,
            password: testUsers.user1.password,
            role: 'user'
          },
          {
            username: testUsers.user2.email,
            password: testUsers.user2.password,
            role: 'user'
          },
          {
            username: testUsers.admin.email,
            password: testUsers.admin.password,
            role: 'admin'
          }
        ]
      };

      const targetsPath = path.join(__dirname, '../reports/zap-targets.json');
      fs.mkdirSync(path.dirname(targetsPath), { recursive: true });
      fs.writeFileSync(targetsPath, JSON.stringify(scanTargets, null, 2));

      expect(fs.existsSync(targetsPath)).toBe(true);
    });
  });
});