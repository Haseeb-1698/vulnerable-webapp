import React, { useState } from 'react';
import { VulnerabilityConfig, TestResult } from '../SecurityLabDashboard';
import { VulnerabilityLabTemplate } from './VulnerabilityLabTemplate';

interface SQLInjectionLabProps {
  config: VulnerabilityConfig;
  enabled: boolean;
  onToggle: () => void;
  onTest: (vulnType: string, payload: string, target?: string) => Promise<TestResult>;
  testResults: TestResult[];
}

export const SQLInjectionLab: React.FC<SQLInjectionLabProps> = ({
  config,
  enabled,
  onToggle,
  onTest,
  testResults
}) => {
  const vulnerableCode = `// VULNERABLE CODE - Raw SQL Query
app.get('/api/tasks/search', authenticateUser, async (req, res) => {
  const { query } = req.query;
  
  // DANGER: Direct string concatenation
  const sqlQuery = \`
    SELECT t.*, u.first_name, u.last_name 
    FROM tasks t 
    JOIN users u ON t.user_id = u.id 
    WHERE t.title LIKE '%\${query}%' 
    OR t.description LIKE '%\${query}%'
  \`;
  
  try {
    const result = await db.query(sqlQuery);
    res.json(result.rows);
  } catch (error) {
    // VULNERABILITY: Exposing database errors
    res.status(500).json({ error: error.message });
  }
});`;

  const secureCode = `// SECURE CODE - Parameterized Query
app.get('/api/tasks/search', authenticateUser, async (req, res) => {
  const { query } = req.query;
  
  // Input validation
  if (!query || query.length > 100) {
    return res.status(400).json({ error: 'Invalid search query' });
  }
  
  try {
    // Safe parameterized query using Prisma
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
    // Safe error handling
    res.status(500).json({ error: 'Search failed' });
  }
});`;

  const testPayloads = [
    "' OR '1'='1",
    "' UNION SELECT id, email, password_hash FROM users--",
    "'; DROP TABLE tasks; --",
    "' UNION SELECT 1, username, password FROM users WHERE '1'='1",
    "admin'--",
    "' OR 1=1#",
    "' UNION ALL SELECT NULL, NULL, NULL--",
    "' AND (SELECT COUNT(*) FROM users) > 0--"
  ];

  const exploitationSteps = [
    {
      step: 1,
      title: "Basic SQL Injection Test",
      description: "Test if the application is vulnerable to basic SQL injection",
      payload: "' OR '1'='1",
      explanation: "This payload attempts to bypass authentication by making the WHERE clause always true"
    },
    {
      step: 2,
      title: "Union-Based Data Extraction",
      description: "Extract sensitive data from other tables",
      payload: "' UNION SELECT id, email, password_hash FROM users--",
      explanation: "Uses UNION to combine results from the users table, potentially exposing credentials"
    },
    {
      step: 3,
      title: "Database Structure Discovery",
      description: "Discover database schema and table information",
      payload: "' UNION SELECT table_name, column_name, data_type FROM information_schema.columns--",
      explanation: "Queries system tables to understand the database structure"
    },
    {
      step: 4,
      title: "Destructive Attack Simulation",
      description: "Simulate a destructive attack (safe in this environment)",
      payload: "'; DROP TABLE tasks; --",
      explanation: "Attempts to delete the tasks table - this would be catastrophic in production"
    }
  ];

  return (
    <VulnerabilityLabTemplate
      title="SQL Injection Laboratory (CWE-89)"
      description="Learn how SQL injection attacks work and how to prevent them using parameterized queries and input validation."
      vulnerableCode={vulnerableCode}
      secureCode={secureCode}
      enabled={enabled}
      onToggle={onToggle}
      testPayloads={testPayloads}
      onTest={onTest}
      testResults={testResults}
      vulnerabilityType="sqlInjection"
      additionalContent={
        <div className="space-y-6">
          {/* Attack Methodology */}
          <div className="bg-red-50 border border-red-200 rounded-lg p-4">
            <h4 className="font-semibold text-red-900 mb-3">🎯 Attack Methodology</h4>
            <div className="space-y-3">
              {exploitationSteps.map((step) => (
                <div key={step.step} className="border-l-4 border-red-400 pl-4">
                  <div className="flex items-center space-x-2 mb-1">
                    <span className="bg-red-100 text-red-800 text-xs font-medium px-2 py-1 rounded">
                      Step {step.step}
                    </span>
                    <h5 className="font-medium text-red-900">{step.title}</h5>
                  </div>
                  <p className="text-sm text-red-700 mb-2">{step.description}</p>
                  <code className="block bg-red-100 p-2 rounded text-xs font-mono text-red-800">
                    {step.payload}
                  </code>
                  <p className="text-xs text-red-600 mt-1 italic">{step.explanation}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Impact Assessment */}
          <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
            <h4 className="font-semibold text-orange-900 mb-3">💥 Impact Assessment</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <h5 className="font-medium text-orange-800 mb-2">Data Confidentiality</h5>
                <ul className="text-sm text-orange-700 space-y-1">
                  <li>• Access to user credentials</li>
                  <li>• Exposure of personal information</li>
                  <li>• Database schema discovery</li>
                  <li>• Administrative data access</li>
                </ul>
              </div>
              <div>
                <h5 className="font-medium text-orange-800 mb-2">Data Integrity</h5>
                <ul className="text-sm text-orange-700 space-y-1">
                  <li>• Unauthorized data modification</li>
                  <li>• Record deletion</li>
                  <li>• Database corruption</li>
                  <li>• Privilege escalation</li>
                </ul>
              </div>
            </div>
          </div>

          {/* Prevention Techniques */}
          <div className="bg-green-50 border border-green-200 rounded-lg p-4">
            <h4 className="font-semibold text-green-900 mb-3">🛡️ Prevention Techniques</h4>
            <div className="space-y-3">
              <div>
                <h5 className="font-medium text-green-800">1. Parameterized Queries</h5>
                <p className="text-sm text-green-700">Use prepared statements with parameter binding</p>
                <code className="block bg-green-100 p-2 rounded text-xs font-mono text-green-800 mt-1">
                  SELECT * FROM tasks WHERE title LIKE ? AND user_id = ?
                </code>
              </div>
              <div>
                <h5 className="font-medium text-green-800">2. Input Validation</h5>
                <p className="text-sm text-green-700">Validate and sanitize all user inputs</p>
                <code className="block bg-green-100 p-2 rounded text-xs font-mono text-green-800 mt-1">
                  {`if (!query || query.length > 100) return error;`}
                </code>
              </div>
              <div>
                <h5 className="font-medium text-green-800">3. Least Privilege</h5>
                <p className="text-sm text-green-700">Use database accounts with minimal necessary permissions</p>
              </div>
              <div>
                <h5 className="font-medium text-green-800">4. Error Handling</h5>
                <p className="text-sm text-green-700">Never expose database errors to users</p>
              </div>
            </div>
          </div>

          {/* Real-World Examples */}
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <h4 className="font-semibold text-blue-900 mb-3">🌍 Real-World Examples</h4>
            <div className="space-y-2 text-sm text-blue-800">
              <p><strong>Equifax (2017):</strong> SQL injection led to breach of 147 million records</p>
              <p><strong>TalkTalk (2015):</strong> SQL injection exposed 157,000 customer records</p>
              <p><strong>Sony Pictures (2011):</strong> SQL injection compromised 1 million accounts</p>
            </div>
          </div>
        </div>
      }
    />
  );
};