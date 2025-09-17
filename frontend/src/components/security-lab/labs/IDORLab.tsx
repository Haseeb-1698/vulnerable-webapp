import React from 'react';
import { VulnerabilityConfig, TestResult } from '../SecurityLabDashboard';
import { VulnerabilityLabTemplate } from './VulnerabilityLabTemplate';

interface IDORLabProps {
  config: VulnerabilityConfig;
  enabled: boolean;
  onToggle: () => void;
  onTest: (vulnType: string, payload: string, target?: string) => Promise<TestResult>;
  testResults: TestResult[];
}

export const IDORLab: React.FC<IDORLabProps> = ({
  config,
  enabled,
  onToggle,
  onTest,
  testResults
}) => {
  const vulnerableCode = `// VULNERABLE CODE - No Authorization Check
app.get('/api/tasks/:id', authenticateUser, async (req, res) => {
  const { id } = req.params;
  
  try {
    // DANGER: No ownership verification
    const task = await prisma.task.findUnique({
      where: { id: parseInt(id) },
      include: {
        user: { select: { firstName: true, lastName: true } },
        comments: true
      }
    });
    
    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }
    
    // Returns task regardless of ownership
    res.json(task);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// VULNERABLE: Update without ownership check
app.put('/api/tasks/:id', authenticateUser, async (req, res) => {
  const { id } = req.params;
  const { title, description, status } = req.body;
  
  // DANGER: Any authenticated user can modify any task
  const task = await prisma.task.update({
    where: { id: parseInt(id) },
    data: { title, description, status }
  });
  
  res.json(task);
});`;

  const secureCode = `// SECURE CODE - Proper Authorization
app.get('/api/tasks/:id', authenticateUser, async (req, res) => {
  const { id } = req.params;
  
  try {
    // Safe: Check ownership
    const task = await prisma.task.findFirst({
      where: { 
        id: parseInt(id),
        userId: req.user.id // Ensure user owns the task
      },
      include: {
        user: { select: { firstName: true, lastName: true } },
        comments: {
          include: {
            user: { select: { firstName: true, lastName: true } }
          }
        }
      }
    });
    
    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }
    
    res.json(task);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// SECURE: Update with ownership verification
app.put('/api/tasks/:id', authenticateUser, async (req, res) => {
  const { id } = req.params;
  const { title, description, status } = req.body;
  
  // Safe: Verify ownership before update
  const existingTask = await prisma.task.findFirst({
    where: { 
      id: parseInt(id),
      userId: req.user.id 
    }
  });
  
  if (!existingTask) {
    return res.status(404).json({ error: 'Task not found' });
  }
  
  const task = await prisma.task.update({
    where: { id: parseInt(id) },
    data: { title, description, status }
  });
  
  res.json(task);
});`;

  const testPayloads = [
    "Increment task ID: /api/tasks/123 → /api/tasks/124",
    "Decrement task ID: /api/tasks/123 → /api/tasks/122", 
    "Try sequential IDs: 1, 2, 3, 4, 5...",
    "Access admin tasks: /api/tasks/1",
    "Modify other user's task: PUT /api/tasks/456",
    "Delete other user's task: DELETE /api/tasks/789",
    "Bulk enumerate: /api/tasks/1 through /api/tasks/1000",
    "Access with different user context"
  ];

  const idorScenarios = [
    {
      scenario: "Direct Object Access",
      description: "Accessing resources by manipulating object identifiers",
      example: "GET /api/tasks/123 → GET /api/tasks/124",
      impact: "View other users' private tasks and sensitive information"
    },
    {
      scenario: "Horizontal Privilege Escalation",
      description: "Accessing resources belonging to users at the same privilege level",
      example: "User A accesses User B's profile: /api/users/456",
      impact: "Access to peer user data and functionality"
    },
    {
      scenario: "Vertical Privilege Escalation",
      description: "Accessing administrative or higher-privilege resources",
      example: "Regular user accesses admin panel: /api/admin/users",
      impact: "Unauthorized administrative access and control"
    },
    {
      scenario: "Bulk Data Enumeration",
      description: "Systematically accessing multiple objects to harvest data",
      example: "Iterate through /api/tasks/1 to /api/tasks/10000",
      impact: "Mass data extraction and privacy violations"
    }
  ];

  const exploitationTechniques = [
    {
      technique: "Parameter Manipulation",
      description: "Modify URL parameters, form fields, or API endpoints",
      tools: ["Burp Suite", "OWASP ZAP", "Browser DevTools"],
      example: "Change user_id=123 to user_id=456 in requests"
    },
    {
      technique: "Sequential ID Testing",
      description: "Test incremental or predictable identifiers",
      tools: ["Custom scripts", "Burp Intruder", "ffuf"],
      example: "Automate requests to /api/tasks/1 through /api/tasks/1000"
    },
    {
      technique: "Session Context Switching",
      description: "Use different user sessions to test access controls",
      tools: ["Multiple browser sessions", "Postman", "curl"],
      example: "Login as different users and test same resource access"
    },
    {
      technique: "HTTP Method Testing",
      description: "Try different HTTP methods on the same endpoint",
      tools: ["Burp Suite", "curl", "Postman"],
      example: "GET /api/tasks/123 vs PUT /api/tasks/123 vs DELETE /api/tasks/123"
    }
  ];

  return (
    <VulnerabilityLabTemplate
      title="Insecure Direct Object References Laboratory (CWE-639)"
      description="Learn how IDOR vulnerabilities work and how to implement proper authorization controls."
      vulnerableCode={vulnerableCode}
      secureCode={secureCode}
      enabled={enabled}
      onToggle={onToggle}
      testPayloads={testPayloads}
      onTest={onTest}
      testResults={testResults}
      vulnerabilityType="idor"
      additionalContent={
        <div className="space-y-6">
          {/* IDOR Scenarios */}
          <div className="bg-red-50 border border-red-200 rounded-lg p-4">
            <h4 className="font-semibold text-red-900 mb-3">🎯 IDOR Attack Scenarios</h4>
            <div className="space-y-4">
              {idorScenarios.map((scenario, index) => (
                <div key={index} className="border-l-4 border-red-400 pl-4">
                  <h5 className="font-medium text-red-900">{scenario.scenario}</h5>
                  <p className="text-sm text-red-700 mb-2">{scenario.description}</p>
                  <code className="block bg-red-100 p-2 rounded text-xs font-mono text-red-800">
                    {scenario.example}
                  </code>
                  <p className="text-xs text-red-600 mt-1 italic">{scenario.impact}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Exploitation Techniques */}
          <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
            <h4 className="font-semibold text-orange-900 mb-3">🔧 Exploitation Techniques</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {exploitationTechniques.map((technique, index) => (
                <div key={index} className="bg-white border border-orange-200 rounded p-3">
                  <h5 className="font-medium text-orange-800 mb-1">{technique.technique}</h5>
                  <p className="text-xs text-orange-700 mb-2">{technique.description}</p>
                  <div className="mb-2">
                    <span className="text-xs font-medium text-orange-800">Tools:</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {technique.tools.map((tool, toolIndex) => (
                        <span key={toolIndex} className="bg-orange-100 text-orange-800 text-xs px-2 py-1 rounded">
                          {tool}
                        </span>
                      ))}
                    </div>
                  </div>
                  <code className="block bg-orange-100 p-2 rounded text-xs font-mono text-orange-800">
                    {technique.example}
                  </code>
                </div>
              ))}
            </div>
          </div>

          {/* Testing Methodology */}
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <h4 className="font-semibold text-blue-900 mb-3">🧪 Testing Methodology</h4>
            <div className="space-y-3">
              <div className="flex items-start space-x-3">
                <span className="bg-blue-100 text-blue-800 text-xs font-medium px-2 py-1 rounded">Step 1</span>
                <div>
                  <h5 className="font-medium text-blue-800">Identify Object References</h5>
                  <p className="text-sm text-blue-700">Find URLs, forms, and API endpoints that use object identifiers</p>
                </div>
              </div>
              <div className="flex items-start space-x-3">
                <span className="bg-blue-100 text-blue-800 text-xs font-medium px-2 py-1 rounded">Step 2</span>
                <div>
                  <h5 className="font-medium text-blue-800">Create Test Accounts</h5>
                  <p className="text-sm text-blue-700">Set up multiple user accounts with different privilege levels</p>
                </div>
              </div>
              <div className="flex items-start space-x-3">
                <span className="bg-blue-100 text-blue-800 text-xs font-medium px-2 py-1 rounded">Step 3</span>
                <div>
                  <h5 className="font-medium text-blue-800">Map Object Relationships</h5>
                  <p className="text-sm text-blue-700">Understand which objects belong to which users</p>
                </div>
              </div>
              <div className="flex items-start space-x-3">
                <span className="bg-blue-100 text-blue-800 text-xs font-medium px-2 py-1 rounded">Step 4</span>
                <div>
                  <h5 className="font-medium text-blue-800">Test Access Controls</h5>
                  <p className="text-sm text-blue-700">Attempt to access objects owned by other users</p>
                </div>
              </div>
              <div className="flex items-start space-x-3">
                <span className="bg-blue-100 text-blue-800 text-xs font-medium px-2 py-1 rounded">Step 5</span>
                <div>
                  <h5 className="font-medium text-blue-800">Automate Testing</h5>
                  <p className="text-sm text-blue-700">Use tools to systematically test large ranges of identifiers</p>
                </div>
              </div>
            </div>
          </div>

          {/* Prevention Strategies */}
          <div className="bg-green-50 border border-green-200 rounded-lg p-4">
            <h4 className="font-semibold text-green-900 mb-3">🛡️ Prevention Strategies</h4>
            <div className="space-y-4">
              <div>
                <h5 className="font-medium text-green-800">1. Implement Proper Authorization</h5>
                <p className="text-sm text-green-700 mb-2">Always verify user ownership before granting access</p>
                <code className="block bg-green-100 p-2 rounded text-xs font-mono text-green-800">
                  {`WHERE resource.user_id = current_user.id`}
                </code>
              </div>
              
              <div>
                <h5 className="font-medium text-green-800">2. Use Indirect References</h5>
                <p className="text-sm text-green-700 mb-2">Use session-specific or user-specific mappings</p>
                <code className="block bg-green-100 p-2 rounded text-xs font-mono text-green-800">
                  {`/api/my-tasks/first instead of /api/tasks/123`}
                </code>
              </div>
              
              <div>
                <h5 className="font-medium text-green-800">3. Implement Access Control Lists</h5>
                <p className="text-sm text-green-700 mb-2">Define explicit permissions for each resource</p>
                <code className="block bg-green-100 p-2 rounded text-xs font-mono text-green-800">
                  {`if (!acl.canAccess(user, resource, 'read')) deny();`}
                </code>
              </div>
              
              <div>
                <h5 className="font-medium text-green-800">4. Use UUIDs Instead of Sequential IDs</h5>
                <p className="text-sm text-green-700 mb-2">Make object identifiers unpredictable</p>
                <code className="block bg-green-100 p-2 rounded text-xs font-mono text-green-800">
                  {`/api/tasks/550e8400-e29b-41d4-a716-446655440000`}
                </code>
              </div>
            </div>
          </div>

          {/* Real-World Examples */}
          <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
            <h4 className="font-semibold text-purple-900 mb-3">🌍 Real-World Examples</h4>
            <div className="space-y-2 text-sm text-purple-800">
              <p><strong>Facebook (2013):</strong> IDOR vulnerability allowed access to private photos by manipulating photo IDs</p>
              <p><strong>Instagram (2017):</strong> Business account information exposed through predictable user IDs</p>
              <p><strong>Uber (2016):</strong> Trip details accessible by manipulating trip UUIDs in mobile app</p>
              <p><strong>Tesla (2020):</strong> Vehicle information accessible through VIN manipulation in API</p>
            </div>
          </div>
        </div>
      }
    />
  );
};