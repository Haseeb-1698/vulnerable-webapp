import React, { useState } from 'react';
import { VulnerabilityConfig, TestResult } from './SecurityLabDashboard';
import { PayloadLibrary } from './PayloadLibrary';
import { AttackTestingDashboard } from './AttackTestingDashboard';

interface LiveAttackTesterProps {
  vulnerabilityType: string;
  config: VulnerabilityConfig;
  onTest: (vulnType: string, payload: string, target?: string) => Promise<TestResult>;
  testResults: TestResult[];
}

export const LiveAttackTester: React.FC<LiveAttackTesterProps> = ({
  vulnerabilityType,
  config,
  onTest,
  testResults
}) => {
  const [selectedPayload, setSelectedPayload] = useState(config.testPayloads[0] || '');
  const [customPayload, setCustomPayload] = useState('');
  const [target, setTarget] = useState('');
  const [testing, setTesting] = useState(false);
  const [useCustom, setUseCustom] = useState(false);
  const [showPayloadLibrary, setShowPayloadLibrary] = useState(false);
  const [attackHistory, setAttackHistory] = useState<TestResult[]>([]);
  const [activeTab, setActiveTab] = useState<'manual' | 'automated'>('manual');

  const handleTest = async () => {
    const payload = useCustom ? customPayload : selectedPayload;
    
    if (!payload.trim()) {
      alert('Please enter a payload to test');
      return;
    }

    setTesting(true);
    try {
      const result = await onTest(vulnerabilityType, payload, target || undefined);
      
      // Validate result structure
      if (!result) {
        throw new Error('No result returned from test');
      }
      
      // Add to local attack history
      setAttackHistory(prev => [result, ...prev].slice(0, 20)); // Keep last 20 results
      
      // Show success/failure notification with more detail
      if (result.result === 'VULNERABLE') {
        if (result.attackSucceeded) {
          console.log('🚨 Real attack successful!', result);
          alert(`🚨 Attack Successful!\n\n${result.description}`);
        } else {
          console.log('⚠️ Vulnerability exists but attack limited', result);
          alert(`⚠️ Vulnerability Confirmed!\n\n${result.description}`);
        }
      } else if (result.result === 'SECURE') {
        console.log('✅ Attack blocked by security measures', result);
        alert(`✅ Attack Blocked!\n\n${result.description}`);
      } else {
        console.log('❌ Attack execution error', result);
        alert(`❌ Attack Error!\n\n${result.description}`);
      }
    } catch (error) {
      console.error('Test failed:', error);
      alert(`Test failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setTesting(false);
    }
  };

  const getTargetPlaceholder = () => {
    const placeholders = {
      sqlInjection: 'Search query (e.g., "test")',
      xss: 'Comment content',
      idor: 'Task ID (e.g., 123)',
      sessionManagement: 'Token or session data',
      ssrfLfi: 'URL or file path'
    };
    return placeholders[vulnerabilityType as keyof typeof placeholders] || 'Target';
  };

  return (
    <div className="space-y-6">
      {/* Tab Navigation */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-900">Live Attack Testing</h3>
          <div className="flex bg-gray-100 rounded-lg p-1">
            <button
              onClick={() => setActiveTab('manual')}
              className={`
                px-3 py-1 rounded text-sm font-medium transition-colors
                ${activeTab === 'manual'
                  ? 'bg-white text-gray-900 shadow-sm'
                  : 'text-gray-600 hover:text-gray-900'
                }
              `}
            >
              Manual Testing
            </button>
            <button
              onClick={() => setActiveTab('automated')}
              className={`
                px-3 py-1 rounded text-sm font-medium transition-colors
                ${activeTab === 'automated'
                  ? 'bg-white text-gray-900 shadow-sm'
                  : 'text-gray-600 hover:text-gray-900'
                }
              `}
            >
              Automated Scenarios
            </button>
          </div>
        </div>
        
        {!config.enabled && (
          <div className="mb-4 p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
            <div className="flex items-center space-x-2">
              <span className="text-yellow-600">⚠️</span>
              <span className="text-yellow-800 font-medium">Vulnerability Disabled</span>
            </div>
            <p className="text-yellow-700 text-sm mt-1">
              The secure code is currently active. Enable the vulnerability to test attack payloads.
            </p>
          </div>
        )}
      </div>

      {/* Tab Content */}
      {activeTab === 'manual' ? (
        <div className="space-y-4">{/* Manual testing content */}

      {/* Payload Selection */}
      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Attack Payload
          </label>
          
          <div className="space-y-3">
            {/* Predefined payloads */}
            <div>
              <label className="flex items-center space-x-2">
                <input
                  type="radio"
                  checked={!useCustom}
                  onChange={() => setUseCustom(false)}
                  className="text-blue-600"
                />
                <span className="text-sm text-gray-700">Use predefined payload</span>
              </label>
              
              {!useCustom && (
                <select
                  value={selectedPayload}
                  onChange={(e) => setSelectedPayload(e.target.value)}
                  className="mt-2 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                >
                  {config.testPayloads.map((payload, index) => (
                    <option key={index} value={payload}>
                      {payload.length > 60 ? `${payload.substring(0, 60)}...` : payload}
                    </option>
                  ))}
                </select>
              )}
            </div>

            {/* Custom payload */}
            <div>
              <label className="flex items-center space-x-2">
                <input
                  type="radio"
                  checked={useCustom}
                  onChange={() => setUseCustom(true)}
                  className="text-blue-600"
                />
                <span className="text-sm text-gray-700">Use custom payload</span>
              </label>
              
              {useCustom && (
                <textarea
                  value={customPayload}
                  onChange={(e) => setCustomPayload(e.target.value)}
                  placeholder="Enter your custom attack payload..."
                  rows={3}
                  className="mt-2 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                />
              )}
            </div>
          </div>
        </div>

        {/* Target field (optional) */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Target (Optional)
          </label>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder={getTargetPlaceholder()}
            className="block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500"
          />
        </div>

        {/* Action buttons */}
        <div className="flex space-x-3">
          <button
            onClick={handleTest}
            disabled={testing}
            className={`
              flex-1 px-4 py-2 rounded-lg font-medium transition-colors
              ${testing
                ? 'bg-gray-400 cursor-not-allowed'
                : 'bg-red-600 hover:bg-red-700'
              } text-white
            `}
          >
            {testing ? (
              <span className="flex items-center justify-center space-x-2">
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                <span>Testing...</span>
              </span>
            ) : (
              '🧪 Execute Attack'
            )}
          </button>
          
          <button
            onClick={() => setShowPayloadLibrary(true)}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors"
          >
            📚 Payload Library
          </button>
        </div>
      </div>
        </div>
      ) : (
        <div>
          {/* Automated testing content would go here */}
          <p className="text-gray-500 text-center py-8">Automated testing scenarios coming soon...</p>
        </div>
      )}

      {/* Test Results */}
      {testResults.length > 0 ? (
        <div>
          <h4 className="text-md font-semibold text-gray-900 mb-3">Recent Test Results</h4>
          <div className="space-y-3 max-h-96 overflow-y-auto">
            {testResults.map((result, index) => (
              <div
                key={index}
                className={`
                  p-4 rounded-lg border
                  ${result.result === 'VULNERABLE'
                    ? result.attackSucceeded 
                      ? 'bg-red-50 border-red-200'
                      : 'bg-orange-50 border-orange-200'
                    : result.result === 'ERROR'
                    ? 'bg-gray-50 border-gray-200'
                    : 'bg-green-50 border-green-200'
                  }
                `}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    <span
                      className={`
                        px-2 py-1 rounded text-xs font-medium
                        ${result.result === 'VULNERABLE'
                          ? result.attackSucceeded
                            ? 'bg-red-100 text-red-800'
                            : 'bg-orange-100 text-orange-800'
                          : result.result === 'ERROR'
                          ? 'bg-gray-100 text-gray-800'
                          : 'bg-green-100 text-green-800'
                        }
                      `}
                    >
                      {result.result}
                    </span>
                    {result.attackSucceeded && (
                      <span className="text-xs bg-red-600 text-white px-2 py-1 rounded">
                        EXECUTED
                      </span>
                    )}
                  </div>
                  <span className="text-xs text-gray-500">
                    {new Date(result.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                
                <div className="space-y-2">
                  <div>
                    <span className="text-sm font-medium text-gray-700">Payload:</span>
                    <code className="block mt-1 p-2 bg-gray-100 rounded text-xs font-mono">
                      {result.payload}
                    </code>
                  </div>
                  
                  {result.target && (
                    <div>
                      <span className="text-sm font-medium text-gray-700">Target:</span>
                      <code className="block mt-1 p-2 bg-gray-100 rounded text-xs font-mono">
                        {result.target}
                      </code>
                    </div>
                  )}
                  
                  <div>
                    <span className="text-sm font-medium text-gray-700">Result:</span>
                    <p className="text-sm text-gray-600 mt-1">{result.description}</p>
                  </div>

                  {result.actualResponse && (
                    <div>
                      <span className="text-sm font-medium text-gray-700">Server Response:</span>
                      <details className="mt-1">
                        <summary className="text-xs text-blue-600 cursor-pointer hover:text-blue-800">
                          Show raw response
                        </summary>
                        <pre className="mt-2 p-2 bg-gray-100 rounded text-xs font-mono overflow-x-auto max-h-32">
                          {JSON.stringify(result.actualResponse, null, 2)}
                        </pre>
                      </details>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {/* Payload Library Modal */}
      {showPayloadLibrary && (
        <PayloadLibrary
          vulnerabilityType={vulnerabilityType}
          onSelectPayload={(payload) => {
            setCustomPayload(payload);
            setUseCustom(true);
            setShowPayloadLibrary(false);
          }}
          onClose={() => setShowPayloadLibrary(false)}
        />
      )}
    </div>
  );
};