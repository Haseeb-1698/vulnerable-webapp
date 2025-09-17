import React, { useState, useEffect } from 'react';
import { securityLabApi } from '../../utils/api';

interface RealTimeCodeSwitcherProps {
  vulnerabilityType: string;
  enabled: boolean;
  onToggle: () => void;
  vulnerableCode: string;
  secureCode: string;
}

interface CodeInjectionLog {
  timestamp: string;
  vulnerabilityType: string;
  codeType: 'vulnerable' | 'secure';
  success: boolean;
  message: string;
}

export const RealTimeCodeSwitcher: React.FC<RealTimeCodeSwitcherProps> = ({
  vulnerabilityType,
  enabled,
  onToggle,
  vulnerableCode,
  secureCode
}) => {
  const [isToggling, setIsToggling] = useState(false);
  const [injectionLogs, setInjectionLogs] = useState<CodeInjectionLog[]>([]);
  const [showLogs, setShowLogs] = useState(false);

  const handleToggleWithInjection = async () => {
    setIsToggling(true);
    
    try {
      // First, perform the code injection simulation
      const targetCodeType = enabled ? 'secure' : 'vulnerable';
      
      const injectionResponse = await securityLabApi.injectCode(vulnerabilityType, targetCodeType);
      
      // Add to injection logs
      const newLog: CodeInjectionLog = {
        timestamp: new Date().toISOString(),
        vulnerabilityType,
        codeType: targetCodeType,
        success: injectionResponse.data.success,
        message: injectionResponse.data.message
      };
      
      setInjectionLogs(prev => [newLog, ...prev].slice(0, 10)); // Keep last 10 logs
      
      // Then perform the actual toggle
      await onToggle();
      
      // Show success notification
      console.log(`🔄 Code switched to ${targetCodeType} for ${vulnerabilityType}`);
      
    } catch (error) {
      console.error('Code injection failed:', error);
      
      // Add error log
      const errorLog: CodeInjectionLog = {
        timestamp: new Date().toISOString(),
        vulnerabilityType,
        codeType: enabled ? 'secure' : 'vulnerable',
        success: false,
        message: 'Code injection failed'
      };
      
      setInjectionLogs(prev => [errorLog, ...prev].slice(0, 10));
    } finally {
      setIsToggling(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Real-time Toggle Control */}
      <div className="bg-white border border-gray-200 rounded-lg p-4">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">
              🔄 Real-time Code Switching
            </h3>
            <p className="text-sm text-gray-600">
              Dynamically switch between vulnerable and secure code implementations
            </p>
          </div>
          
          <div className="flex items-center space-x-3">
            {/* Status indicator */}
            <div className="flex items-center space-x-2">
              <div
                className={`w-3 h-3 rounded-full ${
                  enabled ? 'bg-red-500 animate-pulse' : 'bg-green-500'
                }`}
              />
              <span className="text-sm font-medium">
                {enabled ? 'VULNERABLE' : 'SECURE'}
              </span>
            </div>
            
            {/* Toggle switch */}
            <button
              onClick={handleToggleWithInjection}
              disabled={isToggling}
              className={`
                relative inline-flex h-6 w-11 items-center rounded-full transition-colors
                ${enabled ? 'bg-red-600' : 'bg-green-600'}
                ${isToggling ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
              `}
            >
              <span
                className={`
                  inline-block h-4 w-4 transform rounded-full bg-white transition-transform
                  ${enabled ? 'translate-x-6' : 'translate-x-1'}
                `}
              />
            </button>
          </div>
        </div>

        {/* Code injection status */}
        {isToggling && (
          <div className="mb-4 p-3 bg-blue-50 border border-blue-200 rounded">
            <div className="flex items-center space-x-2">
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600"></div>
              <span className="text-blue-800 text-sm font-medium">
                Injecting {enabled ? 'secure' : 'vulnerable'} code...
              </span>
            </div>
          </div>
        )}

        {/* Current code preview */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className={`p-3 rounded border ${
            enabled ? 'border-red-200 bg-red-50' : 'border-gray-200 bg-gray-50'
          }`}>
            <h4 className="font-medium text-sm mb-2 flex items-center">
              <span className={`w-2 h-2 rounded-full mr-2 ${
                enabled ? 'bg-red-500' : 'bg-gray-400'
              }`}></span>
              Vulnerable Code
            </h4>
            <pre className="text-xs text-gray-700 overflow-hidden">
              <code>{vulnerableCode.substring(0, 200)}...</code>
            </pre>
          </div>
          
          <div className={`p-3 rounded border ${
            !enabled ? 'border-green-200 bg-green-50' : 'border-gray-200 bg-gray-50'
          }`}>
            <h4 className="font-medium text-sm mb-2 flex items-center">
              <span className={`w-2 h-2 rounded-full mr-2 ${
                !enabled ? 'bg-green-500' : 'bg-gray-400'
              }`}></span>
              Secure Code
            </h4>
            <pre className="text-xs text-gray-700 overflow-hidden">
              <code>{secureCode.substring(0, 200)}...</code>
            </pre>
          </div>
        </div>
      </div>

      {/* Injection Logs */}
      <div className="bg-white border border-gray-200 rounded-lg">
        <div className="p-4 border-b">
          <div className="flex items-center justify-between">
            <h4 className="font-semibold text-gray-900">Code Injection Logs</h4>
            <button
              onClick={() => setShowLogs(!showLogs)}
              className="text-sm text-blue-600 hover:text-blue-800"
            >
              {showLogs ? 'Hide' : 'Show'} Logs
            </button>
          </div>
        </div>
        
        {showLogs && (
          <div className="p-4">
            {injectionLogs.length === 0 ? (
              <p className="text-gray-500 text-sm text-center py-4">
                No code injections performed yet
              </p>
            ) : (
              <div className="space-y-2 max-h-64 overflow-y-auto">
                {injectionLogs.map((log, index) => (
                  <div
                    key={index}
                    className={`p-3 rounded border text-sm ${
                      log.success
                        ? 'border-green-200 bg-green-50'
                        : 'border-red-200 bg-red-50'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className={`font-medium ${
                        log.success ? 'text-green-800' : 'text-red-800'
                      }`}>
                        {log.success ? '✅' : '❌'} Code Injection {log.success ? 'Success' : 'Failed'}
                      </span>
                      <span className="text-xs text-gray-500">
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                    
                    <div className="text-xs space-y-1">
                      <div>
                        <span className="font-medium">Type:</span> {log.vulnerabilityType}
                      </div>
                      <div>
                        <span className="font-medium">Target:</span> {log.codeType} code
                      </div>
                      <div>
                        <span className="font-medium">Message:</span> {log.message}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Hot Reload Simulation */}
      <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
        <h4 className="font-semibold text-gray-900 mb-2">🔥 Hot Reload Simulation</h4>
        <p className="text-sm text-gray-600 mb-3">
          In a real implementation, this would dynamically replace route handlers without restarting the application.
        </p>
        
        <div className="bg-gray-800 text-green-400 p-3 rounded font-mono text-xs">
          <div>$ curl -X POST /api/security-lab/inject-code</div>
          <div>{"{"}</div>
          <div>&nbsp;&nbsp;"vulnerabilityType": "{vulnerabilityType}",</div>
          <div>&nbsp;&nbsp;"codeType": "{enabled ? 'secure' : 'vulnerable'}"</div>
          <div>{"}"}</div>
          <div className="mt-2 text-yellow-400">
            → Hot-reloading endpoint: /api/tasks/search
          </div>
          <div className="text-green-400">
            ✓ Code injection completed successfully
          </div>
        </div>
      </div>
    </div>
  );
};