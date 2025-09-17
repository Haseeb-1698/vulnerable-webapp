import React, { useState, useEffect } from 'react';
import { TestResult } from './SecurityLabDashboard';
import { securityLabApi } from '../../utils/api';

interface AttackHistoryProps {
  results: TestResult[];
}

interface AttackHistoryEntry {
  id: number;
  vulnerabilityType: string;
  payload: string;
  timestamp: string;
  result: 'VULNERABLE' | 'SECURE';
  success: boolean;
}

export const AttackHistory: React.FC<AttackHistoryProps> = ({ results }) => {
  const [globalHistory, setGlobalHistory] = useState<AttackHistoryEntry[]>([]);
  const [showGlobal, setShowGlobal] = useState(false);
  const [loading, setLoading] = useState(false);

  const loadGlobalHistory = async () => {
    try {
      setLoading(true);
      const response = await securityLabApi.getAttackHistory();
      setGlobalHistory(response.data.history || []);
    } catch (error) {
      console.error('Failed to load attack history:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (showGlobal) {
      loadGlobalHistory();
    }
  }, [showGlobal]);
  if (results.length === 0) {
    return (
      <div className="bg-white rounded-lg shadow-sm border">
        <div className="p-4 border-b">
          <h3 className="text-lg font-semibold text-gray-900">Attack History</h3>
        </div>
        <div className="p-4 text-center text-gray-500">
          <div className="text-4xl mb-2">🕐</div>
          <p className="text-sm">No tests performed yet</p>
        </div>
      </div>
    );
  }

  const displayResults = showGlobal ? globalHistory : results;

  return (
    <div className="bg-white rounded-lg shadow-sm border">
      <div className="p-4 border-b">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-gray-900">Attack History</h3>
            <p className="text-sm text-gray-600">
              {showGlobal ? 'All attack attempts' : 'Current session results'}
            </p>
          </div>
          <div className="flex space-x-2">
            <button
              onClick={() => setShowGlobal(!showGlobal)}
              className={`
                px-3 py-1 rounded text-xs font-medium transition-colors
                ${showGlobal 
                  ? 'bg-blue-100 text-blue-800' 
                  : 'bg-gray-100 text-gray-800 hover:bg-gray-200'
                }
              `}
            >
              {showGlobal ? 'Session' : 'Global'}
            </button>
            {showGlobal && (
              <button
                onClick={loadGlobalHistory}
                disabled={loading}
                className="px-3 py-1 bg-gray-100 hover:bg-gray-200 text-gray-800 rounded text-xs font-medium transition-colors"
              >
                {loading ? '⟳' : '↻'}
              </button>
            )}
          </div>
        </div>
      </div>
      
      <div className="p-2">
        <div className="space-y-2 max-h-64 overflow-y-auto">
          {displayResults.map((result, index) => (
            <div
              key={index}
              className={`
                p-3 rounded-lg border transition-colors
                ${result.result === 'VULNERABLE'
                  ? 'bg-red-50 border-red-200 hover:bg-red-100'
                  : 'bg-green-50 border-green-200 hover:bg-green-100'
                }
              `}
            >
              <div className="flex items-center justify-between mb-2">
                <span
                  className={`
                    px-2 py-1 rounded text-xs font-medium
                    ${result.result === 'VULNERABLE'
                      ? 'bg-red-100 text-red-800'
                      : 'bg-green-100 text-green-800'
                    }
                  `}
                >
                  {result.result}
                </span>
                <span className="text-xs text-gray-500">
                  {new Date(result.timestamp).toLocaleTimeString()}
                </span>
              </div>
              
              <div className="space-y-1">
                <div className="text-xs text-gray-600">
                  <span className="font-medium">Payload:</span>
                </div>
                <code className="block p-2 bg-white rounded text-xs font-mono border">
                  {result.payload.length > 40 
                    ? `${result.payload.substring(0, 40)}...` 
                    : result.payload
                  }
                </code>
                
                {showGlobal && 'vulnerabilityType' in result && (
                  <div className="mt-2">
                    <span className="text-xs font-medium text-gray-600">Type:</span>
                    <span className="ml-1 px-2 py-1 bg-blue-100 text-blue-800 text-xs rounded">
                      {result.vulnerabilityType}
                    </span>
                  </div>
                )}
                
                {'target' in result && result.target && (
                  <>
                    <div className="text-xs text-gray-600 mt-2">
                      <span className="font-medium">Target:</span>
                    </div>
                    <code className="block p-2 bg-white rounded text-xs font-mono border">
                      {result.target}
                    </code>
                  </>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
      
      {displayResults.length > 5 && (
        <div className="p-3 border-t bg-gray-50 text-center">
          <span className="text-xs text-gray-500">
            Showing last {Math.min(displayResults.length, 10)} results
            {showGlobal && ' (Global history may include mock data for demonstration)'}
          </span>
        </div>
      )}
    </div>
  );
};