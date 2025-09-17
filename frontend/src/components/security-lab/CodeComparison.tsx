import React, { useState } from 'react';
import { CodeBlock } from './CodeBlock';

interface CodeComparisonProps {
  vulnerableCode: string;
  secureCode: string;
  enabled: boolean;
}

export const CodeComparison: React.FC<CodeComparisonProps> = ({
  vulnerableCode,
  secureCode,
  enabled
}) => {
  const [view, setView] = useState<'side-by-side' | 'current'>('side-by-side');

  return (
    <div className="space-y-4">
      {/* View Toggle */}
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-gray-900">Code Comparison</h3>
        <div className="flex bg-gray-100 rounded-lg p-1">
          <button
            onClick={() => setView('side-by-side')}
            className={`
              px-3 py-1 rounded text-sm font-medium transition-colors
              ${view === 'side-by-side'
                ? 'bg-white text-gray-900 shadow-sm'
                : 'text-gray-600 hover:text-gray-900'
              }
            `}
          >
            Side by Side
          </button>
          <button
            onClick={() => setView('current')}
            className={`
              px-3 py-1 rounded text-sm font-medium transition-colors
              ${view === 'current'
                ? 'bg-white text-gray-900 shadow-sm'
                : 'text-gray-600 hover:text-gray-900'
              }
            `}
          >
            Current Code
          </button>
        </div>
      </div>

      {view === 'side-by-side' ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Vulnerable Code */}
          <div className="space-y-2">
            <div className="flex items-center space-x-2">
              <div className="w-3 h-3 bg-red-500 rounded-full"></div>
              <h4 className="font-semibold text-red-700">Vulnerable Code</h4>
            </div>
            <div className="bg-red-50 border border-red-200 rounded-lg overflow-hidden">
              <div className="bg-red-100 px-4 py-2 border-b border-red-200">
                <span className="text-sm font-medium text-red-800">⚠️ Security Risk</span>
              </div>
              <CodeBlock
                code={vulnerableCode}
                language="javascript"
                theme="vulnerable"
                simpleDisplay={true}
              />
            </div>
          </div>

          {/* Secure Code */}
          <div className="space-y-2">
            <div className="flex items-center space-x-2">
              <div className="w-3 h-3 bg-green-500 rounded-full"></div>
              <h4 className="font-semibold text-green-700">Secure Code</h4>
            </div>
            <div className="bg-green-50 border border-green-200 rounded-lg overflow-hidden">
              <div className="bg-green-100 px-4 py-2 border-b border-green-200">
                <span className="text-sm font-medium text-green-800">✅ Secure Implementation</span>
              </div>
              <CodeBlock
                code={secureCode}
                language="javascript"
                theme="secure"
                simpleDisplay={true}
              />
            </div>
          </div>
        </div>
      ) : (
        <div className="space-y-2">
          <div className="flex items-center space-x-2">
            <div className={`w-3 h-3 rounded-full ${enabled ? 'bg-red-500' : 'bg-green-500'}`}></div>
            <h4 className={`font-semibold ${enabled ? 'text-red-700' : 'text-green-700'}`}>
              Currently Active: {enabled ? 'Vulnerable Code' : 'Secure Code'}
            </h4>
          </div>
          <div className={`border rounded-lg overflow-hidden ${
            enabled 
              ? 'bg-red-50 border-red-200' 
              : 'bg-green-50 border-green-200'
          }`}>
            <div className={`px-4 py-2 border-b ${
              enabled 
                ? 'bg-red-100 border-red-200' 
                : 'bg-green-100 border-green-200'
            }`}>
              <span className={`text-sm font-medium ${
                enabled ? 'text-red-800' : 'text-green-800'
              }`}>
                {enabled ? '⚠️ Security Risk - This code is currently active' : '✅ Secure Implementation - This code is currently active'}
              </span>
            </div>
            <CodeBlock
              code={enabled ? vulnerableCode : secureCode}
              language="javascript"
              theme={enabled ? "vulnerable" : "secure"}
              showLineNumbers={true}
              highlightVulnerabilities={true}
              simpleDisplay={true}
            />
          </div>
        </div>
      )}

      {/* Key Differences */}
      <div className="mt-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
        <h4 className="font-semibold text-blue-900 mb-2">🔍 Key Security Differences</h4>
        <div className="text-sm text-blue-800 space-y-1">
          {enabled ? (
            <div>
              <p><strong>Current Risk:</strong> The vulnerable code is active and exploitable.</p>
              <p><strong>Recommendation:</strong> Toggle to secure code to see the proper implementation.</p>
            </div>
          ) : (
            <div>
              <p><strong>Current Status:</strong> Secure code is active with proper protections.</p>
              <p><strong>Learning:</strong> Compare with vulnerable version to understand the risks.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};