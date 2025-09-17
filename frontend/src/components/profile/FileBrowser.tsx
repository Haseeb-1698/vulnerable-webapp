import React, { useState } from 'react';
import { api } from '../../utils/api';

interface FileRequest {
  filename: string;
}

interface FileResponse {
  success?: boolean;
  content?: string;
  error?: string;
  path?: string;
  requestedFile?: string;
  details?: string;
  warning?: string;
}

const FileBrowser: React.FC = () => {
  const [filename, setFilename] = useState('');
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState<FileResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showExamples, setShowExamples] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!filename.trim()) return;

    setLoading(true);
    setError(null);
    setResponse(null);

    try {
      // Make request to the vulnerable file serving endpoint
      const result = await api.get(`/users/files/${encodeURIComponent(filename.trim())}`, {
        responseType: 'text'
      });
      
      setResponse({
        success: true,
        content: result.data,
        requestedFile: filename.trim()
      });
    } catch (err: any) {
      setError(err.response?.data?.error || err.message || 'Failed to retrieve file');
      if (err.response?.data) {
        setResponse(err.response.data);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleExampleClick = (examplePath: string) => {
    setFilename(examplePath);
  };

  const pathTraversalExamples = [
    {
      category: 'Basic Path Traversal',
      examples: [
        {
          name: 'Parent Directory',
          path: '../',
          description: 'Navigate to parent directory'
        },
        {
          name: 'Root Directory',
          path: '../../../',
          description: 'Navigate multiple levels up'
        },
        {
          name: 'System Files',
          path: '../../../../etc/passwd',
          description: 'Access system user file'
        },
        {
          name: 'Host Configuration',
          path: '../../../../etc/hosts',
          description: 'Read network host configuration'
        }
      ]
    },
    {
      category: 'Application Files',
      examples: [
        {
          name: 'Environment Variables',
          path: '../../../.env',
          description: 'Read application environment variables'
        },
        {
          name: 'Package Configuration',
          path: '../../../package.json',
          description: 'Read Node.js package configuration'
        },
        {
          name: 'Source Code',
          path: '../../../src/server.ts',
          description: 'Access application source code'
        },
        {
          name: 'Database Schema',
          path: '../../../prisma/schema.prisma',
          description: 'Read database schema definition'
        }
      ]
    },
    {
      category: 'System Information',
      examples: [
        {
          name: 'System Version',
          path: '../../../../proc/version',
          description: 'Read system version information'
        },
        {
          name: 'Memory Information',
          path: '../../../../proc/meminfo',
          description: 'Read system memory information'
        },
        {
          name: 'CPU Information',
          path: '../../../../proc/cpuinfo',
          description: 'Read CPU information'
        },
        {
          name: 'Network Interfaces',
          path: '../../../../proc/net/dev',
          description: 'Read network interface information'
        }
      ]
    },
    {
      category: 'Windows Specific (if applicable)',
      examples: [
        {
          name: 'Windows Hosts File',
          path: '../../../../windows/system32/drivers/etc/hosts',
          description: 'Read Windows hosts file'
        },
        {
          name: 'System Information',
          path: '../../../../windows/system32/drivers/etc/services',
          description: 'Read Windows services file'
        }
      ]
    }
  ];

  return (
    <div className="space-y-6">
      {/* File Browser Form */}
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="filename" className="block text-sm font-medium text-gray-700">
            File Path
          </label>
          <input
            type="text"
            id="filename"
            value={filename}
            onChange={(e) => setFilename(e.target.value)}
            placeholder="example.txt or ../../../etc/passwd"
            className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
            required
          />
          <p className="mt-1 text-sm text-gray-500">
            Enter a filename or path. This endpoint is vulnerable to path traversal attacks.
          </p>
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-orange-600 text-white py-2 px-4 rounded-md hover:bg-orange-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {loading ? 'Retrieving...' : 'Retrieve File'}
        </button>
      </form>

      {/* Path Traversal Examples */}
      <div>
        <button
          onClick={() => setShowExamples(!showExamples)}
          className="flex items-center text-sm font-medium text-gray-700 hover:text-gray-900"
        >
          <svg
            className={`mr-2 h-4 w-4 transform transition-transform ${showExamples ? 'rotate-90' : ''}`}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
          </svg>
          Path Traversal Examples
        </button>

        {showExamples && (
          <div className="mt-4 space-y-4">
            {pathTraversalExamples.map((category, categoryIndex) => (
              <div key={categoryIndex} className="bg-gray-50 rounded-md p-4">
                <h4 className="text-sm font-medium text-gray-900 mb-3">{category.category}</h4>
                <div className="grid grid-cols-1 gap-2">
                  {category.examples.map((example, exampleIndex) => (
                    <div key={exampleIndex} className="flex items-center justify-between p-3 bg-white border border-gray-200 rounded-md">
                      <div className="flex-1">
                        <h5 className="text-sm font-medium text-gray-900">{example.name}</h5>
                        <p className="text-xs text-gray-600 mt-1">{example.description}</p>
                        <code className="text-xs text-gray-500 bg-gray-100 px-1 rounded mt-1 block">
                          {example.path}
                        </code>
                      </div>
                      <button
                        type="button"
                        onClick={() => handleExampleClick(example.path)}
                        className="ml-3 text-xs bg-orange-100 text-orange-700 px-2 py-1 rounded hover:bg-orange-200 transition-colors"
                      >
                        Use
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Error Display */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-md p-4">
          <div className="flex">
            <div className="flex-shrink-0">
              <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
              </svg>
            </div>
            <div className="ml-3">
              <h3 className="text-sm font-medium text-red-800">File Access Failed</h3>
              <p className="text-sm text-red-700 mt-1">{error}</p>
            </div>
          </div>
        </div>
      )}

      {/* Response Display */}
      {response && (
        <div className="space-y-4">
          {response.success ? (
            <div className="bg-green-50 border border-green-200 rounded-md p-4">
              <div className="flex">
                <div className="flex-shrink-0">
                  <svg className="h-5 w-5 text-green-400" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                  </svg>
                </div>
                <div className="ml-3">
                  <h3 className="text-sm font-medium text-green-800">File Retrieved Successfully</h3>
                  <p className="text-sm text-green-700 mt-1">File content loaded successfully</p>
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-yellow-50 border border-yellow-200 rounded-md p-4">
              <div className="flex">
                <div className="flex-shrink-0">
                  <svg className="h-5 w-5 text-yellow-400" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                  </svg>
                </div>
                <div className="ml-3">
                  <h3 className="text-sm font-medium text-yellow-800">File Access Attempt</h3>
                  <p className="text-sm text-yellow-700 mt-1">File access completed with warnings</p>
                </div>
              </div>
            </div>
          )}

          {response.warning && (
            <div className="bg-red-50 border border-red-200 rounded-md p-4">
              <h4 className="text-sm font-medium text-red-800">Security Warning</h4>
              <p className="text-sm text-red-700 mt-1">{response.warning}</p>
            </div>
          )}

          {/* File Information */}
          <div className="bg-gray-50 rounded-md p-4">
            <h4 className="text-sm font-medium text-gray-900 mb-3">File Information</h4>
            <div className="space-y-2 text-sm">
              {response.requestedFile && (
                <div>
                  <span className="font-medium text-gray-700">Requested File:</span>
                  <span className="ml-2 text-gray-600 font-mono">{response.requestedFile}</span>
                </div>
              )}
              
              {response.path && (
                <div>
                  <span className="font-medium text-gray-700">Resolved Path:</span>
                  <span className="ml-2 text-gray-600 font-mono">{response.path}</span>
                </div>
              )}

              {response.details && (
                <div>
                  <span className="font-medium text-gray-700">Details:</span>
                  <span className="ml-2 text-gray-600">{response.details}</span>
                </div>
              )}
            </div>

            {/* File Content Display */}
            {response.content && (
              <div className="mt-4">
                <h5 className="text-sm font-medium text-gray-900 mb-2">File Content:</h5>
                <div className="bg-white border border-gray-200 rounded p-3 max-h-96 overflow-y-auto">
                  <pre className="text-xs text-gray-700 whitespace-pre-wrap font-mono">{response.content}</pre>
                </div>
                <div className="mt-2 text-xs text-gray-500">
                  Content length: {response.content.length} characters
                </div>
              </div>
            )}
          </div>

          {/* Security Analysis */}
          <div className="bg-red-50 border border-red-200 rounded-md p-4">
            <h4 className="text-sm font-medium text-red-800 mb-2">Security Analysis</h4>
            <div className="text-sm text-red-700 space-y-1">
              <p>• This endpoint demonstrates a path traversal vulnerability (CWE-22)</p>
              <p>• Attackers can access files outside the intended directory</p>
              <p>• No input validation or path sanitization is performed</p>
              <p>• Error messages expose file system information</p>
              <p>• Sensitive system files may be accessible</p>
            </div>
          </div>
        </div>
      )}

      {/* Educational Information */}
      <div className="bg-blue-50 border border-blue-200 rounded-md p-4">
        <h4 className="text-sm font-medium text-blue-800 mb-2">Educational Information</h4>
        <div className="text-sm text-blue-700 space-y-2">
          <p><strong>Path Traversal Attack:</strong> Also known as directory traversal, this vulnerability allows attackers to access files and directories outside the web root folder.</p>
          <p><strong>Common Techniques:</strong></p>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Using "../" sequences to navigate up directories</li>
            <li>URL encoding (%2e%2e%2f) to bypass basic filters</li>
            <li>Double encoding (%252e%252e%252f) for additional evasion</li>
            <li>Null byte injection (%00) to truncate file extensions</li>
          </ul>
          <p><strong>Prevention:</strong> Validate and sanitize all user input, use whitelisting for allowed files, and implement proper access controls.</p>
        </div>
      </div>
    </div>
  );
};

export default FileBrowser;