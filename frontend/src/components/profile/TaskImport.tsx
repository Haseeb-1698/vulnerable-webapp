import React, { useState } from 'react';
import { api } from '../../utils/api';
import { TaskImportRequest, TaskImportResponse } from '../../types';

const TaskImport: React.FC = () => {
  const [importUrl, setImportUrl] = useState('');
  const [format, setFormat] = useState<'json' | 'csv' | 'xml' | 'txt'>('json');
  const [parseContent, setParseContent] = useState(true);
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState<TaskImportResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showExamples, setShowExamples] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!importUrl.trim()) return;

    setLoading(true);
    setError(null);
    setResponse(null);

    try {
      const requestData: TaskImportRequest = {
        importUrl: importUrl.trim(),
        format,
        parseContent
      };

      const result = await api.post('/tasks/import', requestData);
      setResponse(result.data);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to import tasks');
      if (err.response?.data) {
        setResponse(err.response.data);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleExampleClick = (exampleUrl: string) => {
    setImportUrl(exampleUrl);
  };

  const ssrfExamples = [
    {
      category: 'Cloud Metadata Services',
      examples: [
        {
          name: 'AWS Instance Metadata',
          url: 'http://169.254.169.254/latest/meta-data/instance-id',
          description: 'Retrieve AWS instance ID'
        },
        {
          name: 'AWS IAM Role',
          url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
          description: 'List available IAM roles'
        },
        {
          name: 'GCP Metadata',
          url: 'http://metadata.google.internal/computeMetadata/v1/instance/',
          description: 'Access GCP instance metadata'
        },
        {
          name: 'Azure Metadata',
          url: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
          description: 'Access Azure instance metadata'
        }
      ]
    },
    {
      category: 'Internal Network Scanning',
      examples: [
        {
          name: 'Redis Service',
          url: 'http://localhost:6379/info',
          description: 'Scan internal Redis service'
        },
        {
          name: 'MySQL Service',
          url: 'http://localhost:3306/',
          description: 'Scan internal MySQL service'
        },
        {
          name: 'PostgreSQL Service',
          url: 'http://localhost:5432/',
          description: 'Scan internal PostgreSQL service'
        },
        {
          name: 'Elasticsearch',
          url: 'http://localhost:9200/_cluster/health',
          description: 'Check Elasticsearch cluster health'
        },
        {
          name: 'Internal Web Service',
          url: 'http://192.168.1.1:8080/admin',
          description: 'Access internal admin panel'
        }
      ]
    },
    {
      category: 'Local File Inclusion',
      examples: [
        {
          name: 'System Users',
          url: 'file:///etc/passwd',
          description: 'Read system user accounts'
        },
        {
          name: 'Environment Variables',
          url: 'file:///.env',
          description: 'Read application environment variables'
        },
        {
          name: 'SSH Keys',
          url: 'file:///root/.ssh/id_rsa',
          description: 'Access SSH private keys'
        },
        {
          name: 'System Information',
          url: 'file:///proc/version',
          description: 'Read system version information'
        },
        {
          name: 'Network Configuration',
          url: 'file:///etc/hosts',
          description: 'Read network host configuration'
        }
      ]
    }
  ];

  return (
    <div className="space-y-6">
      {/* Import Form */}
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="importUrl" className="block text-sm font-medium text-gray-700">
            Import URL
          </label>
          <input
            type="text"
            id="importUrl"
            value={importUrl}
            onChange={(e) => setImportUrl(e.target.value)}
            placeholder="https://api.example.com/tasks.json or file:///path/to/file"
            className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
            required
          />
          <p className="mt-1 text-sm text-gray-500">
            Enter any URL to import tasks from. This endpoint is vulnerable to SSRF attacks.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label htmlFor="format" className="block text-sm font-medium text-gray-700">
              Expected Format
            </label>
            <select
              id="format"
              value={format}
              onChange={(e) => setFormat(e.target.value as 'json' | 'csv' | 'xml' | 'txt')}
              className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="json">JSON</option>
              <option value="csv">CSV</option>
              <option value="xml">XML</option>
              <option value="txt">Text</option>
            </select>
          </div>

          <div className="flex items-center">
            <input
              type="checkbox"
              id="parseContent"
              checked={parseContent}
              onChange={(e) => setParseContent(e.target.checked)}
              className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
            />
            <label htmlFor="parseContent" className="ml-2 block text-sm text-gray-700">
              Parse and create tasks from content
            </label>
          </div>
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-red-600 text-white py-2 px-4 rounded-md hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {loading ? 'Importing...' : 'Import Tasks'}
        </button>
      </form>

      {/* SSRF Examples */}
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
          SSRF Attack Examples
        </button>

        {showExamples && (
          <div className="mt-4 space-y-4">
            {ssrfExamples.map((category, categoryIndex) => (
              <div key={categoryIndex} className="bg-gray-50 rounded-md p-4">
                <h4 className="text-sm font-medium text-gray-900 mb-3">{category.category}</h4>
                <div className="grid grid-cols-1 gap-2">
                  {category.examples.map((example, exampleIndex) => (
                    <div key={exampleIndex} className="flex items-center justify-between p-3 bg-white border border-gray-200 rounded-md">
                      <div className="flex-1">
                        <h5 className="text-sm font-medium text-gray-900">{example.name}</h5>
                        <p className="text-xs text-gray-600 mt-1">{example.description}</p>
                        <code className="text-xs text-gray-500 bg-gray-100 px-1 rounded mt-1 block break-all">
                          {example.url}
                        </code>
                      </div>
                      <button
                        type="button"
                        onClick={() => handleExampleClick(example.url)}
                        className="ml-3 text-xs bg-red-100 text-red-700 px-2 py-1 rounded hover:bg-red-200 transition-colors"
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
              <h3 className="text-sm font-medium text-red-800">Import Failed</h3>
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
                  <h3 className="text-sm font-medium text-green-800">Import Successful</h3>
                  <p className="text-sm text-green-700 mt-1">{response.message}</p>
                  {response.importedCount !== undefined && (
                    <p className="text-sm text-green-700">Imported {response.importedCount} tasks</p>
                  )}
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
                  <h3 className="text-sm font-medium text-yellow-800">Import Completed</h3>
                  <p className="text-sm text-yellow-700 mt-1">{response.message}</p>
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

          {/* Import Type Badge */}
          <div className="flex items-center space-x-2">
            <span className="text-sm font-medium text-gray-700">Import Type:</span>
            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
              response.importType === 'cloud_metadata' ? 'bg-red-100 text-red-800' :
              response.importType === 'internal_network_scan' ? 'bg-orange-100 text-orange-800' :
              response.importType === 'local_file_inclusion' ? 'bg-yellow-100 text-yellow-800' :
              'bg-blue-100 text-blue-800'
            }`}>
              {response.importType.replace(/_/g, ' ').toUpperCase()}
            </span>
          </div>

          {/* Response Details */}
          <div className="bg-gray-50 rounded-md p-4">
            <h4 className="text-sm font-medium text-gray-900 mb-3">Response Details</h4>
            <div className="space-y-2 text-sm">
              {response.metadataType && (
                <div>
                  <span className="font-medium text-gray-700">Metadata Type:</span>
                  <span className="ml-2 text-red-600">{response.metadataType}</span>
                </div>
              )}
              
              {response.serviceType && (
                <div>
                  <span className="font-medium text-gray-700">Service Type:</span>
                  <span className="ml-2 text-orange-600">{response.serviceType}</span>
                </div>
              )}

              {response.fileType && (
                <div>
                  <span className="font-medium text-gray-700">File Type:</span>
                  <span className="ml-2 text-yellow-600">{response.fileType}</span>
                </div>
              )}

              {response.parseErrors && response.parseErrors.length > 0 && (
                <div>
                  <span className="font-medium text-gray-700">Parse Errors:</span>
                  <ul className="ml-2 mt-1 space-y-1">
                    {response.parseErrors.map((error, index) => (
                      <li key={index} className="text-red-600 text-xs">• {error}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            {/* Imported Tasks */}
            {response.importedTasks && response.importedTasks.length > 0 && (
              <div className="mt-4">
                <h5 className="text-sm font-medium text-gray-900 mb-2">Imported Tasks:</h5>
                <div className="space-y-2">
                  {response.importedTasks.slice(0, 5).map((task, index) => (
                    <div key={index} className="bg-white border border-gray-200 rounded p-2">
                      <h6 className="text-sm font-medium text-gray-900">{task.title}</h6>
                      {task.description && (
                        <p className="text-xs text-gray-600 mt-1">{task.description}</p>
                      )}
                      <div className="flex items-center space-x-2 mt-1">
                        <span className="text-xs text-gray-500">Priority: {task.priority}</span>
                        <span className="text-xs text-gray-500">Status: {task.status}</span>
                      </div>
                    </div>
                  ))}
                  {response.importedTasks.length > 5 && (
                    <p className="text-xs text-gray-500">... and {response.importedTasks.length - 5} more tasks</p>
                  )}
                </div>
              </div>
            )}

            {/* Raw Content Display */}
            {response.content && (
              <div className="mt-4">
                <h5 className="text-sm font-medium text-gray-900 mb-2">Retrieved Content:</h5>
                <div className="bg-white border border-gray-200 rounded p-3 max-h-64 overflow-y-auto">
                  <pre className="text-xs text-gray-700 whitespace-pre-wrap">{response.content}</pre>
                </div>
              </div>
            )}

            {/* Raw Data Display */}
            {response.data && (
              <div className="mt-4">
                <h5 className="text-sm font-medium text-gray-900 mb-2">Raw Response Data:</h5>
                <div className="bg-white border border-gray-200 rounded p-3 max-h-64 overflow-y-auto">
                  <pre className="text-xs text-gray-700">{JSON.stringify(response.data, null, 2)}</pre>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default TaskImport;