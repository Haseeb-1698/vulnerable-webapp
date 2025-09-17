import React, { useState } from 'react';
import { Task } from '../../types';
import TaskCard from './TaskCard';

interface SearchResultsProps {
  results: Task[];
  query: string;
  loading?: boolean;
  error?: string;
  onTaskClick?: (task: Task) => void;
  onTaskEdit?: (task: Task) => void;
  onTaskDelete?: (taskId: number) => void;
  onStatusChange?: (taskId: number, status: Task['status']) => void;
  onPriorityChange?: (taskId: number, priority: Task['priority']) => void;
}

interface SearchMetadata {
  originalQuery?: string;
  sqlQuery?: string;
  executedAt?: string;
  vulnerability?: string;
}

const SearchResults: React.FC<SearchResultsProps> = ({
  results,
  query,
  loading = false,
  error,
  onTaskClick,
  onTaskEdit,
  onTaskDelete,
  onStatusChange,
  onPriorityChange
}) => {
  const [showDebugInfo, setShowDebugInfo] = useState(false);
  const [showVulnerabilityDetails, setShowVulnerabilityDetails] = useState(false);

  // Extract metadata from first result (if available)
  const metadata: SearchMetadata = results[0]?.searchMetadata || {};
  
  // Check if results contain sensitive data (password hashes, etc.)
  const hasSensitiveData = results.some(task => 
    task.user?.passwordHash || 
    (task as any).password_hash ||
    (task as any).email?.includes('@')
  );

  // Analyze results for potential SQL injection success
  const analysisResults = {
    totalResults: results.length,
    uniqueUsers: new Set(results.map(task => task.userId)).size,
    hasPasswordHashes: results.some(task => task.user?.passwordHash),
    hasEmailAddresses: results.some(task => task.user?.email),
    suspiciousData: results.filter(task => 
      !task.title || 
      !task.description || 
      task.title === 'null' ||
      (task as any).password_hash
    ),
    potentialSQLInjectionSuccess: query.includes('UNION') || query.includes('SELECT') || query.includes('--')
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
        <span className="ml-2 text-gray-600">Searching...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-md p-4">
        <div className="flex items-start">
          <div className="flex-shrink-0">
            <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
            </svg>
          </div>
          <div className="ml-3">
            <h3 className="text-sm font-medium text-red-800">Search Error</h3>
            <div className="mt-2 text-sm text-red-700">
              <p>{error}</p>
            </div>
            
            {/* VULNERABILITY: Show helpful SQL injection error information */}
            <div className="mt-3 p-3 bg-red-100 rounded border border-red-300">
              <div className="text-xs font-medium text-red-800 mb-2">🚨 SQL Injection Debug Info:</div>
              <div className="text-xs text-red-700 space-y-1">
                <div>• This error might indicate a successful SQL injection attempt</div>
                <div>• Check browser console for detailed database error information</div>
                <div>• Try simpler payloads if complex ones fail</div>
                <div>• Look for database schema information in error details</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Search Results Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">
            Search Results
          </h2>
          <p className="text-sm text-gray-600 mt-1">
            Found {results.length} result{results.length !== 1 ? 's' : ''} for "{query}"
          </p>
        </div>
        
        <div className="flex space-x-2">
          <button
            type="button"
            onClick={() => setShowDebugInfo(!showDebugInfo)}
            className="px-3 py-1 text-xs bg-yellow-100 text-yellow-800 rounded hover:bg-yellow-200"
          >
            {showDebugInfo ? 'Hide' : 'Show'} Debug Info
          </button>
          
          {analysisResults.potentialSQLInjectionSuccess && (
            <button
              type="button"
              onClick={() => setShowVulnerabilityDetails(!showVulnerabilityDetails)}
              className="px-3 py-1 text-xs bg-red-100 text-red-800 rounded hover:bg-red-200"
            >
              {showVulnerabilityDetails ? 'Hide' : 'Show'} Vulnerability Analysis
            </button>
          )}
        </div>
      </div>

      {/* VULNERABILITY: Debug Information Panel */}
      {showDebugInfo && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
          <h3 className="text-sm font-medium text-yellow-800 mb-3">🔍 Search Debug Information</h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div>
              <div className="font-medium text-yellow-800 mb-2">Query Information:</div>
              <div className="space-y-1 text-yellow-700">
                <div><strong>Original Query:</strong> {metadata.originalQuery || query}</div>
                <div><strong>Executed At:</strong> {metadata.executedAt || 'Unknown'}</div>
                <div><strong>Results Count:</strong> {results.length}</div>
                <div><strong>Unique Users:</strong> {analysisResults.uniqueUsers}</div>
              </div>
            </div>
            
            <div>
              <div className="font-medium text-yellow-800 mb-2">Data Analysis:</div>
              <div className="space-y-1 text-yellow-700">
                <div><strong>Has Password Hashes:</strong> {analysisResults.hasPasswordHashes ? '⚠️ Yes' : 'No'}</div>
                <div><strong>Has Email Addresses:</strong> {analysisResults.hasEmailAddresses ? '⚠️ Yes' : 'No'}</div>
                <div><strong>Suspicious Records:</strong> {analysisResults.suspiciousData.length}</div>
                <div><strong>Potential SQL Injection:</strong> {analysisResults.potentialSQLInjectionSuccess ? '🚨 Detected' : 'None'}</div>
              </div>
            </div>
          </div>
          
          {metadata.sqlQuery && (
            <div className="mt-4">
              <div className="font-medium text-yellow-800 mb-2">🗄️ Executed SQL Query:</div>
              <div className="bg-yellow-100 p-3 rounded border font-mono text-xs text-yellow-900 overflow-x-auto">
                {metadata.sqlQuery}
              </div>
            </div>
          )}
        </div>
      )}

      {/* VULNERABILITY: SQL Injection Success Analysis */}
      {showVulnerabilityDetails && analysisResults.potentialSQLInjectionSuccess && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <h3 className="text-sm font-medium text-red-800 mb-3">🚨 SQL Injection Vulnerability Analysis</h3>
          
          <div className="space-y-3 text-xs text-red-700">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <div className="font-medium mb-2">Exploitation Indicators:</div>
                <ul className="space-y-1 list-disc list-inside">
                  <li>Query contains SQL keywords: {query.match(/(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|--)/gi)?.join(', ') || 'None'}</li>
                  <li>Results contain password hashes: {analysisResults.hasPasswordHashes ? '✅ Success' : '❌ Failed'}</li>
                  <li>Results contain email addresses: {analysisResults.hasEmailAddresses ? '✅ Success' : '❌ Failed'}</li>
                  <li>Suspicious data records: {analysisResults.suspiciousData.length > 0 ? `✅ ${analysisResults.suspiciousData.length} found` : '❌ None'}</li>
                </ul>
              </div>
              
              <div>
                <div className="font-medium mb-2">Next Steps for Testing:</div>
                <ul className="space-y-1 list-disc list-inside">
                  <li>Try extracting user table: <code>' UNION SELECT id, email, password_hash FROM users--</code></li>
                  <li>Enumerate database schema: <code>' UNION SELECT table_name FROM information_schema.tables--</code></li>
                  <li>Test time-based injection: <code>'; SELECT pg_sleep(5)--</code></li>
                  <li>Check for admin users: <code>' OR email LIKE '%admin%'--</code></li>
                </ul>
              </div>
            </div>
            
            {analysisResults.suspiciousData.length > 0 && (
              <div>
                <div className="font-medium mb-2">🔍 Suspicious Data Found:</div>
                <div className="bg-red-100 p-3 rounded border max-h-32 overflow-y-auto">
                  {analysisResults.suspiciousData.map((task, index) => (
                    <div key={index} className="font-mono text-xs mb-1">
                      ID: {task.id}, Title: "{task.title}", User: {task.user?.email || 'Unknown'}
                      {(task as any).password_hash && <span className="text-red-600"> [PASSWORD HASH EXPOSED]</span>}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Sensitive Data Warning */}
      {hasSensitiveData && (
        <div className="bg-orange-50 border border-orange-200 rounded-md p-4">
          <div className="flex">
            <div className="flex-shrink-0">
              <svg className="h-5 w-5 text-orange-400" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
              </svg>
            </div>
            <div className="ml-3">
              <h3 className="text-sm font-medium text-orange-800">
                ⚠️ Sensitive Data Detected
              </h3>
              <div className="mt-2 text-sm text-orange-700">
                <p>The search results contain sensitive information that should not be exposed. This indicates a successful SQL injection attack.</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Results Grid */}
      {results.length === 0 ? (
        <div className="text-center py-12">
          <div className="text-gray-500 text-lg mb-4">No results found</div>
          <div className="text-sm text-gray-400">
            Try a different search query or check the SQL injection examples above
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {results.map((task) => (
            <div key={task.id} className="relative">
              <TaskCard
                task={task}
                onEdit={onTaskEdit || (() => {})}
                onDelete={onTaskDelete || (() => {})}
                onStatusChange={onStatusChange || (() => {})}
                onPriorityChange={onPriorityChange || (() => {})}
                onClick={onTaskClick}
              />
              
              {/* VULNERABILITY: Show if this task belongs to another user */}
              {task.user?.email && (
                <div className="absolute top-2 right-2">
                  <div className="bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded">
                    {task.user.email}
                  </div>
                </div>
              )}
              
              {/* VULNERABILITY: Show password hash if exposed */}
              {(task.user?.passwordHash || (task as any).password_hash) && (
                <div className="absolute bottom-2 left-2 right-2">
                  <div className="bg-red-100 text-red-800 text-xs p-2 rounded border border-red-300">
                    <div className="font-medium">🚨 Password Hash Exposed:</div>
                    <div className="font-mono text-xs mt-1 truncate">
                      {task.user?.passwordHash || (task as any).password_hash}
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* VULNERABILITY: Show raw result data for educational purposes */}
      {results.length > 0 && showDebugInfo && (
        <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
          <h3 className="text-sm font-medium text-gray-800 mb-3">📊 Raw Search Results Data</h3>
          <div className="bg-white p-3 rounded border font-mono text-xs overflow-x-auto max-h-64 overflow-y-auto">
            <pre>{JSON.stringify(results, null, 2)}</pre>
          </div>
        </div>
      )}
    </div>
  );
};

export default SearchResults;