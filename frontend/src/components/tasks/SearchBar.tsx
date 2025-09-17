import React, { useState, useEffect, useCallback } from 'react';
import { Task } from '../../types';
import { taskApi } from '../../utils/api';

interface SearchBarProps {
  onResults?: (results: Task[], query?: string) => void;
  onError?: (error: string) => void;
  onLoading?: (loading: boolean) => void;
  placeholder?: string;
  className?: string;
}

interface SearchHistory {
  query: string;
  timestamp: Date;
  resultCount: number;
}

const SearchBar: React.FC<SearchBarProps> = ({
  onResults,
  onError,
  onLoading,
  placeholder = "Search tasks... (Try SQL injection: ' OR '1'='1)",
  className = ""
}) => {
  const [query, setQuery] = useState('');
  const [isSearching, setIsSearching] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [searchHistory, setSearchHistory] = useState<SearchHistory[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  
  // Advanced search filters
  const [filters, setFilters] = useState({
    category: '',
    priority: '',
    status: '',
    sortBy: 'created_at',
    order: 'desc' as 'asc' | 'desc'
  });

  // Load search history from localStorage
  useEffect(() => {
    const saved = localStorage.getItem('vulnerable_search_history');
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        setSearchHistory(parsed.map((item: any) => ({
          ...item,
          timestamp: new Date(item.timestamp)
        })));
      } catch (error) {
        console.error('Failed to load search history:', error);
      }
    }
  }, []);

  // Save search history to localStorage
  const saveSearchHistory = useCallback((searchQuery: string, resultCount: number) => {
    const newEntry: SearchHistory = {
      query: searchQuery,
      timestamp: new Date(),
      resultCount
    };
    
    const updated = [newEntry, ...searchHistory.slice(0, 9)]; // Keep last 10 searches
    setSearchHistory(updated);
    
    // VULNERABILITY: Store search history in localStorage (including potential SQL injection attempts)
    localStorage.setItem('vulnerable_search_history', JSON.stringify(updated));
    console.warn('⚠️  Search history stored in localStorage - may contain malicious queries!');
  }, [searchHistory]);

  // Debounced search function
  const performSearch = useCallback(async (searchQuery: string, searchFilters = filters) => {
    if (!searchQuery.trim()) {
      onResults?.([], searchQuery);
      return;
    }

    setIsSearching(true);
    onLoading?.(true);

    try {
      // VULNERABILITY: Use the vulnerable search endpoint
      const response: any = await taskApi.searchTasks({
        query: searchQuery,
        category: searchFilters.category || undefined,
        priority: searchFilters.priority || undefined,
        status: searchFilters.status || undefined,
        sortBy: searchFilters.sortBy || undefined,
        order: searchFilters.order
      });

      const results = response.results || response || [];
      onResults?.(results, searchQuery);
      
      // Save to search history
      saveSearchHistory(searchQuery, results.length);
      
      // VULNERABILITY: Log search results including potentially sensitive data
      console.log('🔍 Search Results:', {
        query: searchQuery,
        filters: searchFilters,
        resultCount: results.length,
        results: results,
        debug: response.debug,
        exploitationHints: response.exploitationHints,
        vulnerability: 'Search results may contain sensitive data from SQL injection'
      });

      // VULNERABILITY: Show exploitation hints in console
      if (response.exploitationHints) {
        console.group('🚨 SQL Injection Exploitation Hints:');
        Object.entries(response.exploitationHints).forEach(([key, hint]) => {
          console.log(`${key}:`, hint);
        });
        console.groupEnd();
      }

    } catch (error: any) {
      const errorMessage = error.message || 'Search failed';
      onError?.(errorMessage);
      
      // VULNERABILITY: Log detailed error information that may help with SQL injection
      console.error('🚨 Search Error (may contain useful SQL injection info):', {
        error: error,
        details: error.details,
        response: error.response,
        query: searchQuery,
        filters: searchFilters,
        vulnerability: 'Error details may reveal database structure'
      });
      
      // VULNERABILITY: Show database error details to user for educational purposes
      if (error.details?.databaseSchema) {
        console.group('🗄️  Database Schema Information (from error):');
        console.log('Tables:', error.details.databaseSchema.tables);
        console.log('User Columns:', error.details.databaseSchema.userColumns);
        console.log('Task Columns:', error.details.databaseSchema.taskColumns);
        console.log('Comment Columns:', error.details.databaseSchema.commentColumns);
        console.groupEnd();
      }
    } finally {
      setIsSearching(false);
      onLoading?.(false);
    }
  }, [filters, onResults, onError, onLoading, saveSearchHistory]);

  // Debounce search
  useEffect(() => {
    const timeoutId = setTimeout(() => {
      if (query) {
        performSearch(query);
      }
    }, 300);

    return () => clearTimeout(timeoutId);
  }, [query, performSearch]);

  const handleFilterChange = (field: string, value: string) => {
    const newFilters = { ...filters, [field]: value };
    setFilters(newFilters);
    
    if (query) {
      performSearch(query, newFilters);
    }
  };

  const handleHistorySelect = (historyQuery: string) => {
    setQuery(historyQuery);
    setShowHistory(false);
    performSearch(historyQuery);
  };

  const clearHistory = () => {
    setSearchHistory([]);
    localStorage.removeItem('vulnerable_search_history');
    setShowHistory(false);
  };

  // VULNERABILITY: Provide common SQL injection payloads as suggestions
  const sqlInjectionSuggestions = [
    "' OR '1'='1",
    "' UNION SELECT id, email, password_hash FROM users--",
    "'; DROP TABLE tasks; --",
    "' OR 1=1--",
    "admin'--",
    "' OR 'x'='x",
    "1' OR '1'='1' /*",
    "' UNION SELECT null, username, password FROM users--"
  ];

  return (
    <div className={`relative ${className}`}>
      {/* Main Search Input */}
      <div className="relative">
        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
          <svg className="h-5 w-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
        </div>
        
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={placeholder}
          className="block w-full pl-10 pr-12 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 text-sm"
        />
        
        <div className="absolute inset-y-0 right-0 flex items-center pr-3 space-x-2">
          {isSearching && (
            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600"></div>
          )}
          
          <button
            type="button"
            onClick={() => setShowHistory(!showHistory)}
            className="text-gray-400 hover:text-gray-600 focus:outline-none"
            title="Search History"
          >
            <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </button>
          
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="text-gray-400 hover:text-gray-600 focus:outline-none"
            title="Advanced Search"
          >
            <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 100 4m0-4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 100 4m0-4v2m0-6V4" />
            </svg>
          </button>
        </div>
      </div>

      {/* Search History Dropdown */}
      {showHistory && (
        <div className="absolute z-10 mt-1 w-full bg-white border border-gray-300 rounded-md shadow-lg max-h-60 overflow-auto">
          <div className="p-2 border-b border-gray-200 flex justify-between items-center">
            <span className="text-sm font-medium text-gray-700">Search History</span>
            {searchHistory.length > 0 && (
              <button
                onClick={clearHistory}
                className="text-xs text-red-600 hover:text-red-800"
              >
                Clear All
              </button>
            )}
          </div>
          
          {searchHistory.length === 0 ? (
            <div className="p-3 text-sm text-gray-500">No search history</div>
          ) : (
            <div className="max-h-48 overflow-y-auto">
              {searchHistory.map((item, index) => (
                <button
                  key={index}
                  onClick={() => handleHistorySelect(item.query)}
                  className="w-full text-left p-2 hover:bg-gray-50 focus:bg-gray-50 focus:outline-none"
                >
                  <div className="text-sm text-gray-900 truncate">{item.query}</div>
                  <div className="text-xs text-gray-500">
                    {item.resultCount} results • {item.timestamp.toLocaleDateString()}
                  </div>
                </button>
              ))}
            </div>
          )}
          
          {/* VULNERABILITY: SQL Injection Suggestions */}
          <div className="border-t border-gray-200 p-2">
            <div className="text-xs font-medium text-red-600 mb-2">⚠️ SQL Injection Test Payloads:</div>
            <div className="space-y-1">
              {sqlInjectionSuggestions.slice(0, 3).map((payload, index) => (
                <button
                  key={index}
                  onClick={() => handleHistorySelect(payload)}
                  className="block w-full text-left text-xs text-red-600 hover:text-red-800 font-mono bg-red-50 p-1 rounded"
                >
                  {payload}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Advanced Search Filters */}
      {showAdvanced && (
        <div className="absolute z-10 mt-1 w-full bg-white border border-gray-300 rounded-md shadow-lg p-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">Category</label>
              <input
                type="text"
                value={filters.category}
                onChange={(e) => handleFilterChange('category', e.target.value)}
                placeholder="e.g., work, personal"
                className="w-full px-2 py-1 text-sm border border-gray-300 rounded focus:ring-1 focus:ring-blue-500"
              />
            </div>
            
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">Priority</label>
              <select
                value={filters.priority}
                onChange={(e) => handleFilterChange('priority', e.target.value)}
                className="w-full px-2 py-1 text-sm border border-gray-300 rounded focus:ring-1 focus:ring-blue-500"
                aria-label="Filter by priority"
              >
                <option value="">All</option>
                <option value="LOW">Low</option>
                <option value="MEDIUM">Medium</option>
                <option value="HIGH">High</option>
                <option value="URGENT">Urgent</option>
              </select>
            </div>
            
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">Status</label>
              <select
                value={filters.status}
                onChange={(e) => handleFilterChange('status', e.target.value)}
                className="w-full px-2 py-1 text-sm border border-gray-300 rounded focus:ring-1 focus:ring-blue-500"
                aria-label="Filter by status"
              >
                <option value="">All</option>
                <option value="TODO">To Do</option>
                <option value="IN_PROGRESS">In Progress</option>
                <option value="COMPLETED">Completed</option>
                <option value="CANCELLED">Cancelled</option>
              </select>
            </div>
            
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">Sort By</label>
              <div className="flex space-x-1">
                <select
                  value={filters.sortBy}
                  onChange={(e) => handleFilterChange('sortBy', e.target.value)}
                  className="flex-1 px-2 py-1 text-sm border border-gray-300 rounded focus:ring-1 focus:ring-blue-500"
                  aria-label="Sort by field"
                >
                  <option value="created_at">Created</option>
                  <option value="title">Title</option>
                  <option value="priority">Priority</option>
                  <option value="due_date">Due Date</option>
                </select>
                <button
                  onClick={() => handleFilterChange('order', filters.order === 'asc' ? 'desc' : 'asc')}
                  className="px-2 py-1 text-sm border border-gray-300 rounded hover:bg-gray-50"
                >
                  {filters.order === 'asc' ? '↑' : '↓'}
                </button>
              </div>
            </div>
          </div>
          
          {/* VULNERABILITY: Raw SQL Query Builder */}
          <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded">
            <div className="text-xs font-medium text-red-800 mb-2">⚠️ Raw SQL Query Builder (Educational)</div>
            <div className="text-xs text-red-700 mb-2">
              Current query will be inserted into: WHERE (t.title LIKE '%{query}%' OR t.description LIKE '%{query}%')
            </div>
            <div className="space-y-1">
              <div className="text-xs font-mono text-red-600">
                Try: <code>' UNION SELECT id, email, password_hash FROM users--</code>
              </div>
              <div className="text-xs font-mono text-red-600">
                Or: <code>'; DROP TABLE tasks; --</code>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SearchBar;