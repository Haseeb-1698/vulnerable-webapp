import React, { useState, useEffect } from 'react';
import { 
  MagnifyingGlassIcon, 
  FunnelIcon, 
  ArrowPathIcon,
  ExclamationTriangleIcon,
  ShieldExclamationIcon,
  InformationCircleIcon,
  XCircleIcon
} from '@heroicons/react/24/outline';
import { api } from '../../utils/api';
import LoadingSpinner from './LoadingSpinner';

interface AuditEntry {
  id: string;
  timestamp: string;
  eventType: string;
  action: string;
  description: string;
  userId?: number;
  userEmail?: string;
  ip?: string;
  userAgent?: string;
  resource?: string;
  resourceId?: string;
  oldValue?: any;
  newValue?: any;
  metadata?: any;
  severity: 'low' | 'medium' | 'high' | 'critical';
  success: boolean;
  errorMessage?: string;
}

const LogsViewer: React.FC = () => {
  const [auditEntries, setAuditEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState({
    eventType: '',
    severity: '',
    userId: '',
    resource: '',
    action: '',
    startDate: '',
    endDate: '',
    limit: 100
  });
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedEntry, setExpandedEntry] = useState<string | null>(null);

  const fetchAuditEntries = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      
      Object.entries(filters).forEach(([key, value]) => {
        if (value) {
          params.append(key, value.toString());
        }
      });

      const response = await api.get(`/monitoring/audit?${params.toString()}`);
      setAuditEntries(response.data.data);
      setError(null);
    } catch (err: any) {
      console.error('Audit fetch error:', err);
      setError(err.response?.data?.error || 'Failed to fetch audit entries');
      
      // Provide fallback data for development
      setAuditEntries([
        {
          id: 'audit_1',
          timestamp: new Date(Date.now() - 300000).toISOString(),
          eventType: 'vulnerability_toggle',
          action: 'toggle_xss',
          description: 'XSS vulnerability enabled for testing',
          userId: 1,
          userEmail: 'alice@example.com',
          ip: '192.168.1.100',
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          resource: 'vulnerability_configuration',
          resourceId: 'xss',
          oldValue: { enabled: false },
          newValue: { enabled: true },
          metadata: { reason: 'Security testing' },
          severity: 'high' as const,
          success: true
        },
        {
          id: 'audit_2',
          timestamp: new Date(Date.now() - 600000).toISOString(),
          eventType: 'authentication_event',
          action: 'login',
          description: 'User login successful',
          userId: 1,
          userEmail: 'alice@example.com',
          ip: '192.168.1.100',
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          resource: 'user_authentication',
          resourceId: '1',
          severity: 'low' as const,
          success: true
        },
        {
          id: 'audit_3',
          timestamp: new Date(Date.now() - 900000).toISOString(),
          eventType: 'data_access',
          action: 'view_monitoring_dashboard',
          description: 'User accessed monitoring dashboard',
          userId: 1,
          userEmail: 'alice@example.com',
          ip: '192.168.1.100',
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          resource: 'monitoring_dashboard',
          severity: 'low' as const,
          success: true
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    console.log('LogsViewer: Component mounted, fetching audit entries...');
    fetchAuditEntries();
  }, []);

  const handleFilterChange = (key: string, value: string) => {
    setFilters(prev => ({ ...prev, [key]: value }));
  };

  const handleSearch = () => {
    fetchAuditEntries();
  };

  const clearFilters = () => {
    setFilters({
      eventType: '',
      severity: '',
      userId: '',
      resource: '',
      action: '',
      startDate: '',
      endDate: '',
      limit: 100
    });
    setSearchTerm('');
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
        return <XCircleIcon className="h-5 w-5 text-red-600" />;
      case 'high':
        return <ExclamationTriangleIcon className="h-5 w-5 text-orange-600" />;
      case 'medium':
        return <ShieldExclamationIcon className="h-5 w-5 text-yellow-600" />;
      case 'low':
        return <InformationCircleIcon className="h-5 w-5 text-blue-600" />;
      default:
        return <InformationCircleIcon className="h-5 w-5 text-gray-600" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-red-100 text-red-800 border-red-200';
      case 'high':
        return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'low':
        return 'bg-blue-100 text-blue-800 border-blue-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const filteredEntries = (auditEntries || []).filter(entry => {
    if (!searchTerm) return true;
    
    const searchLower = searchTerm.toLowerCase();
    return (
      entry.description?.toLowerCase().includes(searchLower) ||
      entry.action?.toLowerCase().includes(searchLower) ||
      entry.eventType?.toLowerCase().includes(searchLower) ||
      entry.userEmail?.toLowerCase().includes(searchLower) ||
      entry.ip?.includes(searchTerm)
    );
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Audit Logs</h1>
          <p className="text-sm text-gray-600">
            View and search system audit trail and security events
          </p>
        </div>
        <button
          onClick={fetchAuditEntries}
          disabled={loading}
          className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50"
        >
          <ArrowPathIcon className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex items-center mb-4">
          <FunnelIcon className="h-5 w-5 text-gray-400 mr-2" />
          <h3 className="text-lg font-medium text-gray-900">Filters</h3>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Event Type
            </label>
            <select
              value={filters.eventType}
              onChange={(e) => handleFilterChange('eventType', e.target.value)}
              className="w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
            >
              <option value="">All Types</option>
              <option value="vulnerability_toggle">Vulnerability Toggle</option>
              <option value="authentication_event">Authentication</option>
              <option value="data_access">Data Access</option>
              <option value="system_event">System Event</option>
              <option value="configuration_change">Configuration</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Severity
            </label>
            <select
              value={filters.severity}
              onChange={(e) => handleFilterChange('severity', e.target.value)}
              className="w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
            >
              <option value="">All Severities</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              User ID
            </label>
            <input
              type="number"
              value={filters.userId}
              onChange={(e) => handleFilterChange('userId', e.target.value)}
              placeholder="Enter user ID"
              className="w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Resource
            </label>
            <input
              type="text"
              value={filters.resource}
              onChange={(e) => handleFilterChange('resource', e.target.value)}
              placeholder="Enter resource name"
              className="w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Start Date
            </label>
            <input
              type="datetime-local"
              value={filters.startDate}
              onChange={(e) => handleFilterChange('startDate', e.target.value)}
              className="w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              End Date
            </label>
            <input
              type="datetime-local"
              value={filters.endDate}
              onChange={(e) => handleFilterChange('endDate', e.target.value)}
              className="w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Limit
            </label>
            <select
              value={filters.limit}
              onChange={(e) => handleFilterChange('limit', e.target.value)}
              className="w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
            >
              <option value={50}>50 entries</option>
              <option value={100}>100 entries</option>
              <option value={250}>250 entries</option>
              <option value={500}>500 entries</option>
            </select>
          </div>
        </div>

        <div className="flex items-center space-x-4">
          <div className="flex-1">
            <div className="relative">
              <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search logs..."
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
          </div>
          <button
            onClick={handleSearch}
            className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
          >
            Search
          </button>
          <button
            onClick={clearFilters}
            className="px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700"
          >
            Clear
          </button>
        </div>
      </div>

      {/* Results */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-medium text-gray-900">
            Audit Entries ({filteredEntries.length})
          </h3>
        </div>

        {loading ? (
          <div className="py-12">
            <LoadingSpinner message="Loading audit entries..." />
          </div>
        ) : error ? (
          <div className="p-6">
            <div className="bg-red-50 border border-red-200 rounded-md p-4">
              <div className="flex">
                <XCircleIcon className="h-5 w-5 text-red-400" />
                <div className="ml-3">
                  <h3 className="text-sm font-medium text-red-800">Error</h3>
                  <p className="mt-1 text-sm text-red-700">{error}</p>
                </div>
              </div>
            </div>
          </div>
        ) : filteredEntries.length === 0 ? (
          <div className="p-6 text-center text-gray-500">
            No audit entries found matching your criteria.
          </div>
        ) : (
          <div className="divide-y divide-gray-200">
            {filteredEntries.map((entry) => (
              <div key={entry.id} className="p-6 hover:bg-gray-50">
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-3 flex-1">
                    {getSeverityIcon(entry.severity)}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center space-x-2 mb-1">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${getSeverityColor(entry.severity)}`}>
                          {entry.severity}
                        </span>
                        <span className="text-sm font-medium text-gray-900">
                          {entry.eventType.replace(/_/g, ' ')}
                        </span>
                        <span className="text-xs text-gray-500">
                          {new Date(entry.timestamp).toLocaleString()}
                        </span>
                      </div>
                      <p className="text-sm text-gray-700 mb-2">{entry.description}</p>
                      <div className="flex items-center space-x-4 text-xs text-gray-500">
                        {entry.userEmail && (
                          <span>User: {entry.userEmail}</span>
                        )}
                        {entry.ip && (
                          <span>IP: {entry.ip}</span>
                        )}
                        {entry.resource && (
                          <span>Resource: {entry.resource}</span>
                        )}
                        <span className={entry.success ? 'text-green-600' : 'text-red-600'}>
                          {entry.success ? 'Success' : 'Failed'}
                        </span>
                      </div>
                    </div>
                  </div>
                  <button
                    onClick={() => setExpandedEntry(expandedEntry === entry.id ? null : entry.id)}
                    className="text-sm text-blue-600 hover:text-blue-800"
                  >
                    {expandedEntry === entry.id ? 'Hide Details' : 'Show Details'}
                  </button>
                </div>

                {expandedEntry === entry.id && (
                  <div className="mt-4 pl-8 border-l-2 border-gray-200">
                    <div className="space-y-3">
                      <div>
                        <h4 className="text-sm font-medium text-gray-900">Event Details</h4>
                        <dl className="mt-2 grid grid-cols-1 md:grid-cols-2 gap-x-4 gap-y-2 text-sm">
                          <div>
                            <dt className="font-medium text-gray-500">Action:</dt>
                            <dd className="text-gray-900">{entry.action}</dd>
                          </div>
                          <div>
                            <dt className="font-medium text-gray-500">Event ID:</dt>
                            <dd className="text-gray-900 font-mono">{entry.id}</dd>
                          </div>
                          {entry.userId && (
                            <div>
                              <dt className="font-medium text-gray-500">User ID:</dt>
                              <dd className="text-gray-900">{entry.userId}</dd>
                            </div>
                          )}
                          {entry.resourceId && (
                            <div>
                              <dt className="font-medium text-gray-500">Resource ID:</dt>
                              <dd className="text-gray-900">{entry.resourceId}</dd>
                            </div>
                          )}
                          {entry.userAgent && (
                            <div className="md:col-span-2">
                              <dt className="font-medium text-gray-500">User Agent:</dt>
                              <dd className="text-gray-900 break-all">{entry.userAgent}</dd>
                            </div>
                          )}
                        </dl>
                      </div>

                      {(entry.oldValue || entry.newValue) && (
                        <div>
                          <h4 className="text-sm font-medium text-gray-900">Value Changes</h4>
                          <div className="mt-2 grid grid-cols-1 md:grid-cols-2 gap-4">
                            {entry.oldValue && (
                              <div>
                                <dt className="text-xs font-medium text-gray-500 uppercase tracking-wide">Old Value</dt>
                                <dd className="mt-1 text-sm bg-red-50 border border-red-200 rounded p-2">
                                  <pre className="whitespace-pre-wrap text-xs">
                                    {JSON.stringify(entry.oldValue, null, 2)}
                                  </pre>
                                </dd>
                              </div>
                            )}
                            {entry.newValue && (
                              <div>
                                <dt className="text-xs font-medium text-gray-500 uppercase tracking-wide">New Value</dt>
                                <dd className="mt-1 text-sm bg-green-50 border border-green-200 rounded p-2">
                                  <pre className="whitespace-pre-wrap text-xs">
                                    {JSON.stringify(entry.newValue, null, 2)}
                                  </pre>
                                </dd>
                              </div>
                            )}
                          </div>
                        </div>
                      )}

                      {entry.metadata && (
                        <div>
                          <h4 className="text-sm font-medium text-gray-900">Metadata</h4>
                          <div className="mt-2 bg-gray-50 border border-gray-200 rounded p-3">
                            <pre className="whitespace-pre-wrap text-xs text-gray-700">
                              {JSON.stringify(entry.metadata, null, 2)}
                            </pre>
                          </div>
                        </div>
                      )}

                      {entry.errorMessage && (
                        <div>
                          <h4 className="text-sm font-medium text-gray-900">Error Message</h4>
                          <div className="mt-2 bg-red-50 border border-red-200 rounded p-3">
                            <p className="text-sm text-red-700">{entry.errorMessage}</p>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default LogsViewer;