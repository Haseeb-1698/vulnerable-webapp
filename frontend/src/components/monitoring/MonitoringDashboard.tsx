import React, { useState, useEffect } from 'react';
import { 
  ChartBarIcon, 
  ShieldExclamationIcon, 
  ClockIcon, 
  UserGroupIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon
} from '@heroicons/react/24/outline';
import { api } from '../../utils/api';
import LoadingSpinner from './LoadingSpinner';

interface DashboardData {
  timestamp: string;
  performance: {
    current: {
      timestamp: number;
      system: {
        memory: number;
        cpu: number;
        uptime: number;
      } | null;
      activity: {
        requestsPerMinute: number;
        activeRequests: number;
        concurrentUsers: number;
      };
    };
    summary: {
      totalRequests: number;
      errorRate: number;
      avgResponseTime: number;
      concurrentUsers: number;
    };
  };
  security: {
    totalAttacks: number;
    recentAttacks: number;
    attacksByType: Record<string, number>;
    topAttackers: [string, number][];
  };
  audit: {
    totalEvents: number;
    vulnerabilityToggles: number;
    successRate: number;
    eventsBySeverity: Record<string, number>;
  };
  logs: {
    security: { exists: boolean; lines?: number; size?: number };
    application: { exists: boolean; lines?: number; size?: number };
    attacks: { exists: boolean; lines?: number; size?: number };
  };
}

const MonitoringDashboard: React.FC = () => {
  const [dashboardData, setDashboardData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchDashboardData = async () => {
    try {
      const response = await api.get('/monitoring/dashboard');
      setDashboardData(response.data.data);
      setError(null);
    } catch (err: any) {
      console.error('Dashboard fetch error:', err);
      setError(err.response?.data?.error || 'Failed to fetch dashboard data');
      
      // Provide fallback data for development
      setDashboardData({
        timestamp: new Date().toISOString(),
        performance: {
          current: {
            timestamp: Date.now(),
            system: {
              memory: 45.2,
              cpu: 23.1,
              uptime: 3600
            },
            activity: {
              requestsPerMinute: 12,
              activeRequests: 3,
              concurrentUsers: 5
            }
          },
          summary: {
            totalRequests: 1250,
            errorRate: 2.1,
            avgResponseTime: 145,
            concurrentUsers: 5
          }
        },
        security: {
          totalAttacks: 23,
          recentAttacks: 3,
          attacksByType: {
            'sql_injection': 8,
            'xss': 7,
            'idor': 5,
            'ssrf': 3
          },
          topAttackers: [
            ['192.168.1.100', 5],
            ['10.0.0.50', 4],
            ['172.16.0.25', 3]
          ]
        },
        audit: {
          totalEvents: 156,
          vulnerabilityToggles: 12,
          successRate: 94.2,
          eventsBySeverity: {
            'low': 89,
            'medium': 45,
            'high': 18,
            'critical': 4
          }
        },
        logs: {
          security: { exists: true, lines: 234, size: 45678 },
          application: { exists: true, lines: 1567, size: 234567 },
          attacks: { exists: true, lines: 89, size: 12345 }
        }
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    console.log('MonitoringDashboard: Component mounted, fetching data...');
    fetchDashboardData();
  }, []);

  useEffect(() => {
    if (autoRefresh) {
      const interval = setInterval(fetchDashboardData, 30000); // Refresh every 30 seconds
      return () => clearInterval(interval);
    }
  }, [autoRefresh]);

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatUptime = (seconds: number): string => {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    
    if (days > 0) return `${days}d ${hours}h ${minutes}m`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
  };

  const getStatusColor = (value: number, thresholds: { warning: number; critical: number }): string => {
    if (value >= thresholds.critical) return 'text-red-600';
    if (value >= thresholds.warning) return 'text-yellow-600';
    return 'text-green-600';
  };

  const getStatusIcon = (value: number, thresholds: { warning: number; critical: number }) => {
    if (value >= thresholds.critical) return <XCircleIcon className="h-5 w-5 text-red-600" />;
    if (value >= thresholds.warning) return <ExclamationTriangleIcon className="h-5 w-5 text-yellow-600" />;
    return <CheckCircleIcon className="h-5 w-5 text-green-600" />;
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <LoadingSpinner message="Loading monitoring dashboard..." size="large" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-md p-4">
        <div className="flex">
          <XCircleIcon className="h-5 w-5 text-red-400" />
          <div className="ml-3">
            <h3 className="text-sm font-medium text-red-800">Error Loading Dashboard</h3>
            <p className="mt-1 text-sm text-red-700">{error}</p>
            <button
              onClick={fetchDashboardData}
              className="mt-2 text-sm text-red-800 underline hover:text-red-900"
            >
              Try Again
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (!dashboardData) return null;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Monitoring Dashboard</h1>
          <p className="text-sm text-gray-600">
            Last updated: {new Date(dashboardData.timestamp).toLocaleString()}
          </p>
        </div>
        <div className="flex items-center space-x-4">
          <label className="flex items-center">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
            />
            <span className="ml-2 text-sm text-gray-700">Auto-refresh</span>
          </label>
          <button
            onClick={fetchDashboardData}
            className="px-3 py-1 text-sm bg-blue-600 text-white rounded hover:bg-blue-700"
          >
            Refresh
          </button>
        </div>
      </div>

      {/* System Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* System Health */}
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <ChartBarIcon className="h-8 w-8 text-blue-600" />
            </div>
            <div className="ml-5 w-0 flex-1">
              <dl>
                <dt className="text-sm font-medium text-gray-500 truncate">System Health</dt>
                <dd className="flex items-baseline">
                  <div className="text-2xl font-semibold text-gray-900">
                    {dashboardData.performance.current.system ? 'Online' : 'Unknown'}
                  </div>
                  {dashboardData.performance.current.system && (
                    <div className="ml-2 flex items-baseline text-sm">
                      {getStatusIcon(
                        Math.max(
                          dashboardData.performance.current.system.cpu,
                          dashboardData.performance.current.system.memory
                        ),
                        { warning: 70, critical: 90 }
                      )}
                    </div>
                  )}
                </dd>
              </dl>
            </div>
          </div>
          {dashboardData.performance.current.system && (
            <div className="mt-4 space-y-2">
              <div className="flex justify-between text-sm">
                <span>CPU Usage:</span>
                <span className={getStatusColor(dashboardData.performance.current.system.cpu, { warning: 70, critical: 90 })}>
                  {dashboardData.performance.current.system.cpu.toFixed(1)}%
                </span>
              </div>
              <div className="flex justify-between text-sm">
                <span>Memory Usage:</span>
                <span className={getStatusColor(dashboardData.performance.current.system.memory, { warning: 70, critical: 90 })}>
                  {dashboardData.performance.current.system.memory.toFixed(1)}%
                </span>
              </div>
              <div className="flex justify-between text-sm">
                <span>Uptime:</span>
                <span>{formatUptime(dashboardData.performance.current.system.uptime)}</span>
              </div>
            </div>
          )}
        </div>

        {/* Active Users */}
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <UserGroupIcon className="h-8 w-8 text-green-600" />
            </div>
            <div className="ml-5 w-0 flex-1">
              <dl>
                <dt className="text-sm font-medium text-gray-500 truncate">Active Users</dt>
                <dd className="flex items-baseline">
                  <div className="text-2xl font-semibold text-gray-900">
                    {dashboardData.performance.current.activity.concurrentUsers}
                  </div>
                  <div className="ml-2 flex items-baseline text-sm text-gray-600">
                    concurrent
                  </div>
                </dd>
              </dl>
            </div>
          </div>
          <div className="mt-4 space-y-2">
            <div className="flex justify-between text-sm">
              <span>Requests/min:</span>
              <span>{dashboardData.performance.current.activity.requestsPerMinute}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span>Active Requests:</span>
              <span>{dashboardData.performance.current.activity.activeRequests}</span>
            </div>
          </div>
        </div>

        {/* Performance */}
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <ClockIcon className="h-8 w-8 text-yellow-600" />
            </div>
            <div className="ml-5 w-0 flex-1">
              <dl>
                <dt className="text-sm font-medium text-gray-500 truncate">Performance</dt>
                <dd className="flex items-baseline">
                  <div className="text-2xl font-semibold text-gray-900">
                    {dashboardData.performance.summary.avgResponseTime}ms
                  </div>
                  <div className="ml-2 flex items-baseline text-sm text-gray-600">
                    avg
                  </div>
                </dd>
              </dl>
            </div>
          </div>
          <div className="mt-4 space-y-2">
            <div className="flex justify-between text-sm">
              <span>Total Requests:</span>
              <span>{dashboardData.performance.summary.totalRequests.toLocaleString()}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span>Error Rate:</span>
              <span className={getStatusColor(dashboardData.performance.summary.errorRate, { warning: 5, critical: 10 })}>
                {dashboardData.performance.summary.errorRate.toFixed(2)}%
              </span>
            </div>
          </div>
        </div>

        {/* Security Alerts */}
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <ShieldExclamationIcon className="h-8 w-8 text-red-600" />
            </div>
            <div className="ml-5 w-0 flex-1">
              <dl>
                <dt className="text-sm font-medium text-gray-500 truncate">Security Alerts</dt>
                <dd className="flex items-baseline">
                  <div className="text-2xl font-semibold text-gray-900">
                    {dashboardData.security.totalAttacks}
                  </div>
                  <div className="ml-2 flex items-baseline text-sm text-gray-600">
                    total
                  </div>
                </dd>
              </dl>
            </div>
          </div>
          <div className="mt-4 space-y-2">
            <div className="flex justify-between text-sm">
              <span>Recent Attacks:</span>
              <span className="text-red-600">{dashboardData.security.recentAttacks}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span>Vuln Toggles:</span>
              <span>{dashboardData.audit.vulnerabilityToggles}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Attack Types Chart */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Attack Types</h3>
          <div className="space-y-3">
            {Object.entries(dashboardData.security.attacksByType || {}).map(([type, count]) => (
              <div key={type} className="flex items-center justify-between">
                <span className="text-sm font-medium text-gray-700 capitalize">
                  {type.replace(/_/g, ' ')}
                </span>
                <div className="flex items-center">
                  <div className="w-32 bg-gray-200 rounded-full h-2 mr-3">
                    <div
                      className="bg-red-600 h-2 rounded-full"
                      style={{
                        width: `${Math.min((count / Math.max(...Object.values(dashboardData.security.attacksByType || {}), 1)) * 100, 100)}%`
                      }}
                    ></div>
                  </div>
                  <span className="text-sm text-gray-900 w-8 text-right">{count}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Top Attackers */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Top Attack Sources</h3>
          <div className="space-y-3">
            {(dashboardData.security.topAttackers || []).slice(0, 5).map(([ip, count], index) => (
              <div key={ip} className="flex items-center justify-between">
                <div className="flex items-center">
                  <span className="text-xs font-medium text-gray-500 w-4">#{index + 1}</span>
                  <span className="text-sm font-mono text-gray-700 ml-2">{ip}</span>
                </div>
                <span className="text-sm text-red-600 font-medium">{count} attacks</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Audit Events by Severity */}
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-medium text-gray-900 mb-4">Audit Events by Severity</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {Object.entries(dashboardData.audit.eventsBySeverity || {}).map(([severity, count]) => (
            <div key={severity} className="text-center">
              <div className={`text-2xl font-bold ${
                severity === 'critical' ? 'text-red-600' :
                severity === 'high' ? 'text-orange-600' :
                severity === 'medium' ? 'text-yellow-600' :
                'text-green-600'
              }`}>
                {count}
              </div>
              <div className="text-sm text-gray-600 capitalize">{severity}</div>
            </div>
          ))}
        </div>
        <div className="mt-4 pt-4 border-t border-gray-200">
          <div className="flex justify-between text-sm">
            <span>Success Rate:</span>
            <span className={getStatusColor(100 - dashboardData.audit.successRate, { warning: 10, critical: 20 })}>
              {dashboardData.audit.successRate.toFixed(1)}%
            </span>
          </div>
        </div>
      </div>

      {/* Log Files Status */}
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-medium text-gray-900 mb-4">Log Files Status</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {Object.entries(dashboardData.logs).map(([logType, stats]) => (
            <div key={logType} className="border border-gray-200 rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-sm font-medium text-gray-900 capitalize">
                  {logType.replace(/_/g, ' ')} Log
                </h4>
                {stats.exists ? (
                  <CheckCircleIcon className="h-5 w-5 text-green-600" />
                ) : (
                  <XCircleIcon className="h-5 w-5 text-red-600" />
                )}
              </div>
              {stats.exists ? (
                <div className="space-y-1 text-sm text-gray-600">
                  <div>Lines: {stats.lines?.toLocaleString() || 'N/A'}</div>
                  <div>Size: {stats.size ? formatBytes(stats.size) : 'N/A'}</div>
                </div>
              ) : (
                <div className="text-sm text-gray-500">No log file found</div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default MonitoringDashboard;