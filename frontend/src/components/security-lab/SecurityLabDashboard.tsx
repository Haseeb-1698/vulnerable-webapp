import React, { useState, useEffect } from 'react';
import { VulnerabilityCard } from './VulnerabilityCard';
import { VulnerabilityDetailView } from './VulnerabilityDetailView';
import { AttackHistory } from './AttackHistory';
import { api } from '../../utils/api';

export interface VulnerabilityConfig {
  enabled: boolean;
  endpoint?: string;
  component?: string;
  vulnerableCode: string;
  secureCode: string;
  testPayloads: string[];
  description: string;
  cweId: string;
}

export interface VulnerabilityState {
  sqlInjection: VulnerabilityConfig;
  xss: VulnerabilityConfig;
  idor: VulnerabilityConfig;
  sessionManagement: VulnerabilityConfig;
  ssrfLfi: VulnerabilityConfig;
}

export interface TestResult {
  success: boolean;
  vulnerabilityType: string;
  payload: string;
  target?: string;
  enabled: boolean;
  result: 'VULNERABLE' | 'SECURE' | 'ERROR';
  timestamp: string;
  description: string;
  actualResponse?: any;
  attackSucceeded?: boolean;
}

export const SecurityLabDashboard: React.FC = () => {
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityState | null>(null);
  const [activeVuln, setActiveVuln] = useState<keyof VulnerabilityState>('sqlInjection');
  const [testResults, setTestResults] = useState<Record<string, TestResult[]>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadVulnerabilities();
  }, []);

  const loadVulnerabilities = async () => {
    try {
      setLoading(true);
      const response = await api.get('/security-lab/vulnerabilities');
      // Handle different response structures
      const vulnData = response.data?.vulnerabilities || response.vulnerabilities || response.data || response;
      setVulnerabilities(vulnData);
      setError(null);
    } catch (err) {
      setError('Failed to load vulnerability configurations');
      console.error('Error loading vulnerabilities:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleVulnerabilityToggle = async (vulnType: keyof VulnerabilityState) => {
    try {
      const response = await api.post(`/security-lab/vulnerabilities/${vulnType}/toggle`);
      
      if (response.data.success && vulnerabilities) {
        setVulnerabilities({
          ...vulnerabilities,
          [vulnType]: {
            ...vulnerabilities[vulnType],
            enabled: response.data.enabled
          }
        });
      }
    } catch (err) {
      console.error('Error toggling vulnerability:', err);
      setError('Failed to toggle vulnerability');
    }
  };

  const handleLiveTest = async (vulnType: keyof VulnerabilityState, payload: string, target?: string) => {
    try {
      const response = await api.post(`/security-lab/vulnerabilities/${vulnType}/test`, {
        payload,
        target
      });
      
      // Handle different response structures
      const result: TestResult = response.data || response;
      
      setTestResults(prev => ({
        ...prev,
        [vulnType]: [result, ...(prev[vulnType] || [])].slice(0, 10) // Keep last 10 results
      }));
      
      return result;
    } catch (err) {
      console.error('Error testing vulnerability:', err);
      throw new Error('Failed to test vulnerability');
    }
  };

  const vulnerabilityTypes = [
    { key: 'sqlInjection', name: 'SQL Injection', icon: '🗃️' },
    { key: 'xss', name: 'Cross-Site Scripting', icon: '🔗' },
    { key: 'idor', name: 'IDOR', icon: '🔐' },
    { key: 'sessionManagement', name: 'Session Management', icon: '🎫' },
    { key: 'ssrfLfi', name: 'SSRF/LFI', icon: '🌐' }
  ];

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading Security Lab...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="text-red-500 text-xl mb-4">⚠️ Error</div>
          <p className="text-gray-600 mb-4">{error}</p>
          <button
            onClick={loadVulnerabilities}
            className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (!vulnerabilities) {
    return null;
  }

  return (
    <div className="min-h-screen bg-slate-50 bg-grid-slate bg-ornaments">
      {/* Header */}
      <div className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="py-6">
            <h1 className="text-3xl font-bold text-gray-900">Security Lab</h1>
            <p className="mt-2 text-gray-600">
              Interactive vulnerability testing and learning environment
            </p>
            <div className="mt-4 flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                <span className="text-sm text-gray-600">Vulnerable</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                <span className="text-sm text-gray-600">Secure</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
          {/* Vulnerability Sidebar */}
          <div className="lg:col-span-1">
            <div className="bg-white rounded-lg shadow-sm border">
              <div className="p-4 border-b">
                <h2 className="text-lg font-semibold text-gray-900">Vulnerabilities</h2>
              </div>
              <div className="p-2">
                {vulnerabilityTypes.map(({ key, name, icon }) => (
                  <VulnerabilityCard
                    key={key}
                    type={key as keyof VulnerabilityState}
                    name={name}
                    icon={icon}
                    config={vulnerabilities[key as keyof VulnerabilityState]}
                    active={activeVuln === key}
                    onClick={() => setActiveVuln(key as keyof VulnerabilityState)}
                  />
                ))}
              </div>
            </div>

            {/* Attack History */}
            <div className="mt-6">
              <AttackHistory results={testResults[activeVuln] || []} />
            </div>
          </div>

          {/* Main Content */}
          <div className="lg:col-span-3">
            <VulnerabilityDetailView
              vulnerabilityType={activeVuln}
              config={vulnerabilities[activeVuln]}
              onToggle={() => handleVulnerabilityToggle(activeVuln)}
              onTest={handleLiveTest}
              testResults={testResults[activeVuln] || []}
            />
          </div>
        </div>
      </div>
    </div>
  );
};