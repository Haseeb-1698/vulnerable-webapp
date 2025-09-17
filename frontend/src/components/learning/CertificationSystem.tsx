import React, { useState, useEffect } from 'react';
import { TrophyIcon, AcademicCapIcon, ShieldCheckIcon, StarIcon, ClockIcon } from '@heroicons/react/24/outline';

interface Certification {
  id: string;
  title: string;
  description: string;
  category: 'vulnerability' | 'tool-mastery' | 'comprehensive' | 'advanced';
  difficulty: 'intermediate' | 'advanced' | 'expert';
  requirements: {
    type: 'modules_completed' | 'quizzes_passed' | 'score_average' | 'time_spent' | 'streak_days' | 'vulnerabilities_found';
    target: number;
    description: string;
  }[];
  badge: string;
  color: string;
  estimatedTime: number; // hours
  skills: string[];
  earnedAt?: Date;
  certificateUrl?: string;
}

interface CertificationSystemProps {
  userProgress: {
    totalModulesCompleted: number;
    totalQuizzesPassed: number;
    certificationsEarned: string[];
    currentStreak: number;
    totalTimeSpent: number;
    skillLevel: 'novice' | 'intermediate' | 'advanced' | 'expert';
  };
  onCertificationEarned: (certId: string) => void;
}

export const CertificationSystem: React.FC<CertificationSystemProps> = ({ 
  userProgress, 
  onCertificationEarned 
}) => {
  const [certifications, setCertifications] = useState<Certification[]>([]);
  const [selectedCert, setSelectedCert] = useState<Certification | null>(null);
  const [showCertificate, setShowCertificate] = useState(false);

  // Initialize certifications
  useEffect(() => {
    const defaultCertifications: Certification[] = [
      {
        id: 'sql-injection-specialist',
        title: 'SQL Injection Specialist',
        description: 'Demonstrates mastery of SQL injection techniques, detection, and prevention methods',
        category: 'vulnerability',
        difficulty: 'intermediate',
        badge: '🛡️',
        color: 'from-red-500 to-red-600',
        estimatedTime: 8,
        skills: [
          'Union-based SQL injection',
          'Blind SQL injection techniques',
          'SQLMap automation',
          'Parameterized query implementation',
          'Database security hardening'
        ],
        requirements: [
          {
            type: 'modules_completed',
            target: 2,
            description: 'Complete SQL Injection Fundamentals and Advanced modules'
          },
          {
            type: 'quizzes_passed',
            target: 1,
            description: 'Pass SQL Injection quiz with 85% or higher'
          },
          {
            type: 'vulnerabilities_found',
            target: 3,
            description: 'Successfully exploit 3 SQL injection vulnerabilities'
          }
        ]
      },
      {
        id: 'xss-expert',
        title: 'Cross-Site Scripting Expert',
        description: 'Certified expertise in identifying, exploiting, and preventing XSS vulnerabilities',
        category: 'vulnerability',
        difficulty: 'intermediate',
        badge: '⚡',
        color: 'from-orange-500 to-orange-600',
        estimatedTime: 6,
        skills: [
          'Reflected XSS exploitation',
          'Stored XSS payload crafting',
          'DOM-based XSS analysis',
          'XSS filter bypass techniques',
          'Content Security Policy implementation'
        ],
        requirements: [
          {
            type: 'modules_completed',
            target: 2,
            description: 'Complete XSS Fundamentals and Exploitation modules'
          },
          {
            type: 'quizzes_passed',
            target: 1,
            description: 'Pass XSS quiz with 80% or higher'
          },
          {
            type: 'vulnerabilities_found',
            target: 2,
            description: 'Successfully exploit 2 XSS vulnerabilities'
          }
        ]
      },
      {
        id: 'access-control-master',
        title: 'Access Control Master',
        description: 'Advanced understanding of authorization flaws and secure access control implementation',
        category: 'vulnerability',
        difficulty: 'advanced',
        badge: '🔐',
        color: 'from-blue-500 to-blue-600',
        estimatedTime: 10,
        skills: [
          'IDOR vulnerability discovery',
          'Privilege escalation techniques',
          'JWT security analysis',
          'Session management security',
          'Role-based access control design'
        ],
        requirements: [
          {
            type: 'modules_completed',
            target: 3,
            description: 'Complete IDOR, Session Management, and related modules'
          },
          {
            type: 'quizzes_passed',
            target: 2,
            description: 'Pass IDOR and Session Management quizzes'
          },
          {
            type: 'score_average',
            target: 85,
            description: 'Maintain 85% average across all quizzes'
          }
        ]
      },
      {
        id: 'penetration-tester',
        title: 'Web Application Penetration Tester',
        description: 'Comprehensive certification covering multiple vulnerability types and testing methodologies',
        category: 'comprehensive',
        difficulty: 'advanced',
        badge: '🎯',
        color: 'from-purple-500 to-purple-600',
        estimatedTime: 20,
        skills: [
          'Comprehensive vulnerability assessment',
          'Automated security testing',
          'Manual penetration testing',
          'Security report writing',
          'Risk assessment and prioritization'
        ],
        requirements: [
          {
            type: 'modules_completed',
            target: 7,
            description: 'Complete at least 7 learning modules'
          },
          {
            type: 'quizzes_passed',
            target: 5,
            description: 'Pass 5 different security quizzes'
          },
          {
            type: 'score_average',
            target: 80,
            description: 'Maintain 80% average across all assessments'
          },
          {
            type: 'vulnerabilities_found',
            target: 10,
            description: 'Successfully identify and exploit 10 vulnerabilities'
          }
        ]
      },
      {
        id: 'security-architect',
        title: 'Security Architect',
        description: 'Expert-level certification demonstrating ability to design and implement secure systems',
        category: 'advanced',
        difficulty: 'expert',
        badge: '🏛️',
        color: 'from-green-500 to-green-600',
        estimatedTime: 30,
        skills: [
          'Secure architecture design',
          'Threat modeling',
          'Security control implementation',
          'Compliance and governance',
          'Security training and awareness'
        ],
        requirements: [
          {
            type: 'modules_completed',
            target: 10,
            description: 'Complete all available learning modules'
          },
          {
            type: 'quizzes_passed',
            target: 8,
            description: 'Pass all available quizzes'
          },
          {
            type: 'score_average',
            target: 90,
            description: 'Maintain 90% average across all assessments'
          },
          {
            type: 'time_spent',
            target: 1200, // 20 hours
            description: 'Spend at least 20 hours in learning activities'
          },
          {
            type: 'streak_days',
            target: 14,
            description: 'Maintain a 14-day learning streak'
          }
        ]
      },
      {
        id: 'burp-suite-certified',
        title: 'Burp Suite Certified User',
        description: 'Proficiency in using Burp Suite for web application security testing',
        category: 'tool-mastery',
        difficulty: 'intermediate',
        badge: '🔧',
        color: 'from-indigo-500 to-indigo-600',
        estimatedTime: 12,
        skills: [
          'Burp Suite configuration',
          'Proxy and interceptor usage',
          'Scanner automation',
          'Extension development',
          'Professional testing workflows'
        ],
        requirements: [
          {
            type: 'modules_completed',
            target: 1,
            description: 'Complete Burp Suite Fundamentals module'
          },
          {
            type: 'vulnerabilities_found',
            target: 5,
            description: 'Find 5 vulnerabilities using Burp Suite'
          },
          {
            type: 'time_spent',
            target: 480, // 8 hours
            description: 'Spend at least 8 hours using security tools'
          }
        ]
      }
    ];

    setCertifications(defaultCertifications);
  }, []);

  // Check if certification requirements are met
  const checkCertificationEligibility = (cert: Certification) => {
    // Mock data for demonstration - in real app, this would come from actual user progress
    const mockProgress = {
      modules_completed: userProgress.totalModulesCompleted,
      quizzes_passed: userProgress.totalQuizzesPassed,
      score_average: 85, // This would be calculated from actual quiz scores
      time_spent: userProgress.totalTimeSpent,
      streak_days: userProgress.currentStreak,
      vulnerabilities_found: Math.floor(userProgress.totalModulesCompleted * 1.5) // Mock calculation
    };

    return cert.requirements.every(req => {
      const currentValue = mockProgress[req.type as keyof typeof mockProgress] || 0;
      return currentValue >= req.target;
    });
  };

  // Calculate progress for each requirement
  const getRequirementProgress = (cert: Certification) => {
    const mockProgress = {
      modules_completed: userProgress.totalModulesCompleted,
      quizzes_passed: userProgress.totalQuizzesPassed,
      score_average: 85,
      time_spent: userProgress.totalTimeSpent,
      streak_days: userProgress.currentStreak,
      vulnerabilities_found: Math.floor(userProgress.totalModulesCompleted * 1.5)
    };

    return cert.requirements.map(req => {
      const currentValue = mockProgress[req.type as keyof typeof mockProgress] || 0;
      return {
        ...req,
        current: currentValue,
        progress: Math.min(100, (currentValue / req.target) * 100),
        completed: currentValue >= req.target
      };
    });
  };

  // Earn certification
  const earnCertification = (cert: Certification) => {
    const updatedCert = {
      ...cert,
      earnedAt: new Date(),
      certificateUrl: `/certificates/${cert.id}-${Date.now()}.pdf`
    };

    setCertifications(prev => prev.map(c => c.id === cert.id ? updatedCert : c));
    onCertificationEarned(cert.id);
    setSelectedCert(updatedCert);
    setShowCertificate(true);
  };

  // Generate certificate (mock implementation)
  const generateCertificate = (cert: Certification) => {
    // In a real implementation, this would generate a PDF certificate
    const certificateData = {
      recipientName: 'Security Learner', // Would come from user profile
      certificationTitle: cert.title,
      earnedDate: cert.earnedAt?.toLocaleDateString(),
      skills: cert.skills,
      certificateId: `CERT-${cert.id.toUpperCase()}-${Date.now()}`
    };

    console.log('Certificate generated:', certificateData);
    // Mock download
    alert(`Certificate for ${cert.title} would be downloaded here!`);
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'vulnerability': return ShieldCheckIcon;
      case 'tool-mastery': return AcademicCapIcon;
      case 'comprehensive': return TrophyIcon;
      case 'advanced': return StarIcon;
      default: return TrophyIcon;
    }
  };

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'intermediate': return 'text-yellow-600 bg-yellow-100';
      case 'advanced': return 'text-red-600 bg-red-100';
      case 'expert': return 'text-purple-600 bg-purple-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const earnedCertifications = certifications.filter(cert => cert.earnedAt);
  const availableCertifications = certifications.filter(cert => !cert.earnedAt);

  // Certificate Modal
  if (showCertificate && selectedCert) {
    return (
      <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
        <div className="bg-white rounded-lg shadow-xl max-w-2xl w-full mx-4 p-8">
          <div className="text-center">
            <div className={`inline-flex items-center justify-center w-20 h-20 rounded-full bg-gradient-to-r ${selectedCert.color} text-white text-4xl mb-6`}>
              {selectedCert.badge}
            </div>
            
            <h2 className="text-3xl font-bold text-gray-900 mb-2">Congratulations!</h2>
            <p className="text-lg text-gray-600 mb-6">
              You've earned the <strong>{selectedCert.title}</strong> certification
            </p>
            
            <div className="bg-gray-50 rounded-lg p-6 mb-6">
              <div className="border-2 border-dashed border-gray-300 rounded-lg p-8">
                <div className="text-center">
                  <div className={`inline-block text-6xl mb-4`}>{selectedCert.badge}</div>
                  <h3 className="text-2xl font-bold text-gray-900 mb-2">{selectedCert.title}</h3>
                  <p className="text-gray-600 mb-4">This certifies that</p>
                  <p className="text-xl font-semibold text-gray-900 mb-4">Security Learner</p>
                  <p className="text-gray-600 mb-4">has successfully completed all requirements for</p>
                  <p className="text-lg font-medium text-gray-900 mb-6">{selectedCert.title}</p>
                  <p className="text-sm text-gray-500">
                    Earned on {selectedCert.earnedAt?.toLocaleDateString()}
                  </p>
                </div>
              </div>
            </div>
            
            <div className="flex justify-center space-x-4">
              <button
                onClick={() => generateCertificate(selectedCert)}
                className="bg-blue-600 text-white px-6 py-2 rounded-md hover:bg-blue-700 transition-colors"
              >
                Download Certificate
              </button>
              <button
                onClick={() => setShowCertificate(false)}
                className="bg-gray-200 text-gray-700 px-6 py-2 rounded-md hover:bg-gray-300 transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="text-center">
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Security Certifications</h2>
        <p className="text-gray-600">
          Earn industry-recognized certifications by demonstrating your security expertise
        </p>
      </div>

      {/* Earned Certifications */}
      {earnedCertifications.length > 0 && (
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
            <TrophyIcon className="h-5 w-5 mr-2 text-yellow-500" />
            Your Certifications ({earnedCertifications.length})
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {earnedCertifications.map((cert) => (
              <div
                key={cert.id}
                className="border border-green-200 rounded-lg p-4 bg-green-50 hover:shadow-md transition-shadow cursor-pointer"
                onClick={() => {
                  setSelectedCert(cert);
                  setShowCertificate(true);
                }}
              >
                <div className="text-center">
                  <div className={`inline-flex items-center justify-center w-12 h-12 rounded-full bg-gradient-to-r ${cert.color} text-white text-2xl mb-3`}>
                    {cert.badge}
                  </div>
                  <h4 className="font-medium text-gray-900 mb-1">{cert.title}</h4>
                  <p className="text-sm text-gray-600 mb-2">
                    Earned {cert.earnedAt?.toLocaleDateString()}
                  </p>
                  <div className="text-xs text-green-600 font-medium">✓ Certified</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Available Certifications */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {availableCertifications.map((cert) => {
          const isEligible = checkCertificationEligibility(cert);
          const requirements = getRequirementProgress(cert);
          const overallProgress = requirements.reduce((sum, req) => sum + req.progress, 0) / requirements.length;
          const IconComponent = getCategoryIcon(cert.category);

          return (
            <div
              key={cert.id}
              className={`border rounded-lg p-6 ${
                isEligible ? 'border-green-300 bg-green-50' : 'border-gray-200 bg-white'
              } hover:shadow-md transition-shadow`}
            >
              {/* Header */}
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center space-x-3">
                  <div className={`w-12 h-12 rounded-full bg-gradient-to-r ${cert.color} flex items-center justify-center text-white text-xl`}>
                    {cert.badge}
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold text-gray-900">{cert.title}</h3>
                    <div className="flex items-center space-x-2 mt-1">
                      <IconComponent className="h-4 w-4 text-gray-500" />
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${getDifficultyColor(cert.difficulty)}`}>
                        {cert.difficulty}
                      </span>
                    </div>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-sm text-gray-500 flex items-center">
                    <ClockIcon className="h-4 w-4 mr-1" />
                    {cert.estimatedTime}h
                  </div>
                </div>
              </div>

              {/* Description */}
              <p className="text-sm text-gray-600 mb-4">{cert.description}</p>

              {/* Skills */}
              <div className="mb-4">
                <h4 className="text-sm font-medium text-gray-900 mb-2">Skills Covered:</h4>
                <div className="flex flex-wrap gap-1">
                  {cert.skills.slice(0, 3).map((skill, index) => (
                    <span
                      key={index}
                      className="inline-flex items-center px-2 py-1 rounded-full text-xs bg-gray-100 text-gray-700"
                    >
                      {skill}
                    </span>
                  ))}
                  {cert.skills.length > 3 && (
                    <span className="inline-flex items-center px-2 py-1 rounded-full text-xs bg-gray-100 text-gray-700">
                      +{cert.skills.length - 3} more
                    </span>
                  )}
                </div>
              </div>

              {/* Requirements Progress */}
              <div className="mb-4">
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-sm font-medium text-gray-900">Progress</h4>
                  <span className="text-sm text-gray-600">{Math.round(overallProgress)}%</span>
                </div>
                <div className="bg-gray-200 rounded-full h-2 mb-3">
                  <div
                    className={`h-2 rounded-full bg-gradient-to-r ${cert.color}`}
                    style={{ width: `${overallProgress}%` }}
                  />
                </div>
                
                <div className="space-y-2">
                  {requirements.map((req, index) => (
                    <div key={index} className="flex items-center justify-between text-sm">
                      <span className={req.completed ? 'text-green-600' : 'text-gray-600'}>
                        {req.completed ? '✓' : '○'} {req.description}
                      </span>
                      <span className="text-gray-500">
                        {req.current}/{req.target}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Action Button */}
              <button
                onClick={() => isEligible && earnCertification(cert)}
                disabled={!isEligible}
                className={`w-full py-2 px-4 rounded-md text-sm font-medium transition-colors ${
                  isEligible
                    ? 'bg-green-600 text-white hover:bg-green-700'
                    : 'bg-gray-200 text-gray-500 cursor-not-allowed'
                }`}
              >
                {isEligible ? 'Earn Certification' : 'Complete Requirements'}
              </button>
            </div>
          );
        })}
      </div>

      {/* Certification Benefits */}
      <div className="bg-blue-50 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Certification Benefits</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="text-center">
            <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-3">
              <TrophyIcon className="h-6 w-6 text-blue-600" />
            </div>
            <h4 className="font-medium text-gray-900 mb-1">Industry Recognition</h4>
            <p className="text-sm text-gray-600">Demonstrate your expertise to employers and peers</p>
          </div>
          <div className="text-center">
            <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-3">
              <AcademicCapIcon className="h-6 w-6 text-blue-600" />
            </div>
            <h4 className="font-medium text-gray-900 mb-1">Skill Validation</h4>
            <p className="text-sm text-gray-600">Prove your practical security knowledge and abilities</p>
          </div>
          <div className="text-center">
            <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-3">
              <StarIcon className="h-6 w-6 text-blue-600" />
            </div>
            <h4 className="font-medium text-gray-900 mb-1">Career Advancement</h4>
            <p className="text-sm text-gray-600">Enhance your professional profile and opportunities</p>
          </div>
        </div>
      </div>
    </div>
  );
};