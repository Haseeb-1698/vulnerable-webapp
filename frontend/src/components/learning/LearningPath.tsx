import React, { useState, useEffect } from 'react';
import { CheckCircleIcon, LockClosedIcon, PlayIcon, ClockIcon, StarIcon } from '@heroicons/react/24/outline';

interface LearningPathStep {
  id: string;
  title: string;
  description: string;
  type: 'tutorial' | 'quiz' | 'lab' | 'assessment';
  estimatedTime: number; // minutes
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  prerequisites: string[];
  completed: boolean;
  locked: boolean;
  moduleId?: string;
  quizId?: string;
}

interface LearningPath {
  id: string;
  title: string;
  description: string;
  category: 'beginner' | 'intermediate' | 'advanced' | 'specialized';
  totalTime: number; // hours
  steps: LearningPathStep[];
  completionRate: number;
  enrolled: boolean;
}

interface LearningPathProps {
  userProgress: {
    totalModulesCompleted: number;
    totalQuizzesPassed: number;
    certificationsEarned: string[];
    currentStreak: number;
    totalTimeSpent: number;
    skillLevel: 'novice' | 'intermediate' | 'advanced' | 'expert';
  };
  onStepStart: (step: LearningPathStep) => void;
}

export const LearningPath: React.FC<LearningPathProps> = ({ userProgress, onStepStart }) => {
  const [learningPaths, setLearningPaths] = useState<LearningPath[]>([]);
  const [selectedPath, setSelectedPath] = useState<LearningPath | null>(null);
  const [enrolledPaths, setEnrolledPaths] = useState<string[]>([]);

  // Initialize learning paths
  useEffect(() => {
    const paths: LearningPath[] = [
      {
        id: 'web-security-fundamentals',
        title: 'Web Security Fundamentals',
        description: 'Master the basics of web application security with hands-on practice',
        category: 'beginner',
        totalTime: 12,
        completionRate: 0,
        enrolled: false,
        steps: [
          {
            id: 'intro-web-security',
            title: 'Introduction to Web Security',
            description: 'Learn the fundamentals of web application security and common attack vectors',
            type: 'tutorial',
            estimatedTime: 45,
            difficulty: 'beginner',
            prerequisites: [],
            completed: false,
            locked: false,
            moduleId: 'web-security-intro'
          },
          {
            id: 'sql-injection-basics',
            title: 'SQL Injection Fundamentals',
            description: 'Understand how SQL injection works and how to prevent it',
            type: 'tutorial',
            estimatedTime: 60,
            difficulty: 'beginner',
            prerequisites: ['intro-web-security'],
            completed: false,
            locked: true,
            moduleId: 'sql-injection-basics'
          },
          {
            id: 'sql-injection-quiz',
            title: 'SQL Injection Knowledge Check',
            description: 'Test your understanding of SQL injection concepts',
            type: 'quiz',
            estimatedTime: 20,
            difficulty: 'beginner',
            prerequisites: ['sql-injection-basics'],
            completed: false,
            locked: true,
            quizId: 'sql-injection-basics'
          },
          {
            id: 'sql-injection-lab',
            title: 'SQL Injection Hands-on Lab',
            description: 'Practice exploiting SQL injection vulnerabilities in a safe environment',
            type: 'lab',
            estimatedTime: 90,
            difficulty: 'beginner',
            prerequisites: ['sql-injection-quiz'],
            completed: false,
            locked: true
          },
          {
            id: 'xss-fundamentals',
            title: 'Cross-Site Scripting (XSS)',
            description: 'Learn about XSS vulnerabilities and prevention techniques',
            type: 'tutorial',
            estimatedTime: 75,
            difficulty: 'beginner',
            prerequisites: ['sql-injection-lab'],
            completed: false,
            locked: true,
            moduleId: 'xss-fundamentals'
          },
          {
            id: 'xss-quiz',
            title: 'XSS Knowledge Assessment',
            description: 'Evaluate your XSS knowledge and skills',
            type: 'quiz',
            estimatedTime: 25,
            difficulty: 'beginner',
            prerequisites: ['xss-fundamentals'],
            completed: false,
            locked: true,
            quizId: 'xss-fundamentals'
          },
          {
            id: 'web-security-assessment',
            title: 'Web Security Fundamentals Assessment',
            description: 'Comprehensive assessment covering all fundamental concepts',
            type: 'assessment',
            estimatedTime: 45,
            difficulty: 'intermediate',
            prerequisites: ['xss-quiz'],
            completed: false,
            locked: true
          }
        ]
      },
      {
        id: 'advanced-exploitation',
        title: 'Advanced Exploitation Techniques',
        description: 'Master advanced attack techniques and complex vulnerability chains',
        category: 'advanced',
        totalTime: 20,
        completionRate: 0,
        enrolled: false,
        steps: [
          {
            id: 'idor-advanced',
            title: 'Advanced IDOR Techniques',
            description: 'Learn complex IDOR exploitation and privilege escalation',
            type: 'tutorial',
            estimatedTime: 90,
            difficulty: 'advanced',
            prerequisites: [],
            completed: false,
            locked: false,
            moduleId: 'idor-discovery'
          },
          {
            id: 'session-attacks',
            title: 'Session Management Attacks',
            description: 'Master session hijacking, fixation, and JWT attacks',
            type: 'tutorial',
            estimatedTime: 120,
            difficulty: 'advanced',
            prerequisites: ['idor-advanced'],
            completed: false,
            locked: true,
            moduleId: 'session-management'
          },
          {
            id: 'ssrf-exploitation',
            title: 'SSRF and LFI Exploitation',
            description: 'Learn Server-Side Request Forgery and Local File Inclusion attacks',
            type: 'tutorial',
            estimatedTime: 150,
            difficulty: 'advanced',
            prerequisites: ['session-attacks'],
            completed: false,
            locked: true,
            moduleId: 'ssrf-lfi-basics'
          },
          {
            id: 'chaining-attacks',
            title: 'Vulnerability Chaining',
            description: 'Learn to chain multiple vulnerabilities for maximum impact',
            type: 'lab',
            estimatedTime: 180,
            difficulty: 'advanced',
            prerequisites: ['ssrf-exploitation'],
            completed: false,
            locked: true
          },
          {
            id: 'advanced-assessment',
            title: 'Advanced Exploitation Mastery',
            description: 'Comprehensive practical assessment of advanced techniques',
            type: 'assessment',
            estimatedTime: 120,
            difficulty: 'advanced',
            prerequisites: ['chaining-attacks'],
            completed: false,
            locked: true
          }
        ]
      },
      {
        id: 'penetration-testing',
        title: 'Web Application Penetration Testing',
        description: 'Complete methodology for professional web application security testing',
        category: 'specialized',
        totalTime: 25,
        completionRate: 0,
        enrolled: false,
        steps: [
          {
            id: 'pentest-methodology',
            title: 'Penetration Testing Methodology',
            description: 'Learn systematic approaches to web application testing',
            type: 'tutorial',
            estimatedTime: 90,
            difficulty: 'intermediate',
            prerequisites: [],
            completed: false,
            locked: false
          },
          {
            id: 'reconnaissance',
            title: 'Information Gathering and Reconnaissance',
            description: 'Master passive and active information gathering techniques',
            type: 'tutorial',
            estimatedTime: 120,
            difficulty: 'intermediate',
            prerequisites: ['pentest-methodology'],
            completed: false,
            locked: true
          },
          {
            id: 'automated-scanning',
            title: 'Automated Vulnerability Scanning',
            description: 'Learn to use OWASP ZAP, Burp Suite, and other scanning tools',
            type: 'lab',
            estimatedTime: 150,
            difficulty: 'intermediate',
            prerequisites: ['reconnaissance'],
            completed: false,
            locked: true
          },
          {
            id: 'manual-testing',
            title: 'Manual Security Testing',
            description: 'Develop skills for manual vulnerability discovery and exploitation',
            type: 'lab',
            estimatedTime: 200,
            difficulty: 'advanced',
            prerequisites: ['automated-scanning'],
            completed: false,
            locked: true
          },
          {
            id: 'reporting',
            title: 'Security Assessment Reporting',
            description: 'Learn to write professional penetration testing reports',
            type: 'tutorial',
            estimatedTime: 90,
            difficulty: 'intermediate',
            prerequisites: ['manual-testing'],
            completed: false,
            locked: true
          },
          {
            id: 'pentest-capstone',
            title: 'Penetration Testing Capstone Project',
            description: 'Complete end-to-end penetration test with full documentation',
            type: 'assessment',
            estimatedTime: 300,
            difficulty: 'advanced',
            prerequisites: ['reporting'],
            completed: false,
            locked: true
          }
        ]
      },
      {
        id: 'secure-development',
        title: 'Secure Development Practices',
        description: 'Learn to build secure applications from the ground up',
        category: 'intermediate',
        totalTime: 18,
        completionRate: 0,
        enrolled: false,
        steps: [
          {
            id: 'secure-coding-principles',
            title: 'Secure Coding Principles',
            description: 'Fundamental principles for writing secure code',
            type: 'tutorial',
            estimatedTime: 90,
            difficulty: 'intermediate',
            prerequisites: [],
            completed: false,
            locked: false
          },
          {
            id: 'input-validation',
            title: 'Input Validation and Sanitization',
            description: 'Master proper input handling and validation techniques',
            type: 'tutorial',
            estimatedTime: 120,
            difficulty: 'intermediate',
            prerequisites: ['secure-coding-principles'],
            completed: false,
            locked: true
          },
          {
            id: 'authentication-authorization',
            title: 'Secure Authentication and Authorization',
            description: 'Implement robust authentication and authorization systems',
            type: 'tutorial',
            estimatedTime: 150,
            difficulty: 'intermediate',
            prerequisites: ['input-validation'],
            completed: false,
            locked: true
          },
          {
            id: 'secure-apis',
            title: 'API Security Best Practices',
            description: 'Design and implement secure REST and GraphQL APIs',
            type: 'tutorial',
            estimatedTime: 120,
            difficulty: 'intermediate',
            prerequisites: ['authentication-authorization'],
            completed: false,
            locked: true
          },
          {
            id: 'security-testing',
            title: 'Security Testing in Development',
            description: 'Integrate security testing into the development lifecycle',
            type: 'lab',
            estimatedTime: 180,
            difficulty: 'intermediate',
            prerequisites: ['secure-apis'],
            completed: false,
            locked: true
          },
          {
            id: 'secure-dev-assessment',
            title: 'Secure Development Portfolio',
            description: 'Build a secure application demonstrating all learned concepts',
            type: 'assessment',
            estimatedTime: 420,
            difficulty: 'advanced',
            prerequisites: ['security-testing'],
            completed: false,
            locked: true
          }
        ]
      }
    ];

    setLearningPaths(paths);
    
    // Load enrolled paths from localStorage
    const saved = localStorage.getItem('enrolledPaths');
    if (saved) {
      setEnrolledPaths(JSON.parse(saved));
    }
  }, []);

  // Update step completion status based on user progress
  useEffect(() => {
    setLearningPaths(prev => prev.map(path => ({
      ...path,
      steps: path.steps.map((step, index) => {
        // Check if prerequisites are met
        const prereqsMet = step.prerequisites.every(prereqId => 
          path.steps.find(s => s.id === prereqId)?.completed
        );
        
        // Mock completion status based on user progress
        const completed = userProgress.totalModulesCompleted > index;
        
        return {
          ...step,
          completed,
          locked: !prereqsMet && !completed
        };
      }),
      completionRate: Math.round((path.steps.filter(s => s.completed).length / path.steps.length) * 100)
    })));
  }, [userProgress]);

  const enrollInPath = (pathId: string) => {
    const updatedEnrolled = [...enrolledPaths, pathId];
    setEnrolledPaths(updatedEnrolled);
    localStorage.setItem('enrolledPaths', JSON.stringify(updatedEnrolled));
    
    setLearningPaths(prev => prev.map(path => 
      path.id === pathId ? { ...path, enrolled: true } : path
    ));
  };

  const unenrollFromPath = (pathId: string) => {
    const updatedEnrolled = enrolledPaths.filter(id => id !== pathId);
    setEnrolledPaths(updatedEnrolled);
    localStorage.setItem('enrolledPaths', JSON.stringify(updatedEnrolled));
    
    setLearningPaths(prev => prev.map(path => 
      path.id === pathId ? { ...path, enrolled: false } : path
    ));
  };

  const getStepIcon = (type: string) => {
    switch (type) {
      case 'tutorial': return '📚';
      case 'quiz': return '❓';
      case 'lab': return '🧪';
      case 'assessment': return '📋';
      default: return '📖';
    }
  };

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'beginner': return 'text-green-600 bg-green-100';
      case 'intermediate': return 'text-yellow-600 bg-yellow-100';
      case 'advanced': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'beginner': return 'from-green-500 to-green-600';
      case 'intermediate': return 'from-blue-500 to-blue-600';
      case 'advanced': return 'from-purple-500 to-purple-600';
      case 'specialized': return 'from-red-500 to-red-600';
      default: return 'from-gray-500 to-gray-600';
    }
  };

  const getRecommendedPath = () => {
    const { skillLevel, totalModulesCompleted } = userProgress;
    
    if (skillLevel === 'novice' || totalModulesCompleted < 3) {
      return learningPaths.find(p => p.id === 'web-security-fundamentals');
    } else if (skillLevel === 'intermediate' || totalModulesCompleted < 7) {
      return learningPaths.find(p => p.id === 'secure-development');
    } else {
      return learningPaths.find(p => p.id === 'advanced-exploitation');
    }
  };

  const recommendedPath = getRecommendedPath();

  // Path Detail View
  if (selectedPath) {
    return (
      <div className="max-w-4xl mx-auto">
        <div className="mb-6">
          <button
            onClick={() => setSelectedPath(null)}
            className="text-blue-600 hover:text-blue-800 mb-4"
          >
            ← Back to Learning Paths
          </button>
          
          <div className={`bg-gradient-to-r ${getCategoryColor(selectedPath.category)} rounded-lg p-6 text-white mb-6`}>
            <h1 className="text-2xl font-bold mb-2">{selectedPath.title}</h1>
            <p className="text-blue-100 mb-4">{selectedPath.description}</p>
            
            <div className="flex items-center space-x-6 text-sm">
              <div className="flex items-center">
                <ClockIcon className="h-4 w-4 mr-1" />
                {selectedPath.totalTime} hours
              </div>
              <div className="flex items-center">
                <StarIcon className="h-4 w-4 mr-1" />
                {selectedPath.category}
              </div>
              <div>
                {selectedPath.completionRate}% complete
              </div>
            </div>
          </div>
        </div>

        {/* Progress Bar */}
        <div className="mb-8">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-gray-700">Overall Progress</span>
            <span className="text-sm text-gray-500">{selectedPath.completionRate}%</span>
          </div>
          <div className="bg-gray-200 rounded-full h-3">
            <div
              className={`h-3 rounded-full bg-gradient-to-r ${getCategoryColor(selectedPath.category)}`}
              style={{ width: `${selectedPath.completionRate}%` }}
            />
          </div>
        </div>

        {/* Steps */}
        <div className="space-y-4">
          {selectedPath.steps.map((step, index) => (
            <div
              key={step.id}
              className={`border rounded-lg p-6 ${
                step.completed ? 'border-green-200 bg-green-50' :
                step.locked ? 'border-gray-200 bg-gray-50 opacity-60' :
                'border-blue-200 bg-blue-50 hover:shadow-md'
              } transition-shadow`}
            >
              <div className="flex items-start space-x-4">
                <div className={`w-10 h-10 rounded-full flex items-center justify-center text-sm font-medium ${
                  step.completed ? 'bg-green-100 text-green-800' :
                  step.locked ? 'bg-gray-100 text-gray-600' :
                  'bg-blue-100 text-blue-800'
                }`}>
                  {step.completed ? <CheckCircleIcon className="h-5 w-5" /> :
                   step.locked ? <LockClosedIcon className="h-5 w-5" /> :
                   index + 1}
                </div>
                
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-2">
                    <span className="text-xl">{getStepIcon(step.type)}</span>
                    <h3 className="text-lg font-semibold text-gray-900">{step.title}</h3>
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getDifficultyColor(step.difficulty)}`}>
                      {step.difficulty}
                    </span>
                  </div>
                  
                  <p className="text-gray-600 mb-3">{step.description}</p>
                  
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-4 text-sm text-gray-500">
                      <span className="flex items-center">
                        <ClockIcon className="h-4 w-4 mr-1" />
                        {step.estimatedTime} min
                      </span>
                      <span className="capitalize">{step.type}</span>
                    </div>
                    
                    {!step.locked && !step.completed && (
                      <button
                        onClick={() => onStepStart(step)}
                        className="flex items-center bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 transition-colors"
                      >
                        <PlayIcon className="h-4 w-4 mr-1" />
                        Start
                      </button>
                    )}
                    
                    {step.completed && (
                      <div className="flex items-center text-green-600 text-sm font-medium">
                        <CheckCircleIcon className="h-4 w-4 mr-1" />
                        Completed
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  // Path Selection View
  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="text-center">
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Learning Paths</h2>
        <p className="text-gray-600">
          Follow structured learning paths to master web application security
        </p>
      </div>

      {/* Recommended Path */}
      {recommendedPath && !recommendedPath.enrolled && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
          <div className="flex items-start space-x-4">
            <div className="flex-shrink-0">
              <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center">
                <StarIcon className="h-6 w-6 text-blue-600" />
              </div>
            </div>
            <div className="flex-1">
              <h3 className="text-lg font-semibold text-gray-900 mb-1">
                Recommended for You: {recommendedPath.title}
              </h3>
              <p className="text-gray-600 mb-3">{recommendedPath.description}</p>
              <button
                onClick={() => enrollInPath(recommendedPath.id)}
                className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 transition-colors"
              >
                Enroll Now
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Enrolled Paths */}
      {enrolledPaths.length > 0 && (
        <div>
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Your Enrolled Paths</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {learningPaths
              .filter(path => path.enrolled)
              .map((path) => (
                <div
                  key={path.id}
                  className="border border-green-200 rounded-lg p-6 bg-green-50 hover:shadow-md transition-shadow cursor-pointer"
                  onClick={() => setSelectedPath(path)}
                >
                  <div className="flex items-center justify-between mb-3">
                    <h4 className="text-lg font-semibold text-gray-900">{path.title}</h4>
                    <span className="text-sm text-green-600 font-medium">
                      {path.completionRate}% complete
                    </span>
                  </div>
                  
                  <p className="text-gray-600 text-sm mb-4">{path.description}</p>
                  
                  <div className="mb-4">
                    <div className="bg-gray-200 rounded-full h-2">
                      <div
                        className={`h-2 rounded-full bg-gradient-to-r ${getCategoryColor(path.category)}`}
                        style={{ width: `${path.completionRate}%` }}
                      />
                    </div>
                  </div>
                  
                  <div className="flex items-center justify-between text-sm">
                    <div className="flex items-center space-x-4 text-gray-500">
                      <span className="flex items-center">
                        <ClockIcon className="h-4 w-4 mr-1" />
                        {path.totalTime}h
                      </span>
                      <span className="capitalize">{path.category}</span>
                    </div>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        unenrollFromPath(path.id);
                      }}
                      className="text-red-600 hover:text-red-800"
                    >
                      Unenroll
                    </button>
                  </div>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* All Learning Paths */}
      <div>
        <h3 className="text-lg font-semibold text-gray-900 mb-4">All Learning Paths</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {learningPaths.map((path) => (
            <div
              key={path.id}
              className={`border rounded-lg p-6 hover:shadow-md transition-shadow cursor-pointer ${
                path.enrolled ? 'border-green-200 bg-green-50' : 'border-gray-200 bg-white'
              }`}
              onClick={() => setSelectedPath(path)}
            >
              <div className="flex items-start justify-between mb-3">
                <div>
                  <h4 className="text-lg font-semibold text-gray-900 mb-1">{path.title}</h4>
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getDifficultyColor(path.category)}`}>
                    {path.category}
                  </span>
                </div>
                {path.enrolled && (
                  <div className="text-green-600">
                    <CheckCircleIcon className="h-5 w-5" />
                  </div>
                )}
              </div>
              
              <p className="text-gray-600 text-sm mb-4">{path.description}</p>
              
              <div className="flex items-center justify-between text-sm text-gray-500 mb-4">
                <span className="flex items-center">
                  <ClockIcon className="h-4 w-4 mr-1" />
                  {path.totalTime} hours
                </span>
                <span>{path.steps.length} steps</span>
              </div>
              
              {!path.enrolled && (
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    enrollInPath(path.id);
                  }}
                  className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 transition-colors"
                >
                  Enroll in Path
                </button>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};