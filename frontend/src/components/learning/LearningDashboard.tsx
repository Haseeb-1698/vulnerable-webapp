import React, { useState, useEffect } from 'react';
import { BookOpenIcon, AcademicCapIcon, TrophyIcon, ClockIcon, ChartBarIcon, MapIcon, DocumentTextIcon } from '@heroicons/react/24/outline';
import { GuidedTutorial } from './GuidedTutorial';
import { ProgressTracker } from './ProgressTracker';
import { QuizSystem } from './QuizSystem';
import { CertificationSystem } from './CertificationSystem';
import { LearningAnalytics } from './LearningAnalytics';
import { LearningPath } from './LearningPath';
import { KnowledgeBase } from './KnowledgeBase';

interface LearningModule {
  id: string;
  title: string;
  description: string;
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  estimatedTime: number;
  prerequisites: string[];
  completed: boolean;
  progress: number;
  vulnerabilityType: string;
}

interface UserProgress {
  totalModulesCompleted: number;
  totalQuizzesPassed: number;
  certificationsEarned: string[];
  currentStreak: number;
  totalTimeSpent: number;
  skillLevel: 'novice' | 'intermediate' | 'advanced' | 'expert';
}

export const LearningDashboard: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'overview' | 'paths' | 'tutorials' | 'quizzes' | 'certifications' | 'analytics' | 'knowledge'>('overview');
  const [selectedModule, setSelectedModule] = useState<LearningModule | null>(null);
  const [userProgress, setUserProgress] = useState<UserProgress>({
    totalModulesCompleted: 0,
    totalQuizzesPassed: 0,
    certificationsEarned: [],
    currentStreak: 0,
    totalTimeSpent: 0,
    skillLevel: 'novice'
  });

  const learningModules: LearningModule[] = [
    {
      id: 'sql-injection-basics',
      title: 'SQL Injection Fundamentals',
      description: 'Learn the basics of SQL injection vulnerabilities and how they work',
      difficulty: 'beginner',
      estimatedTime: 45,
      prerequisites: [],
      completed: false,
      progress: 0,
      vulnerabilityType: 'sql-injection'
    },
    {
      id: 'sql-injection-advanced',
      title: 'Advanced SQL Injection Techniques',
      description: 'Master blind SQL injection, union-based attacks, and automated exploitation',
      difficulty: 'advanced',
      estimatedTime: 90,
      prerequisites: ['sql-injection-basics'],
      completed: false,
      progress: 0,
      vulnerabilityType: 'sql-injection'
    },
    {
      id: 'xss-fundamentals',
      title: 'Cross-Site Scripting (XSS) Basics',
      description: 'Understand reflected, stored, and DOM-based XSS vulnerabilities',
      difficulty: 'beginner',
      estimatedTime: 60,
      prerequisites: [],
      completed: false,
      progress: 0,
      vulnerabilityType: 'xss'
    },
    {
      id: 'xss-exploitation',
      title: 'XSS Exploitation and Payloads',
      description: 'Learn to craft effective XSS payloads and bypass filters',
      difficulty: 'intermediate',
      estimatedTime: 75,
      prerequisites: ['xss-fundamentals'],
      completed: false,
      progress: 0,
      vulnerabilityType: 'xss'
    },
    {
      id: 'idor-discovery',
      title: 'IDOR Vulnerability Discovery',
      description: 'Learn to identify and exploit Insecure Direct Object References',
      difficulty: 'intermediate',
      estimatedTime: 50,
      prerequisites: [],
      completed: false,
      progress: 0,
      vulnerabilityType: 'idor'
    },
    {
      id: 'session-management',
      title: 'Session Management Security',
      description: 'Understand session vulnerabilities and JWT security',
      difficulty: 'intermediate',
      estimatedTime: 65,
      prerequisites: [],
      completed: false,
      progress: 0,
      vulnerabilityType: 'session-management'
    },
    {
      id: 'ssrf-lfi-basics',
      title: 'SSRF and LFI Fundamentals',
      description: 'Learn Server-Side Request Forgery and Local File Inclusion attacks',
      difficulty: 'advanced',
      estimatedTime: 80,
      prerequisites: [],
      completed: false,
      progress: 0,
      vulnerabilityType: 'ssrf-lfi'
    }
  ];

  useEffect(() => {
    // Load user progress from localStorage or API
    const savedProgress = localStorage.getItem('learningProgress');
    if (savedProgress) {
      setUserProgress(JSON.parse(savedProgress));
    }
  }, []);

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'beginner': return 'text-green-600 bg-green-100';
      case 'intermediate': return 'text-yellow-600 bg-yellow-100';
      case 'advanced': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getSkillLevelColor = (level: string) => {
    switch (level) {
      case 'novice': return 'text-gray-600';
      case 'intermediate': return 'text-blue-600';
      case 'advanced': return 'text-purple-600';
      case 'expert': return 'text-gold-600';
      default: return 'text-gray-600';
    }
  };

  const handleModuleStart = (module: LearningModule) => {
    setSelectedModule(module);
    setActiveTab('tutorials');
  };

  const handleModuleComplete = (moduleId: string) => {
    // Update progress and save to localStorage
    const updatedProgress = {
      ...userProgress,
      totalModulesCompleted: userProgress.totalModulesCompleted + 1
    };
    setUserProgress(updatedProgress);
    localStorage.setItem('learningProgress', JSON.stringify(updatedProgress));
  };

  if (selectedModule && activeTab === 'tutorials') {
    return (
      <GuidedTutorial
        module={selectedModule}
        onComplete={() => handleModuleComplete(selectedModule.id)}
        onBack={() => {
          setSelectedModule(null);
          setActiveTab('overview');
        }}
      />
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="py-6">
            <h1 className="text-3xl font-bold text-gray-900">Security Learning Center</h1>
            <p className="mt-2 text-gray-600">
              Master web application security through interactive tutorials and hands-on practice
            </p>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="border-b border-gray-200">
          <nav className="-mb-px flex space-x-8">
            {[
              { id: 'overview', name: 'Overview', icon: BookOpenIcon },
              { id: 'paths', name: 'Learning Paths', icon: MapIcon },
              { id: 'tutorials', name: 'Tutorials', icon: AcademicCapIcon },
              { id: 'quizzes', name: 'Quizzes', icon: ClockIcon },
              { id: 'certifications', name: 'Certifications', icon: TrophyIcon },
              { id: 'knowledge', name: 'Knowledge Base', icon: DocumentTextIcon },
              { id: 'analytics', name: 'Analytics', icon: ChartBarIcon }
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`${
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                } whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm flex items-center space-x-2`}
              >
                <tab.icon className="h-5 w-5" />
                <span>{tab.name}</span>
              </button>
            ))}
          </nav>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'overview' && (
          <div className="space-y-8">
            {/* Progress Overview */}
            <div className="bg-white rounded-lg shadow p-6">
              <h2 className="text-xl font-semibold text-gray-900 mb-4">Your Progress</h2>
              <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                <div className="text-center">
                  <div className="text-3xl font-bold text-blue-600">{userProgress.totalModulesCompleted}</div>
                  <div className="text-sm text-gray-600">Modules Completed</div>
                </div>
                <div className="text-center">
                  <div className="text-3xl font-bold text-green-600">{userProgress.totalQuizzesPassed}</div>
                  <div className="text-sm text-gray-600">Quizzes Passed</div>
                </div>
                <div className="text-center">
                  <div className="text-3xl font-bold text-purple-600">{userProgress.certificationsEarned.length}</div>
                  <div className="text-sm text-gray-600">Certifications</div>
                </div>
                <div className="text-center">
                  <div className={`text-3xl font-bold ${getSkillLevelColor(userProgress.skillLevel)}`}>
                    {userProgress.skillLevel.charAt(0).toUpperCase() + userProgress.skillLevel.slice(1)}
                  </div>
                  <div className="text-sm text-gray-600">Skill Level</div>
                </div>
              </div>
            </div>

            {/* Learning Path */}
            <div className="bg-white rounded-lg shadow p-6">
              <h2 className="text-xl font-semibold text-gray-900 mb-4">Recommended Learning Path</h2>
              <div className="space-y-4">
                {learningModules.map((module, index) => (
                  <div
                    key={module.id}
                    className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-3">
                          <div className="flex-shrink-0">
                            <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${
                              module.completed ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-600'
                            }`}>
                              {index + 1}
                            </div>
                          </div>
                          <div>
                            <h3 className="text-lg font-medium text-gray-900">{module.title}</h3>
                            <p className="text-sm text-gray-600">{module.description}</p>
                            <div className="flex items-center space-x-4 mt-2">
                              <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getDifficultyColor(module.difficulty)}`}>
                                {module.difficulty}
                              </span>
                              <span className="text-xs text-gray-500 flex items-center">
                                <ClockIcon className="h-4 w-4 mr-1" />
                                {module.estimatedTime} min
                              </span>
                            </div>
                          </div>
                        </div>
                      </div>
                      <div className="flex-shrink-0">
                        <button
                          onClick={() => handleModuleStart(module)}
                          className="bg-blue-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-blue-700 transition-colors"
                        >
                          {module.completed ? 'Review' : 'Start'}
                        </button>
                      </div>
                    </div>
                    {module.progress > 0 && !module.completed && (
                      <div className="mt-3">
                        <div className="bg-gray-200 rounded-full h-2">
                          <div
                            className="bg-blue-600 h-2 rounded-full"
                            style={{ width: `${module.progress}%` }}
                          />
                        </div>
                        <div className="text-xs text-gray-600 mt-1">{module.progress}% complete</div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'tutorials' && !selectedModule && (
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-xl font-semibold text-gray-900 mb-4">Interactive Tutorials</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {learningModules.map((module) => (
                <div
                  key={module.id}
                  className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow cursor-pointer"
                  onClick={() => handleModuleStart(module)}
                >
                  <h3 className="text-lg font-medium text-gray-900 mb-2">{module.title}</h3>
                  <p className="text-sm text-gray-600 mb-3">{module.description}</p>
                  <div className="flex items-center justify-between">
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getDifficultyColor(module.difficulty)}`}>
                      {module.difficulty}
                    </span>
                    <span className="text-xs text-gray-500">{module.estimatedTime} min</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'quizzes' && (
          <QuizSystem
            userProgress={userProgress}
            onQuizComplete={(quizId, score) => {
              const updatedProgress = {
                ...userProgress,
                totalQuizzesPassed: userProgress.totalQuizzesPassed + (score >= 80 ? 1 : 0)
              };
              setUserProgress(updatedProgress);
              localStorage.setItem('learningProgress', JSON.stringify(updatedProgress));
            }}
          />
        )}

        {activeTab === 'certifications' && (
          <CertificationSystem
            userProgress={userProgress}
            onCertificationEarned={(certId) => {
              const updatedProgress = {
                ...userProgress,
                certificationsEarned: [...userProgress.certificationsEarned, certId]
              };
              setUserProgress(updatedProgress);
              localStorage.setItem('learningProgress', JSON.stringify(updatedProgress));
            }}
          />
        )}

        {activeTab === 'analytics' && (
          <LearningAnalytics />
        )}

        {activeTab === 'paths' && (
          <LearningPath
            userProgress={userProgress}
            onStepStart={(step) => {
              // Handle step start - could navigate to tutorial or quiz
              if (step.moduleId) {
                const module = learningModules.find(m => m.id === step.moduleId);
                if (module) {
                  handleModuleStart(module);
                }
              }
            }}
          />
        )}

        {activeTab === 'knowledge' && (
          <KnowledgeBase
            onArticleRead={(articleId) => {
              // Track article reading for analytics
              console.log(`Article read: ${articleId}`);
            }}
          />
        )}
      </div>
    </div>
  );
};