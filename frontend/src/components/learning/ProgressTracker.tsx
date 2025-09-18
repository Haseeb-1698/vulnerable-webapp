import React, { useState, useEffect } from 'react';
import { TrophyIcon, ClockIcon, BoltIcon, AcademicCapIcon } from '@heroicons/react/24/outline';

interface LearningObjective {
  id: string;
  title: string;
  description: string;
  category: 'vulnerability' | 'tool' | 'concept' | 'skill';
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  completed: boolean;
  completedAt?: Date;
  progress: number;
  prerequisites: string[];
}

interface Achievement {
  id: string;
  title: string;
  description: string;
  icon: string;
  unlockedAt?: Date;
  criteria: {
    type: 'modules_completed' | 'quizzes_passed' | 'streak_days' | 'time_spent' | 'vulnerability_found';
    target: number;
    current: number;
  };
}

interface ProgressStats {
  totalTimeSpent: number; // in minutes
  currentStreak: number; // consecutive days
  longestStreak: number;
  modulesCompleted: number;
  quizzesCompleted: number;
  vulnerabilitiesFound: number;
  skillLevel: 'novice' | 'intermediate' | 'advanced' | 'expert';
  experiencePoints: number;
}

interface ProgressTrackerProps {
  userId?: string;
}

export const ProgressTracker: React.FC<ProgressTrackerProps> = ({ userId }) => {
  const [objectives, setObjectives] = useState<LearningObjective[]>([]);
  const [achievements, setAchievements] = useState<Achievement[]>([]);
  const [stats, setStats] = useState<ProgressStats>({
    totalTimeSpent: 0,
    currentStreak: 0,
    longestStreak: 0,
    modulesCompleted: 0,
    quizzesCompleted: 0,
    vulnerabilitiesFound: 0,
    skillLevel: 'novice',
    experiencePoints: 0
  });

  // Initialize learning objectives
  useEffect(() => {
    const defaultObjectives: LearningObjective[] = [
      {
        id: 'sql-injection-basics',
        title: 'SQL Injection Fundamentals',
        description: 'Understand basic SQL injection techniques and prevention',
        category: 'vulnerability',
        difficulty: 'beginner',
        completed: false,
        progress: 0,
        prerequisites: []
      },
      {
        id: 'sql-injection-advanced',
        title: 'Advanced SQL Injection',
        description: 'Master blind SQL injection and automated exploitation',
        category: 'vulnerability',
        difficulty: 'advanced',
        completed: false,
        progress: 0,
        prerequisites: ['sql-injection-basics']
      },
      {
        id: 'xss-fundamentals',
        title: 'Cross-Site Scripting (XSS)',
        description: 'Learn about reflected, stored, and DOM-based XSS',
        category: 'vulnerability',
        difficulty: 'beginner',
        completed: false,
        progress: 0,
        prerequisites: []
      },
      {
        id: 'xss-exploitation',
        title: 'XSS Exploitation Techniques',
        description: 'Advanced XSS payloads and bypass techniques',
        category: 'vulnerability',
        difficulty: 'intermediate',
        completed: false,
        progress: 0,
        prerequisites: ['xss-fundamentals']
      },
      {
        id: 'idor-discovery',
        title: 'IDOR Vulnerability Discovery',
        description: 'Identify and exploit Insecure Direct Object References',
        category: 'vulnerability',
        difficulty: 'intermediate',
        completed: false,
        progress: 0,
        prerequisites: []
      },
      {
        id: 'session-management',
        title: 'Session Management Security',
        description: 'Understand session vulnerabilities and JWT security',
        category: 'vulnerability',
        difficulty: 'intermediate',
        completed: false,
        progress: 0,
        prerequisites: []
      },
      {
        id: 'ssrf-lfi',
        title: 'SSRF and LFI Attacks',
        description: 'Server-Side Request Forgery and Local File Inclusion',
        category: 'vulnerability',
        difficulty: 'advanced',
        completed: false,
        progress: 0,
        prerequisites: []
      },
      {
        id: 'burp-suite-basics',
        title: 'Burp Suite Fundamentals',
        description: 'Learn to use Burp Suite for web application testing',
        category: 'tool',
        difficulty: 'beginner',
        completed: false,
        progress: 0,
        prerequisites: []
      },
      {
        id: 'sqlmap-usage',
        title: 'SQLMap Automation',
        description: 'Automate SQL injection testing with SQLMap',
        category: 'tool',
        difficulty: 'intermediate',
        completed: false,
        progress: 0,
        prerequisites: ['sql-injection-basics']
      },
      {
        id: 'owasp-top10',
        title: 'OWASP Top 10 Mastery',
        description: 'Complete understanding of OWASP Top 10 vulnerabilities',
        category: 'concept',
        difficulty: 'intermediate',
        completed: false,
        progress: 0,
        prerequisites: ['sql-injection-basics', 'xss-fundamentals', 'idor-discovery']
      }
    ];

    setObjectives(defaultObjectives);
  }, []);

  // Initialize achievements
  useEffect(() => {
    const defaultAchievements: Achievement[] = [
      {
        id: 'first-steps',
        title: 'First Steps',
        description: 'Complete your first tutorial module',
        icon: '🎯',
        criteria: {
          type: 'modules_completed',
          target: 1,
          current: stats.modulesCompleted
        }
      },
      {
        id: 'sql-ninja',
        title: 'SQL Ninja',
        description: 'Master SQL injection techniques',
        icon: '🥷',
        criteria: {
          type: 'modules_completed',
          target: 2,
          current: stats.modulesCompleted
        }
      },
      {
        id: 'quiz-master',
        title: 'Quiz Master',
        description: 'Pass 5 security quizzes',
        icon: '🧠',
        criteria: {
          type: 'quizzes_passed',
          target: 5,
          current: stats.quizzesCompleted
        }
      },
      {
        id: 'streak-warrior',
        title: 'Streak Warrior',
        description: 'Maintain a 7-day learning streak',
        icon: '🔥',
        criteria: {
          type: 'streak_days',
          target: 7,
          current: stats.currentStreak
        }
      },
      {
        id: 'time-master',
        title: 'Time Master',
        description: 'Spend 10 hours learning security',
        icon: '⏰',
        criteria: {
          type: 'time_spent',
          target: 600, // 10 hours in minutes
          current: stats.totalTimeSpent
        }
      },
      {
        id: 'vulnerability-hunter',
        title: 'Vulnerability Hunter',
        description: 'Find 10 vulnerabilities in practice labs',
        icon: '🎯',
        criteria: {
          type: 'vulnerability_found',
          target: 10,
          current: stats.vulnerabilitiesFound
        }
      },
      {
        id: 'security-expert',
        title: 'Security Expert',
        description: 'Complete all learning modules',
        icon: '🏆',
        criteria: {
          type: 'modules_completed',
          target: 10,
          current: stats.modulesCompleted
        }
      }
    ];

    setAchievements(defaultAchievements);
  }, [stats]);

  // Load progress from localStorage
  useEffect(() => {
    const savedProgress = localStorage.getItem('learningProgress');
    if (savedProgress) {
      const progress = JSON.parse(savedProgress);
      setStats(progress.stats || stats);
      
      // Update objectives with saved progress
      if (progress.objectives) {
        setObjectives(prev => prev.map(obj => {
          const saved = progress.objectives.find((s: any) => s.id === obj.id);
          return saved ? { ...obj, ...saved } : obj;
        }));
      }
    }
  }, []);

  // Save progress to localStorage
  const saveProgress = () => {
    const progressData = {
      stats,
      objectives,
      lastUpdated: new Date().toISOString()
    };
    localStorage.setItem('learningProgress', JSON.stringify(progressData));
  };

  // Update objective progress
  const updateObjectiveProgress = (objectiveId: string, progress: number, completed: boolean = false) => {
    setObjectives(prev => prev.map(obj => {
      if (obj.id === objectiveId) {
        const updated = {
          ...obj,
          progress,
          completed,
          completedAt: completed ? new Date() : obj.completedAt
        };
        
        // Update stats if completed
        if (completed && !obj.completed) {
          setStats(prevStats => {
            const newXP = prevStats.experiencePoints + (obj.difficulty === 'advanced' ? 100 : obj.difficulty === 'intermediate' ? 75 : 50);
            return {
              ...prevStats,
              modulesCompleted: prevStats.modulesCompleted + 1,
              experiencePoints: newXP,
              skillLevel: calculateSkillLevel(newXP)
            };
          });
        }
        
        return updated;
      }
      return obj;
    }));
    
    saveProgress();
  };

  // Update streak tracking
  const updateStreak = () => {
    const today = new Date().toDateString();
    const lastActivity = localStorage.getItem('lastActivityDate');
    
    if (lastActivity !== today) {
      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);
      
      if (lastActivity === yesterday.toDateString()) {
        // Continue streak
        setStats(prev => ({
          ...prev,
          currentStreak: prev.currentStreak + 1,
          longestStreak: Math.max(prev.longestStreak, prev.currentStreak + 1)
        }));
      } else if (lastActivity !== today) {
        // Reset streak
        setStats(prev => ({
          ...prev,
          currentStreak: 1,
          longestStreak: Math.max(prev.longestStreak, 1)
        }));
      }
      
      localStorage.setItem('lastActivityDate', today);
    }
  };

  // Track time spent
  const trackTimeSpent = (minutes: number) => {
    setStats(prev => ({
      ...prev,
      totalTimeSpent: prev.totalTimeSpent + minutes
    }));
    saveProgress();
  };

  // Track vulnerability found
  const trackVulnerabilityFound = () => {
    setStats(prev => ({
      ...prev,
      vulnerabilitiesFound: prev.vulnerabilitiesFound + 1,
      experiencePoints: prev.experiencePoints + 25
    }));
    saveProgress();
  };

  // Expose tracking functions
  useEffect(() => {
    // Make tracking functions available globally
    (window as any).learningTracker = {
      updateObjectiveProgress,
      updateStreak,
      trackTimeSpent,
      trackVulnerabilityFound
    };
    
    // Update streak on component mount
    updateStreak();
  }, []);

  // Calculate skill level based on experience points
  const calculateSkillLevel = (xp: number): ProgressStats['skillLevel'] => {
    if (xp >= 1000) return 'expert';
    if (xp >= 500) return 'advanced';
    if (xp >= 200) return 'intermediate';
    return 'novice';
  };

  // Get category color
  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'vulnerability': return 'bg-red-100 text-red-800';
      case 'tool': return 'bg-blue-100 text-blue-800';
      case 'concept': return 'bg-green-100 text-green-800';
      case 'skill': return 'bg-purple-100 text-purple-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  // Get difficulty color
  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'beginner': return 'text-green-600';
      case 'intermediate': return 'text-yellow-600';
      case 'advanced': return 'text-red-600';
      default: return 'text-gray-600';
    }
  };

  // Check if objective is available (prerequisites met)
  const isObjectiveAvailable = (objective: LearningObjective) => {
    return objective.prerequisites.every(prereqId => 
      objectives.find(obj => obj.id === prereqId)?.completed
    );
  };

  // Get unlocked achievements
  const unlockedAchievements = achievements.filter(achievement => 
    achievement.criteria.current >= achievement.criteria.target
  );

  return (
    <div className="space-y-8">
      {/* Stats Overview */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Learning Progress</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
          <div className="text-center">
            <div className="text-3xl font-bold text-blue-600">{stats.experiencePoints}</div>
            <div className="text-sm text-gray-600">Experience Points</div>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-green-600">{stats.modulesCompleted}</div>
            <div className="text-sm text-gray-600">Modules Completed</div>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-purple-600">{Math.round(stats.totalTimeSpent / 60)}h</div>
            <div className="text-sm text-gray-600">Time Spent</div>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-orange-600">{stats.currentStreak}</div>
            <div className="text-sm text-gray-600">Day Streak</div>
          </div>
        </div>
        
        {/* Skill Level */}
        <div className="mt-6 text-center">
          <div className="text-lg font-medium text-gray-900">
            Skill Level: <span className={getDifficultyColor(stats.skillLevel)}>{stats.skillLevel.charAt(0).toUpperCase() + stats.skillLevel.slice(1)}</span>
          </div>
          <div className="mt-2 bg-gray-200 rounded-full h-3 max-w-md mx-auto">
            <div
              className="bg-gradient-to-r from-blue-500 to-purple-600 h-3 rounded-full"
              style={{ width: `${Math.min(100, (stats.experiencePoints % 250) / 250 * 100)}%` }}
            />
          </div>
          <div className="text-sm text-gray-600 mt-1">
            {stats.experiencePoints % 250} / 250 XP to next level
          </div>
        </div>
      </div>

      {/* Learning Objectives */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Learning Objectives</h2>
        <div className="space-y-4">
          {objectives.map((objective) => {
            const isAvailable = isObjectiveAvailable(objective);
            
            return (
              <div
                key={objective.id}
                className={`border rounded-lg p-4 ${
                  !isAvailable ? 'opacity-50 bg-gray-50' : 'bg-white hover:shadow-md'
                } transition-shadow`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3">
                      <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${
                        objective.completed ? 'bg-green-100 text-green-800' : 
                        isAvailable ? 'bg-blue-100 text-blue-800' : 'bg-gray-100 text-gray-600'
                      }`}>
                        {objective.completed ? '✓' : '○'}
                      </div>
                      <div>
                        <h3 className="text-lg font-medium text-gray-900">{objective.title}</h3>
                        <p className="text-sm text-gray-600">{objective.description}</p>
                        <div className="flex items-center space-x-3 mt-2">
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getCategoryColor(objective.category)}`}>
                            {objective.category}
                          </span>
                          <span className={`text-xs font-medium ${getDifficultyColor(objective.difficulty)}`}>
                            {objective.difficulty}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm font-medium text-gray-900">{objective.progress}%</div>
                    {objective.progress > 0 && !objective.completed && (
                      <div className="w-20 bg-gray-200 rounded-full h-2 mt-1">
                        <div
                          className="bg-blue-600 h-2 rounded-full"
                          style={{ width: `${objective.progress}%` }}
                        />
                      </div>
                    )}
                  </div>
                </div>
                
                {objective.prerequisites.length > 0 && (
                  <div className="mt-3 text-xs text-gray-500">
                    Prerequisites: {objective.prerequisites.map(prereqId => {
                      const prereq = objectives.find(obj => obj.id === prereqId);
                      return prereq?.title;
                    }).join(', ')}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Achievements */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Achievements</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {achievements.map((achievement) => {
            const isUnlocked = achievement.criteria.current >= achievement.criteria.target;
            const progress = Math.min(100, (achievement.criteria.current / achievement.criteria.target) * 100);
            
            return (
              <div
                key={achievement.id}
                className={`border rounded-lg p-4 ${
                  isUnlocked ? 'bg-gradient-to-br from-yellow-50 to-orange-50 border-yellow-200' : 'bg-gray-50 border-gray-200'
                }`}
              >
                <div className="text-center">
                  <div className={`text-4xl mb-2 ${isUnlocked ? '' : 'grayscale opacity-50'}`}>
                    {achievement.icon}
                  </div>
                  <h3 className={`font-medium ${isUnlocked ? 'text-gray-900' : 'text-gray-600'}`}>
                    {achievement.title}
                  </h3>
                  <p className={`text-sm mt-1 ${isUnlocked ? 'text-gray-700' : 'text-gray-500'}`}>
                    {achievement.description}
                  </p>
                  
                  {!isUnlocked && (
                    <div className="mt-3">
                      <div className="bg-gray-200 rounded-full h-2">
                        <div
                          className="bg-blue-600 h-2 rounded-full"
                          style={{ width: `${progress}%` }}
                        />
                      </div>
                      <div className="text-xs text-gray-600 mt-1">
                        {achievement.criteria.current} / {achievement.criteria.target}
                      </div>
                    </div>
                  )}
                  
                  {isUnlocked && (
                    <div className="mt-2 text-xs text-green-600 font-medium">
                      ✓ Unlocked!
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};