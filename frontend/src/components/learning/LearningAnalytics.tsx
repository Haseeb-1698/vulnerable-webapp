import React, { useState, useEffect } from 'react';
import { ChartBarIcon, ClockIcon, TrendingUpIcon, CalendarIcon } from '@heroicons/react/24/outline';

interface LearningSession {
  id: string;
  date: Date;
  duration: number; // minutes
  modulesCompleted: string[];
  quizzesAttempted: string[];
  vulnerabilitiesFound: number;
  skillsLearned: string[];
}

interface WeeklyProgress {
  week: string;
  timeSpent: number;
  modulesCompleted: number;
  quizzesPassed: number;
  vulnerabilitiesFound: number;
}

interface SkillProgress {
  skill: string;
  level: number; // 0-100
  lastPracticed: Date;
  timeSpent: number;
}

export const LearningAnalytics: React.FC = () => {
  const [sessions, setSessions] = useState<LearningSession[]>([]);
  const [weeklyProgress, setWeeklyProgress] = useState<WeeklyProgress[]>([]);
  const [skillProgress, setSkillProgress] = useState<SkillProgress[]>([]);
  const [selectedTimeframe, setSelectedTimeframe] = useState<'week' | 'month' | 'all'>('week');

  // Initialize analytics data
  useEffect(() => {
    loadAnalyticsData();
  }, []);

  const loadAnalyticsData = () => {
    // Load from localStorage or API
    const savedSessions = localStorage.getItem('learningSessions');
    if (savedSessions) {
      setSessions(JSON.parse(savedSessions));
    }

    // Generate mock weekly progress data
    const weeks = generateWeeklyProgress();
    setWeeklyProgress(weeks);

    // Generate skill progress data
    const skills = generateSkillProgress();
    setSkillProgress(skills);
  };

  const generateWeeklyProgress = (): WeeklyProgress[] => {
    const weeks: WeeklyProgress[] = [];
    const now = new Date();
    
    for (let i = 7; i >= 0; i--) {
      const weekStart = new Date(now);
      weekStart.setDate(now.getDate() - (i * 7));
      
      weeks.push({
        week: `Week ${8 - i}`,
        timeSpent: Math.floor(Math.random() * 300) + 60, // 60-360 minutes
        modulesCompleted: Math.floor(Math.random() * 3) + 1,
        quizzesPassed: Math.floor(Math.random() * 2) + 1,
        vulnerabilitiesFound: Math.floor(Math.random() * 5) + 2
      });
    }
    
    return weeks;
  };

  const generateSkillProgress = (): SkillProgress[] => {
    const skills = [
      'SQL Injection Detection',
      'XSS Prevention',
      'IDOR Testing',
      'Session Security',
      'SSRF Exploitation',
      'Secure Code Review',
      'Penetration Testing',
      'Vulnerability Assessment'
    ];

    return skills.map(skill => ({
      skill,
      level: Math.floor(Math.random() * 100),
      lastPracticed: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000),
      timeSpent: Math.floor(Math.random() * 180) + 30
    }));
  };

  // Calculate analytics metrics
  const getTotalTimeSpent = () => {
    return weeklyProgress.reduce((sum, week) => sum + week.timeSpent, 0);
  };

  const getAverageSessionTime = () => {
    if (sessions.length === 0) return 0;
    const totalTime = sessions.reduce((sum, session) => sum + session.duration, 0);
    return Math.round(totalTime / sessions.length);
  };

  const getStreakData = () => {
    // Calculate current streak and longest streak
    const today = new Date();
    let currentStreak = 0;
    let longestStreak = 0;
    let tempStreak = 0;

    // This would be calculated from actual session data
    return { currentStreak: 5, longestStreak: 12 };
  };

  const getTopSkills = () => {
    return skillProgress
      .sort((a, b) => b.level - a.level)
      .slice(0, 5);
  };

  const getRecentActivity = () => {
    return sessions
      .sort((a, b) => b.date.getTime() - a.date.getTime())
      .slice(0, 10);
  };

  const formatDuration = (minutes: number) => {
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    return hours > 0 ? `${hours}h ${mins}m` : `${mins}m`;
  };

  const getSkillLevelColor = (level: number) => {
    if (level >= 80) return 'bg-green-500';
    if (level >= 60) return 'bg-blue-500';
    if (level >= 40) return 'bg-yellow-500';
    return 'bg-red-500';
  };

  const streakData = getStreakData();
  const topSkills = getTopSkills();
  const recentActivity = getRecentActivity();

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Learning Analytics</h2>
          <p className="text-gray-600">Track your progress and identify areas for improvement</p>
        </div>
        <div className="flex space-x-2">
          {(['week', 'month', 'all'] as const).map((timeframe) => (
            <button
              key={timeframe}
              onClick={() => setSelectedTimeframe(timeframe)}
              className={`px-3 py-1 rounded-md text-sm font-medium ${
                selectedTimeframe === timeframe
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              }`}
            >
              {timeframe.charAt(0).toUpperCase() + timeframe.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <ClockIcon className="h-8 w-8 text-blue-600" />
            </div>
            <div className="ml-4">
              <div className="text-2xl font-bold text-gray-900">{formatDuration(getTotalTimeSpent())}</div>
              <div className="text-sm text-gray-600">Total Time Spent</div>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <TrendingUpIcon className="h-8 w-8 text-green-600" />
            </div>
            <div className="ml-4">
              <div className="text-2xl font-bold text-gray-900">{streakData.currentStreak}</div>
              <div className="text-sm text-gray-600">Current Streak (days)</div>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <ChartBarIcon className="h-8 w-8 text-purple-600" />
            </div>
            <div className="ml-4">
              <div className="text-2xl font-bold text-gray-900">{formatDuration(getAverageSessionTime())}</div>
              <div className="text-sm text-gray-600">Avg Session Time</div>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <CalendarIcon className="h-8 w-8 text-orange-600" />
            </div>
            <div className="ml-4">
              <div className="text-2xl font-bold text-gray-900">{streakData.longestStreak}</div>
              <div className="text-sm text-gray-600">Longest Streak (days)</div>
            </div>
          </div>
        </div>
      </div>

      {/* Weekly Progress Chart */}
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Weekly Progress</h3>
        <div className="space-y-4">
          {weeklyProgress.map((week, index) => (
            <div key={index} className="flex items-center space-x-4">
              <div className="w-16 text-sm text-gray-600">{week.week}</div>
              <div className="flex-1">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium text-gray-900">Time Spent</span>
                  <span className="text-sm text-gray-600">{formatDuration(week.timeSpent)}</span>
                </div>
                <div className="bg-gray-200 rounded-full h-2">
                  <div
                    className="bg-blue-600 h-2 rounded-full"
                    style={{ width: `${Math.min(100, (week.timeSpent / 300) * 100)}%` }}
                  />
                </div>
              </div>
              <div className="flex space-x-4 text-sm text-gray-600">
                <span>{week.modulesCompleted} modules</span>
                <span>{week.quizzesPassed} quizzes</span>
                <span>{week.vulnerabilitiesFound} vulns</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Skills Progress */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Top Skills</h3>
          <div className="space-y-4">
            {topSkills.map((skill, index) => (
              <div key={index} className="flex items-center space-x-4">
                <div className="flex-shrink-0 w-8 h-8 bg-gray-100 rounded-full flex items-center justify-center text-sm font-medium text-gray-600">
                  {index + 1}
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-medium text-gray-900">{skill.skill}</span>
                    <span className="text-sm text-gray-600">{skill.level}%</span>
                  </div>
                  <div className="bg-gray-200 rounded-full h-2">
                    <div
                      className={`h-2 rounded-full ${getSkillLevelColor(skill.level)}`}
                      style={{ width: `${skill.level}%` }}
                    />
                  </div>
                </div>
                <div className="text-xs text-gray-500">
                  {formatDuration(skill.timeSpent)}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Recent Activity */}
        <div className="bg-white rounded-lg shadow p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Activity</h3>
          <div className="space-y-3">
            {recentActivity.length > 0 ? (
              recentActivity.map((session, index) => (
                <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div>
                    <div className="text-sm font-medium text-gray-900">
                      Learning Session
                    </div>
                    <div className="text-xs text-gray-600">
                      {session.modulesCompleted.length} modules, {session.quizzesAttempted.length} quizzes
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm text-gray-900">{formatDuration(session.duration)}</div>
                    <div className="text-xs text-gray-600">
                      {session.date.toLocaleDateString()}
                    </div>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center py-8 text-gray-500">
                <ClockIcon className="h-12 w-12 mx-auto mb-4 text-gray-300" />
                <p>No recent activity</p>
                <p className="text-sm">Start learning to see your progress here!</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Learning Insights */}
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Learning Insights</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="text-center p-4 bg-blue-50 rounded-lg">
            <div className="text-2xl font-bold text-blue-600 mb-2">📈</div>
            <h4 className="font-medium text-gray-900 mb-1">Most Improved</h4>
            <p className="text-sm text-gray-600">SQL Injection skills increased by 25% this week</p>
          </div>
          
          <div className="text-center p-4 bg-green-50 rounded-lg">
            <div className="text-2xl font-bold text-green-600 mb-2">🎯</div>
            <h4 className="font-medium text-gray-900 mb-1">Achievement Unlocked</h4>
            <p className="text-sm text-gray-600">Completed 5 consecutive days of learning</p>
          </div>
          
          <div className="text-center p-4 bg-yellow-50 rounded-lg">
            <div className="text-2xl font-bold text-yellow-600 mb-2">💡</div>
            <h4 className="font-medium text-gray-900 mb-1">Recommendation</h4>
            <p className="text-sm text-gray-600">Focus on SSRF techniques to round out your skills</p>
          </div>
        </div>
      </div>

      {/* Study Schedule */}
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Recommended Study Schedule</h3>
        <div className="grid grid-cols-7 gap-2">
          {['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'].map((day, index) => (
            <div key={day} className="text-center">
              <div className="text-sm font-medium text-gray-900 mb-2">{day}</div>
              <div className={`h-20 rounded-lg flex items-center justify-center text-xs ${
                index < 5 ? 'bg-blue-100 text-blue-800' : 'bg-gray-100 text-gray-600'
              }`}>
                {index < 5 ? '30 min' : 'Rest'}
              </div>
            </div>
          ))}
        </div>
        <div className="mt-4 text-sm text-gray-600">
          <p>💡 <strong>Tip:</strong> Consistent daily practice is more effective than long weekend sessions.</p>
        </div>
      </div>
    </div>
  );
};