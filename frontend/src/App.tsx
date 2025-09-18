import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Provider } from 'react-redux';
import { Toaster } from 'react-hot-toast';
import { store } from './store/store';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import Login from './components/auth/Login';
import Register from './components/auth/Register';
import ProtectedRoute, { PublicOnlyRoute } from './components/auth/ProtectedRoute';
import { TaskList, TaskDetail, TaskForm, SearchPage } from './components/tasks';
import ProfilePage from './components/profile/ProfilePage';
import { SecurityLabDashboard } from './components/security-lab/SecurityLabDashboard';
import MonitoringDashboard from './components/monitoring/MonitoringDashboard';
import LogsViewer from './components/monitoring/LogsViewer';
import ErrorBoundary from './components/monitoring/ErrorBoundary';
import DocsPage from './components/docs/DocsPage';
import LandingPage from './components/LandingPage';
import { LearningDashboard } from './components/learning/LearningDashboard';
import { Task } from './types';

// Navigation component
const Navigation: React.FC<{ onShowSearch?: () => void; onShowTasks?: () => void }> = ({ 
  onShowSearch, 
  onShowTasks 
}) => {
  const { user, logout } = useAuth();

  return (
    <nav className="sticky top-0 z-50 bg-white border-b border-slate-200 shadow-sm">
      <div className="max-w-7xl mx-auto pl-4 sm:pl-6 lg:pl-8 pr-0">
        <div className="flex justify-between items-center h-16">
          {/* Brand */}
          <div className="flex items-center space-x-8 flex-1 min-w-0">
            <h1 className="text-xl font-bold text-slate-800">
              SecureTask Manager
            </h1>
            
            {/* Navigation Links */}
            <div className="hidden lg:flex items-center flex-nowrap whitespace-nowrap space-x-3">
              <button
                type="button"
                onClick={onShowTasks}
                className="nav-link group shrink-0"
              >
                <svg className="w-4 h-4 mr-2 text-slate-600 group-hover:text-primary-600 transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                </svg>
                Tasks
              </button>
              <button
                type="button"
                onClick={onShowSearch}
                className="nav-link group shrink-0"
              >
                <svg className="w-4 h-4 mr-2 text-slate-600 group-hover:text-primary-600 transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
                <span className="hidden xl:inline">Search</span>
                <span className="xl:hidden">Search</span>
                <span className="ml-1 text-xs bg-warning-100 text-warning-700 px-2 py-0.5 rounded-full">Vuln</span>
              </button>
              <a
                href="/profile"
                className="nav-link group shrink-0"
              >
                <svg className="w-4 h-4 mr-2 text-slate-600 group-hover:text-primary-600 transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                </svg>
                <span className="hidden xl:inline">Profile</span>
                <span className="xl:hidden">Profile</span>
                <span className="ml-1 text-xs bg-accent-100 text-accent-700 px-2 py-0.5 rounded-full">SSRF</span>
              </a>
              <a
                href="/security-lab"
                className="nav-link group shrink-0"
              >
                <svg className="w-4 h-4 mr-2 text-slate-600 group-hover:text-primary-600 transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                <span>Lab</span>
              </a>
              <a
                href="/learning"
                className="nav-link group shrink-0"
              >
                <svg className="w-4 h-4 mr-2 text-slate-600 group-hover:text-primary-600 transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.746 0 3.332.477 4.5 1.253v13C19.832 18.477 18.246 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
                </svg>
                <span className="hidden xl:inline">Learning</span>
                <span className="xl:hidden">Learn</span>
              </a>
              <a
                href="/docs"
                className="nav-link group shrink-0"
              >
                <svg className="w-4 h-4 mr-2 text-slate-600 group-hover:text-primary-600 transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 20l9-4-9-4-9 4 9 4z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 12l9-4-9-4-9 4 9 4z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 12v8" />
                </svg>
                <span className="hidden xl:inline">Docs</span>
                <span className="xl:hidden">Docs</span>
              </a>

            </div>
          </div>

          {/* User Menu */}
          <div className="flex items-center space-x-4 ml-6 whitespace-nowrap ml-auto pr-2">
            {/* User Info */}
            <div className="hidden md:flex items-center space-x-3">
              <div className="flex items-center justify-center w-8 h-8 bg-gradient-to-r from-slate-600 to-slate-700 rounded-lg">
                <span className="text-sm font-semibold text-white">
                  {user?.firstName?.[0]}{user?.lastName?.[0]}
                </span>
              </div>
              <div className="flex flex-col min-w-0">
                <span className="text-sm font-medium text-slate-700 truncate">
                  {user?.firstName} {user?.lastName}
                </span>
                <span className="text-xs text-slate-500">Security Learner</span>
              </div>
            </div>

            {/* Logout Button (rightmost) */}
            <button
              type="button"
              onClick={logout}
              className="inline-flex items-center px-4 py-2 bg-slate-800 text-white rounded-lg hover:bg-slate-900 text-sm"
            >
              <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
              </svg>
              <span>Logout</span>
            </button>

            {/* Mobile Menu Button */}
            <button 
              className="lg:hidden p-2 rounded-xl hover:bg-slate-100 transition-colors"
              title="Open mobile menu"
              aria-label="Open mobile menu"
            >
              <svg className="w-6 h-6 text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
};

// Main Dashboard component with task management
const Dashboard: React.FC = () => {
  const [currentView, setCurrentView] = useState<'list' | 'detail' | 'form' | 'search'>('list');
  const [selectedTask, setSelectedTask] = useState<Task | null>(null);
  const [editingTask, setEditingTask] = useState<Task | null>(null);

  const handleTaskClick = (task: Task) => {
    setSelectedTask(task);
    setCurrentView('detail');
  };

  const handleEditTask = (task: Task) => {
    setEditingTask(task);
    setCurrentView('form');
  };

  const handleBackToList = () => {
    setCurrentView('list');
    setSelectedTask(null);
    setEditingTask(null);
  };

  const handleShowSearch = () => {
    setCurrentView('search');
    setSelectedTask(null);
    setEditingTask(null);
  };

  const handleFormSubmit = () => {
    // Form submission is handled by the TaskForm component
    // After successful submission, go back to list
    handleBackToList();
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <Navigation 
        onShowSearch={handleShowSearch}
        onShowTasks={handleBackToList}
      />
      <main className="w-full py-6 px-0">
        {currentView === 'list' && (
          <TaskList onTaskClick={handleTaskClick} />
        )}
        
        {currentView === 'detail' && selectedTask && (
          <TaskDetail
            taskId={selectedTask.id}
            onBack={handleBackToList}
            onEdit={handleEditTask}
          />
        )}
        
        {currentView === 'form' && (
          <TaskForm
            task={editingTask}
            onSubmit={handleFormSubmit}
            onCancel={handleBackToList}
          />
        )}
        
        {currentView === 'search' && (
          <SearchPage
            onTaskClick={handleTaskClick}
            onBack={handleBackToList}
          />
        )}
      </main>
    </div>
  );
};

// Home page component - now using LandingPage
const Home: React.FC = () => {
  return <LandingPage />;
};

function App() {
  return (
    <Provider store={store}>
      <Router>
        <AuthProvider>
          <div className="min-h-screen bg-gray-50">
            <Routes>
              {/* Public routes */}
              <Route path="/" element={<Home />} />
              <Route path="/docs" element={<DocsPage />} />
              
              {/* Auth routes - redirect to dashboard if already logged in */}
              <Route 
                path="/login" 
                element={
                  <PublicOnlyRoute>
                    <Login />
                  </PublicOnlyRoute>
                } 
              />
              <Route 
                path="/register" 
                element={
                  <PublicOnlyRoute>
                    <Register />
                  </PublicOnlyRoute>
                } 
              />
              
              {/* Protected routes */}
              <Route 
                path="/dashboard" 
                element={
                  <ProtectedRoute>
                    <Dashboard />
                  </ProtectedRoute>
                } 
              />
              <Route 
                path="/tasks" 
                element={
                  <ProtectedRoute>
                    <Dashboard />
                  </ProtectedRoute>
                } 
              />
              <Route 
                path="/search" 
                element={
                  <ProtectedRoute>
                    <SearchPage />
                  </ProtectedRoute>
                } 
              />
              <Route 
                path="/profile" 
                element={
                  <ProtectedRoute>
                    <ProfilePage />
                  </ProtectedRoute>
                } 
              />
              <Route 
                path="/security-lab" 
                element={
                  <ProtectedRoute>
                    <SecurityLabDashboard />
                  </ProtectedRoute>
                } 
              />
              <Route 
                path="/monitoring" 
                element={
                  <ProtectedRoute>
                    <ErrorBoundary>
                      <MonitoringDashboard />
                    </ErrorBoundary>
                  </ProtectedRoute>
                } 
              />
              <Route 
                path="/logs" 
                element={
                  <ProtectedRoute>
                    <ErrorBoundary>
                      <LogsViewer />
                    </ErrorBoundary>
                  </ProtectedRoute>
                } 
              />
              <Route 
                path="/learning" 
                element={
                  <ProtectedRoute>
                    <LearningDashboard />
                  </ProtectedRoute>
                } 
              />
              
              {/* Redirect unknown routes to home */}
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </div>
          <Toaster position="top-right" />
        </AuthProvider>
      </Router>
    </Provider>
  );
}

export default App;