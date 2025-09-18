import React from 'react';
import ErrorBoundary from './ErrorBoundary';

interface MonitoringWrapperProps {
  children: React.ReactNode;
  title: string;
}

const MonitoringWrapper: React.FC<MonitoringWrapperProps> = ({ children, title }) => {
  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
        <ErrorBoundary>
          {children}
        </ErrorBoundary>
      </div>
    </div>
  );
};

export default MonitoringWrapper;