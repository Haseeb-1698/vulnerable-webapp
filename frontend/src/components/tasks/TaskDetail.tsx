import React, { useState, useEffect } from 'react';
import { Task, Comment } from '../../types';
import { taskApi } from '../../utils/api';
import CommentSection from '../comments/CommentSection';

interface TaskDetailProps {
  taskId: number;
  onBack: () => void;
  onEdit: (task: Task) => void;
}

const TaskDetail: React.FC<TaskDetailProps> = ({ taskId, onBack, onEdit }) => {
  const [task, setTask] = useState<Task | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Load task details
  const loadTask = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await taskApi.getTask(taskId);
      setTask(response.task);
      
      // VULNERABILITY: Log ownership information
      if (response.ownership) {
        console.log('Task ownership info:', response.ownership);
        if (!response.ownership.isOwner) {
          console.warn('⚠️  Accessing task owned by another user (IDOR vulnerability)');
        }
      }
      
    } catch (err) {
      console.error('Failed to load task:', err);
      setError(err instanceof Error ? err.message : 'Failed to load task');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadTask();
  }, [taskId]);

  // Handle comment updates
  const handleCommentAdded = (comment: Comment) => {
    setTask(prev => prev ? {
      ...prev,
      comments: [...(prev.comments || []), comment]
    } : null);
  };

  const handleCommentUpdated = (updatedComment: Comment) => {
    setTask(prev => prev ? {
      ...prev,
      comments: (prev.comments || []).map(comment => 
        comment.id === updatedComment.id ? updatedComment : comment
      )
    } : null);
  };

  const handleCommentDeleted = (commentId: number) => {
    setTask(prev => prev ? {
      ...prev,
      comments: (prev.comments || []).filter(comment => comment.id !== commentId)
    } : null);
  };

  const getPriorityColor = (priority: Task['priority']) => {
    switch (priority) {
      case 'URGENT': return 'bg-red-100 text-red-800 border-red-200';
      case 'HIGH': return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'MEDIUM': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'LOW': return 'bg-green-100 text-green-800 border-green-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getStatusColor = (status: Task['status']) => {
    switch (status) {
      case 'COMPLETED': return 'bg-green-100 text-green-800 border-green-200';
      case 'IN_PROGRESS': return 'bg-blue-100 text-blue-800 border-blue-200';
      case 'TODO': return 'bg-gray-100 text-gray-800 border-gray-200';
      case 'CANCELLED': return 'bg-red-100 text-red-800 border-red-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const formatDateShort = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  };

  const isOverdue = (dueDate?: string) => {
    if (!dueDate) return false;
    return new Date(dueDate) < new Date() && task?.status !== 'COMPLETED';
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
        <span className="ml-2 text-gray-600">Loading task...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-md p-4">
        <div className="flex justify-between items-center">
          <div className="text-red-800">
            <strong>Error:</strong> {error}
          </div>
          <button
            onClick={onBack}
            className="text-red-600 hover:text-red-800 font-medium"
          >
            Go Back
          </button>
        </div>
      </div>
    );
  }

  if (!task) {
    return (
      <div className="text-center py-12">
        <div className="text-gray-500 text-lg mb-4">Task not found</div>
        <button
          onClick={onBack}
          className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700"
        >
          Go Back
        </button>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 bg-grid-slate bg-ornaments -mx-4 sm:-mx-6 lg:-mx-8 px-4 sm:px-6 lg:px-8 py-8">
      <div className="max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <button
          onClick={onBack}
          className="flex items-center text-blue-600 hover:text-blue-800 font-medium"
        >
          ← Back to Tasks
        </button>
        <button
          onClick={() => onEdit(task)}
          className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700"
        >
          Edit Task
        </button>
      </div>

      {/* Task Details */}
      <div className="bg-white rounded-lg shadow-lg border border-gray-200 p-6">
        {/* Title and Status */}
        <div className="flex justify-between items-start mb-4">
          <h1 className="text-3xl font-bold text-gray-900 flex-1 mr-4">
            {task.title}
          </h1>
          <div className="flex space-x-2">
            <span className={`px-3 py-1 text-sm font-medium rounded-full border ${getPriorityColor(task.priority)}`}>
              {task.priority}
            </span>
            <span className={`px-3 py-1 text-sm font-medium rounded-full border ${getStatusColor(task.status)}`}>
              {task.status.replace('_', ' ')}
            </span>
          </div>
        </div>

        {/* Description */}
        {task.description && (
          <div className="mb-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-2">Description</h3>
            <div className="prose max-w-none">
              <p className="text-gray-700 whitespace-pre-wrap">{task.description}</p>
            </div>
          </div>
        )}

        {/* Task Metadata */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
          {/* Due Date */}
          {task.dueDate && (
            <div>
              <h4 className="text-sm font-medium text-gray-500 mb-1">Due Date</h4>
              <p className={`text-lg ${isOverdue(task.dueDate) ? 'text-red-600 font-medium' : 'text-gray-900'}`}>
                {formatDateShort(task.dueDate)}
                {isOverdue(task.dueDate) && ' (Overdue)'}
              </p>
            </div>
          )}

          {/* Created By */}
          {task.user && (
            <div>
              <h4 className="text-sm font-medium text-gray-500 mb-1">Created By</h4>
              <p className="text-lg text-gray-900">
                {task.user.firstName} {task.user.lastName}
              </p>
            </div>
          )}

          {/* Created Date */}
          <div>
            <h4 className="text-sm font-medium text-gray-500 mb-1">Created</h4>
            <p className="text-lg text-gray-900">{formatDate(task.createdAt)}</p>
          </div>

          {/* Last Updated */}
          {task.updatedAt !== task.createdAt && (
            <div>
              <h4 className="text-sm font-medium text-gray-500 mb-1">Last Updated</h4>
              <p className="text-lg text-gray-900">{formatDate(task.updatedAt)}</p>
            </div>
          )}
        </div>
      </div>

      {/* Comments Section */}
      <div className="bg-white rounded-lg shadow-lg border border-gray-200 p-6">
        <CommentSection
          taskId={task.id}
          initialComments={task.comments || []}
          onCommentAdded={handleCommentAdded}
          onCommentUpdated={handleCommentUpdated}
          onCommentDeleted={handleCommentDeleted}
        />
        </div>
      </div>
    </div>
  );
};

export default TaskDetail;