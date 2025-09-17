import React from 'react';
import { Task } from '../../types';

interface TaskCardProps {
  task: Task;
  onEdit: (task: Task) => void;
  onDelete: (taskId: number) => void;
  onStatusChange: (taskId: number, status: Task['status']) => void;
  onPriorityChange: (taskId: number, priority: Task['priority']) => void;
  onClick?: (task: Task) => void;
}

const TaskCard: React.FC<TaskCardProps> = ({
  task,
  onEdit,
  onDelete,
  onStatusChange,
  onPriorityChange,
  onClick
}) => {
  const getPriorityColor = (priority: Task['priority']) => {
    switch (priority) {
      case 'URGENT': return 'bg-danger-100 text-danger-800 border-danger-200';
      case 'HIGH': return 'bg-warning-100 text-warning-800 border-warning-200';
      case 'MEDIUM': return 'bg-accent-100 text-accent-800 border-accent-200';
      case 'LOW': return 'bg-success-100 text-success-800 border-success-200';
      default: return 'bg-slate-100 text-slate-800 border-slate-200';
    }
  };

  const getStatusColor = (status: Task['status']) => {
    switch (status) {
      case 'COMPLETED': return 'status-completed';
      case 'IN_PROGRESS': return 'status-in-progress';
      case 'TODO': return 'status-todo';
      case 'CANCELLED': return 'status-cancelled';
      default: return 'status-todo';
    }
  };

  const getPriorityClass = (priority: Task['priority']) => {
    switch (priority) {
      case 'URGENT': return 'task-priority-urgent';
      case 'HIGH': return 'task-priority-high';
      case 'MEDIUM': return 'task-priority-medium';
      case 'LOW': return 'task-priority-low';
      default: return '';
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  };

  const isOverdue = (dueDate?: string) => {
    if (!dueDate) return false;
    return new Date(dueDate) < new Date() && task.status !== 'COMPLETED';
  };

  return (
    <div 
      className={`task-card p-6 group ${getPriorityClass(task.priority)} ${
        onClick ? 'cursor-pointer' : ''
      } ${isOverdue(task.dueDate) ? 'ring-2 ring-red-200' : ''}`}
      onClick={() => onClick?.(task)}
    >
      {/* Header */}
      <div className="flex justify-between items-start mb-4">
        <h3 className="text-lg font-semibold text-slate-800 truncate flex-1 mr-3 group-hover:text-blue-600 transition-colors">
          {task.title}
        </h3>
        <div className="flex flex-col space-y-2">
          <span className={`status-badge ${getStatusColor(task.status)}`}>
            {task.status.replace('_', ' ')}
          </span>
          <span className={`status-badge ${getPriorityColor(task.priority)}`}>
            {task.priority}
          </span>
        </div>
      </div>

      {/* Description */}
      {task.description && (
        <p className="text-slate-600 text-sm mb-4 line-clamp-2 leading-relaxed">
          {task.description}
        </p>
      )}

      {/* Due Date */}
      {task.dueDate && (
        <div className="mb-4">
          <div className="flex items-center text-sm">
            <svg className="w-4 h-4 mr-2 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
            </svg>
            <span className={`font-medium ${isOverdue(task.dueDate) ? 'text-red-600' : 'text-slate-600'}`}>
              Due: {formatDate(task.dueDate)}
              {isOverdue(task.dueDate) && (
                <span className="ml-2 text-red-500 font-semibold">• Overdue</span>
              )}
            </span>
          </div>
        </div>
      )}

      {/* Owner Info */}
      {task.user && (
        <div className="mb-4 flex items-center text-sm text-slate-500">
          <div className="flex items-center justify-center w-6 h-6 bg-slate-100 rounded-full mr-2">
            <span className="text-xs font-medium text-slate-600">
              {task.user.firstName?.[0]}{task.user.lastName?.[0]}
            </span>
          </div>
          Created by {task.user.firstName} {task.user.lastName}
        </div>
      )}

      {/* Comments Count */}
      {task.comments && task.comments.length > 0 && (
        <div className="mb-4 flex items-center text-sm text-slate-500">
          <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
          </svg>
          {task.comments.length} comment{task.comments.length !== 1 ? 's' : ''}
        </div>
      )}

      {/* Actions */}
      <div className="flex justify-between items-center pt-4 border-t border-slate-100">
        <div className="flex space-x-2">
          {/* Status Quick Actions */}
          <select
            value={task.status}
            onChange={(e) => onStatusChange(task.id, e.target.value as Task['status'])}
            className="text-xs input py-1 px-3 focus:outline-none min-w-[120px]"
            onClick={(e) => e.stopPropagation()}
            title="Change task status"
            aria-label="Change task status"
          >
            <option value="TODO">To Do</option>
            <option value="IN_PROGRESS">In Progress</option>
            <option value="COMPLETED">Completed</option>
            <option value="CANCELLED">Cancelled</option>
          </select>

          <select
            value={task.priority}
            onChange={(e) => onPriorityChange(task.id, e.target.value as Task['priority'])}
            className="text-xs input py-1 px-3 focus:outline-none min-w-[100px]"
            onClick={(e) => e.stopPropagation()}
            title="Change task priority"
            aria-label="Change task priority"
          >
            <option value="LOW">Low</option>
            <option value="MEDIUM">Medium</option>
            <option value="HIGH">High</option>
            <option value="URGENT">Urgent</option>
          </select>
        </div>

        <div className="flex space-x-2">
          <button
            onClick={(e) => {
              e.stopPropagation();
              onEdit(task);
            }}
            className="btn-ghost text-xs py-1 px-2"
          >
            <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
            </svg>
            Edit
          </button>
          <button
            onClick={(e) => {
              e.stopPropagation();
              if (window.confirm('Are you sure you want to delete this task?')) {
                onDelete(task.id);
              }
            }}
            className="text-red-600 hover:text-red-700 text-xs font-medium py-1 px-2 rounded-lg hover:bg-red-50 transition-colors"
          >
            <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
            </svg>
            Delete
          </button>
        </div>
      </div>

      {/* Metadata */}
      <div className="mt-3 text-xs text-slate-400 flex items-center justify-between">
        <span>Created: {formatDate(task.createdAt)}</span>
        {task.updatedAt !== task.createdAt && (
          <span>Updated: {formatDate(task.updatedAt)}</span>
        )}
      </div>
    </div>
  );
};

export default TaskCard;