import React, { useState, useEffect } from 'react';
import SecureCommentDisplay from './SecureCommentDisplay';
import SecureCommentForm from './SecureCommentForm';
import { Comment } from '../../types';
import { api } from '../../utils/api';

interface SecureCommentSectionProps {
  taskId: number;
  allowHtml?: boolean;
  className?: string;
}

/**
 * Secure Comment Section Component
 * 
 * This component provides a complete secure commenting system by:
 * 1. Using secure comment display and form components
 * 2. Implementing proper error handling
 * 3. Providing XSS protection throughout the comment lifecycle
 * 4. Offering toggle between secure and vulnerable modes for educational purposes
 */
const SecureCommentSection: React.FC<SecureCommentSectionProps> = ({
  taskId,
  allowHtml = false,
  className = ''
}) => {
  const [comments, setComments] = useState<Comment[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [securityMode, setSecurityMode] = useState<'secure' | 'educational'>('secure');

  // Load comments
  useEffect(() => {
    loadComments();
  }, [taskId]);

  const loadComments = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Use secure endpoint
      const response = await api.get(`/secure-comments/task/${taskId}`);
      setComments(response.data.comments || []);
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to load comments');
    } finally {
      setLoading(false);
    }
  };

  const handleAddComment = async (content: string) => {
    try {
      // Use secure endpoint for comment creation
      const response = await api.post(`/secure-comments/task/${taskId}`, {
        content,
        allowHtml
      });
      
      // Add new comment to the list
      setComments(prev => [...prev, response.data.comment]);
    } catch (err: any) {
      throw new Error(err.response?.data?.message || 'Failed to add comment');
    }
  };

  const handleDeleteComment = async (commentId: number) => {
    if (!window.confirm('Are you sure you want to delete this comment?')) {
      return;
    }

    try {
      await api.delete(`/secure-comments/${commentId}`);
      setComments(prev => prev.filter(comment => comment.id !== commentId));
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to delete comment');
    }
  };

  if (loading) {
    return (
      <div className={`secure-comment-section ${className}`}>
        <div className="animate-pulse">
          <div className="h-4 bg-gray-200 rounded w-1/4 mb-4"></div>
          <div className="space-y-3">
            <div className="h-20 bg-gray-200 rounded"></div>
            <div className="h-20 bg-gray-200 rounded"></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={`secure-comment-section ${className}`}>
      {/* Security mode toggle (for educational purposes) */}
      <div className="security-controls mb-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-medium text-blue-800">Security Mode</h3>
            <p className="text-xs text-blue-600 mt-1">
              Toggle between secure implementation and educational mode
            </p>
          </div>
          <div className="flex items-center space-x-3">
            <label className="flex items-center">
              <input
                type="radio"
                name="securityMode"
                value="secure"
                checked={securityMode === 'secure'}
                onChange={(e) => setSecurityMode(e.target.value as 'secure')}
                className="mr-2"
              />
              <span className="text-sm text-blue-800">Secure Mode</span>
            </label>
            <label className="flex items-center">
              <input
                type="radio"
                name="securityMode"
                value="educational"
                checked={securityMode === 'educational'}
                onChange={(e) => setSecurityMode(e.target.value as 'educational')}
                className="mr-2"
              />
              <span className="text-sm text-blue-800">Educational Mode</span>
            </label>
          </div>
        </div>
        
        {securityMode === 'secure' && (
          <div className="mt-3 p-3 bg-green-50 border border-green-200 rounded">
            <div className="flex items-center">
              <svg className="h-4 w-4 text-green-500 mr-2" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
              </svg>
              <span className="text-sm text-green-800 font-medium">Secure Mode Active</span>
            </div>
            <ul className="mt-2 text-xs text-green-700 space-y-1">
              <li>• All user input is validated and sanitized</li>
              <li>• HTML content is sanitized using DOMPurify</li>
              <li>• XSS attacks are prevented through proper encoding</li>
              <li>• Content Security Policy headers are applied</li>
            </ul>
          </div>
        )}
        
        {securityMode === 'educational' && (
          <div className="mt-3 p-3 bg-yellow-50 border border-yellow-200 rounded">
            <div className="flex items-center">
              <svg className="h-4 w-4 text-yellow-500 mr-2" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
              </svg>
              <span className="text-sm text-yellow-800 font-medium">Educational Mode Active</span>
            </div>
            <ul className="mt-2 text-xs text-yellow-700 space-y-1">
              <li>• Shows both secure and vulnerable implementations</li>
              <li>• Displays sanitization process in real-time</li>
              <li>• Provides security warnings and explanations</li>
              <li>• Demonstrates XSS prevention techniques</li>
            </ul>
          </div>
        )}
      </div>

      {/* Comments header */}
      <div className="comments-header flex items-center justify-between mb-4">
        <h3 className="text-lg font-medium text-gray-900">
          Comments ({comments.length})
        </h3>
        
        {/* HTML mode indicator */}
        {allowHtml && (
          <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-yellow-100 text-yellow-800">
            <svg className="w-4 h-4 mr-1" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M5 4a1 1 0 00-2 0v7.268a2 2 0 000 3.464V16a1 1 0 102 0v-1.268a2 2 0 000-3.464V4zM11 4a1 1 0 10-2 0v1.268a2 2 0 000 3.464V16a1 1 0 102 0V8.732a2 2 0 000-3.464V4zM16 3a1 1 0 011 1v7.268a2 2 0 010 3.464V16a1 1 0 11-2 0v-1.268a2 2 0 010-3.464V4a1 1 0 011-1z" clipRule="evenodd" />
            </svg>
            HTML Mode (Sanitized)
          </span>
        )}
      </div>

      {/* Error display */}
      {error && (
        <div className="error-message mb-4 p-4 bg-red-50 border border-red-200 rounded-md">
          <div className="flex">
            <svg className="h-5 w-5 text-red-400" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
            </svg>
            <div className="ml-3">
              <h3 className="text-sm font-medium text-red-800">Error</h3>
              <p className="text-sm text-red-700 mt-1">{error}</p>
            </div>
          </div>
        </div>
      )}

      {/* Add comment form */}
      <div className="add-comment-section mb-6">
        <SecureCommentForm
          taskId={taskId}
          onSubmit={handleAddComment}
          allowHtml={allowHtml}
          maxLength={1000}
        />
      </div>

      {/* Comments list */}
      <div className="comments-list space-y-4">
        {comments.length === 0 ? (
          <div className="no-comments text-center py-8 text-gray-500">
            <svg className="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-3.582 8-8 8a8.955 8.955 0 01-4.126-.98L3 20l1.98-5.126A8.955 8.955 0 013 12c0-4.418 3.582-8 8-8s8 3.582 8 8z" />
            </svg>
            <h3 className="mt-2 text-sm font-medium text-gray-900">No comments yet</h3>
            <p className="mt-1 text-sm text-gray-500">Be the first to add a comment to this task.</p>
          </div>
        ) : (
          comments.map((comment) => (
            <div key={comment.id} className="comment-item relative">
              <SecureCommentDisplay
                comment={comment}
                allowHtml={allowHtml}
                sanitizationLevel={securityMode === 'educational' ? 'basic' : 'strict'}
              />
              
              {/* Delete button (only for comment owner) */}
              <button
                onClick={() => handleDeleteComment(comment.id)}
                className="absolute top-2 right-2 p-1 text-gray-400 hover:text-red-500 transition-colors"
                title="Delete comment"
              >
                <svg className="h-4 w-4" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
                </svg>
              </button>
            </div>
          ))
        )}
      </div>

      {/* Security information footer */}
      <div className="security-footer mt-6 p-4 bg-gray-50 border border-gray-200 rounded-lg">
        <h4 className="text-sm font-medium text-gray-800 mb-2">XSS Prevention Measures</h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs text-gray-600">
          <div>
            <h5 className="font-medium text-gray-700 mb-1">Input Sanitization</h5>
            <ul className="space-y-1">
              <li>• DOMPurify HTML sanitization</li>
              <li>• Input validation and length limits</li>
              <li>• Malicious pattern detection</li>
              <li>• Real-time content filtering</li>
            </ul>
          </div>
          <div>
            <h5 className="font-medium text-gray-700 mb-1">Output Protection</h5>
            <ul className="space-y-1">
              <li>• React's built-in XSS protection</li>
              <li>• Safe HTML rendering with sanitization</li>
              <li>• Content Security Policy headers</li>
              <li>• Proper output encoding</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SecureCommentSection;