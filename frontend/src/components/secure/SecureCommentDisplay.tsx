import React from 'react';
import { sanitizeHtml, escapeHtml } from '../../utils/xssPrevention';
import { Comment } from '../../types';

interface SecureCommentDisplayProps {
  comment: Comment;
  allowHtml?: boolean;
  sanitizationLevel?: 'strict' | 'basic' | 'textOnly';
  className?: string;
}

/**
 * Secure Comment Display Component
 * 
 * This component safely displays user-generated content by:
 * 1. Sanitizing HTML content using DOMPurify
 * 2. Escaping HTML entities when HTML is not allowed
 * 3. Providing different sanitization levels
 * 4. Never using dangerouslySetInnerHTML without sanitization
 */
const SecureCommentDisplay: React.FC<SecureCommentDisplayProps> = ({
  comment,
  allowHtml = false,
  sanitizationLevel = 'strict',
  className = ''
}) => {
  // Safely render comment content
  const renderContent = () => {
    if (!comment.content) {
      return <span className="text-gray-500 italic">No content</span>;
    }

    if (allowHtml) {
      // Sanitize HTML content before rendering
      const sanitizedContent = sanitizeHtml(comment.content, sanitizationLevel);
      
      return (
        <div 
          className="prose prose-sm max-w-none"
          // SECURITY: Only use dangerouslySetInnerHTML with sanitized content
          dangerouslySetInnerHTML={{ __html: sanitizedContent }}
        />
      );
    } else {
      // For text-only content, use React's built-in XSS protection
      return (
        <div className="whitespace-pre-wrap">
          {comment.content}
        </div>
      );
    }
  };

  // Format date safely
  const formatDate = (date: string | Date) => {
    try {
      return new Date(date).toLocaleString();
    } catch (error) {
      return 'Invalid date';
    }
  };

  return (
    <div className={`comment-display bg-gray-50 p-4 rounded-lg ${className}`}>
      <div className="comment-header flex justify-between items-start mb-2">
        <div className="author-info">
          <span className="font-medium text-gray-900">
            {/* SECURITY: React automatically escapes these values */}
            {comment.user.firstName} {comment.user.lastName}
          </span>
          <span className="text-sm text-gray-500 ml-2">
            {formatDate(comment.createdAt)}
          </span>
        </div>
        
        {/* Security indicator */}
        <div className="security-indicator">
          {allowHtml ? (
            <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
              <svg className="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
              </svg>
              HTML Sanitized
            </span>
          ) : (
            <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
              <svg className="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
              </svg>
              Text Only
            </span>
          )}
        </div>
      </div>
      
      <div className="comment-content">
        {renderContent()}
      </div>
      
      {/* Show original content in development for comparison */}
      {process.env.NODE_ENV === 'development' && allowHtml && (
        <details className="mt-4 p-2 bg-gray-100 rounded text-xs">
          <summary className="cursor-pointer font-medium">Debug: Original Content</summary>
          <pre className="mt-2 whitespace-pre-wrap break-all">
            {comment.content}
          </pre>
        </details>
      )}
    </div>
  );
};

export default SecureCommentDisplay;