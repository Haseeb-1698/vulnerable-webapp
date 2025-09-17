import React, { useState } from 'react';
import { Comment } from '../../types';
import CommentForm from './CommentForm';

interface CommentDisplayProps {
  comment: Comment;
  isEditing?: boolean;
  onEdit?: () => void;
  onCancelEdit?: () => void;
  onSave?: (content: string) => Promise<void> | void;
  onDelete?: () => void;
  showActions?: boolean;
}

const CommentDisplay: React.FC<CommentDisplayProps> = ({
  comment,
  isEditing = false,
  onEdit,
  onCancelEdit,
  onSave,
  onDelete,
  showActions = true
}) => {
  const [showRawContent, setShowRawContent] = useState(false);

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getRelativeTime = (dateString: string) => {
    const now = new Date();
    const commentDate = new Date(dateString);
    const diffInSeconds = Math.floor((now.getTime() - commentDate.getTime()) / 1000);
    
    if (diffInSeconds < 60) return 'just now';
    if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)}m ago`;
    if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)}h ago`;
    if (diffInSeconds < 604800) return `${Math.floor(diffInSeconds / 86400)}d ago`;
    
    return formatDate(dateString);
  };

  // VULNERABILITY: Detect potential XSS content for educational display
  const detectXSSContent = (content: string) => {
    const xssPatterns = [
      /<script/i,
      /javascript:/i,
      /onerror=/i,
      /onload=/i,
      /onclick=/i,
      /onmouseover=/i,
      /<iframe/i,
      /<object/i,
      /<embed/i,
      /<svg/i
    ];
    
    return xssPatterns.some(pattern => pattern.test(content));
  };

  const hasXSSContent = detectXSSContent(comment.content);

  if (isEditing && onSave && onCancelEdit) {
    return (
      <div className="border border-blue-200 bg-blue-50 rounded-lg p-4">
        <div className="text-sm font-medium text-blue-800 mb-3">
          Editing comment by {comment.user?.firstName} {comment.user?.lastName}
        </div>
        <CommentForm
          onSubmit={onSave}
          initialContent={comment.content}
          submitButtonText="Save Changes"
          cancelButtonText="Cancel"
          onCancel={onCancelEdit}
          showCancel={true}
          allowRichText={true}
        />
      </div>
    );
  }

  return (
    <div className={`border rounded-lg p-4 ${hasXSSContent ? 'border-red-300 bg-red-50' : 'border-gray-200 bg-white'}`}>
      {/* Header */}
      <div className="flex justify-between items-start mb-3">
        <div className="flex items-center space-x-2">
          {/* User avatar placeholder */}
          <div className="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center text-white text-sm font-medium">
            {comment.user?.firstName?.[0]?.toUpperCase() || '?'}
          </div>
          
          <div>
            <div className="font-medium text-gray-900">
              {comment.user?.firstName} {comment.user?.lastName}
            </div>
            <div className="text-sm text-gray-500" title={formatDate(comment.createdAt)}>
              {getRelativeTime(comment.createdAt)}
              {comment.updatedAt !== comment.createdAt && (
                <span className="ml-1 text-xs">(edited)</span>
              )}
            </div>
          </div>
        </div>

        {/* Actions */}
        {showActions && (
          <div className="flex items-center space-x-2">
            {/* XSS indicator */}
            {hasXSSContent && (
              <span className="text-xs bg-red-200 text-red-800 px-2 py-1 rounded border border-red-300">
                ⚠️ XSS
              </span>
            )}
            
            {/* Raw content toggle */}
            <button
              onClick={() => setShowRawContent(!showRawContent)}
              className="text-xs bg-gray-100 text-gray-700 px-2 py-1 rounded hover:bg-gray-200"
              title="Toggle raw HTML view"
            >
              {showRawContent ? 'Rendered' : 'Raw HTML'}
            </button>
            
            {onEdit && (
              <button
                onClick={onEdit}
                className="text-xs bg-blue-100 text-blue-800 px-2 py-1 rounded hover:bg-blue-200"
                title="Edit comment (IDOR vulnerability - can edit any comment)"
              >
                Edit
              </button>
            )}
            
            {onDelete && (
              <button
                onClick={onDelete}
                className="text-xs bg-red-100 text-red-800 px-2 py-1 rounded hover:bg-red-200"
                title="Delete comment (Authorization vulnerability - can delete any comment)"
              >
                Delete
              </button>
            )}
          </div>
        )}
      </div>

      {/* Content */}
      <div className="space-y-3">
        {showRawContent ? (
          /* Raw HTML content display */
          <div className="bg-gray-100 border border-gray-300 rounded p-3">
            <div className="text-xs font-semibold text-gray-700 mb-2">Raw HTML Content:</div>
            <pre className="text-sm text-gray-800 whitespace-pre-wrap font-mono">
              {comment.content}
            </pre>
          </div>
        ) : (
          /* VULNERABILITY: Rendered content using dangerouslySetInnerHTML */
          <div className="prose max-w-none">
            <div 
              className="text-gray-700"
              dangerouslySetInnerHTML={{ __html: comment.content }}
            />
          </div>
        )}

        {/* XSS Warning */}
        {hasXSSContent && (
          <div className="bg-red-100 border border-red-300 rounded p-2">
            <div className="text-xs font-semibold text-red-800 mb-1">
              🚨 XSS Content Detected
            </div>
            <div className="text-xs text-red-700">
              This comment contains potentially malicious JavaScript code that will execute when displayed. 
              This demonstrates the XSS vulnerability in the comment system.
            </div>
          </div>
        )}
      </div>

      {/* Comment metadata for debugging */}
      <details className="mt-3">
        <summary className="cursor-pointer text-xs text-gray-500 hover:text-gray-700">
          🔍 Debug Info (Click to expand)
        </summary>
        <div className="mt-2 text-xs bg-gray-50 border border-gray-200 rounded p-2">
          <div><strong>Comment ID:</strong> {comment.id}</div>
          <div><strong>Task ID:</strong> {comment.taskId}</div>
          <div><strong>User ID:</strong> {comment.userId}</div>
          <div><strong>Created:</strong> {formatDate(comment.createdAt)}</div>
          <div><strong>Updated:</strong> {formatDate(comment.updatedAt)}</div>
          <div><strong>Content Length:</strong> {comment.content.length} characters</div>
          <div><strong>Has XSS:</strong> {hasXSSContent ? 'Yes' : 'No'}</div>
          <div className="mt-1 text-red-600">
            <strong>Vulnerabilities:</strong> Content rendered without sanitization (XSS), 
            Edit/Delete actions don't verify ownership (IDOR)
          </div>
        </div>
      </details>
    </div>
  );
};

export default CommentDisplay;