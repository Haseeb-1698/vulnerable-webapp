import React, { useState, useEffect } from 'react';
import { Comment } from '../../types';
import { commentApi } from '../../utils/api';
import CommentForm from './CommentForm';
import CommentDisplay from './CommentDisplay';

interface CommentSectionProps {
  taskId: number;
  initialComments?: Comment[];
  onCommentAdded?: (comment: Comment) => void;
  onCommentUpdated?: (comment: Comment) => void;
  onCommentDeleted?: (commentId: number) => void;
}

const CommentSection: React.FC<CommentSectionProps> = ({
  taskId,
  initialComments = [],
  onCommentAdded,
  onCommentUpdated,
  onCommentDeleted
}) => {
  const [comments, setComments] = useState<Comment[]>(initialComments);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [editingCommentId, setEditingCommentId] = useState<number | null>(null);

  // Load comments from API
  const loadComments = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await commentApi.getTaskComments(taskId);
      setComments(response.comments || []);
      
      // VULNERABILITY: Log access information
      if (response.accessInfo) {
        console.log('Comment access info:', response.accessInfo);
        if (!response.accessInfo.isTaskOwner) {
          console.warn('⚠️  Accessing comments for task owned by another user (IDOR vulnerability)');
        }
      }
      
    } catch (err) {
      console.error('Failed to load comments:', err);
      setError(err instanceof Error ? err.message : 'Failed to load comments');
    } finally {
      setLoading(false);
    }
  };

  // Load comments on mount if not provided initially
  useEffect(() => {
    if (initialComments.length === 0) {
      loadComments();
    }
  }, [taskId]);

  // Handle new comment creation
  const handleCommentAdded = async (content: string) => {
    try {
      setError(null);
      
      // VULNERABILITY: Log the raw content being submitted
      console.log('🔍 SUBMITTING COMMENT:');
      console.log('📝 Raw Content:', content);
      console.log('📋 Task ID:', taskId);
      console.log('⚠️  Content will be stored without sanitization!');
      console.log('─'.repeat(80));
      
      const response = await commentApi.createComment(taskId, { content });
      const newComment = response.comment;
      
      setComments(prev => [...prev, newComment]);
      
      // VULNERABILITY: Log security information from response
      if (response.securityInfo) {
        console.warn('Security Info:', response.securityInfo);
      }
      
      if (response.xssTestingHints) {
        console.log('XSS Testing Hints:', response.xssTestingHints);
      }
      
      if (onCommentAdded) {
        onCommentAdded(newComment);
      }
      
    } catch (err) {
      console.error('Failed to create comment:', err);
      setError(err instanceof Error ? err.message : 'Failed to create comment');
    }
  };

  // Handle comment update
  const handleCommentUpdated = async (commentId: number, content: string) => {
    try {
      setError(null);
      
      // VULNERABILITY: Log the update attempt
      console.log('🔍 UPDATING COMMENT:');
      console.log('📝 Comment ID:', commentId);
      console.log('📝 New Content:', content);
      console.log('⚠️  No ownership verification will be performed!');
      console.log('─'.repeat(80));
      
      const response = await commentApi.updateComment(commentId, { content });
      const updatedComment = response.comment;
      
      setComments(prev => 
        prev.map(comment => 
          comment.id === commentId ? updatedComment : comment
        )
      );
      
      setEditingCommentId(null);
      
      // VULNERABILITY: Log ownership information from response
      if (response.ownershipInfo) {
        console.warn('Ownership Info:', response.ownershipInfo);
      }
      
      if (onCommentUpdated) {
        onCommentUpdated(updatedComment);
      }
      
    } catch (err) {
      console.error('Failed to update comment:', err);
      setError(err instanceof Error ? err.message : 'Failed to update comment');
    }
  };

  // Handle comment deletion
  const handleCommentDeleted = async (commentId: number) => {
    if (!window.confirm('Are you sure you want to delete this comment?')) {
      return;
    }
    
    try {
      setError(null);
      
      // VULNERABILITY: Log the deletion attempt
      console.log('🔍 DELETING COMMENT:');
      console.log('📝 Comment ID:', commentId);
      console.log('⚠️  No authorization check will be performed!');
      console.log('─'.repeat(80));
      
      const response = await commentApi.deleteComment(commentId);
      
      setComments(prev => prev.filter(comment => comment.id !== commentId));
      
      // VULNERABILITY: Log authorization information from response
      if (response.authorizationInfo) {
        console.warn('Authorization Info:', response.authorizationInfo);
      }
      
      if (onCommentDeleted) {
        onCommentDeleted(commentId);
      }
      
    } catch (err) {
      console.error('Failed to delete comment:', err);
      setError(err instanceof Error ? err.message : 'Failed to delete comment');
    }
  };

  // Handle edit mode toggle
  const handleEditToggle = (commentId: number | null) => {
    setEditingCommentId(commentId);
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center py-8">
        <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
        <span className="ml-2 text-gray-600">Loading comments...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <h3 className="text-xl font-semibold text-gray-900">
          Comments ({comments.length})
        </h3>
        
        {/* VULNERABILITY: Show XSS testing buttons for educational purposes */}
        <div className="flex space-x-2">
          <button
            onClick={() => handleCommentAdded('<script>alert("Basic XSS Test")</script>')}
            className="text-xs bg-red-100 text-red-800 px-2 py-1 rounded border border-red-200 hover:bg-red-200"
            title="Test XSS vulnerability"
          >
            Test XSS
          </button>
          <button
            onClick={() => handleCommentAdded('<img src=x onerror="alert(\'Image XSS Test\')">')}
            className="text-xs bg-orange-100 text-orange-800 px-2 py-1 rounded border border-orange-200 hover:bg-orange-200"
            title="Test Image XSS vulnerability"
          >
            Test Img XSS
          </button>
          <button
            onClick={() => handleCommentAdded('<svg onload="alert(\'SVG XSS Test\')">')}
            className="text-xs bg-yellow-100 text-yellow-800 px-2 py-1 rounded border border-yellow-200 hover:bg-yellow-200"
            title="Test SVG XSS vulnerability"
          >
            Test SVG XSS
          </button>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-md p-4">
          <div className="text-red-800">
            <strong>Error:</strong> {error}
          </div>
        </div>
      )}

      {/* Comment Form */}
      <CommentForm 
        onSubmit={handleCommentAdded}
        placeholder="Add a comment... (HTML and JavaScript allowed for XSS testing)"
      />

      {/* Comments List */}
      <div className="space-y-4">
        {comments.length > 0 ? (
          comments.map((comment) => (
            <CommentDisplay
              key={comment.id}
              comment={comment}
              isEditing={editingCommentId === comment.id}
              onEdit={() => handleEditToggle(comment.id)}
              onCancelEdit={() => handleEditToggle(null)}
              onSave={(content) => handleCommentUpdated(comment.id, content)}
              onDelete={() => handleCommentDeleted(comment.id)}
            />
          ))
        ) : (
          <div className="text-center py-8 text-gray-500 bg-gray-50 rounded-lg border-2 border-dashed border-gray-200">
            <div className="text-lg mb-2">No comments yet</div>
            <div className="text-sm">Be the first to add a comment!</div>
            <div className="text-xs mt-2 text-red-600">
              ⚠️ This comment system is vulnerable to XSS attacks for educational purposes
            </div>
          </div>
        )}
      </div>

      {/* VULNERABILITY: Display security information */}
      <div className="mt-6 p-4 bg-red-50 border border-red-200 rounded-lg">
        <h4 className="text-sm font-semibold text-red-800 mb-2">🚨 Security Vulnerabilities Present</h4>
        <ul className="text-xs text-red-700 space-y-1">
          <li>• <strong>XSS (Cross-Site Scripting):</strong> Comments are rendered without sanitization using dangerouslySetInnerHTML</li>
          <li>• <strong>IDOR (Insecure Direct Object References):</strong> Can view/edit/delete comments from other users' tasks</li>
          <li>• <strong>Authorization Bypass:</strong> No ownership verification for comment operations</li>
          <li>• <strong>Input Validation:</strong> No client-side or server-side HTML sanitization</li>
          <li>• <strong>Information Disclosure:</strong> Detailed error messages and security info exposed</li>
        </ul>
        <div className="mt-2 text-xs text-red-600">
          This is intentionally vulnerable for educational purposes. In production, implement proper sanitization and authorization.
        </div>
      </div>
    </div>
  );
};

export default CommentSection;