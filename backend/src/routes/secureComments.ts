import express from 'express';
import { body, validationResult } from 'express-validator';
import { PrismaClient } from '@prisma/client';
import { authenticateUser } from '../middleware/auth.js';
import DOMPurify from 'isomorphic-dompurify';
import helmet from 'helmet';

const router = express.Router();
const prisma = new PrismaClient();

/**
 * Secure Comments Routes
 * 
 * This module provides secure comment handling with:
 * 1. HTML sanitization using DOMPurify
 * 2. Content Security Policy (CSP) headers
 * 3. Proper input validation and output encoding
 * 4. XSS prevention mechanisms
 */

// Apply security headers
router.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      fontSrc: ["'self'", "https:"],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));

/**
 * HTML Sanitization Configuration
 */
const sanitizerConfig = {
  strict: {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'u', 'br', 'p', 'span'],
    ALLOWED_ATTR: ['class'],
    FORBID_TAGS: ['script', 'object', 'embed', 'form', 'input', 'iframe', 'meta', 'link', 'style'],
    FORBID_ATTR: ['onclick', 'onload', 'onerror', 'onmouseover', 'onfocus', 'onblur', 'style', 'href', 'src'],
    ALLOW_DATA_ATTR: false,
    ALLOW_UNKNOWN_PROTOCOLS: false,
    SANITIZE_DOM: true,
    KEEP_CONTENT: true
  },
  basic: {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'u', 'br', 'p', 'span', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ul', 'ol', 'li', 'blockquote', 'code', 'pre'],
    ALLOWED_ATTR: ['class'],
    FORBID_TAGS: ['script', 'object', 'embed', 'form', 'input', 'iframe', 'meta', 'link', 'style'],
    FORBID_ATTR: ['onclick', 'onload', 'onerror', 'onmouseover', 'onfocus', 'onblur', 'style', 'href', 'src'],
    ALLOW_DATA_ATTR: false,
    ALLOW_UNKNOWN_PROTOCOLS: false,
    SANITIZE_DOM: true,
    KEEP_CONTENT: true
  }
};

/**
 * Sanitize HTML content
 */
const sanitizeHtml = (html: string, level: 'strict' | 'basic' = 'strict'): string => {
  if (!html || typeof html !== 'string') {
    return '';
  }
  
  const config = sanitizerConfig[level];
  return DOMPurify.sanitize(html, config);
};

/**
 * Validate comment content
 */
const validateCommentContent = (content: string, allowHtml: boolean = false): { isValid: boolean; sanitizedContent: string; errors: string[] } => {
  const errors: string[] = [];
  
  if (!content || typeof content !== 'string') {
    errors.push('Comment content is required');
    return { isValid: false, sanitizedContent: '', errors };
  }
  
  const trimmedContent = content.trim();
  
  if (trimmedContent.length === 0) {
    errors.push('Comment cannot be empty');
    return { isValid: false, sanitizedContent: '', errors };
  }
  
  if (trimmedContent.length > 1000) {
    errors.push('Comment must be less than 1000 characters');
  }
  
  // Check for potentially malicious patterns
  const suspiciousPatterns = [
    /javascript:/i,
    /vbscript:/i,
    /data:text\/html/i,
    /data:application\/javascript/i,
    /<script[\s\S]*?>[\s\S]*?<\/script>/gi,
    /<iframe[\s\S]*?>[\s\S]*?<\/iframe>/gi
  ];
  
  for (const pattern of suspiciousPatterns) {
    if (pattern.test(content)) {
      errors.push('Comment contains potentially malicious content');
      break;
    }
  }
  
  // Sanitize content
  let sanitizedContent: string;
  if (allowHtml) {
    sanitizedContent = sanitizeHtml(trimmedContent, 'basic');
  } else {
    // For text-only content, escape HTML entities
    sanitizedContent = trimmedContent
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');
  }
  
  return {
    isValid: errors.length === 0,
    sanitizedContent,
    errors
  };
};

/**
 * SECURE Get Comments for Task
 * GET /api/secure-comments/task/:taskId
 */
router.get('/task/:taskId', authenticateUser, async (req, res) => {
  try {
    const taskId = parseInt(req.params.taskId);
    
    if (isNaN(taskId) || taskId <= 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid task ID',
        message: 'Task ID must be a positive integer'
      });
    }
    
    // Verify task exists and user has access
    const task = await prisma.task.findFirst({
      where: {
        id: taskId,
        userId: req.user!.id // Ensure user owns the task
      },
      select: { id: true }
    });
    
    if (!task) {
      return res.status(404).json({
        success: false,
        error: 'Task not found',
        message: 'Task not found or access denied'
      });
    }
    
    // Get comments for the task
    const comments = await prisma.comment.findMany({
      where: { taskId },
      include: {
        user: {
          select: {
            id: true,
            firstName: true,
            lastName: true
            // SECURITY: Never expose sensitive data like email or password
          }
        }
      },
      orderBy: { createdAt: 'asc' }
    });
    
    res.json({
      success: true,
      comments,
      taskId,
      count: comments.length
    });
    
  } catch (error) {
    console.error('Secure get comments error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve comments',
      message: 'An error occurred while retrieving comments'
    });
  }
});

/**
 * SECURE Create Comment
 * POST /api/secure-comments/task/:taskId
 */
router.post('/task/:taskId', authenticateUser, [
  body('content')
    .trim()
    .isLength({ min: 1, max: 1000 })
    .withMessage('Comment content is required and must be between 1-1000 characters'),
  body('allowHtml')
    .optional()
    .isBoolean()
    .withMessage('allowHtml must be a boolean value')
], async (req, res) => {
  try {
    // Check validation results
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        details: errors.array()
      });
    }
    
    const taskId = parseInt(req.params.taskId);
    const { content, allowHtml = false } = req.body;
    
    if (isNaN(taskId) || taskId <= 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid task ID',
        message: 'Task ID must be a positive integer'
      });
    }
    
    // Verify task exists and user has access
    const task = await prisma.task.findFirst({
      where: {
        id: taskId,
        userId: req.user!.id // Ensure user owns the task
      },
      select: { id: true }
    });
    
    if (!task) {
      return res.status(404).json({
        success: false,
        error: 'Task not found',
        message: 'Task not found or access denied'
      });
    }
    
    // Validate and sanitize comment content
    const validation = validateCommentContent(content, allowHtml);
    
    if (!validation.isValid) {
      return res.status(400).json({
        success: false,
        error: 'Content validation failed',
        details: validation.errors
      });
    }
    
    // Create comment with sanitized content
    const newComment = await prisma.comment.create({
      data: {
        content: validation.sanitizedContent,
        taskId,
        userId: req.user!.id
      },
      include: {
        user: {
          select: {
            id: true,
            firstName: true,
            lastName: true
          }
        }
      }
    });
    
    res.status(201).json({
      success: true,
      message: 'Comment created successfully',
      comment: newComment,
      sanitization: {
        originalLength: content.length,
        sanitizedLength: validation.sanitizedContent.length,
        htmlAllowed: allowHtml,
        wasSanitized: content !== validation.sanitizedContent
      }
    });
    
  } catch (error) {
    console.error('Secure create comment error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to create comment',
      message: 'An error occurred while creating the comment'
    });
  }
});

/**
 * SECURE Update Comment
 * PUT /api/secure-comments/:id
 */
router.put('/:id', authenticateUser, [
  body('content')
    .trim()
    .isLength({ min: 1, max: 1000 })
    .withMessage('Comment content is required and must be between 1-1000 characters'),
  body('allowHtml')
    .optional()
    .isBoolean()
    .withMessage('allowHtml must be a boolean value')
], async (req, res) => {
  try {
    // Check validation results
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        details: errors.array()
      });
    }
    
    const commentId = parseInt(req.params.id);
    const { content, allowHtml = false } = req.body;
    
    if (isNaN(commentId) || commentId <= 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid comment ID',
        message: 'Comment ID must be a positive integer'
      });
    }
    
    // Verify comment exists and user owns it
    const existingComment = await prisma.comment.findFirst({
      where: {
        id: commentId,
        userId: req.user!.id // Ensure user owns the comment
      },
      include: {
        task: {
          select: { userId: true }
        }
      }
    });
    
    if (!existingComment) {
      return res.status(404).json({
        success: false,
        error: 'Comment not found',
        message: 'Comment not found or access denied'
      });
    }
    
    // Additional check: user must own the task or the comment
    if (existingComment.userId !== req.user!.id && existingComment.task.userId !== req.user!.id) {
      return res.status(403).json({
        success: false,
        error: 'Access denied',
        message: 'You can only edit your own comments'
      });
    }
    
    // Validate and sanitize comment content
    const validation = validateCommentContent(content, allowHtml);
    
    if (!validation.isValid) {
      return res.status(400).json({
        success: false,
        error: 'Content validation failed',
        details: validation.errors
      });
    }
    
    // Update comment with sanitized content
    const updatedComment = await prisma.comment.update({
      where: { id: commentId },
      data: { content: validation.sanitizedContent },
      include: {
        user: {
          select: {
            id: true,
            firstName: true,
            lastName: true
          }
        }
      }
    });
    
    res.json({
      success: true,
      message: 'Comment updated successfully',
      comment: updatedComment,
      sanitization: {
        originalLength: content.length,
        sanitizedLength: validation.sanitizedContent.length,
        htmlAllowed: allowHtml,
        wasSanitized: content !== validation.sanitizedContent
      }
    });
    
  } catch (error) {
    console.error('Secure update comment error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update comment',
      message: 'An error occurred while updating the comment'
    });
  }
});

/**
 * SECURE Delete Comment
 * DELETE /api/secure-comments/:id
 */
router.delete('/:id', authenticateUser, async (req, res) => {
  try {
    const commentId = parseInt(req.params.id);
    
    if (isNaN(commentId) || commentId <= 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid comment ID',
        message: 'Comment ID must be a positive integer'
      });
    }
    
    // Verify comment exists and user has permission to delete
    const existingComment = await prisma.comment.findFirst({
      where: { id: commentId },
      include: {
        task: {
          select: { userId: true }
        }
      }
    });
    
    if (!existingComment) {
      return res.status(404).json({
        success: false,
        error: 'Comment not found',
        message: 'Comment not found'
      });
    }
    
    // User can delete if they own the comment OR own the task
    const canDelete = existingComment.userId === req.user!.id || existingComment.task.userId === req.user!.id;
    
    if (!canDelete) {
      return res.status(403).json({
        success: false,
        error: 'Access denied',
        message: 'You can only delete your own comments or comments on your tasks'
      });
    }
    
    // Delete the comment
    await prisma.comment.delete({
      where: { id: commentId }
    });
    
    res.json({
      success: true,
      message: 'Comment deleted successfully',
      deletedCommentId: commentId
    });
    
  } catch (error) {
    console.error('Secure delete comment error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete comment',
      message: 'An error occurred while deleting the comment'
    });
  }
});

/**
 * SECURE Get Comment by ID
 * GET /api/secure-comments/:id
 */
router.get('/:id', authenticateUser, async (req, res) => {
  try {
    const commentId = parseInt(req.params.id);
    
    if (isNaN(commentId) || commentId <= 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid comment ID',
        message: 'Comment ID must be a positive integer'
      });
    }
    
    // Get comment with access control
    const comment = await prisma.comment.findFirst({
      where: {
        id: commentId,
        OR: [
          { userId: req.user!.id }, // User owns the comment
          { task: { userId: req.user!.id } } // User owns the task
        ]
      },
      include: {
        user: {
          select: {
            id: true,
            firstName: true,
            lastName: true
          }
        },
        task: {
          select: {
            id: true,
            title: true,
            userId: true
          }
        }
      }
    });
    
    if (!comment) {
      return res.status(404).json({
        success: false,
        error: 'Comment not found',
        message: 'Comment not found or access denied'
      });
    }
    
    res.json({
      success: true,
      comment
    });
    
  } catch (error) {
    console.error('Secure get comment error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve comment',
      message: 'An error occurred while retrieving the comment'
    });
  }
});

/**
 * SECURE Bulk Comment Operations
 * POST /api/secure-comments/bulk
 */
router.post('/bulk', authenticateUser, [
  body('action')
    .isIn(['delete'])
    .withMessage('Action must be delete'),
  body('commentIds')
    .isArray({ min: 1, max: 50 })
    .withMessage('Comment IDs must be a non-empty array with maximum 50 items'),
  body('commentIds.*')
    .isInt({ min: 1 })
    .withMessage('Each comment ID must be a positive integer')
], async (req, res) => {
  try {
    // Check validation results
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        details: errors.array()
      });
    }
    
    const { action, commentIds } = req.body;
    
    if (action === 'delete') {
      // Get comments that user can delete (owns comment or owns task)
      const deletableComments = await prisma.comment.findMany({
        where: {
          id: { in: commentIds },
          OR: [
            { userId: req.user!.id }, // User owns the comment
            { task: { userId: req.user!.id } } // User owns the task
          ]
        },
        select: { id: true }
      });
      
      const deletableIds = deletableComments.map(c => c.id);
      
      // Delete the comments
      const result = await prisma.comment.deleteMany({
        where: { id: { in: deletableIds } }
      });
      
      res.json({
        success: true,
        message: `Successfully deleted ${result.count} comment(s)`,
        deletedCount: result.count,
        requestedCount: commentIds.length,
        skippedCount: commentIds.length - result.count
      });
    }
    
  } catch (error) {
    console.error('Secure bulk comment operation error:', error);
    res.status(500).json({
      success: false,
      error: 'Bulk operation failed',
      message: 'An error occurred during the bulk operation'
    });
  }
});

export default router;