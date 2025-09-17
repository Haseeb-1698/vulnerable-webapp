import express from 'express';
import { body, validationResult } from 'express-validator';
import { PrismaClient } from '@prisma/client';
import { authenticateUser } from '../middleware/auth.js';

const router = express.Router();
const prisma = new PrismaClient();

/**
 * Get Comments for Task Endpoint
 * GET /api/comments/task/:taskId
 * VULNERABILITY: No authorization check - allows viewing comments for any task
 */
router.get('/task/:taskId', authenticateUser, async (req: express.Request, res: express.Response) => {
  try {
    const { taskId } = req.params;
    const taskIdNum = parseInt(taskId!);

    if (isNaN(taskIdNum)) {
      return res.status(400).json({
        error: 'Invalid task ID',
        message: 'Task ID must be a valid number'
      });
    }

    // VULNERABILITY: No ownership verification - allows viewing comments for any task
    const comments = await prisma.comment.findMany({
      where: { taskId: taskIdNum },
      include: {
        user: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true
          }
        },
        task: {
          select: {
            id: true,
            title: true,
            userId: true
          }
        }
      },
      orderBy: { createdAt: 'asc' }
    });

    // Check if task exists
    const task = await prisma.task.findUnique({
      where: { id: taskIdNum },
      select: { id: true, userId: true, title: true }
    });

    if (!task) {
      return res.status(404).json({
        error: 'Task not found',
        message: 'No task found with the specified ID'
      });
    }

    res.json({
      comments,
      taskInfo: task,
      // VULNERABILITY: Expose ownership information
      accessInfo: {
        taskOwnerId: task.userId,
        requestUserId: req.user!.id,
        isTaskOwner: task.userId === req.user!.id,
        vulnerability: 'This endpoint allows viewing comments for tasks owned by other users'
      }
    });

  } catch (error) {
    console.error('Get comments error:', error);
    
    // VULNERABILITY: Exposing internal database errors
    res.status(500).json({
      error: 'Failed to retrieve comments',
      details: error instanceof Error ? error.message : 'Unknown error',
      stack: process.env.NODE_ENV === 'development' ? (error as Error).stack : undefined
    });
  }
});

/**
 * Create Comment Endpoint
 * POST /api/comments/task/:taskId
 * VULNERABILITY: No input sanitization - allows XSS through comment content
 */
router.post('/task/:taskId', authenticateUser, [
  body('content')
    .trim()
    .isLength({ min: 1, max: 5000 })
    .withMessage('Comment content is required and must be between 1-5000 characters')
], async (req: express.Request, res: express.Response) => {
  try {
    // Check validation results
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { taskId } = req.params;
    const { content } = req.body;
    const taskIdNum = parseInt(taskId!);

    if (isNaN(taskIdNum)) {
      return res.status(400).json({
        error: 'Invalid task ID',
        message: 'Task ID must be a valid number'
      });
    }

    // Check if task exists
    const task = await prisma.task.findUnique({
      where: { id: taskIdNum },
      select: { id: true, userId: true, title: true }
    });

    if (!task) {
      return res.status(404).json({
        error: 'Task not found',
        message: 'No task found with the specified ID'
      });
    }

    // VULNERABILITY: No input sanitization - store raw HTML/JavaScript content
    // This allows XSS attacks through comment content
    const newComment = await prisma.comment.create({
      data: {
        taskId: taskIdNum,
        userId: req.user!.id,
        content: content // VULNERABILITY: Raw content without sanitization
      },
      include: {
        user: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true
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

    // VULNERABILITY: Log the raw content for debugging (exposes XSS payloads)
    console.log('🔍 NEW COMMENT CREATED:');
    console.log('📝 Raw Content:', content);
    console.log('👤 User ID:', req.user!.id);
    console.log('📋 Task ID:', taskIdNum);
    console.log('⏰ Timestamp:', new Date().toISOString());
    console.log('🚨 WARNING: Content not sanitized - XSS vulnerability!');
    console.log('─'.repeat(80));

    res.status(201).json({
      message: 'Comment created successfully',
      comment: newComment,
      // VULNERABILITY: Expose security information
      securityInfo: {
        contentSanitized: false,
        xssVulnerability: true,
        rawContentStored: true,
        vulnerability: 'Comment content is stored without sanitization, allowing XSS attacks'
      },
      // VULNERABILITY: Provide XSS testing hints
      xssTestingHints: {
        basicXSS: '<script>alert("XSS")</script>',
        imageXSS: '<img src=x onerror="alert(document.cookie)">',
        svgXSS: '<svg onload="alert(\'XSS via SVG\')">',
        iframeXSS: '<iframe src="javascript:alert(\'XSS via iframe\')"></iframe>'
      }
    });

  } catch (error) {
    console.error('Comment creation error:', error);
    
    // VULNERABILITY: Exposing internal database errors
    res.status(500).json({
      error: 'Comment creation failed',
      details: error instanceof Error ? error.message : 'Unknown error',
      stack: process.env.NODE_ENV === 'development' ? (error as Error).stack : undefined
    });
  }
});

/**
 * Update Comment Endpoint
 * PUT /api/comments/:id
 * VULNERABILITY: No ownership verification - allows editing any comment
 */
router.put('/:id', authenticateUser, [
  body('content')
    .trim()
    .isLength({ min: 1, max: 5000 })
    .withMessage('Comment content is required and must be between 1-5000 characters')
], async (req: express.Request, res: express.Response) => {
  try {
    // Check validation results
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { id } = req.params;
    const { content } = req.body;
    const commentId = parseInt(id!);

    if (isNaN(commentId)) {
      return res.status(400).json({
        error: 'Invalid comment ID',
        message: 'Comment ID must be a valid number'
      });
    }

    // Check if comment exists
    const existingComment = await prisma.comment.findUnique({
      where: { id: commentId },
      select: { id: true, userId: true, content: true, taskId: true }
    });

    if (!existingComment) {
      return res.status(404).json({
        error: 'Comment not found',
        message: 'No comment found with the specified ID'
      });
    }

    // VULNERABILITY: No ownership verification - allows editing any comment
    // VULNERABILITY: No input sanitization - allows XSS through updated content
    const updatedComment = await prisma.comment.update({
      where: { id: commentId },
      data: {
        content: content // VULNERABILITY: Raw content without sanitization
      },
      include: {
        user: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true
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

    // VULNERABILITY: Log the update details
    console.log('🔍 COMMENT UPDATED:');
    console.log('📝 Old Content:', existingComment.content);
    console.log('📝 New Content:', content);
    console.log('👤 Comment Owner ID:', existingComment.userId);
    console.log('👤 Request User ID:', req.user!.id);
    console.log('⚠️  Ownership Check Bypassed:', existingComment.userId !== req.user!.id);
    console.log('─'.repeat(80));

    res.json({
      message: 'Comment updated successfully',
      comment: updatedComment,
      // VULNERABILITY: Expose ownership information
      ownershipInfo: {
        commentOwnerId: existingComment.userId,
        requestUserId: req.user!.id,
        isOwner: existingComment.userId === req.user!.id,
        vulnerability: 'This endpoint allows editing comments owned by other users'
      },
      // VULNERABILITY: Expose security information
      securityInfo: {
        contentSanitized: false,
        xssVulnerability: true,
        ownershipCheckBypassed: existingComment.userId !== req.user!.id
      }
    });

  } catch (error) {
    console.error('Comment update error:', error);
    
    // VULNERABILITY: Exposing internal database errors
    res.status(500).json({
      error: 'Comment update failed',
      details: error instanceof Error ? error.message : 'Unknown error',
      stack: process.env.NODE_ENV === 'development' ? (error as Error).stack : undefined
    });
  }
});

/**
 * Delete Comment Endpoint
 * DELETE /api/comments/:id
 * VULNERABILITY: Authorization flaws - allows deleting any comment
 */
router.delete('/:id', authenticateUser, async (req: express.Request, res: express.Response) => {
  try {
    const { id } = req.params;
    const commentId = parseInt(id!);

    if (isNaN(commentId)) {
      return res.status(400).json({
        error: 'Invalid comment ID',
        message: 'Comment ID must be a valid number'
      });
    }

    // Check if comment exists
    const existingComment = await prisma.comment.findUnique({
      where: { id: commentId },
      select: { 
        id: true, 
        userId: true, 
        content: true, 
        taskId: true,
        task: {
          select: { userId: true, title: true }
        }
      }
    });

    if (!existingComment) {
      return res.status(404).json({
        error: 'Comment not found',
        message: 'No comment found with the specified ID'
      });
    }

    // VULNERABILITY: No ownership verification - allows deleting any comment
    const deletedComment = await prisma.comment.delete({
      where: { id: commentId }
    });

    // VULNERABILITY: Log the deletion details
    console.log('🔍 COMMENT DELETED:');
    console.log('📝 Content:', existingComment.content);
    console.log('👤 Comment Owner ID:', existingComment.userId);
    console.log('👤 Request User ID:', req.user!.id);
    console.log('📋 Task Owner ID:', existingComment.task.userId);
    console.log('⚠️  Authorization Bypassed:', existingComment.userId !== req.user!.id);
    console.log('─'.repeat(80));

    res.json({
      message: 'Comment deleted successfully',
      deletedComment: {
        id: deletedComment.id,
        content: existingComment.content,
        userId: existingComment.userId,
        taskId: existingComment.taskId
      },
      // VULNERABILITY: Expose ownership and authorization information
      authorizationInfo: {
        commentOwnerId: existingComment.userId,
        taskOwnerId: existingComment.task.userId,
        requestUserId: req.user!.id,
        isCommentOwner: existingComment.userId === req.user!.id,
        isTaskOwner: existingComment.task.userId === req.user!.id,
        authorizationBypassed: existingComment.userId !== req.user!.id && existingComment.task.userId !== req.user!.id,
        vulnerability: 'This endpoint allows deleting comments without proper authorization checks'
      }
    });

  } catch (error) {
    console.error('Comment deletion error:', error);
    
    // VULNERABILITY: Exposing internal database errors
    res.status(500).json({
      error: 'Comment deletion failed',
      details: error instanceof Error ? error.message : 'Unknown error',
      stack: process.env.NODE_ENV === 'development' ? (error as Error).stack : undefined
    });
  }
});

/**
 * Get All Comments Endpoint (Admin-like functionality)
 * GET /api/comments
 * VULNERABILITY: Exposes all comments from all users without authorization
 */
router.get('/', authenticateUser, async (req: express.Request, res: express.Response) => {
  try {
    const { page = '1', limit = '50' } = req.query;
    
    const pageNum = parseInt(page as string);
    const limitNum = parseInt(limit as string);
    const skip = (pageNum - 1) * limitNum;

    // VULNERABILITY: No authorization check - returns all comments from all users
    const comments = await prisma.comment.findMany({
      include: {
        user: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true
          }
        },
        task: {
          select: {
            id: true,
            title: true,
            userId: true,
            user: {
              select: {
                firstName: true,
                lastName: true,
                email: true
              }
            }
          }
        }
      },
      orderBy: { createdAt: 'desc' },
      skip,
      take: limitNum
    });

    const totalComments = await prisma.comment.count();

    res.json({
      comments,
      pagination: {
        page: pageNum,
        limit: limitNum,
        total: totalComments,
        pages: Math.ceil(totalComments / limitNum)
      },
      // VULNERABILITY: Expose that this is a data leak
      securityWarning: {
        dataLeakOccurred: true,
        exposedComments: comments.length,
        vulnerability: 'This endpoint exposes all comments from all users without authorization',
        affectedUsers: [...new Set(comments.map(c => c.user.email))].length
      }
    });

  } catch (error) {
    console.error('Get all comments error:', error);
    
    // VULNERABILITY: Exposing internal database errors
    res.status(500).json({
      error: 'Failed to retrieve comments',
      details: error instanceof Error ? error.message : 'Unknown error',
      stack: process.env.NODE_ENV === 'development' ? (error as Error).stack : undefined
    });
  }
});

export default router;