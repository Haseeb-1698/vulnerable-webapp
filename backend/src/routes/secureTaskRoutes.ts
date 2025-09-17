import express from 'express';
import { body, validationResult } from 'express-validator';
import { PrismaClient } from '@prisma/client';
import { authenticateUser } from '../middleware/auth.js';
import {
  secureTaskSearch,
  secureGetTask,
  secureUpdateTask,
  secureDeleteTask,
  secureGetUserTasks,
  secureBulkTaskOperation,
  handleSecureError
} from '../utils/secureQueries.js';

const router = express.Router();
const prisma = new PrismaClient();

/**
 * SECURE Task Search Endpoint
 * GET /api/secure-tasks/search
 * 
 * Security improvements:
 * - Uses parameterized queries via Prisma ORM
 * - Proper input validation and sanitization
 * - Access control with ownership verification
 * - Safe error handling without information disclosure
 * - Query result limiting
 */
router.get('/search', authenticateUser, async (req: express.Request, res: express.Response) => {
  try {
    const result = await secureTaskSearch(req.user!.id, req.query as any);
    
    res.json({
      success: true,
      message: 'Search completed successfully',
      ...result
    });
    
  } catch (error: any) {
    const errorResponse = handleSecureError(error, 'search');
    res.status(400).json(errorResponse);
  }
});

/**
 * SECURE Get All Tasks Endpoint
 * GET /api/secure-tasks
 * 
 * Security improvements:
 * - Always filters by authenticated user ID
 * - Proper pagination validation
 * - Safe error handling
 * - No data leakage
 */
router.get('/', authenticateUser, async (req, res) => {
  try {
    const result = await secureGetUserTasks(req.user!.id, req.query as any);
    
    res.json({
      success: true,
      message: 'Tasks retrieved successfully',
      ...result
    });
    
  } catch (error: any) {
    const errorResponse = handleSecureError(error, 'get tasks');
    res.status(400).json(errorResponse);
  }
});

/**
 * SECURE Get Single Task Endpoint
 * GET /api/secure-tasks/:id
 * 
 * Security improvements:
 * - Ownership verification prevents IDOR
 * - Input validation for task ID
 * - Safe error handling
 */
router.get('/:id', authenticateUser, async (req, res) => {
  try {
    const taskId = parseInt(req.params.id);
    
    if (isNaN(taskId) || taskId <= 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid task ID',
        message: 'Task ID must be a positive integer'
      });
    }
    
    const result = await secureGetTask(taskId, req.user!.id);
    
    res.json({
      success: true,
      message: 'Task retrieved successfully',
      ...result
    });
    
  } catch (error: any) {
    const errorResponse = handleSecureError(error, 'get task');
    res.status(404).json(errorResponse);
  }
});

/**
 * SECURE Create Task Endpoint
 * POST /api/secure-tasks
 * 
 * Security improvements:
 * - Comprehensive input validation
 * - Automatic user association
 * - Safe error handling
 */
router.post('/', authenticateUser, [
  body('title')
    .trim()
    .isLength({ min: 1, max: 200 })
    .withMessage('Title is required and must be between 1-200 characters')
    .escape(), // HTML escape for XSS prevention
  body('description')
    .optional()
    .isLength({ max: 1000 })
    .withMessage('Description must be less than 1000 characters')
    .escape(), // HTML escape for XSS prevention
  body('priority')
    .optional()
    .isIn(['LOW', 'MEDIUM', 'HIGH', 'URGENT'])
    .withMessage('Priority must be LOW, MEDIUM, HIGH, or URGENT'),
  body('status')
    .optional()
    .isIn(['TODO', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED'])
    .withMessage('Status must be TODO, IN_PROGRESS, COMPLETED, or CANCELLED'),
  body('dueDate')
    .optional()
    .isISO8601()
    .withMessage('Due date must be a valid ISO 8601 date')
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

    const { title, description, priority, status, dueDate } = req.body;

    // Create new task with automatic user association
    const newTask = await prisma.task.create({
      data: {
        title,
        description: description || null,
        priority: priority || 'MEDIUM',
        status: status || 'TODO',
        dueDate: dueDate ? new Date(dueDate) : null,
        userId: req.user!.id // SECURITY: Always associate with authenticated user
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
      message: 'Task created successfully',
      task: newTask
    });

  } catch (error) {
    const errorResponse = handleSecureError(error, 'create task');
    res.status(500).json(errorResponse);
  }
});

/**
 * SECURE Update Task Endpoint
 * PUT /api/secure-tasks/:id
 * 
 * Security improvements:
 * - Ownership verification prevents IDOR
 * - Input validation and sanitization
 * - Safe error handling
 */
router.put('/:id', authenticateUser, [
  body('title')
    .optional()
    .trim()
    .isLength({ min: 1, max: 200 })
    .withMessage('Title must be between 1-200 characters')
    .escape(),
  body('description')
    .optional()
    .isLength({ max: 1000 })
    .withMessage('Description must be less than 1000 characters')
    .escape(),
  body('priority')
    .optional()
    .isIn(['LOW', 'MEDIUM', 'HIGH', 'URGENT'])
    .withMessage('Priority must be LOW, MEDIUM, HIGH, or URGENT'),
  body('status')
    .optional()
    .isIn(['TODO', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED'])
    .withMessage('Status must be TODO, IN_PROGRESS, COMPLETED, or CANCELLED'),
  body('dueDate')
    .optional()
    .isISO8601()
    .withMessage('Due date must be a valid ISO 8601 date')
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

    const taskId = parseInt(req.params.id);
    
    if (isNaN(taskId) || taskId <= 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid task ID',
        message: 'Task ID must be a positive integer'
      });
    }

    const result = await secureUpdateTask(taskId, req.user!.id, req.body);
    
    res.json({
      success: true,
      message: 'Task updated successfully',
      ...result
    });

  } catch (error: any) {
    const errorResponse = handleSecureError(error, 'update task');
    res.status(404).json(errorResponse);
  }
});

/**
 * SECURE Delete Task Endpoint
 * DELETE /api/secure-tasks/:id
 * 
 * Security improvements:
 * - Ownership verification prevents IDOR
 * - Input validation
 * - Safe error handling
 */
router.delete('/:id', authenticateUser, async (req, res) => {
  try {
    const taskId = parseInt(req.params.id);
    
    if (isNaN(taskId) || taskId <= 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid task ID',
        message: 'Task ID must be a positive integer'
      });
    }

    const result = await secureDeleteTask(taskId, req.user!.id);
    
    res.json({
      success: true,
      message: 'Task deleted successfully',
      ...result
    });

  } catch (error: any) {
    const errorResponse = handleSecureError(error, 'delete task');
    res.status(404).json(errorResponse);
  }
});

/**
 * SECURE Bulk Task Operations Endpoint
 * POST /api/secure-tasks/bulk
 * 
 * Security improvements:
 * - Ownership verification for all operations
 * - Input validation and limits
 * - Safe error handling
 */
router.post('/bulk', authenticateUser, [
  body('action')
    .isIn(['delete', 'update_status', 'update_priority'])
    .withMessage('Action must be delete, update_status, or update_priority'),
  body('taskIds')
    .isArray({ min: 1, max: 100 })
    .withMessage('Task IDs must be a non-empty array with maximum 100 items'),
  body('taskIds.*')
    .isInt({ min: 1 })
    .withMessage('Each task ID must be a positive integer'),
  body('newStatus')
    .optional()
    .isIn(['TODO', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED'])
    .withMessage('Status must be TODO, IN_PROGRESS, COMPLETED, or CANCELLED'),
  body('newPriority')
    .optional()
    .isIn(['LOW', 'MEDIUM', 'HIGH', 'URGENT'])
    .withMessage('Priority must be LOW, MEDIUM, HIGH, or URGENT')
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

    const result = await secureBulkTaskOperation(req.user!.id, req.body);
    
    res.json({
      success: true,
      ...result
    });

  } catch (error: any) {
    const errorResponse = handleSecureError(error, 'bulk operation');
    res.status(400).json(errorResponse);
  }
});

/**
 * SECURE Task Statistics Endpoint
 * GET /api/secure-tasks/stats
 * 
 * Provides task statistics for the authenticated user only
 */
router.get('/stats', authenticateUser, async (req, res) => {
  try {
    const userId = req.user!.id;
    
    const [
      totalTasks,
      todoTasks,
      inProgressTasks,
      completedTasks,
      cancelledTasks,
      highPriorityTasks,
      overdueTasks
    ] = await Promise.all([
      prisma.task.count({ where: { userId } }),
      prisma.task.count({ where: { userId, status: 'TODO' } }),
      prisma.task.count({ where: { userId, status: 'IN_PROGRESS' } }),
      prisma.task.count({ where: { userId, status: 'COMPLETED' } }),
      prisma.task.count({ where: { userId, status: 'CANCELLED' } }),
      prisma.task.count({ where: { userId, priority: 'HIGH' } }),
      prisma.task.count({ 
        where: { 
          userId, 
          dueDate: { lt: new Date() },
          status: { notIn: ['COMPLETED', 'CANCELLED'] }
        } 
      })
    ]);
    
    res.json({
      success: true,
      stats: {
        total: totalTasks,
        byStatus: {
          todo: todoTasks,
          inProgress: inProgressTasks,
          completed: completedTasks,
          cancelled: cancelledTasks
        },
        highPriority: highPriorityTasks,
        overdue: overdueTasks,
        completionRate: totalTasks > 0 ? ((completedTasks / totalTasks) * 100).toFixed(1) : '0'
      }
    });
    
  } catch (error) {
    const errorResponse = handleSecureError(error, 'get statistics');
    res.status(500).json(errorResponse);
  }
});

export default router;