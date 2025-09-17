import express from 'express';
import { body, validationResult } from 'express-validator';
import { PrismaClient } from '@prisma/client';
import { authenticateUser } from '../middleware/auth.js';
import axios from 'axios';

const router = express.Router();
const prisma = new PrismaClient();

// Import pg for raw SQL queries (vulnerable implementation)
import pkg from 'pg';
const { Pool } = pkg;

// Create database connection pool for raw SQL queries
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Vulnerable logging function that exposes SQL details
const logSQLQuery = (query: string, params: any[], userId: number) => {
  console.log('🔍 SQL SEARCH QUERY EXECUTED:');
  console.log('📝 Raw SQL:', query);
  console.log('🔢 Parameters:', params);
  console.log('👤 User ID:', userId);
  console.log('⏰ Timestamp:', new Date().toISOString());
  console.log('🚨 WARNING: This logging exposes sensitive SQL information!');
  console.log('─'.repeat(80));
};

/**
 * VULNERABLE Search Tasks Endpoint
 * GET /api/tasks/search
 * VULNERABILITY: SQL Injection through raw query string concatenation
 * CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
 */
/**
 * EXTREMELY VULNERABLE Search Tasks Endpoint (NO AUTH REQUIRED FOR TESTING)
 * GET /api/tasks/search-raw
 * VULNERABILITY: Direct SQL injection with minimal protection
 */
router.get('/search-raw', async (req: express.Request, res: express.Response) => {
  try {
    const { q } = req.query;
    
    if (!q) {
      return res.status(400).json({
        error: 'Query parameter q is required',
        message: 'Please provide a q parameter',
        example: '/api/tasks/search-raw?q=test'
      });
    }

    // VULNERABILITY: Completely unprotected SQL injection
    const sqlQuery = `SELECT * FROM users WHERE first_name = '${q}' OR last_name = '${q}'`;
    
    console.log('🔍 EXECUTING RAW SQL:', sqlQuery);
    
    const result = await pool.query(sqlQuery);
    
    res.json({
      success: true,
      query: q,
      sql: sqlQuery,
      results: result.rows
    });

  } catch (error: any) {
    console.error('🚨 Raw SQL Error:', error);
    res.status(500).json({
      error: 'Database error',
      message: error.message,
      sql: `SELECT * FROM users WHERE first_name = '${req.query.q}' OR last_name = '${req.query.q}'`
    });
  }
});

/**
 * SIMPLE VULNERABLE Search Endpoint that matches your security lab tests
 * GET /api/tasks/simple-search
 * VULNERABILITY: Direct SQL injection in WHERE clause
 */
router.get('/simple-search', async (req: express.Request, res: express.Response) => {
  try {
    const { query } = req.query;
    
    if (!query) {
      return res.status(400).json({
        error: 'Search query is required'
      });
    }

    // VULNERABILITY: Direct injection point that allows breaking out of quotes
    const sqlQuery = `SELECT t.*, u.first_name, u.last_name, u.email, u.password_hash FROM tasks t LEFT JOIN users u ON t.user_id = u.id WHERE t.title = '${query}'`;
    
    console.log('🔍 SQL SEARCH QUERY EXECUTED:');
    console.log('📝 Raw SQL:', sqlQuery);
    
    const result = await pool.query(sqlQuery);
    
    res.json({
      success: true,
      results: result.rows,
      query: query,
      sql: sqlQuery
    });

  } catch (error: any) {
    console.error('🚨 SQL Search Error:', error);
    res.status(500).json({
      error: 'Database error',
      message: error.message,
      sql: `SELECT t.*, u.first_name, u.last_name, u.email, u.password_hash FROM tasks t LEFT JOIN users u ON t.user_id = u.id WHERE t.title = '${req.query.query}'`
    });
  }
});

router.get('/search', authenticateUser, async (req: express.Request, res: express.Response) => {
  try {
    const { query, category, priority, status, sortBy, order } = req.query;
    
    if (!query) {
      return res.status(400).json({
        error: 'Search query is required',
        message: 'Please provide a search query parameter',
        example: '/api/tasks/search?query=meeting'
      });
    }

    // VULNERABILITY: Direct string concatenation in SQL query - NO PARAMETERIZATION
    // Making it extremely vulnerable by removing quotes and allowing direct injection
    let sqlQuery = `
      SELECT 
        t.id,
        t.title,
        t.description,
        t.priority,
        t.status,
        t.due_date,
        t.created_at,
        t.updated_at,
        t.user_id,
        u.first_name,
        u.last_name,
        u.email,
        u.password_hash,
        COUNT(c.id) as comment_count
      FROM tasks t 
      LEFT JOIN users u ON t.user_id = u.id 
      LEFT JOIN comments c ON t.id = c.task_id
      WHERE (t.title LIKE '%${query}%' OR t.description LIKE '%${query}%')
    `;

    // VULNERABILITY: Additional filter concatenation without sanitization
    if (category) {
      sqlQuery += ` AND t.title LIKE '%${category}%'`;
    }
    
    if (priority) {
      sqlQuery += ` AND t.priority = '${priority}'`;
    }
    
    if (status) {
      sqlQuery += ` AND t.status = '${status}'`;
    }

    // Add GROUP BY clause
    sqlQuery += ` GROUP BY t.id, u.id`;

    // VULNERABILITY: Dynamic ORDER BY clause construction
    if (sortBy) {
      const orderDirection = order === 'desc' ? 'DESC' : 'ASC';
      sqlQuery += ` ORDER BY ${sortBy} ${orderDirection}`;
    } else {
      sqlQuery += ` ORDER BY t.created_at DESC`;
    }

    // VULNERABILITY: Log the complete SQL query with sensitive details
    logSQLQuery(sqlQuery, [], req.user!.id);

    // Execute the vulnerable raw SQL query
    const result = await pool.query(sqlQuery);
    
    // VULNERABILITY: Return potentially sensitive user data including password hashes
    const tasks = result.rows.map(row => ({
      id: row.id,
      title: row.title,
      description: row.description,
      priority: row.priority,
      status: row.status,
      dueDate: row.due_date,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      userId: row.user_id,
      user: {
        id: row.user_id,
        firstName: row.first_name,
        lastName: row.last_name,
        email: row.email,
        // VULNERABILITY: Exposing password hashes in search results
        passwordHash: row.password_hash
      },
      commentCount: parseInt(row.comment_count) || 0,
      // VULNERABILITY: Expose search metadata
      searchMetadata: {
        originalQuery: query,
        sqlQuery: sqlQuery,
        executedAt: new Date().toISOString(),
        vulnerability: 'SQL Injection possible through query parameter'
      }
    }));

    res.json({
      success: true,
      message: 'Search completed successfully',
      query: query,
      results: tasks,
      resultCount: tasks.length,
      // VULNERABILITY: Expose the actual SQL query in response
      debug: {
        executedSQL: sqlQuery,
        searchParameters: { query, category, priority, status, sortBy, order },
        databaseInfo: {
          connectionString: process.env.DATABASE_URL?.replace(/:[^:@]*@/, ':***@'), // Partially hide password
          tableStructure: 'tasks, users, comments tables joined',
          vulnerability: 'This endpoint is vulnerable to SQL injection attacks'
        }
      },
      // VULNERABILITY: Provide exploitation hints
      exploitationHints: {
        sqlInjection: "Try: ' UNION SELECT id, email, password_hash, null, null, null, null, null, 1, 'hacked', 'user', 'hack@evil.com', 'hash', 0 FROM users--",
        unionAttack: "Use UNION to extract data from other tables",
        blindInjection: "Use time delays: '; SELECT pg_sleep(5)--",
        errorBased: "Trigger errors to reveal database structure"
      }
    });

  } catch (error: any) {
    console.error('🚨 SQL Search Error:', error);
    
    // VULNERABILITY: Extremely verbose error handling that exposes database internals
    res.status(500).json({
      error: 'Database query failed',
      message: error.message,
      // VULNERABILITY: Expose full error details including SQL syntax errors
      details: {
        errorCode: error.code,
        errorDetail: error.detail,
        errorHint: error.hint,
        errorPosition: error.position,
        internalPosition: error.internalPosition,
        internalQuery: error.internalQuery,
        where: error.where,
        schema: error.schema,
        table: error.table,
        column: error.column,
        dataType: error.dataType,
        constraint: error.constraint,
        file: error.file,
        line: error.line,
        routine: error.routine,
        stack: error.stack
      },
      // VULNERABILITY: Expose database schema information
      databaseSchema: {
        tables: ['users', 'tasks', 'comments'],
        userColumns: ['id', 'email', 'password_hash', 'first_name', 'last_name', 'avatar_url', 'created_at', 'updated_at', 'email_verified'],
        taskColumns: ['id', 'user_id', 'title', 'description', 'priority', 'status', 'due_date', 'created_at', 'updated_at'],
        commentColumns: ['id', 'task_id', 'user_id', 'content', 'created_at', 'updated_at']
      },
      // VULNERABILITY: Provide debugging information that helps attackers
      debugInfo: {
        timestamp: new Date().toISOString(),
        userId: req.user?.id,
        originalQuery: req.query.query,
        vulnerability: 'Error messages expose sensitive database information'
      }
    });
  }
});

/**
 * Create Task Endpoint
 * POST /api/tasks
 * Requires authentication
 */
router.post('/', authenticateUser, [
  body('title')
    .trim()
    .isLength({ min: 1, max: 200 })
    .withMessage('Title is required and must be between 1-200 characters'),
  body('description')
    .optional()
    .isLength({ max: 1000 })
    .withMessage('Description must be less than 1000 characters'),
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
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { title, description, priority, status, dueDate } = req.body;

    // Create new task
    const newTask = await prisma.task.create({
      data: {
        title,
        description: description || null,
        priority: priority || 'MEDIUM',
        status: status || 'TODO',
        dueDate: dueDate ? new Date(dueDate) : null,
        userId: req.user!.id
      },
      include: {
        user: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true
          }
        }
      }
    });

    res.status(201).json({
      message: 'Task created successfully',
      task: newTask
    });

  } catch (error) {
    console.error('Task creation error:', error);
    
    // VULNERABILITY: Exposing internal database errors
    res.status(500).json({
      error: 'Task creation failed',
      details: error instanceof Error ? error.message : 'Unknown error',
      stack: process.env.NODE_ENV === 'development' ? (error as Error).stack : undefined
    });
  }
});

/**
 * Get All Tasks Endpoint
 * GET /api/tasks
 * VULNERABILITY: Potential data exposure - returns all tasks without proper filtering
 */
router.get('/', authenticateUser, async (req, res) => {
  try {
    const { page = '1', limit = '10', status, priority, search } = req.query;
    
    const pageNum = parseInt(page as string);
    const limitNum = parseInt(limit as string);
    const skip = (pageNum - 1) * limitNum;

    // VULNERABILITY: Sometimes return all users' tasks instead of just current user's
    let whereClause: any = {};
    
    if (Math.random() > 0.7) {
      // 30% chance to expose all users' tasks
      console.warn('⚠️  Exposing all users\' tasks - this is a data leak vulnerability!');
      whereClause = {}; // No user filtering
    } else {
      whereClause = { userId: req.user!.id };
    }

    // Add additional filters
    if (status) {
      whereClause.status = status;
    }
    if (priority) {
      whereClause.priority = priority;
    }
    if (search) {
      whereClause.OR = [
        { title: { contains: search as string, mode: 'insensitive' } },
        { description: { contains: search as string, mode: 'insensitive' } }
      ];
    }

    const tasks = await prisma.task.findMany({
      where: whereClause,
      include: {
        user: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true
          }
        },
        comments: {
          include: {
            user: {
              select: {
                id: true,
                firstName: true,
                lastName: true
              }
            }
          }
        }
      },
      orderBy: { createdAt: 'desc' },
      skip,
      take: limitNum
    });

    // Get total count for pagination
    const totalTasks = await prisma.task.count({
      where: whereClause
    });

    res.json({
      tasks,
      pagination: {
        page: pageNum,
        limit: limitNum,
        total: totalTasks,
        pages: Math.ceil(totalTasks / limitNum)
      },
      // VULNERABILITY: Expose whether data leak occurred
      dataLeakOccurred: Object.keys(whereClause).length === 0 || !whereClause.userId,
      warning: 'This endpoint may occasionally return other users\' tasks due to a vulnerability'
    });

  } catch (error) {
    console.error('Get tasks error:', error);
    
    // VULNERABILITY: Exposing internal database errors
    res.status(500).json({
      error: 'Failed to retrieve tasks',
      details: error instanceof Error ? error.message : 'Unknown error',
      stack: process.env.NODE_ENV === 'development' ? (error as Error).stack : undefined
    });
  }
});

/**
 * Get Single Task Endpoint
 * GET /api/tasks/:id
 * VULNERABILITY: IDOR - No ownership verification
 */
router.get('/:id', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    const taskId = parseInt(id);

    if (isNaN(taskId)) {
      return res.status(400).json({
        error: 'Invalid task ID',
        message: 'Task ID must be a valid number'
      });
    }

    // VULNERABILITY: No ownership verification - allows access to any task
    const task = await prisma.task.findUnique({
      where: { id: taskId },
      include: {
        user: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true
          }
        },
        comments: {
          include: {
            user: {
              select: {
                id: true,
                firstName: true,
                lastName: true
              }
            }
          },
          orderBy: { createdAt: 'asc' }
        }
      }
    });

    if (!task) {
      return res.status(404).json({
        error: 'Task not found',
        message: 'No task found with the specified ID'
      });
    }

    // VULNERABILITY: Return task regardless of ownership
    res.json({
      task,
      // VULNERABILITY: Expose ownership information
      ownership: {
        taskOwnerId: task.userId,
        requestUserId: req.user!.id,
        isOwner: task.userId === req.user!.id,
        vulnerability: 'This endpoint allows access to tasks owned by other users (IDOR)'
      }
    });

  } catch (error) {
    console.error('Get task error:', error);
    
    // VULNERABILITY: Exposing internal database errors
    res.status(500).json({
      error: 'Failed to retrieve task',
      details: error instanceof Error ? error.message : 'Unknown error',
      stack: process.env.NODE_ENV === 'development' ? (error as Error).stack : undefined
    });
  }
});

/**
 * Update Task Endpoint
 * PUT /api/tasks/:id
 * VULNERABILITY: IDOR - Allows unauthorized modifications
 */
router.put('/:id', authenticateUser, [
  body('title')
    .optional()
    .trim()
    .isLength({ min: 1, max: 200 })
    .withMessage('Title must be between 1-200 characters'),
  body('description')
    .optional()
    .isLength({ max: 1000 })
    .withMessage('Description must be less than 1000 characters'),
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
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { id } = req.params;
    const taskId = parseInt(id);

    if (isNaN(taskId)) {
      return res.status(400).json({
        error: 'Invalid task ID',
        message: 'Task ID must be a valid number'
      });
    }

    // Check if task exists first
    const existingTask = await prisma.task.findUnique({
      where: { id: taskId },
      select: { id: true, userId: true, title: true }
    });

    if (!existingTask) {
      return res.status(404).json({
        error: 'Task not found',
        message: 'No task found with the specified ID'
      });
    }

    // VULNERABILITY: No ownership verification - allows updating any task
    const { title, description, priority, status, dueDate } = req.body;
    
    const updateData: any = {};
    if (title !== undefined) updateData.title = title;
    if (description !== undefined) updateData.description = description;
    if (priority !== undefined) updateData.priority = priority;
    if (status !== undefined) updateData.status = status;
    if (dueDate !== undefined) updateData.dueDate = dueDate ? new Date(dueDate) : null;

    const updatedTask = await prisma.task.update({
      where: { id: taskId },
      data: updateData,
      include: {
        user: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true
          }
        }
      }
    });

    res.json({
      message: 'Task updated successfully',
      task: updatedTask,
      // VULNERABILITY: Expose ownership information
      ownership: {
        taskOwnerId: existingTask.userId,
        requestUserId: req.user!.id,
        isOwner: existingTask.userId === req.user!.id,
        vulnerability: 'This endpoint allows updating tasks owned by other users (IDOR)'
      }
    });

  } catch (error) {
    console.error('Task update error:', error);
    
    // VULNERABILITY: Exposing internal database errors
    res.status(500).json({
      error: 'Task update failed',
      details: error instanceof Error ? error.message : 'Unknown error',
      stack: process.env.NODE_ENV === 'development' ? (error as Error).stack : undefined
    });
  }
});

/**
 * Delete Task Endpoint
 * DELETE /api/tasks/:id
 * VULNERABILITY: IDOR - Missing authorization checks
 */
router.delete('/:id', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    const taskId = parseInt(id);

    if (isNaN(taskId)) {
      return res.status(400).json({
        error: 'Invalid task ID',
        message: 'Task ID must be a valid number'
      });
    }

    // Check if task exists first
    const existingTask = await prisma.task.findUnique({
      where: { id: taskId },
      select: { 
        id: true, 
        userId: true, 
        title: true,
        _count: {
          select: { comments: true }
        }
      }
    });

    if (!existingTask) {
      return res.status(404).json({
        error: 'Task not found',
        message: 'No task found with the specified ID'
      });
    }

    // VULNERABILITY: No ownership verification - allows deleting any task
    const deletedTask = await prisma.task.delete({
      where: { id: taskId }
    });

    res.json({
      message: 'Task deleted successfully',
      deletedTask: {
        id: deletedTask.id,
        title: deletedTask.title,
        userId: deletedTask.userId
      },
      // VULNERABILITY: Expose ownership and deletion information
      deletionInfo: {
        taskOwnerId: existingTask.userId,
        requestUserId: req.user!.id,
        isOwner: existingTask.userId === req.user!.id,
        commentsDeleted: existingTask._count.comments,
        vulnerability: 'This endpoint allows deleting tasks owned by other users (IDOR)'
      }
    });

  } catch (error) {
    console.error('Task deletion error:', error);
    
    // VULNERABILITY: Exposing internal database errors
    res.status(500).json({
      error: 'Task deletion failed',
      details: error instanceof Error ? error.message : 'Unknown error',
      stack: process.env.NODE_ENV === 'development' ? (error as Error).stack : undefined
    });
  }
});

/**
 * Get Tasks by User Endpoint
 * GET /api/tasks/user/:userId
 * VULNERABILITY: Allows viewing any user's tasks
 */
router.get('/user/:userId', authenticateUser, async (req, res) => {
  try {
    const { userId } = req.params;
    const targetUserId = parseInt(userId);

    if (isNaN(targetUserId)) {
      return res.status(400).json({
        error: 'Invalid user ID',
        message: 'User ID must be a valid number'
      });
    }

    // VULNERABILITY: No authorization check - allows viewing any user's tasks
    const tasks = await prisma.task.findMany({
      where: { userId: targetUserId },
      include: {
        user: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true
          }
        },
        _count: {
          select: { comments: true }
        }
      },
      orderBy: { createdAt: 'desc' }
    });

    // Get user info
    const targetUser = await prisma.user.findUnique({
      where: { id: targetUserId },
      select: {
        id: true,
        firstName: true,
        lastName: true,
        email: true
      }
    });

    if (!targetUser) {
      return res.status(404).json({
        error: 'User not found',
        message: 'No user found with the specified ID'
      });
    }

    res.json({
      tasks,
      targetUser,
      taskCount: tasks.length,
      // VULNERABILITY: Expose access information
      accessInfo: {
        targetUserId,
        requestUserId: req.user!.id,
        isOwnTasks: targetUserId === req.user!.id,
        vulnerability: 'This endpoint allows viewing tasks of any user without authorization'
      }
    });

  } catch (error) {
    console.error('Get user tasks error:', error);
    
    // VULNERABILITY: Exposing internal database errors
    res.status(500).json({
      error: 'Failed to retrieve user tasks',
      details: error instanceof Error ? error.message : 'Unknown error',
      stack: process.env.NODE_ENV === 'development' ? (error as Error).stack : undefined
    });
  }
});

/**
 * Bulk Task Operations Endpoint
 * POST /api/tasks/bulk
 * VULNERABILITY: Allows bulk operations on tasks without ownership verification
 */
router.post('/bulk', authenticateUser, [
  body('action')
    .isIn(['delete', 'update_status', 'update_priority'])
    .withMessage('Action must be delete, update_status, or update_priority'),
  body('taskIds')
    .isArray({ min: 1 })
    .withMessage('Task IDs must be a non-empty array'),
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
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { action, taskIds, newStatus, newPriority } = req.body;

    // VULNERABILITY: No ownership verification for bulk operations
    let result: any;
    let affectedTasks: any[] = [];

    // Get task ownership info before operation
    const taskOwnership = await prisma.task.findMany({
      where: { id: { in: taskIds } },
      select: { id: true, userId: true, title: true }
    });

    switch (action) {
      case 'delete':
        result = await prisma.task.deleteMany({
          where: { id: { in: taskIds } }
        });
        affectedTasks = taskOwnership;
        break;

      case 'update_status':
        if (!newStatus) {
          return res.status(400).json({
            error: 'New status required',
            message: 'newStatus field is required for update_status action'
          });
        }
        result = await prisma.task.updateMany({
          where: { id: { in: taskIds } },
          data: { status: newStatus }
        });
        affectedTasks = taskOwnership;
        break;

      case 'update_priority':
        if (!newPriority) {
          return res.status(400).json({
            error: 'New priority required',
            message: 'newPriority field is required for update_priority action'
          });
        }
        result = await prisma.task.updateMany({
          where: { id: { in: taskIds } },
          data: { priority: newPriority }
        });
        affectedTasks = taskOwnership;
        break;
    }

    // Analyze ownership violations
    const ownershipAnalysis = affectedTasks.map(task => ({
      taskId: task.id,
      title: task.title,
      ownerId: task.userId,
      requestUserId: req.user!.id,
      isOwner: task.userId === req.user!.id,
      violatesOwnership: task.userId !== req.user!.id
    }));

    const violationCount = ownershipAnalysis.filter(t => t.violatesOwnership).length;

    res.json({
      message: `Bulk ${action} completed successfully`,
      result,
      affectedCount: result.count,
      ownershipAnalysis,
      // VULNERABILITY: Expose ownership violations
      securityIssues: {
        totalTasks: affectedTasks.length,
        ownershipViolations: violationCount,
        violationPercentage: ((violationCount / affectedTasks.length) * 100).toFixed(1) + '%',
        vulnerability: 'Bulk operations allow modifying tasks owned by other users (IDOR)'
      }
    });

  } catch (error) {
    console.error('Bulk task operation error:', error);
    
    // VULNERABILITY: Exposing internal database errors
    res.status(500).json({
      error: 'Bulk operation failed',
      details: error instanceof Error ? error.message : 'Unknown error',
      stack: process.env.NODE_ENV === 'development' ? (error as Error).stack : undefined
    });
  }
});

/**
 * VULNERABLE ENDPOINT: Task Import with SSRF vulnerability
 * POST /api/tasks/import
 * 
 * This endpoint demonstrates advanced SSRF vulnerabilities:
 * 1. SSRF (Server-Side Request Forgery) - CWE-918
 * 2. Cloud metadata service exploitation
 * 3. Internal network scanning
 * 4. Local file inclusion through file:// protocol
 * 5. Information disclosure through error messages
 */
router.post('/import', authenticateUser, [
  body('importUrl')
    .isURL({ protocols: ['http', 'https', 'file', 'ftp'] })
    .withMessage('Import URL must be a valid URL'),
  body('format')
    .optional()
    .isIn(['json', 'csv', 'xml', 'txt'])
    .withMessage('Format must be json, csv, xml, or txt')
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

    const { importUrl, format = 'json', parseContent = true } = req.body;
    
    console.log(`[SECURITY WARNING] Task import from URL: ${importUrl}`);
    console.log(`[SECURITY WARNING] Requested by user: ${req.user!.id}`);
    
    try {
      // VULNERABILITY: No URL validation or domain whitelisting
      // This allows requests to:
      // - Cloud metadata services (AWS, GCP, Azure)
      // - Internal network services
      // - Local file system
      // - Private IP ranges
      const response = await axios.get(importUrl, {
        timeout: 15000,
        maxRedirects: 10,
        headers: {
          'User-Agent': 'VulnerableTaskManager-Importer/1.0',
          'Accept': '*/*',
          'X-Forwarded-For': '127.0.0.1',
          'X-Real-IP': '127.0.0.1'
        },
        // VULNERABILITY: Allow any response size
        maxContentLength: Infinity,
        maxBodyLength: Infinity
      });
      
      // VULNERABILITY: Cloud metadata service exploitation
      if (importUrl.includes('169.254.169.254')) {
        console.log('[SECURITY WARNING] AWS/GCP metadata service access detected');
        
        // Try to extract sensitive cloud metadata
        let metadataType = 'unknown';
        if (importUrl.includes('/iam/security-credentials/')) {
          metadataType = 'AWS IAM credentials';
        } else if (importUrl.includes('/meta-data/')) {
          metadataType = 'AWS instance metadata';
        } else if (importUrl.includes('/computeMetadata/')) {
          metadataType = 'GCP compute metadata';
        }
        
        return res.json({
          success: true,
          importType: 'cloud_metadata',
          metadataType,
          data: response.data,
          headers: response.headers,
          status: response.status,
          message: 'Cloud metadata retrieved successfully',
          warning: 'CRITICAL: Cloud metadata service access detected - potential credential exposure',
          exploitationInfo: {
            awsCredentials: importUrl.includes('/iam/security-credentials/'),
            instanceMetadata: importUrl.includes('/meta-data/'),
            gcpMetadata: importUrl.includes('/computeMetadata/'),
            azureMetadata: importUrl.includes('/metadata/instance')
          }
        });
      }
      
      // VULNERABILITY: Internal network scanning capability
      if (importUrl.includes('localhost') || 
          importUrl.includes('127.0.0.1') || 
          importUrl.match(/192\.168\.\d+\.\d+/) ||
          importUrl.match(/10\.\d+\.\d+\.\d+/) ||
          importUrl.match(/172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+/)) {
        
        console.log('[SECURITY WARNING] Internal network access detected');
        
        // Attempt to identify the service
        let serviceType = 'unknown';
        const port = importUrl.match(/:(\d+)/)?.[1];
        
        if (port === '22') serviceType = 'SSH';
        else if (port === '3306') serviceType = 'MySQL';
        else if (port === '5432') serviceType = 'PostgreSQL';
        else if (port === '6379') serviceType = 'Redis';
        else if (port === '27017') serviceType = 'MongoDB';
        else if (port === '9200') serviceType = 'Elasticsearch';
        else if (port === '8080') serviceType = 'HTTP Service';
        else if (port === '3000') serviceType = 'Node.js App';
        
        return res.json({
          success: true,
          importType: 'internal_network_scan',
          serviceType,
          port,
          data: response.data,
          headers: response.headers,
          status: response.status,
          responseSize: JSON.stringify(response.data).length,
          message: 'Internal network service response',
          warning: 'CRITICAL: Internal network access detected - potential service enumeration',
          networkInfo: {
            targetHost: importUrl.match(/https?:\/\/([^\/]+)/)?.[1],
            detectedPort: port,
            serviceIdentification: serviceType,
            responseIndicatesService: response.status === 200
          }
        });
      }
      
      // VULNERABILITY: Local file inclusion through file:// protocol
      if (importUrl.startsWith('file://')) {
        console.log('[SECURITY WARNING] Local file inclusion detected');
        
        const filePath = importUrl.replace('file://', '');
        let fileType = 'unknown';
        
        // Identify sensitive file types
        if (filePath.includes('/etc/passwd')) fileType = 'system_users';
        else if (filePath.includes('/etc/shadow')) fileType = 'password_hashes';
        else if (filePath.includes('/.env')) fileType = 'environment_variables';
        else if (filePath.includes('/proc/')) fileType = 'system_information';
        else if (filePath.includes('config')) fileType = 'configuration_file';
        
        return res.json({
          success: true,
          importType: 'local_file_inclusion',
          fileType,
          filePath,
          content: response.data,
          message: 'Local file content retrieved',
          warning: 'CRITICAL: Local file inclusion detected - potential sensitive data exposure',
          fileInfo: {
            requestedPath: filePath,
            fileTypeDetected: fileType,
            contentLength: response.data?.length || 0,
            potentiallysensitive: ['passwd', 'shadow', '.env', 'config', 'key', 'secret'].some(term => 
              filePath.toLowerCase().includes(term)
            )
          }
        });
      }
      
      // Handle regular external URL imports
      let importedTasks: any[] = [];
      let parseErrors: string[] = [];
      
      if (parseContent) {
        try {
          let parsedData: any;
          
          // VULNERABILITY: No content validation - parse any format
          if (format === 'json' || importUrl.includes('.json')) {
            parsedData = typeof response.data === 'string' ? JSON.parse(response.data) : response.data;
          } else if (format === 'csv') {
            // Basic CSV parsing (vulnerable to CSV injection)
            const lines = response.data.split('\n');
            const headers = lines[0]?.split(',') || [];
            parsedData = lines.slice(1).map((line: string) => {
              const values = line.split(',');
              const obj: any = {};
              headers.forEach((header: string, index: number) => {
                obj[header.trim()] = values[index]?.trim();
              });
              return obj;
            });
          } else {
            parsedData = { rawContent: response.data };
          }
          
          // VULNERABILITY: Create tasks from any parsed data without validation
          if (Array.isArray(parsedData)) {
            for (const item of parsedData.slice(0, 50)) { // Limit to 50 tasks
              try {
                const task = await prisma.task.create({
                  data: {
                    title: item.title || item.name || `Imported Task ${Date.now()}`,
                    description: item.description || item.content || JSON.stringify(item),
                    priority: ['LOW', 'MEDIUM', 'HIGH', 'URGENT'].includes(item.priority) ? item.priority : 'MEDIUM',
                    status: ['TODO', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED'].includes(item.status) ? item.status : 'TODO',
                    userId: req.user!.id
                  }
                });
                importedTasks.push(task);
              } catch (taskError: any) {
                parseErrors.push(`Failed to create task: ${taskError.message}`);
              }
            }
          } else if (parsedData && typeof parsedData === 'object') {
            // Single task import
            try {
              const task = await prisma.task.create({
                data: {
                  title: parsedData.title || parsedData.name || `Imported Task ${Date.now()}`,
                  description: parsedData.description || parsedData.content || JSON.stringify(parsedData),
                  priority: ['LOW', 'MEDIUM', 'HIGH', 'URGENT'].includes(parsedData.priority) ? parsedData.priority : 'MEDIUM',
                  status: ['TODO', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED'].includes(parsedData.status) ? parsedData.status : 'TODO',
                  userId: req.user!.id
                }
              });
              importedTasks.push(task);
            } catch (taskError: any) {
              parseErrors.push(`Failed to create task: ${taskError.message}`);
            }
          }
          
        } catch (parseError: any) {
          parseErrors.push(`Parse error: ${parseError.message}`);
        }
      }
      
      res.json({
        success: true,
        importType: 'external_url',
        importUrl,
        format,
        importedTasks,
        importedCount: importedTasks.length,
        parseErrors,
        rawResponse: {
          status: response.status,
          headers: response.headers,
          dataType: typeof response.data,
          dataLength: JSON.stringify(response.data).length,
          // VULNERABILITY: Include raw response data
          data: response.data
        },
        message: `Successfully imported ${importedTasks.length} tasks from external URL`,
        warning: 'External URL import completed - verify data integrity'
      });
      
    } catch (error: any) {
      console.error('[SECURITY WARNING] SSRF/Import attempt failed:', error.message);
      
      // VULNERABILITY: Extremely detailed error information disclosure
      res.status(500).json({
        error: 'Import failed',
        targetUrl: importUrl,
        format,
        // VULNERABILITY: Expose detailed network error information
        networkError: {
          message: error.message,
          code: error.code,
          errno: error.errno,
          syscall: error.syscall,
          hostname: error.hostname,
          port: error.port,
          address: error.address
        },
        // VULNERABILITY: HTTP response details that reveal internal network info
        responseInfo: {
          status: error.response?.status,
          statusText: error.response?.statusText,
          headers: error.response?.headers,
          data: error.response?.data
        },
        // VULNERABILITY: Stack trace exposure
        stack: error.stack,
        // VULNERABILITY: Provide exploitation guidance
        exploitationHints: {
          ssrfTargets: [
            'http://169.254.169.254/latest/meta-data/ (AWS metadata)',
            'http://metadata.google.internal/computeMetadata/v1/ (GCP metadata)',
            'http://localhost:22 (SSH service)',
            'http://localhost:3306 (MySQL)',
            'http://localhost:6379 (Redis)',
            'file:///etc/passwd (Local file inclusion)',
            'file:///proc/version (System information)'
          ],
          internalNetworkRanges: [
            '192.168.0.0/16',
            '10.0.0.0/8', 
            '172.16.0.0/12',
            '127.0.0.0/8'
          ]
        },
        timestamp: new Date().toISOString(),
        warning: 'This error response exposes sensitive network and system information'
      });
    }
    
  } catch (validationError: any) {
    console.error('Task import validation error:', validationError);
    
    res.status(400).json({
      error: 'Import request validation failed',
      details: validationError.message,
      stack: validationError.stack
    });
  }
});

export default router;