import { PrismaClient, Prisma } from '@prisma/client';
import { Request } from 'express';

const prisma = new PrismaClient();

/**
 * Secure SQL Query Implementations
 * 
 * This module provides secure alternatives to vulnerable SQL operations
 * following security best practices:
 * 
 * 1. Parameterized queries using Prisma ORM
 * 2. Proper input validation and sanitization
 * 3. Safe error handling without information disclosure
 * 4. Query result limiting and access control
 * 5. Proper authorization checks
 */

// Input validation utilities
export const validateSearchInput = (query: string): { isValid: boolean; error?: string } => {
  if (!query) {
    return { isValid: false, error: 'Search query is required' };
  }
  
  if (typeof query !== 'string') {
    return { isValid: false, error: 'Search query must be a string' };
  }
  
  if (query.length < 1) {
    return { isValid: false, error: 'Search query must be at least 1 character' };
  }
  
  if (query.length > 100) {
    return { isValid: false, error: 'Search query must be less than 100 characters' };
  }
  
  // Check for potentially malicious patterns
  const suspiciousPatterns = [
    /union\s+select/i,
    /drop\s+table/i,
    /delete\s+from/i,
    /insert\s+into/i,
    /update\s+set/i,
    /exec\s*\(/i,
    /script\s*>/i,
    /<\s*script/i,
    /javascript:/i,
    /vbscript:/i
  ];
  
  for (const pattern of suspiciousPatterns) {
    if (pattern.test(query)) {
      return { isValid: false, error: 'Search query contains potentially malicious content' };
    }
  }
  
  return { isValid: true };
};

export const validateSortParameters = (sortBy?: string, order?: string): { isValid: boolean; error?: string } => {
  const allowedSortFields = ['title', 'createdAt', 'updatedAt', 'priority', 'status', 'dueDate'];
  const allowedOrders = ['asc', 'desc'];
  
  if (sortBy && !allowedSortFields.includes(sortBy)) {
    return { isValid: false, error: `Invalid sort field. Allowed fields: ${allowedSortFields.join(', ')}` };
  }
  
  if (order && !allowedOrders.includes(order.toLowerCase())) {
    return { isValid: false, error: `Invalid sort order. Allowed orders: ${allowedOrders.join(', ')}` };
  }
  
  return { isValid: true };
};

export const validatePaginationParameters = (page?: string, limit?: string): { 
  isValid: boolean; 
  error?: string;
  pageNum?: number;
  limitNum?: number;
} => {
  const pageNum = page ? parseInt(page) : 1;
  const limitNum = limit ? parseInt(limit) : 10;
  
  if (isNaN(pageNum) || pageNum < 1) {
    return { isValid: false, error: 'Page must be a positive integer' };
  }
  
  if (isNaN(limitNum) || limitNum < 1 || limitNum > 100) {
    return { isValid: false, error: 'Limit must be between 1 and 100' };
  }
  
  return { isValid: true, pageNum, limitNum };
};

/**
 * Secure Task Search Implementation
 * 
 * Uses Prisma ORM with parameterized queries to prevent SQL injection
 * Implements proper access control and input validation
 */
export const secureTaskSearch = async (
  userId: number,
  searchParams: {
    query?: string;
    category?: string;
    priority?: string;
    status?: string;
    sortBy?: string;
    order?: string;
    page?: string;
    limit?: string;
  }
) => {
  const { query, category, priority, status, sortBy = 'createdAt', order = 'desc', page, limit } = searchParams;
  
  // Validate search input
  if (query) {
    const validation = validateSearchInput(query);
    if (!validation.isValid) {
      throw new Error(validation.error);
    }
  }
  
  // Validate sort parameters
  const sortValidation = validateSortParameters(sortBy, order);
  if (!sortValidation.isValid) {
    throw new Error(sortValidation.error);
  }
  
  // Validate pagination
  const paginationValidation = validatePaginationParameters(page, limit);
  if (!paginationValidation.isValid) {
    throw new Error(paginationValidation.error);
  }
  
  const { pageNum, limitNum } = paginationValidation;
  const skip = ((pageNum || 1) - 1) * (limitNum || 10);
  
  // Build secure where clause with proper access control
  const whereClause: Prisma.TaskWhereInput = {
    // SECURITY: Always filter by user ID to prevent unauthorized access
    userId: userId,
    AND: []
  };
  
  // Add search conditions using Prisma's safe query methods
  if (query) {
    whereClause.AND!.push({
      OR: [
        { title: { contains: query, mode: 'insensitive' } },
        { description: { contains: query, mode: 'insensitive' } }
      ]
    });
  }
  
  // Add category filter (search in title)
  if (category) {
    whereClause.AND!.push({
      title: { contains: category, mode: 'insensitive' }
    });
  }
  
  // Add priority filter with enum validation
  if (priority && ['LOW', 'MEDIUM', 'HIGH', 'URGENT'].includes(priority)) {
    whereClause.AND!.push({
      priority: priority as Prisma.EnumPriorityFilter
    });
  }
  
  // Add status filter with enum validation
  if (status && ['TODO', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED'].includes(status)) {
    whereClause.AND!.push({
      status: status as Prisma.EnumTaskStatusFilter
    });
  }
  
  // Build secure order by clause
  const orderByClause: Prisma.TaskOrderByWithRelationInput = {};
  if (sortBy === 'createdAt') orderByClause.createdAt = order as 'asc' | 'desc';
  else if (sortBy === 'updatedAt') orderByClause.updatedAt = order as 'asc' | 'desc';
  else if (sortBy === 'title') orderByClause.title = order as 'asc' | 'desc';
  else if (sortBy === 'priority') orderByClause.priority = order as 'asc' | 'desc';
  else if (sortBy === 'status') orderByClause.status = order as 'asc' | 'desc';
  else if (sortBy === 'dueDate') orderByClause.dueDate = order as 'asc' | 'desc';
  else orderByClause.createdAt = 'desc'; // Default fallback
  
  try {
    // Execute secure parameterized query
    const [tasks, totalCount] = await Promise.all([
      prisma.task.findMany({
        where: whereClause,
        include: {
          user: {
            select: {
              id: true,
              firstName: true,
              lastName: true,
              // SECURITY: Never expose sensitive data like email or password hash
            }
          },
          _count: {
            select: { comments: true }
          }
        },
        orderBy: orderByClause,
        skip,
        take: limitNum || 10
      }),
      prisma.task.count({ where: whereClause })
    ]);
    
    return {
      success: true,
      tasks: tasks.map(task => ({
        id: task.id,
        title: task.title,
        description: task.description,
        priority: task.priority,
        status: task.status,
        dueDate: task.dueDate,
        createdAt: task.createdAt,
        updatedAt: task.updatedAt,
        user: task.user,
        commentCount: task._count.comments
      })),
      pagination: {
        page: pageNum || 1,
        limit: limitNum || 10,
        total: totalCount,
        pages: Math.ceil(totalCount / (limitNum || 10))
      }
    };
    
  } catch (error) {
    // SECURITY: Safe error handling without exposing internal details
    console.error('Secure task search error:', error);
    throw new Error('Search operation failed');
  }
};

/**
 * Secure Task Retrieval with Ownership Verification
 */
export const secureGetTask = async (taskId: number, userId: number) => {
  if (!Number.isInteger(taskId) || taskId <= 0) {
    throw new Error('Invalid task ID');
  }
  
  try {
    const task = await prisma.task.findFirst({
      where: {
        id: taskId,
        // SECURITY: Always verify ownership
        userId: userId
      },
      include: {
        user: {
          select: {
            id: true,
            firstName: true,
            lastName: true
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
      throw new Error('Task not found or access denied');
    }
    
    return { success: true, task };
    
  } catch (error) {
    console.error('Secure get task error:', error);
    throw new Error('Failed to retrieve task');
  }
};

/**
 * Secure Task Update with Ownership Verification
 */
export const secureUpdateTask = async (
  taskId: number, 
  userId: number, 
  updateData: {
    title?: string;
    description?: string;
    priority?: string;
    status?: string;
    dueDate?: string;
  }
) => {
  if (!Number.isInteger(taskId) || taskId <= 0) {
    throw new Error('Invalid task ID');
  }
  
  // Validate update data
  const validatedData: any = {};
  
  if (updateData.title !== undefined) {
    if (typeof updateData.title !== 'string' || updateData.title.length < 1 || updateData.title.length > 200) {
      throw new Error('Title must be between 1-200 characters');
    }
    validatedData.title = updateData.title.trim();
  }
  
  if (updateData.description !== undefined) {
    if (updateData.description && (typeof updateData.description !== 'string' || updateData.description.length > 1000)) {
      throw new Error('Description must be less than 1000 characters');
    }
    validatedData.description = updateData.description?.trim() || null;
  }
  
  if (updateData.priority !== undefined) {
    if (!['LOW', 'MEDIUM', 'HIGH', 'URGENT'].includes(updateData.priority)) {
      throw new Error('Priority must be LOW, MEDIUM, HIGH, or URGENT');
    }
    validatedData.priority = updateData.priority;
  }
  
  if (updateData.status !== undefined) {
    if (!['TODO', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED'].includes(updateData.status)) {
      throw new Error('Status must be TODO, IN_PROGRESS, COMPLETED, or CANCELLED');
    }
    validatedData.status = updateData.status;
  }
  
  if (updateData.dueDate !== undefined) {
    if (updateData.dueDate) {
      const date = new Date(updateData.dueDate);
      if (isNaN(date.getTime())) {
        throw new Error('Due date must be a valid date');
      }
      validatedData.dueDate = date;
    } else {
      validatedData.dueDate = null;
    }
  }
  
  try {
    // SECURITY: Update only if user owns the task
    const updatedTask = await prisma.task.updateMany({
      where: {
        id: taskId,
        userId: userId // Ownership verification
      },
      data: validatedData
    });
    
    if (updatedTask.count === 0) {
      throw new Error('Task not found or access denied');
    }
    
    // Fetch the updated task with relations
    const task = await prisma.task.findUnique({
      where: { id: taskId },
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
    
    return { success: true, task };
    
  } catch (error) {
    console.error('Secure update task error:', error);
    throw new Error('Failed to update task');
  }
};

/**
 * Secure Task Deletion with Ownership Verification
 */
export const secureDeleteTask = async (taskId: number, userId: number) => {
  if (!Number.isInteger(taskId) || taskId <= 0) {
    throw new Error('Invalid task ID');
  }
  
  try {
    // SECURITY: Delete only if user owns the task
    const deletedTask = await prisma.task.deleteMany({
      where: {
        id: taskId,
        userId: userId // Ownership verification
      }
    });
    
    if (deletedTask.count === 0) {
      throw new Error('Task not found or access denied');
    }
    
    return { success: true, message: 'Task deleted successfully' };
    
  } catch (error) {
    console.error('Secure delete task error:', error);
    throw new Error('Failed to delete task');
  }
};

/**
 * Secure Task Listing with Proper Access Control
 */
export const secureGetUserTasks = async (
  userId: number,
  options: {
    page?: string;
    limit?: string;
    status?: string;
    priority?: string;
    search?: string;
  } = {}
) => {
  const { page, limit, status, priority, search } = options;
  
  // Validate pagination
  const paginationValidation = validatePaginationParameters(page, limit);
  if (!paginationValidation.isValid) {
    throw new Error(paginationValidation.error);
  }
  
  const { pageNum, limitNum } = paginationValidation;
  const skip = ((pageNum || 1) - 1) * (limitNum || 10);
  
  // Build secure where clause
  const whereClause: Prisma.TaskWhereInput = {
    // SECURITY: Always filter by user ID
    userId: userId,
    AND: []
  };
  
  // Add filters
  if (status && ['TODO', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED'].includes(status)) {
    whereClause.AND!.push({ status: status as any });
  }
  
  if (priority && ['LOW', 'MEDIUM', 'HIGH', 'URGENT'].includes(priority)) {
    whereClause.AND!.push({ priority: priority as any });
  }
  
  if (search) {
    const searchValidation = validateSearchInput(search);
    if (!searchValidation.isValid) {
      throw new Error(searchValidation.error);
    }
    
    whereClause.AND!.push({
      OR: [
        { title: { contains: search, mode: 'insensitive' } },
        { description: { contains: search, mode: 'insensitive' } }
      ]
    });
  }
  
  try {
    const [tasks, totalCount] = await Promise.all([
      prisma.task.findMany({
        where: whereClause,
        include: {
          user: {
            select: {
              id: true,
              firstName: true,
              lastName: true
            }
          },
          _count: {
            select: { comments: true }
          }
        },
        orderBy: { createdAt: 'desc' },
        skip,
        take: limitNum || 10
      }),
      prisma.task.count({ where: whereClause })
    ]);
    
    return {
      success: true,
      tasks,
      pagination: {
        page: pageNum || 1,
        limit: limitNum || 10,
        total: totalCount,
        pages: Math.ceil(totalCount / (limitNum || 10))
      }
    };
    
  } catch (error) {
    console.error('Secure get user tasks error:', error);
    throw new Error('Failed to retrieve tasks');
  }
};

/**
 * Secure Bulk Operations with Ownership Verification
 */
export const secureBulkTaskOperation = async (
  userId: number,
  operation: {
    action: 'delete' | 'update_status' | 'update_priority';
    taskIds: number[];
    newStatus?: string;
    newPriority?: string;
  }
) => {
  const { action, taskIds, newStatus, newPriority } = operation;
  
  // Validate input
  if (!Array.isArray(taskIds) || taskIds.length === 0) {
    throw new Error('Task IDs must be a non-empty array');
  }
  
  if (taskIds.length > 100) {
    throw new Error('Cannot process more than 100 tasks at once');
  }
  
  for (const id of taskIds) {
    if (!Number.isInteger(id) || id <= 0) {
      throw new Error('All task IDs must be positive integers');
    }
  }
  
  // Validate action-specific parameters
  if (action === 'update_status') {
    if (!newStatus || !['TODO', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED'].includes(newStatus)) {
      throw new Error('Valid new status is required for status update');
    }
  }
  
  if (action === 'update_priority') {
    if (!newPriority || !['LOW', 'MEDIUM', 'HIGH', 'URGENT'].includes(newPriority)) {
      throw new Error('Valid new priority is required for priority update');
    }
  }
  
  try {
    let result: any;
    
    // SECURITY: All operations include ownership verification
    const baseWhere = {
      id: { in: taskIds },
      userId: userId // Ownership verification
    };
    
    switch (action) {
      case 'delete':
        result = await prisma.task.deleteMany({
          where: baseWhere
        });
        break;
        
      case 'update_status':
        result = await prisma.task.updateMany({
          where: baseWhere,
          data: { status: newStatus as any }
        });
        break;
        
      case 'update_priority':
        result = await prisma.task.updateMany({
          where: baseWhere,
          data: { priority: newPriority as any }
        });
        break;
        
      default:
        throw new Error('Invalid bulk operation action');
    }
    
    return {
      success: true,
      action,
      affectedCount: result.count,
      message: `Successfully ${action.replace('_', ' ')} ${result.count} task(s)`
    };
    
  } catch (error) {
    console.error('Secure bulk operation error:', error);
    throw new Error('Bulk operation failed');
  }
};

/**
 * Safe Error Handler for Database Operations
 * 
 * Provides consistent error responses without exposing internal details
 */
export const handleSecureError = (error: any, operation: string) => {
  console.error(`Secure ${operation} error:`, error);
  
  // Return generic error message without exposing internal details
  return {
    success: false,
    error: `${operation} operation failed`,
    message: 'An error occurred while processing your request. Please try again.',
    // Only include error details in development
    ...(process.env.NODE_ENV === 'development' && {
      details: error.message
    })
  };
};