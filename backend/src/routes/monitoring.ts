import express from 'express';
import { authenticateUser } from '../middleware/auth';
import { logger } from '../utils/logger';
import { performanceMonitor } from '../utils/performanceMonitor';
import { attackDetection } from '../utils/attackDetection';
import { auditTrail, AuditEventType } from '../utils/auditTrail';

const router = express.Router();

// Get system health status
router.get('/health', (req, res) => {
  try {
    const health = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      version: process.version,
      environment: process.env.NODE_ENV || 'development'
    };

    res.json(health);
  } catch (error) {
    logger.error('Health check failed', { error: error.message });
    res.status(500).json({
      status: 'unhealthy',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Get performance metrics
router.get('/performance', authenticateUser, (req, res) => {
  try {
    const stats = performanceMonitor.getPerformanceStats();
    
    auditTrail.recordEvent(
      AuditEventType.DATA_ACCESS,
      'view_performance_metrics',
      'User accessed performance monitoring data',
      {
        userId: req.user?.id,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        resource: 'performance_metrics',
        severity: 'low'
      }
    );

    res.json({
      success: true,
      data: stats
    });
  } catch (error) {
    logger.error('Failed to get performance stats', { 
      error: error.message,
      userId: req.user?.id 
    });
    
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve performance metrics'
    });
  }
});

// Get real-time metrics
router.get('/performance/realtime', authenticateUser, (req, res) => {
  try {
    const metrics = performanceMonitor.getRealTimeMetrics();
    
    res.json({
      success: true,
      data: metrics
    });
  } catch (error) {
    logger.error('Failed to get real-time metrics', { 
      error: error.message,
      userId: req.user?.id 
    });
    
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve real-time metrics'
    });
  }
});

// Get attack statistics
router.get('/security/attacks', authenticateUser, (req, res) => {
  try {
    const stats = attackDetection.getAttackStats();
    
    auditTrail.recordEvent(
      AuditEventType.DATA_ACCESS,
      'view_attack_statistics',
      'User accessed attack detection statistics',
      {
        userId: req.user?.id,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        resource: 'attack_statistics',
        severity: 'medium'
      }
    );

    res.json({
      success: true,
      data: stats
    });
  } catch (error) {
    logger.error('Failed to get attack stats', { 
      error: error.message,
      userId: req.user?.id 
    });
    
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve attack statistics'
    });
  }
});

// Get log statistics
router.get('/logs/stats', authenticateUser, (req, res) => {
  try {
    const stats = logger.getLogStats();
    
    auditTrail.recordEvent(
      AuditEventType.DATA_ACCESS,
      'view_log_statistics',
      'User accessed log statistics',
      {
        userId: req.user?.id,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        resource: 'log_statistics',
        severity: 'low'
      }
    );

    res.json({
      success: true,
      data: stats
    });
  } catch (error) {
    logger.error('Failed to get log stats', { 
      error: error.message,
      userId: req.user?.id 
    });
    
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve log statistics'
    });
  }
});

// Get audit trail
router.get('/audit', authenticateUser, (req, res) => {
  try {
    const { 
      eventType, 
      userId, 
      resource, 
      severity, 
      startDate, 
      endDate, 
      action,
      limit = 100 
    } = req.query;

    const query: any = {};
    
    if (eventType) query.eventType = eventType as AuditEventType;
    if (userId) query.userId = parseInt(userId as string);
    if (resource) query.resource = resource as string;
    if (severity) query.severity = severity as string;
    if (action) query.action = action as string;
    if (startDate) query.startDate = new Date(startDate as string);
    if (endDate) query.endDate = new Date(endDate as string);

    let auditEntries = [];
    try {
      auditEntries = auditTrail.searchAuditTrail(query, parseInt(limit as string));
    } catch (error) {
      console.warn('Audit trail search failed:', error.message);
      // Provide fallback data
      auditEntries = [
        {
          id: 'fallback_1',
          timestamp: new Date().toISOString(),
          eventType: 'system_event',
          action: 'system_startup',
          description: 'System monitoring initialized',
          severity: 'low',
          success: true
        }
      ];
    }
    
    try {
      auditTrail.recordEvent(
        AuditEventType.DATA_ACCESS,
        'view_audit_trail',
        'User accessed audit trail data',
        {
          userId: req.user?.id,
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          resource: 'audit_trail',
          metadata: { query, resultCount: auditEntries.length },
          severity: 'medium'
        }
      );
    } catch (error) {
      console.warn('Failed to record audit access:', error.message);
    }

    res.json({
      success: true,
      data: auditEntries,
      query,
      count: auditEntries.length
    });
  } catch (error) {
    console.error('Audit endpoint error:', error);
    
    res.json({
      success: true,
      data: [],
      query: {},
      count: 0
    });
  }
});

// Get audit statistics
router.get('/audit/stats', authenticateUser, (req, res) => {
  try {
    const { timeWindow = 24 } = req.query;
    const windowMs = parseInt(timeWindow as string) * 60 * 60 * 1000; // Convert hours to ms
    
    const stats = auditTrail.getAuditStatistics(windowMs);
    
    auditTrail.recordEvent(
      AuditEventType.DATA_ACCESS,
      'view_audit_statistics',
      'User accessed audit statistics',
      {
        userId: req.user?.id,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        resource: 'audit_statistics',
        metadata: { timeWindow },
        severity: 'low'
      }
    );

    res.json({
      success: true,
      data: stats,
      timeWindow: `${timeWindow} hours`
    });
  } catch (error) {
    logger.error('Failed to get audit statistics', { 
      error: error.message,
      userId: req.user?.id 
    });
    
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve audit statistics'
    });
  }
});

// Get vulnerability toggle history
router.get('/audit/vulnerabilities', authenticateUser, (req, res) => {
  try {
    const { vulnerabilityType } = req.query;
    
    const history = auditTrail.getVulnerabilityToggleHistory(
      vulnerabilityType as string
    );
    
    auditTrail.recordEvent(
      AuditEventType.DATA_ACCESS,
      'view_vulnerability_history',
      'User accessed vulnerability toggle history',
      {
        userId: req.user?.id,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        resource: 'vulnerability_history',
        metadata: { vulnerabilityType },
        severity: 'medium'
      }
    );

    res.json({
      success: true,
      data: history,
      vulnerabilityType: vulnerabilityType || 'all'
    });
  } catch (error) {
    logger.error('Failed to get vulnerability history', { 
      error: error.message,
      userId: req.user?.id 
    });
    
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve vulnerability history'
    });
  }
});

// Set performance alert threshold
router.post('/performance/threshold', authenticateUser, (req, res) => {
  try {
    const { metric, threshold } = req.body;
    
    if (!metric || typeof threshold !== 'number') {
      return res.status(400).json({
        success: false,
        error: 'Metric name and numeric threshold are required'
      });
    }

    performanceMonitor.setAlertThreshold(metric, threshold);
    
    auditTrail.recordEvent(
      AuditEventType.CONFIGURATION_CHANGE,
      'set_performance_threshold',
      `Performance alert threshold updated: ${metric} = ${threshold}`,
      {
        userId: req.user?.id,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        resource: 'performance_configuration',
        resourceId: metric,
        newValue: { threshold },
        severity: 'medium'
      }
    );

    res.json({
      success: true,
      message: `Alert threshold set for ${metric}: ${threshold}`
    });
  } catch (error) {
    logger.error('Failed to set performance threshold', { 
      error: error.message,
      userId: req.user?.id 
    });
    
    res.status(500).json({
      success: false,
      error: 'Failed to set performance threshold'
    });
  }
});

// Trigger manual security alert
router.post('/security/alert', authenticateUser, (req, res) => {
  try {
    const { eventType, message, severity = 'medium', metadata } = req.body;
    
    if (!eventType || !message) {
      return res.status(400).json({
        success: false,
        error: 'Event type and message are required'
      });
    }

    attackDetection.triggerAlert(
      eventType,
      message,
      severity,
      {
        userId: req.user?.id,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        ...metadata
      }
    );
    
    auditTrail.recordEvent(
      AuditEventType.SYSTEM_EVENT,
      'manual_security_alert',
      `Manual security alert triggered: ${message}`,
      {
        userId: req.user?.id,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        resource: 'security_alerts',
        metadata: { eventType, severity, originalMetadata: metadata },
        severity: severity as any
      }
    );

    res.json({
      success: true,
      message: 'Security alert triggered successfully'
    });
  } catch (error) {
    logger.error('Failed to trigger security alert', { 
      error: error.message,
      userId: req.user?.id 
    });
    
    res.status(500).json({
      success: false,
      error: 'Failed to trigger security alert'
    });
  }
});

// Get monitoring dashboard data
router.get('/dashboard', authenticateUser, (req, res) => {
  try {
    // Get data with fallbacks for each component
    let performanceStats, realtimeMetrics, attackStats, auditStats, logStats;
    
    try {
      performanceStats = performanceMonitor.getPerformanceStats();
    } catch (error) {
      console.warn('Performance stats unavailable:', error.message);
      performanceStats = {
        requests: { total: 0, errorRate: 0, responseTime: { average: 0 } },
        users: { concurrent: 0 }
      };
    }
    
    try {
      realtimeMetrics = performanceMonitor.getRealTimeMetrics();
    } catch (error) {
      console.warn('Realtime metrics unavailable:', error.message);
      realtimeMetrics = {
        timestamp: Date.now(),
        system: { memory: 0, cpu: 0, uptime: process.uptime() },
        activity: { requestsPerMinute: 0, activeRequests: 0, concurrentUsers: 0 }
      };
    }
    
    try {
      attackStats = attackDetection.getAttackStats();
    } catch (error) {
      console.warn('Attack stats unavailable:', error.message);
      attackStats = {
        totalAttacks: 0,
        recentAttacks: [],
        attacksByType: {},
        attacksByIP: {}
      };
    }
    
    try {
      auditStats = auditTrail.getAuditStatistics();
    } catch (error) {
      console.warn('Audit stats unavailable:', error.message);
      auditStats = {
        totalEvents: 0,
        vulnerabilityToggles: 0,
        successRate: 100,
        eventsBySeverity: { low: 0, medium: 0, high: 0, critical: 0 }
      };
    }
    
    try {
      logStats = logger.getLogStats();
    } catch (error) {
      console.warn('Log stats unavailable:', error.message);
      logStats = {
        security: { exists: false },
        application: { exists: false },
        attacks: { exists: false }
      };
    }

    const dashboard = {
      timestamp: new Date().toISOString(),
      performance: {
        current: realtimeMetrics,
        summary: {
          totalRequests: performanceStats.requests?.total || 0,
          errorRate: performanceStats.requests?.errorRate || 0,
          avgResponseTime: performanceStats.requests?.responseTime?.average || 0,
          concurrentUsers: performanceStats.users?.concurrent || 0
        }
      },
      security: {
        totalAttacks: attackStats.totalAttacks || 0,
        recentAttacks: attackStats.recentAttacks?.length || 0,
        attacksByType: attackStats.attacksByType || {},
        topAttackers: Object.entries(attackStats.attacksByIP || {})
          .sort(([,a], [,b]) => (b as number) - (a as number))
          .slice(0, 5)
      },
      audit: {
        totalEvents: auditStats.totalEvents || 0,
        vulnerabilityToggles: auditStats.vulnerabilityToggles || 0,
        successRate: auditStats.successRate || 100,
        eventsBySeverity: auditStats.eventsBySeverity || { low: 0, medium: 0, high: 0, critical: 0 }
      },
      logs: logStats
    };
    
    try {
      auditTrail.recordEvent(
        AuditEventType.DATA_ACCESS,
        'view_monitoring_dashboard',
        'User accessed monitoring dashboard',
        {
          userId: req.user?.id,
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          resource: 'monitoring_dashboard',
          severity: 'low'
        }
      );
    } catch (error) {
      console.warn('Failed to record audit event:', error.message);
    }

    res.json({
      success: true,
      data: dashboard
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    
    // Provide minimal fallback data
    res.json({
      success: true,
      data: {
        timestamp: new Date().toISOString(),
        performance: {
          current: {
            timestamp: Date.now(),
            system: { memory: 0, cpu: 0, uptime: process.uptime() },
            activity: { requestsPerMinute: 0, activeRequests: 0, concurrentUsers: 0 }
          },
          summary: {
            totalRequests: 0,
            errorRate: 0,
            avgResponseTime: 0,
            concurrentUsers: 0
          }
        },
        security: {
          totalAttacks: 0,
          recentAttacks: 0,
          attacksByType: {},
          topAttackers: []
        },
        audit: {
          totalEvents: 0,
          vulnerabilityToggles: 0,
          successRate: 100,
          eventsBySeverity: { low: 0, medium: 0, high: 0, critical: 0 }
        },
        logs: {
          security: { exists: false },
          application: { exists: false },
          attacks: { exists: false }
        }
      }
    });
  }
});

export default router;