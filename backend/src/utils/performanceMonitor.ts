import { logger } from './logger';

// Performance metrics interface
interface PerformanceMetric {
  name: string;
  value: number;
  timestamp: number;
  metadata?: any;
}

// System resource metrics
interface SystemMetrics {
  cpu: {
    usage: number;
    loadAverage: number[];
  };
  memory: {
    used: number;
    free: number;
    total: number;
    percentage: number;
  };
  uptime: number;
  timestamp: number;
}

// Request performance metrics
interface RequestMetrics {
  endpoint: string;
  method: string;
  responseTime: number;
  statusCode: number;
  timestamp: number;
  userId?: number;
}

class PerformanceMonitor {
  private metrics: PerformanceMetric[];
  private requestMetrics: RequestMetrics[];
  private systemMetrics: SystemMetrics[];
  private maxMetricsHistory: number;
  private alertThresholds: Map<string, number>;
  private concurrentUsers: Set<number>;
  private activeRequests: Map<string, number>;

  constructor() {
    this.metrics = [];
    this.requestMetrics = [];
    this.systemMetrics = [];
    this.maxMetricsHistory = 1000; // Keep last 1000 metrics
    this.alertThresholds = new Map();
    this.concurrentUsers = new Set();
    this.activeRequests = new Map();
    
    this.initializeThresholds();
    this.startSystemMonitoring();
    
    // Clean up old metrics every 10 minutes
    setInterval(() => this.cleanup(), 10 * 60 * 1000);
  }

  private initializeThresholds(): void {
    this.alertThresholds.set('response_time', 2000); // 2 seconds
    this.alertThresholds.set('memory_usage', 80); // 80%
    this.alertThresholds.set('cpu_usage', 80); // 80%
    this.alertThresholds.set('concurrent_users', 100); // 100 users
    this.alertThresholds.set('error_rate', 10); // 10%
  }

  private startSystemMonitoring(): void {
    // Monitor system resources every 30 seconds
    setInterval(() => {
      this.collectSystemMetrics();
    }, 30 * 1000);
  }

  // Collect system resource metrics
  private collectSystemMetrics(): void {
    const os = require('os');
    const process = require('process');

    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    const memPercentage = (usedMem / totalMem) * 100;

    const systemMetric: SystemMetrics = {
      cpu: {
        usage: this.getCPUUsage(),
        loadAverage: os.loadavg()
      },
      memory: {
        used: usedMem,
        free: freeMem,
        total: totalMem,
        percentage: memPercentage
      },
      uptime: process.uptime(),
      timestamp: Date.now()
    };

    this.systemMetrics.push(systemMetric);
    
    // Check for alerts
    this.checkSystemAlerts(systemMetric);
    
    // Keep only recent metrics
    if (this.systemMetrics.length > this.maxMetricsHistory) {
      this.systemMetrics = this.systemMetrics.slice(-this.maxMetricsHistory);
    }
  }

  private getCPUUsage(): number {
    const os = require('os');
    const cpus = os.cpus();
    
    let totalIdle = 0;
    let totalTick = 0;
    
    cpus.forEach((cpu: any) => {
      for (const type in cpu.times) {
        totalTick += cpu.times[type];
      }
      totalIdle += cpu.times.idle;
    });
    
    return 100 - (totalIdle / totalTick) * 100;
  }

  // Record request performance
  recordRequest(
    method: string,
    endpoint: string,
    responseTime: number,
    statusCode: number,
    userId?: number
  ): void {
    const requestMetric: RequestMetrics = {
      method,
      endpoint,
      responseTime,
      statusCode,
      timestamp: Date.now(),
      userId
    };

    this.requestMetrics.push(requestMetric);
    
    // Track concurrent users
    if (userId) {
      this.concurrentUsers.add(userId);
    }
    
    // Check for performance alerts
    this.checkRequestAlerts(requestMetric);
    
    // Keep only recent metrics
    if (this.requestMetrics.length > this.maxMetricsHistory) {
      this.requestMetrics = this.requestMetrics.slice(-this.maxMetricsHistory);
    }
  }

  // Track active requests
  startRequest(requestId: string): void {
    this.activeRequests.set(requestId, Date.now());
  }

  endRequest(requestId: string): number {
    const startTime = this.activeRequests.get(requestId);
    if (startTime) {
      this.activeRequests.delete(requestId);
      return Date.now() - startTime;
    }
    return 0;
  }

  // Record custom performance metric
  recordMetric(name: string, value: number, metadata?: any): void {
    const metric: PerformanceMetric = {
      name,
      value,
      timestamp: Date.now(),
      metadata
    };

    this.metrics.push(metric);
    
    // Check for custom metric alerts
    const threshold = this.alertThresholds.get(name);
    if (threshold && value > threshold) {
      logger.warn(`Performance alert: ${name} exceeded threshold`, {
        value,
        threshold,
        metadata
      });
    }
    
    // Keep only recent metrics
    if (this.metrics.length > this.maxMetricsHistory) {
      this.metrics = this.metrics.slice(-this.maxMetricsHistory);
    }
  }

  // Check system resource alerts
  private checkSystemAlerts(metrics: SystemMetrics): void {
    const memThreshold = this.alertThresholds.get('memory_usage') || 80;
    const cpuThreshold = this.alertThresholds.get('cpu_usage') || 80;

    if (metrics.memory.percentage > memThreshold) {
      logger.warn('High memory usage detected', {
        usage: metrics.memory.percentage,
        threshold: memThreshold,
        used: metrics.memory.used,
        total: metrics.memory.total
      });
    }

    if (metrics.cpu.usage > cpuThreshold) {
      logger.warn('High CPU usage detected', {
        usage: metrics.cpu.usage,
        threshold: cpuThreshold,
        loadAverage: metrics.cpu.loadAverage
      });
    }
  }

  // Check request performance alerts
  private checkRequestAlerts(metric: RequestMetrics): void {
    const responseTimeThreshold = this.alertThresholds.get('response_time') || 2000;
    
    if (metric.responseTime > responseTimeThreshold) {
      logger.warn('Slow request detected', {
        endpoint: metric.endpoint,
        method: metric.method,
        responseTime: metric.responseTime,
        threshold: responseTimeThreshold,
        statusCode: metric.statusCode,
        userId: metric.userId
      });
    }

    // Check concurrent users
    const concurrentThreshold = this.alertThresholds.get('concurrent_users') || 100;
    if (this.concurrentUsers.size > concurrentThreshold) {
      logger.warn('High concurrent user count', {
        count: this.concurrentUsers.size,
        threshold: concurrentThreshold
      });
    }
  }

  // Get performance statistics
  getPerformanceStats(): any {
    const now = Date.now();
    const oneHourAgo = now - (60 * 60 * 1000);
    const recentRequests = this.requestMetrics.filter(m => m.timestamp > oneHourAgo);
    const recentSystemMetrics = this.systemMetrics.filter(m => m.timestamp > oneHourAgo);

    // Calculate request statistics
    const totalRequests = recentRequests.length;
    const errorRequests = recentRequests.filter(r => r.statusCode >= 400).length;
    const errorRate = totalRequests > 0 ? (errorRequests / totalRequests) * 100 : 0;
    
    const responseTimes = recentRequests.map(r => r.responseTime);
    const avgResponseTime = responseTimes.length > 0 
      ? responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length 
      : 0;
    
    const maxResponseTime = responseTimes.length > 0 ? Math.max(...responseTimes) : 0;
    const minResponseTime = responseTimes.length > 0 ? Math.min(...responseTimes) : 0;

    // Calculate system statistics
    const latestSystemMetric = recentSystemMetrics[recentSystemMetrics.length - 1];
    const avgMemoryUsage = recentSystemMetrics.length > 0
      ? recentSystemMetrics.reduce((sum, m) => sum + m.memory.percentage, 0) / recentSystemMetrics.length
      : 0;
    
    const avgCpuUsage = recentSystemMetrics.length > 0
      ? recentSystemMetrics.reduce((sum, m) => sum + m.cpu.usage, 0) / recentSystemMetrics.length
      : 0;

    // Endpoint statistics
    const endpointStats = this.getEndpointStats(recentRequests);

    return {
      timestamp: now,
      timeWindow: '1 hour',
      requests: {
        total: totalRequests,
        errors: errorRequests,
        errorRate: Math.round(errorRate * 100) / 100,
        responseTime: {
          average: Math.round(avgResponseTime),
          min: minResponseTime,
          max: maxResponseTime
        }
      },
      system: {
        current: latestSystemMetric ? {
          memory: Math.round(latestSystemMetric.memory.percentage * 100) / 100,
          cpu: Math.round(latestSystemMetric.cpu.usage * 100) / 100,
          uptime: latestSystemMetric.uptime
        } : null,
        averages: {
          memory: Math.round(avgMemoryUsage * 100) / 100,
          cpu: Math.round(avgCpuUsage * 100) / 100
        }
      },
      users: {
        concurrent: this.concurrentUsers.size,
        activeRequests: this.activeRequests.size
      },
      endpoints: endpointStats
    };
  }

  private getEndpointStats(requests: RequestMetrics[]): any {
    const endpointMap = new Map<string, {
      count: number;
      totalTime: number;
      errors: number;
      methods: Set<string>;
    }>();

    requests.forEach(req => {
      const key = req.endpoint;
      const existing = endpointMap.get(key) || {
        count: 0,
        totalTime: 0,
        errors: 0,
        methods: new Set()
      };

      existing.count++;
      existing.totalTime += req.responseTime;
      existing.methods.add(req.method);
      
      if (req.statusCode >= 400) {
        existing.errors++;
      }

      endpointMap.set(key, existing);
    });

    const stats: any[] = [];
    endpointMap.forEach((data, endpoint) => {
      stats.push({
        endpoint,
        requests: data.count,
        averageResponseTime: Math.round(data.totalTime / data.count),
        errorRate: Math.round((data.errors / data.count) * 100 * 100) / 100,
        methods: Array.from(data.methods)
      });
    });

    return stats.sort((a, b) => b.requests - a.requests).slice(0, 10);
  }

  // Clean up old data
  private cleanup(): void {
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours

    this.metrics = this.metrics.filter(m => now - m.timestamp < maxAge);
    this.requestMetrics = this.requestMetrics.filter(m => now - m.timestamp < maxAge);
    this.systemMetrics = this.systemMetrics.filter(m => now - m.timestamp < maxAge);
    
    // Clean up concurrent users (remove inactive users)
    // In a real system, you'd track user activity more precisely
    if (this.concurrentUsers.size > 0) {
      // Simple cleanup - clear every hour
      this.concurrentUsers.clear();
    }
  }

  // Get real-time metrics
  getRealTimeMetrics(): any {
    const latest = this.systemMetrics[this.systemMetrics.length - 1];
    const recentRequests = this.requestMetrics.filter(
      m => Date.now() - m.timestamp < 60000 // Last minute
    );

    return {
      timestamp: Date.now(),
      system: latest ? {
        memory: Math.round(latest.memory.percentage * 100) / 100,
        cpu: Math.round(latest.cpu.usage * 100) / 100,
        uptime: latest.uptime
      } : null,
      activity: {
        requestsPerMinute: recentRequests.length,
        activeRequests: this.activeRequests.size,
        concurrentUsers: this.concurrentUsers.size
      }
    };
  }

  // Set custom alert threshold
  setAlertThreshold(metric: string, threshold: number): void {
    this.alertThresholds.set(metric, threshold);
    logger.info(`Alert threshold updated: ${metric} = ${threshold}`);
  }
}

// Singleton instance
export const performanceMonitor = new PerformanceMonitor();
export default performanceMonitor;