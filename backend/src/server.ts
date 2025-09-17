import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import dotenv from 'dotenv';
import path from 'path';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Basic middleware
app.use(morgan('combined'));
app.use(cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  credentials: true,
}));

// Security middleware (will be intentionally misconfigured for vulnerabilities)
app.use(helmet({
  contentSecurityPolicy: false, // Disabled for XSS vulnerability
  crossOriginEmbedderPolicy: false,
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Monitoring and logging middleware
app.use(requestLogger);
app.use(securityLogger);
app.use(authFailureLogger);
app.use(idorDetectionLogger);
app.use(performanceLogger);

// Static file serving (will be vulnerable to path traversal)
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

// Health check endpoint
app.get('/health', (_req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV,
    version: '1.0.0',
  });
});

// Import routes
import authRoutes from './routes/auth';
import taskRoutes from './routes/tasks';
import commentRoutes from './routes/comments';
import userRoutes from './routes/users';
import securityLabRoutes, { setVulnerabilityManager } from './routes/security-lab';
import monitoringRoutes from './routes/monitoring';
import docsRoutes from './routes/docs';

// Import vulnerability management
import { VulnerabilityManager } from './utils/VulnerabilityManager';
import { PrismaClient } from '@prisma/client';

// Import monitoring and logging middleware
import { 
  requestLogger, 
  securityLogger, 
  authFailureLogger, 
  idorDetectionLogger,
  performanceLogger 
} from './middleware/logging';
import { logger } from './utils/logger';
import { performanceMonitor } from './utils/performanceMonitor';
import { auditTrail, AuditEventType } from './utils/auditTrail';

// Initialize Prisma client and vulnerability manager
const prisma = new PrismaClient();
const vulnerabilityManager = new VulnerabilityManager(app, prisma);

// API routes
app.get('/api', (_req, res) => {
  res.json({
    message: 'Vulnerable Task Manager API',
    version: '1.0.0',
    documentation: '/api/docs',
    warning: 'This API contains intentional security vulnerabilities for educational purposes',
    endpoints: {
      auth: '/api/auth',
      tasks: '/api/tasks',
      comments: '/api/comments',
      users: '/api/users',
      health: '/health'
    }
  });
});

// Authentication routes
app.use('/api/auth', authRoutes);

// Task management routes
app.use('/api/tasks', taskRoutes);

// Comment management routes
app.use('/api/comments', commentRoutes);

// User management routes
app.use('/api/users', userRoutes);

// Security Lab routes
setVulnerabilityManager(vulnerabilityManager);
app.use('/api/security-lab', securityLabRoutes);

// Monitoring routes
app.use('/api/monitoring', monitoringRoutes);

// Documentation routes
app.use('/api/docs', docsRoutes);

// 404 handler
app.use('*', (_req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: 'The requested resource was not found',
  });
});

// Global error handler
app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error('Error:', err);
  
  // Intentionally verbose error handling for educational purposes
  res.status(err.status || 500).json({
    error: err.message || 'Internal Server Error',
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    timestamp: new Date().toISOString(),
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📚 Environment: ${process.env.NODE_ENV}`);
  console.log(`⚠️  WARNING: This application contains intentional security vulnerabilities`);
  console.log(`🔗 API: http://localhost:${PORT}/api`);
  console.log(`🏥 Health: http://localhost:${PORT}/health`);
  console.log(`📊 Monitoring: http://localhost:${PORT}/api/monitoring`);
  
  // Log server startup
  logger.info('Server started successfully', {
    port: PORT,
    environment: process.env.NODE_ENV,
    nodeVersion: process.version,
    uptime: process.uptime()
  });
  
  // Record audit event
  auditTrail.recordEvent(
    AuditEventType.SYSTEM_EVENT,
    'server_startup',
    'Application server started',
    {
      metadata: {
        port: PORT,
        environment: process.env.NODE_ENV,
        nodeVersion: process.version
      },
      severity: 'low'
    }
  );
});