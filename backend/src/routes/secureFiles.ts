import express from 'express';
import { body, validationResult } from 'express-validator';
import { PrismaClient } from '@prisma/client';
import { secureAuthenticateUser } from '../middleware/secureAuth.js';
import {
  validateUrl,
  validateResolvedIP,
  validateFileContent,
  createSecureMulterConfig,
  serveSecureFile,
  scanFileForMalware
} from '../utils/secureFileUpload.js';
import path from 'path';
import fs from 'fs';

const router = express.Router();
const prisma = new PrismaClient();

/**
 * Secure File Upload and External URL Routes
 * 
 * This module provides secure file handling with:
 * 1. URL validation and domain whitelisting
 * 2. Private IP range blocking for SSRF prevention
 * 3. Secure file upload with type validation
 * 4. Path traversal prevention in file serving
 * 5. Malware scanning and content validation
 */

// Configure secure file upload
const UPLOAD_DIR = path.join(process.cwd(), 'secure-uploads');
const upload = createSecureMulterConfig(UPLOAD_DIR);

/**
 * SECURE Avatar Upload
 * POST /api/secure-files/avatar
 */
router.post('/avatar', secureAuthenticateUser, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'No file uploaded',
        message: 'Please select a file to upload'
      });
    }
    
    const filePath = req.file.path;
    
    // Validate file content matches MIME type
    const contentValidation = validateFileContent(filePath, req.file.mimetype);
    if (!contentValidation.isValid) {
      // Delete the uploaded file
      fs.unlinkSync(filePath);
      return res.status(400).json({
        success: false,
        error: 'Invalid file content',
        message: contentValidation.error
      });
    }
    
    // Scan for malware
    const malwareScan = await scanFileForMalware(filePath);
    if (!malwareScan.isClean) {
      // Delete the uploaded file
      fs.unlinkSync(filePath);
      return res.status(400).json({
        success: false,
        error: 'File security check failed',
        message: malwareScan.error || 'File contains suspicious content'
      });
    }
    
    // Update user avatar URL in database
    const avatarUrl = `/api/secure-files/serve/${req.file.filename}`;
    
    await prisma.user.update({
      where: { id: req.user!.id },
      data: { avatarUrl }
    });
    
    res.json({
      success: true,
      message: 'Avatar uploaded successfully',
      avatarUrl,
      fileInfo: {
        filename: req.file.filename,
        originalName: req.file.originalname,
        mimeType: req.file.mimetype,
        size: req.file.size
      }
    });
    
  } catch (error) {
    console.error('Secure avatar upload error:', error);
    
    // Clean up uploaded file if it exists
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    
    res.status(500).json({
      success: false,
      error: 'Upload failed',
      message: 'An error occurred during file upload'
    });
  }
});

/**
 * SECURE External URL Validation (for avatar from URL)
 * POST /api/secure-files/validate-url
 */
router.post('/validate-url', secureAuthenticateUser, [
  body('url')
    .isURL({ protocols: ['http', 'https'] })
    .withMessage('Valid HTTP/HTTPS URL is required'),
  body('purpose')
    .optional()
    .isIn(['avatar', 'import', 'preview'])
    .withMessage('Purpose must be avatar, import, or preview')
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
    
    const { url, purpose = 'preview' } = req.body;
    
    // Validate URL format and security
    const urlValidation = validateUrl(url);
    if (!urlValidation.isValid) {
      return res.status(400).json({
        success: false,
        error: 'Invalid URL',
        message: urlValidation.error
      });
    }
    
    // Additional DNS resolution check
    const urlObj = new URL(urlValidation.sanitizedUrl!);
    const dnsValidation = await validateResolvedIP(urlObj.hostname);
    if (!dnsValidation.isValid) {
      return res.status(400).json({
        success: false,
        error: 'DNS resolution failed',
        message: dnsValidation.error
      });
    }
    
    res.json({
      success: true,
      message: 'URL validation successful',
      validatedUrl: urlValidation.sanitizedUrl,
      purpose,
      securityChecks: {
        urlFormat: 'passed',
        protocolCheck: 'passed',
        privateIpCheck: 'passed',
        dnsResolution: 'passed',
        domainWhitelist: process.env.ENABLE_DOMAIN_WHITELIST === 'true' ? 'enforced' : 'disabled'
      }
    });
    
  } catch (error) {
    console.error('URL validation error:', error);
    res.status(500).json({
      success: false,
      error: 'Validation failed',
      message: 'An error occurred during URL validation'
    });
  }
});

/**
 * SECURE File Serving
 * GET /api/secure-files/serve/:filename
 */
router.get('/serve/:filename', async (req, res) => {
  try {
    const { filename } = req.params;
    
    // Validate filename format
    if (!filename || !/^[a-zA-Z0-9_-]+\.[a-zA-Z0-9]+$/.test(filename)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid filename',
        message: 'Filename contains invalid characters'
      });
    }
    
    // Construct file path
    const requestedPath = path.join(UPLOAD_DIR, filename);
    
    // Secure file serving with path validation
    const fileServing = serveSecureFile(requestedPath, UPLOAD_DIR);
    
    if (!fileServing.success) {
      return res.status(404).json({
        success: false,
        error: 'File not found',
        message: fileServing.error
      });
    }
    
    const safePath = fileServing.safePath!;
    
    // Get file stats
    const stats = fs.statSync(safePath);
    
    // Set security headers
    res.set({
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Cache-Control': 'public, max-age=3600',
      'Content-Length': stats.size.toString()
    });
    
    // Determine MIME type based on file extension
    const ext = path.extname(filename).toLowerCase();
    const mimeTypes: Record<string, string> = {
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.png': 'image/png',
      '.gif': 'image/gif',
      '.webp': 'image/webp',
      '.svg': 'image/svg+xml',
      '.pdf': 'application/pdf',
      '.txt': 'text/plain',
      '.csv': 'text/csv',
      '.json': 'application/json'
    };
    
    const mimeType = mimeTypes[ext] || 'application/octet-stream';
    res.set('Content-Type', mimeType);
    
    // Stream file to response
    const fileStream = fs.createReadStream(safePath);
    fileStream.pipe(res);
    
  } catch (error) {
    console.error('Secure file serving error:', error);
    res.status(500).json({
      success: false,
      error: 'File serving failed',
      message: 'An error occurred while serving the file'
    });
  }
});

/**
 * SECURE Task Import (with URL validation)
 * POST /api/secure-files/import-tasks
 */
router.post('/import-tasks', secureAuthenticateUser, [
  body('importUrl')
    .isURL({ protocols: ['http', 'https'] })
    .withMessage('Valid HTTP/HTTPS URL is required'),
  body('format')
    .optional()
    .isIn(['json', 'csv'])
    .withMessage('Format must be json or csv')
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
    
    const { importUrl, format = 'json' } = req.body;
    
    // Validate URL
    const urlValidation = validateUrl(importUrl);
    if (!urlValidation.isValid) {
      return res.status(400).json({
        success: false,
        error: 'Invalid import URL',
        message: urlValidation.error
      });
    }
    
    // DNS validation
    const urlObj = new URL(urlValidation.sanitizedUrl!);
    const dnsValidation = await validateResolvedIP(urlObj.hostname);
    if (!dnsValidation.isValid) {
      return res.status(400).json({
        success: false,
        error: 'DNS validation failed',
        message: dnsValidation.error
      });
    }
    
    // Make secure HTTP request
    const axios = (await import('axios')).default;
    
    try {
      const response = await axios.get(urlValidation.sanitizedUrl!, {
        timeout: 10000, // 10 second timeout
        maxRedirects: 3, // Limit redirects
        maxContentLength: 1024 * 1024, // 1MB max response size
        headers: {
          'User-Agent': 'SecureTaskManager/1.0',
          'Accept': format === 'json' ? 'application/json' : 'text/csv'
        }
      });
      
      // Validate response content type
      const contentType = response.headers['content-type'] || '';
      const expectedTypes = {
        json: ['application/json', 'text/json'],
        csv: ['text/csv', 'application/csv', 'text/plain']
      };
      
      const isValidContentType = expectedTypes[format as keyof typeof expectedTypes]
        .some(type => contentType.toLowerCase().includes(type));
      
      if (!isValidContentType) {
        return res.status(400).json({
          success: false,
          error: 'Invalid content type',
          message: `Expected ${format} content, received ${contentType}`
        });
      }
      
      // Parse and validate data
      let importData: any;
      
      if (format === 'json') {
        try {
          importData = typeof response.data === 'string' ? JSON.parse(response.data) : response.data;
        } catch (parseError) {
          return res.status(400).json({
            success: false,
            error: 'Invalid JSON format',
            message: 'Failed to parse JSON data'
          });
        }
      } else {
        // For CSV, return raw data for client-side processing
        importData = response.data;
      }
      
      res.json({
        success: true,
        message: 'Import data retrieved successfully',
        data: importData,
        metadata: {
          format,
          contentType: response.headers['content-type'],
          size: response.data.length,
          url: urlValidation.sanitizedUrl
        },
        securityInfo: {
          urlValidated: true,
          dnsValidated: true,
          contentTypeValidated: true,
          sizeLimit: '1MB',
          timeoutLimit: '10s'
        }
      });
      
    } catch (httpError: any) {
      return res.status(400).json({
        success: false,
        error: 'HTTP request failed',
        message: httpError.message || 'Failed to fetch data from URL'
      });
    }
    
  } catch (error) {
    console.error('Secure import error:', error);
    res.status(500).json({
      success: false,
      error: 'Import failed',
      message: 'An error occurred during import'
    });
  }
});

/**
 * Get User Files
 * GET /api/secure-files/my-files
 */
router.get('/my-files', secureAuthenticateUser, async (req, res) => {
  try {
    // Get user's uploaded files (this would typically be stored in database)
    // For now, we'll scan the upload directory for files
    
    const files = fs.readdirSync(UPLOAD_DIR)
      .filter(filename => {
        const filePath = path.join(UPLOAD_DIR, filename);
        const stats = fs.statSync(filePath);
        return stats.isFile();
      })
      .map(filename => {
        const filePath = path.join(UPLOAD_DIR, filename);
        const stats = fs.statSync(filePath);
        
        return {
          filename,
          size: stats.size,
          uploadedAt: stats.birthtime,
          url: `/api/secure-files/serve/${filename}`
        };
      })
      .sort((a, b) => b.uploadedAt.getTime() - a.uploadedAt.getTime());
    
    res.json({
      success: true,
      files,
      count: files.length,
      totalSize: files.reduce((sum, file) => sum + file.size, 0)
    });
    
  } catch (error) {
    console.error('Get user files error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve files',
      message: 'An error occurred while retrieving files'
    });
  }
});

/**
 * Delete File
 * DELETE /api/secure-files/:filename
 */
router.delete('/:filename', secureAuthenticateUser, async (req, res) => {
  try {
    const { filename } = req.params;
    
    // Validate filename
    if (!filename || !/^[a-zA-Z0-9_-]+\.[a-zA-Z0-9]+$/.test(filename)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid filename',
        message: 'Filename contains invalid characters'
      });
    }
    
    const filePath = path.join(UPLOAD_DIR, filename);
    
    // Validate file path
    const fileServing = serveSecureFile(filePath, UPLOAD_DIR);
    if (!fileServing.success) {
      return res.status(404).json({
        success: false,
        error: 'File not found',
        message: fileServing.error
      });
    }
    
    // Delete file
    fs.unlinkSync(fileServing.safePath!);
    
    // Update user avatar if this was their avatar
    const avatarUrl = `/api/secure-files/serve/${filename}`;
    await prisma.user.updateMany({
      where: {
        id: req.user!.id,
        avatarUrl: avatarUrl
      },
      data: {
        avatarUrl: null
      }
    });
    
    res.json({
      success: true,
      message: 'File deleted successfully',
      filename
    });
    
  } catch (error) {
    console.error('Delete file error:', error);
    res.status(500).json({
      success: false,
      error: 'File deletion failed',
      message: 'An error occurred while deleting the file'
    });
  }
});

export default router;