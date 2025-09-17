import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { Request } from 'express';
import multer from 'multer';

/**
 * Secure File Upload and SSRF Prevention Utilities
 * 
 * This module provides comprehensive security measures for:
 * 1. URL validation and domain whitelisting
 * 2. Private IP range blocking for SSRF prevention
 * 3. Secure file upload with type validation
 * 4. Path traversal prevention in file serving
 * 5. File size and content validation
 */

// Private IP ranges to block for SSRF prevention
const PRIVATE_IP_RANGES = [
  /^127\./,                    // Loopback
  /^10\./,                     // Private Class A
  /^172\.(1[6-9]|2[0-9]|3[0-1])\./,  // Private Class B
  /^192\.168\./,               // Private Class C
  /^169\.254\./,               // Link-local
  /^::1$/,                     // IPv6 loopback
  /^fc00:/,                    // IPv6 unique local
  /^fe80:/,                    // IPv6 link-local
  /^ff00:/                     // IPv6 multicast
];

// Cloud metadata service IPs to block
const CLOUD_METADATA_IPS = [
  '169.254.169.254',           // AWS, GCP, Azure metadata
  '100.100.100.200',           // Alibaba Cloud
  '169.254.0.1'                // DigitalOcean
];

// Allowed domains for external requests (whitelist)
const ALLOWED_DOMAINS = [
  'api.github.com',
  'httpbin.org',
  'jsonplaceholder.typicode.com'
  // Add more trusted domains as needed
];

// Allowed file types and their MIME types
const ALLOWED_FILE_TYPES = {
  // Images
  'image/jpeg': ['.jpg', '.jpeg'],
  'image/png': ['.png'],
  'image/gif': ['.gif'],
  'image/webp': ['.webp'],
  'image/svg+xml': ['.svg'],
  
  // Documents
  'application/pdf': ['.pdf'],
  'text/plain': ['.txt'],
  'text/csv': ['.csv'],
  'application/json': ['.json'],
  
  // Archives (be careful with these)
  'application/zip': ['.zip'],
  'application/x-tar': ['.tar']
};

// Maximum file sizes by type (in bytes)
const MAX_FILE_SIZES = {
  'image/jpeg': 5 * 1024 * 1024,      // 5MB
  'image/png': 5 * 1024 * 1024,       // 5MB
  'image/gif': 2 * 1024 * 1024,       // 2MB
  'image/webp': 5 * 1024 * 1024,      // 5MB
  'image/svg+xml': 1 * 1024 * 1024,   // 1MB
  'application/pdf': 10 * 1024 * 1024, // 10MB
  'text/plain': 1 * 1024 * 1024,      // 1MB
  'text/csv': 5 * 1024 * 1024,        // 5MB
  'application/json': 1 * 1024 * 1024, // 1MB
  'application/zip': 50 * 1024 * 1024, // 50MB
  'application/x-tar': 50 * 1024 * 1024 // 50MB
};

/**
 * URL Validation and SSRF Prevention
 */
export const validateUrl = (url: string): { isValid: boolean; error?: string; sanitizedUrl?: string } => {
  if (!url || typeof url !== 'string') {
    return { isValid: false, error: 'URL is required' };
  }
  
  try {
    const urlObj = new URL(url);
    
    // Only allow HTTP and HTTPS protocols
    if (!['http:', 'https:'].includes(urlObj.protocol)) {
      return { isValid: false, error: 'Only HTTP and HTTPS protocols are allowed' };
    }
    
    // Check for dangerous protocols
    const dangerousProtocols = ['file:', 'ftp:', 'gopher:', 'ldap:', 'dict:', 'sftp:'];
    if (dangerousProtocols.includes(urlObj.protocol)) {
      return { isValid: false, error: 'Protocol not allowed for security reasons' };
    }
    
    // Validate hostname
    const hostname = urlObj.hostname.toLowerCase();
    
    // Block private IP ranges
    for (const range of PRIVATE_IP_RANGES) {
      if (range.test(hostname)) {
        return { isValid: false, error: 'Access to private IP ranges is not allowed' };
      }
    }
    
    // Block cloud metadata services
    if (CLOUD_METADATA_IPS.includes(hostname)) {
      return { isValid: false, error: 'Access to cloud metadata services is not allowed' };
    }
    
    // Block localhost variations
    const localhostVariations = ['localhost', '0.0.0.0', '[::]', '[::1]'];
    if (localhostVariations.includes(hostname)) {
      return { isValid: false, error: 'Access to localhost is not allowed' };
    }
    
    // Domain whitelist check (optional - can be disabled for broader access)
    if (process.env.ENABLE_DOMAIN_WHITELIST === 'true') {
      const isAllowedDomain = ALLOWED_DOMAINS.some(domain => 
        hostname === domain || hostname.endsWith('.' + domain)
      );
      
      if (!isAllowedDomain) {
        return { isValid: false, error: 'Domain not in whitelist' };
      }
    }
    
    // Check for suspicious patterns in URL
    const suspiciousPatterns = [
      /@/,                    // Credentials in URL
      /\.\./,                 // Path traversal
      /%2e%2e/i,             // Encoded path traversal
      /%00/i,                // Null byte
      /javascript:/i,         // JavaScript protocol
      /vbscript:/i,          // VBScript protocol
      /data:/i               // Data protocol
    ];
    
    for (const pattern of suspiciousPatterns) {
      if (pattern.test(url)) {
        return { isValid: false, error: 'URL contains suspicious patterns' };
      }
    }
    
    // Reconstruct URL to normalize it
    const sanitizedUrl = urlObj.toString();
    
    return { isValid: true, sanitizedUrl };
    
  } catch (error) {
    return { isValid: false, error: 'Invalid URL format' };
  }
};

/**
 * Resolve hostname to IP and validate
 */
export const validateResolvedIP = async (hostname: string): Promise<{ isValid: boolean; error?: string }> => {
  try {
    const dns = await import('dns');
    const { promisify } = await import('util');
    const lookup = promisify(dns.lookup);
    
    const { address } = await lookup(hostname);
    
    // Check if resolved IP is in private ranges
    for (const range of PRIVATE_IP_RANGES) {
      if (range.test(address)) {
        return { isValid: false, error: 'Hostname resolves to private IP address' };
      }
    }
    
    // Check cloud metadata IPs
    if (CLOUD_METADATA_IPS.includes(address)) {
      return { isValid: false, error: 'Hostname resolves to cloud metadata service' };
    }
    
    return { isValid: true };
    
  } catch (error) {
    return { isValid: false, error: 'Failed to resolve hostname' };
  }
};

/**
 * File Upload Security
 */

// Generate secure filename
export const generateSecureFilename = (originalName: string, mimeType: string): string => {
  const timestamp = Date.now();
  const randomBytes = crypto.randomBytes(8).toString('hex');
  const extension = getSecureFileExtension(originalName, mimeType);
  
  return `${timestamp}_${randomBytes}${extension}`;
};

// Get secure file extension
export const getSecureFileExtension = (filename: string, mimeType: string): string => {
  const allowedExtensions = ALLOWED_FILE_TYPES[mimeType as keyof typeof ALLOWED_FILE_TYPES];
  
  if (!allowedExtensions) {
    return '.bin'; // Default extension for unknown types
  }
  
  const originalExt = path.extname(filename).toLowerCase();
  
  if (allowedExtensions.includes(originalExt)) {
    return originalExt;
  }
  
  return allowedExtensions[0]; // Use first allowed extension
};

// Validate file type
export const validateFileType = (file: Express.Multer.File): { isValid: boolean; error?: string } => {
  const { mimetype, originalname, size } = file;
  
  // Check if MIME type is allowed
  if (!ALLOWED_FILE_TYPES[mimetype as keyof typeof ALLOWED_FILE_TYPES]) {
    return { isValid: false, error: `File type ${mimetype} is not allowed` };
  }
  
  // Check file size
  const maxSize = MAX_FILE_SIZES[mimetype as keyof typeof MAX_FILE_SIZES];
  if (size > maxSize) {
    return { isValid: false, error: `File size exceeds maximum allowed size of ${Math.round(maxSize / 1024 / 1024)}MB` };
  }
  
  // Check file extension
  const extension = path.extname(originalname).toLowerCase();
  const allowedExtensions = ALLOWED_FILE_TYPES[mimetype as keyof typeof ALLOWED_FILE_TYPES];
  
  if (!allowedExtensions.includes(extension)) {
    return { isValid: false, error: `File extension ${extension} does not match MIME type ${mimetype}` };
  }
  
  return { isValid: true };
};

// Validate file content (basic magic number check)
export const validateFileContent = (filePath: string, expectedMimeType: string): { isValid: boolean; error?: string } => {
  try {
    const buffer = fs.readFileSync(filePath, { flag: 'r' });
    const magicNumbers = buffer.subarray(0, 16);
    
    // Magic number signatures for common file types
    const signatures: Record<string, Buffer[]> = {
      'image/jpeg': [
        Buffer.from([0xFF, 0xD8, 0xFF])
      ],
      'image/png': [
        Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
      ],
      'image/gif': [
        Buffer.from('GIF87a'),
        Buffer.from('GIF89a')
      ],
      'application/pdf': [
        Buffer.from('%PDF-')
      ],
      'application/zip': [
        Buffer.from([0x50, 0x4B, 0x03, 0x04]),
        Buffer.from([0x50, 0x4B, 0x05, 0x06]),
        Buffer.from([0x50, 0x4B, 0x07, 0x08])
      ]
    };
    
    const expectedSignatures = signatures[expectedMimeType];
    if (!expectedSignatures) {
      // No signature check available for this type
      return { isValid: true };
    }
    
    const isValidSignature = expectedSignatures.some(signature => 
      magicNumbers.subarray(0, signature.length).equals(signature)
    );
    
    if (!isValidSignature) {
      return { isValid: false, error: 'File content does not match expected file type' };
    }
    
    return { isValid: true };
    
  } catch (error) {
    return { isValid: false, error: 'Failed to validate file content' };
  }
};

// Secure file path validation
export const validateFilePath = (filePath: string, allowedDirectory: string): { isValid: boolean; error?: string; safePath?: string } => {
  try {
    // Resolve paths to absolute paths
    const resolvedFilePath = path.resolve(filePath);
    const resolvedAllowedDir = path.resolve(allowedDirectory);
    
    // Check if file path is within allowed directory
    if (!resolvedFilePath.startsWith(resolvedAllowedDir + path.sep)) {
      return { isValid: false, error: 'Path traversal attempt detected' };
    }
    
    // Check for dangerous path components
    const pathComponents = filePath.split(path.sep);
    const dangerousComponents = ['..', '.', '~', '$'];
    
    for (const component of pathComponents) {
      if (dangerousComponents.includes(component)) {
        return { isValid: false, error: 'Dangerous path component detected' };
      }
    }
    
    // Check for null bytes and other dangerous characters
    if (filePath.includes('\0') || filePath.includes('\x00')) {
      return { isValid: false, error: 'Null byte in path detected' };
    }
    
    return { isValid: true, safePath: resolvedFilePath };
    
  } catch (error) {
    return { isValid: false, error: 'Invalid file path' };
  }
};

// Multer configuration for secure file uploads
export const createSecureMulterConfig = (uploadDir: string) => {
  // Ensure upload directory exists
  if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true, mode: 0o755 });
  }
  
  const storage = multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
      const secureFilename = generateSecureFilename(file.originalname, file.mimetype);
      cb(null, secureFilename);
    }
  });
  
  const fileFilter = (req: Request, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
    const validation = validateFileType(file);
    
    if (validation.isValid) {
      cb(null, true);
    } else {
      cb(new Error(validation.error || 'File type not allowed'));
    }
  };
  
  return multer({
    storage,
    fileFilter,
    limits: {
      fileSize: Math.max(...Object.values(MAX_FILE_SIZES)), // Maximum allowed file size
      files: 5, // Maximum number of files
      fields: 10, // Maximum number of form fields
      fieldSize: 1024 * 1024 // Maximum field size (1MB)
    }
  });
};

// Secure file serving
export const serveSecureFile = (filePath: string, allowedDirectory: string): { success: boolean; error?: string; safePath?: string } => {
  // Validate file path
  const pathValidation = validateFilePath(filePath, allowedDirectory);
  
  if (!pathValidation.isValid) {
    return { success: false, error: pathValidation.error };
  }
  
  const safePath = pathValidation.safePath!;
  
  // Check if file exists
  if (!fs.existsSync(safePath)) {
    return { success: false, error: 'File not found' };
  }
  
  // Check if it's actually a file (not a directory)
  const stats = fs.statSync(safePath);
  if (!stats.isFile()) {
    return { success: false, error: 'Path is not a file' };
  }
  
  return { success: true, safePath };
};

// Clean up old files
export const cleanupOldFiles = (directory: string, maxAgeMs: number = 7 * 24 * 60 * 60 * 1000): void => {
  try {
    const files = fs.readdirSync(directory);
    const now = Date.now();
    
    for (const file of files) {
      const filePath = path.join(directory, file);
      const stats = fs.statSync(filePath);
      
      if (stats.isFile() && (now - stats.mtime.getTime()) > maxAgeMs) {
        fs.unlinkSync(filePath);
        console.log(`Cleaned up old file: ${file}`);
      }
    }
  } catch (error) {
    console.error('Error cleaning up old files:', error);
  }
};

// Scan file for malware (placeholder - integrate with actual antivirus)
export const scanFileForMalware = async (filePath: string): Promise<{ isClean: boolean; error?: string }> => {
  // This is a placeholder implementation
  // In production, integrate with ClamAV, VirusTotal API, or other antivirus solutions
  
  try {
    // Basic checks for suspicious content
    const content = fs.readFileSync(filePath, 'utf8');
    
    // Check for suspicious patterns
    const suspiciousPatterns = [
      /<script[\s\S]*?>[\s\S]*?<\/script>/gi,
      /eval\s*\(/gi,
      /exec\s*\(/gi,
      /system\s*\(/gi,
      /shell_exec\s*\(/gi,
      /passthru\s*\(/gi
    ];
    
    for (const pattern of suspiciousPatterns) {
      if (pattern.test(content)) {
        return { isClean: false, error: 'Suspicious content detected in file' };
      }
    }
    
    return { isClean: true };
    
  } catch (error) {
    // If we can't read as text, assume it's binary and skip content scan
    return { isClean: true };
  }
};

export default {
  validateUrl,
  validateResolvedIP,
  validateFileType,
  validateFileContent,
  validateFilePath,
  generateSecureFilename,
  createSecureMulterConfig,
  serveSecureFile,
  cleanupOldFiles,
  scanFileForMalware
};