import express from 'express';
import { PrismaClient } from '@prisma/client';
import { authenticateUser } from '../middleware/auth';
import axios from 'axios';
import fs from 'fs';
import path from 'path';

const router = express.Router();
const prisma = new PrismaClient();

/**
 * VULNERABLE ENDPOINT: Profile picture upload with SSRF vulnerability
 * 
 * This endpoint demonstrates multiple security vulnerabilities:
 * 1. SSRF (Server-Side Request Forgery) - CWE-918
 * 2. LFI (Local File Inclusion) - CWE-22
 * 3. Information disclosure through error messages
 * 4. No URL validation or domain whitelisting
 */
router.post('/avatar', authenticateUser, async (req, res) => {
  const { imageUrl, fetchFromUrl } = req.body;
  
  if (fetchFromUrl && imageUrl) {
    try {
      console.log(`[SECURITY WARNING] Fetching URL: ${imageUrl}`);
      
      // VULNERABILITY: No URL validation - allows SSRF attacks
      // This allows attackers to make requests to:
      // - Internal network services (localhost, 127.0.0.1, 192.168.x.x)
      // - Cloud metadata services (169.254.169.254)
      // - File system through file:// protocol
      const response = await axios.get(imageUrl, {
        timeout: 10000,
        maxRedirects: 5,
        headers: {
          'User-Agent': 'VulnerableTaskManager/1.0 (Educational Purpose)'
        }
      });
      
      // VULNERABILITY: Allows fetching internal services and files
      if (imageUrl.startsWith('file://')) {
        // Local file inclusion vulnerability
        const filePath = imageUrl.replace('file://', '');
        console.log(`[SECURITY WARNING] Reading local file: ${filePath}`);
        
        try {
          const fileContent = fs.readFileSync(filePath, 'utf8');
          return res.json({ 
            success: true, 
            content: fileContent,
            message: 'File content retrieved successfully',
            filePath: filePath,
            warning: 'This is a security vulnerability - LFI detected'
          });
        } catch (fileError: any) {
          return res.status(500).json({
            error: 'Failed to read local file',
            filePath: filePath,
            details: fileError.message,
            warning: 'File access attempt detected'
          });
        }
      }
      
      // Handle cloud metadata service requests
      if (imageUrl.includes('169.254.169.254')) {
        console.log('[SECURITY WARNING] Cloud metadata service access detected');
        return res.json({
          success: true,
          metadata: response.data,
          headers: response.headers,
          message: 'Cloud metadata retrieved',
          warning: 'This is a security vulnerability - Cloud metadata access'
        });
      }
      
      // Handle internal network requests
      if (imageUrl.includes('localhost') || 
          imageUrl.includes('127.0.0.1') || 
          imageUrl.match(/192\.168\.\d+\.\d+/) ||
          imageUrl.match(/10\.\d+\.\d+\.\d+/) ||
          imageUrl.match(/172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+/)) {
        console.log('[SECURITY WARNING] Internal network access detected');
        return res.json({
          success: true,
          internalService: response.data,
          headers: response.headers,
          status: response.status,
          message: 'Internal service response',
          warning: 'This is a security vulnerability - Internal network access'
        });
      }
      
      // Save the fetched image (if it's actually an image)
      const fileName = `avatar_${req.user.id}_${Date.now()}.jpg`;
      const filePath = path.join('./uploads', fileName);
      
      // VULNERABILITY: No content type validation
      if (typeof response.data === 'string') {
        fs.writeFileSync(filePath, response.data);
      } else {
        fs.writeFileSync(filePath, JSON.stringify(response.data));
      }
      
      // Update user avatar in database
      await prisma.user.update({
        where: { id: req.user.id },
        data: { avatarUrl: `/uploads/${fileName}` }
      });
      
      res.json({ 
        success: true, 
        avatarUrl: `/uploads/${fileName}`,
        message: 'Avatar updated successfully',
        fetchedFrom: imageUrl
      });
      
    } catch (error: any) {
      console.error('[SECURITY WARNING] SSRF attempt failed:', error.message);
      
      // VULNERABILITY: Error messages leak internal network information
      res.status(500).json({ 
        error: 'Failed to fetch image',
        details: error.message,
        requestedUrl: imageUrl,
        internalError: error.code,
        stack: error.stack,
        warning: 'This error message exposes internal information'
      });
    }
  } else {
    // Handle regular file upload (not implemented for this vulnerability demo)
    res.status(400).json({
      error: 'Please provide imageUrl and set fetchFromUrl to true',
      example: {
        imageUrl: 'http://example.com/image.jpg',
        fetchFromUrl: true
      }
    });
  }
});

/**
 * VULNERABLE ENDPOINT: File serving with path traversal vulnerability
 * 
 * This endpoint demonstrates:
 * 1. Path traversal vulnerability - CWE-22
 * 2. Directory traversal attacks
 * 3. Unauthorized file access
 */
router.get('/files/:filename', (req, res) => {
  const { filename } = req.params;
  
  console.log(`[SECURITY WARNING] File access attempt: ${filename}`);
  
  // VULNERABILITY: Path traversal - no input sanitization
  // This allows attackers to access files outside the uploads directory
  // Examples: ../../../etc/passwd, ../../../../windows/system32/drivers/etc/hosts
  const filePath = path.join('./uploads', filename);
  
  try {
    // VULNERABILITY: Allows reading any file on the system
    const fileContent = fs.readFileSync(filePath);
    
    // Try to determine content type (very basic)
    const ext = path.extname(filename).toLowerCase();
    let contentType = 'application/octet-stream';
    
    if (ext === '.jpg' || ext === '.jpeg') contentType = 'image/jpeg';
    else if (ext === '.png') contentType = 'image/png';
    else if (ext === '.gif') contentType = 'image/gif';
    else if (ext === '.txt') contentType = 'text/plain';
    else if (ext === '.json') contentType = 'application/json';
    
    res.setHeader('Content-Type', contentType);
    res.send(fileContent);
    
  } catch (error: any) {
    console.error('[SECURITY WARNING] File access failed:', error.message);
    
    // VULNERABILITY: Error messages expose file system information
    res.status(404).json({ 
      error: 'File not found', 
      path: filePath,
      requestedFile: filename,
      details: error.message,
      warning: 'This error message exposes file system paths'
    });
  }
});

/**
 * Get user profile
 */
router.get('/profile', authenticateUser, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        avatarUrl: true,
        createdAt: true,
        emailVerified: true
      }
    });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(user);
  } catch (error: any) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

/**
 * Update user profile
 */
router.put('/profile', authenticateUser, async (req, res) => {
  const { firstName, lastName } = req.body;
  
  try {
    const updatedUser = await prisma.user.update({
      where: { id: req.user.id },
      data: {
        firstName,
        lastName
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        avatarUrl: true,
        createdAt: true,
        emailVerified: true
      }
    });
    
    res.json(updatedUser);
  } catch (error: any) {
    console.error('Error updating user profile:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

export default router;