import DOMPurify from 'dompurify';

/**
 * XSS Prevention Utilities
 * 
 * This module provides comprehensive XSS prevention mechanisms:
 * 1. HTML sanitization using DOMPurify
 * 2. Content Security Policy (CSP) helpers
 * 3. Safe output encoding functions
 * 4. Input validation and sanitization
 */

/**
 * HTML Sanitization Configuration
 */
const sanitizerConfig = {
  // Strict configuration - only allow safe HTML elements
  strict: {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'u', 'br', 'p', 'span'],
    ALLOWED_ATTR: ['class'],
    FORBID_TAGS: ['script', 'object', 'embed', 'form', 'input', 'iframe', 'meta', 'link'],
    FORBID_ATTR: ['onclick', 'onload', 'onerror', 'onmouseover', 'onfocus', 'onblur', 'style'],
    ALLOW_DATA_ATTR: false,
    ALLOW_UNKNOWN_PROTOCOLS: false,
    SANITIZE_DOM: true,
    KEEP_CONTENT: true
  },
  
  // Basic configuration - allow more formatting but still secure
  basic: {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'u', 'br', 'p', 'span', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ul', 'ol', 'li', 'blockquote', 'code', 'pre'],
    ALLOWED_ATTR: ['class', 'id'],
    FORBID_TAGS: ['script', 'object', 'embed', 'form', 'input', 'iframe', 'meta', 'link', 'style'],
    FORBID_ATTR: ['onclick', 'onload', 'onerror', 'onmouseover', 'onfocus', 'onblur', 'style', 'href', 'src'],
    ALLOW_DATA_ATTR: false,
    ALLOW_UNKNOWN_PROTOCOLS: false,
    SANITIZE_DOM: true,
    KEEP_CONTENT: true
  },
  
  // Text-only configuration - strip all HTML
  textOnly: {
    ALLOWED_TAGS: [],
    ALLOWED_ATTR: [],
    KEEP_CONTENT: true,
    SANITIZE_DOM: true
  }
};

/**
 * Sanitize HTML content using DOMPurify
 * 
 * @param html - The HTML content to sanitize
 * @param level - Sanitization level: 'strict', 'basic', or 'textOnly'
 * @returns Sanitized HTML string
 */
export const sanitizeHtml = (html: string, level: 'strict' | 'basic' | 'textOnly' = 'strict'): string => {
  if (!html || typeof html !== 'string') {
    return '';
  }
  
  const config = sanitizerConfig[level];
  return DOMPurify.sanitize(html, config);
};

/**
 * Escape HTML entities to prevent XSS
 * 
 * @param text - The text to escape
 * @returns HTML-escaped text
 */
export const escapeHtml = (text: string): string => {
  if (!text || typeof text !== 'string') {
    return '';
  }
  
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
};

/**
 * Unescape HTML entities
 * 
 * @param html - The HTML to unescape
 * @returns Unescaped text
 */
export const unescapeHtml = (html: string): string => {
  if (!html || typeof html !== 'string') {
    return '';
  }
  
  const div = document.createElement('div');
  div.innerHTML = html;
  return div.textContent || div.innerText || '';
};

/**
 * Validate and sanitize user input
 * 
 * @param input - User input to validate
 * @param options - Validation options
 * @returns Validation result with sanitized input
 */
export const validateAndSanitizeInput = (
  input: string,
  options: {
    maxLength?: number;
    allowHtml?: boolean;
    sanitizationLevel?: 'strict' | 'basic' | 'textOnly';
    trimWhitespace?: boolean;
  } = {}
): { isValid: boolean; sanitizedInput: string; errors: string[] } => {
  const {
    maxLength = 1000,
    allowHtml = false,
    sanitizationLevel = 'strict',
    trimWhitespace = true
  } = options;
  
  const errors: string[] = [];
  let sanitizedInput = input || '';
  
  // Trim whitespace if requested
  if (trimWhitespace) {
    sanitizedInput = sanitizedInput.trim();
  }
  
  // Check length
  if (sanitizedInput.length > maxLength) {
    errors.push(`Input must be less than ${maxLength} characters`);
    sanitizedInput = sanitizedInput.substring(0, maxLength);
  }
  
  // Sanitize based on HTML allowance
  if (allowHtml) {
    sanitizedInput = sanitizeHtml(sanitizedInput, sanitizationLevel);
  } else {
    sanitizedInput = escapeHtml(sanitizedInput);
  }
  
  // Check for potentially malicious patterns
  const suspiciousPatterns = [
    /javascript:/i,
    /vbscript:/i,
    /data:text\/html/i,
    /data:application\/javascript/i,
    /<script[\s\S]*?>[\s\S]*?<\/script>/gi,
    /<iframe[\s\S]*?>[\s\S]*?<\/iframe>/gi,
    /on\w+\s*=/gi // Event handlers like onclick, onload, etc.
  ];
  
  for (const pattern of suspiciousPatterns) {
    if (pattern.test(input)) {
      errors.push('Input contains potentially malicious content');
      break;
    }
  }
  
  return {
    isValid: errors.length === 0,
    sanitizedInput,
    errors
  };
};

/**
 * Content Security Policy (CSP) helper functions
 */
export const cspHelpers = {
  /**
   * Generate a nonce for inline scripts/styles
   */
  generateNonce: (): string => {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return btoa(String.fromCharCode(...array));
  },
  
  /**
   * Create CSP meta tag content
   */
  createCSPContent: (nonce?: string): string => {
    const policies = [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'" + (nonce ? ` 'nonce-${nonce}'` : ''),
      "style-src 'self' 'unsafe-inline'" + (nonce ? ` 'nonce-${nonce}'` : ''),
      "img-src 'self' data: https:",
      "font-src 'self' https:",
      "connect-src 'self'",
      "frame-src 'none'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'"
    ];
    
    return policies.join('; ');
  },
  
  /**
   * Apply CSP to the document
   */
  applyCSP: (nonce?: string): void => {
    const meta = document.createElement('meta');
    meta.httpEquiv = 'Content-Security-Policy';
    meta.content = cspHelpers.createCSPContent(nonce);
    document.head.appendChild(meta);
  }
};

/**
 * Safe URL validation to prevent XSS through URLs
 */
export const validateUrl = (url: string): { isValid: boolean; error?: string } => {
  if (!url || typeof url !== 'string') {
    return { isValid: false, error: 'URL is required' };
  }
  
  try {
    const urlObj = new URL(url);
    
    // Only allow HTTP and HTTPS protocols
    if (!['http:', 'https:'].includes(urlObj.protocol)) {
      return { isValid: false, error: 'Only HTTP and HTTPS URLs are allowed' };
    }
    
    // Check for suspicious patterns
    const suspiciousPatterns = [
      /javascript:/i,
      /vbscript:/i,
      /data:/i,
      /file:/i,
      /ftp:/i
    ];
    
    for (const pattern of suspiciousPatterns) {
      if (pattern.test(url)) {
        return { isValid: false, error: 'URL contains potentially malicious protocol' };
      }
    }
    
    return { isValid: true };
    
  } catch (error) {
    return { isValid: false, error: 'Invalid URL format' };
  }
};

/**
 * Safe JSON parsing to prevent prototype pollution
 */
export const safeJsonParse = (jsonString: string): { success: boolean; data?: any; error?: string } => {
  try {
    const parsed = JSON.parse(jsonString);
    
    // Check for prototype pollution attempts
    if (parsed && typeof parsed === 'object') {
      const dangerousKeys = ['__proto__', 'constructor', 'prototype'];
      
      const checkObject = (obj: any, path = ''): boolean => {
        for (const key in obj) {
          if (dangerousKeys.includes(key)) {
            return false;
          }
          
          if (typeof obj[key] === 'object' && obj[key] !== null) {
            if (!checkObject(obj[key], `${path}.${key}`)) {
              return false;
            }
          }
        }
        return true;
      };
      
      if (!checkObject(parsed)) {
        return { success: false, error: 'JSON contains potentially dangerous properties' };
      }
    }
    
    return { success: true, data: parsed };
    
  } catch (error) {
    return { success: false, error: 'Invalid JSON format' };
  }
};

/**
 * Text content extraction from HTML (safe alternative to innerHTML)
 */
export const extractTextContent = (html: string): string => {
  if (!html || typeof html !== 'string') {
    return '';
  }
  
  // Create a temporary DOM element to safely extract text
  const tempDiv = document.createElement('div');
  tempDiv.innerHTML = sanitizeHtml(html, 'textOnly');
  return tempDiv.textContent || tempDiv.innerText || '';
};

/**
 * Safe attribute setting for DOM elements
 */
export const setSafeAttribute = (element: HTMLElement, attribute: string, value: string): boolean => {
  // List of dangerous attributes that should never be set
  const dangerousAttributes = [
    'onclick', 'onload', 'onerror', 'onmouseover', 'onfocus', 'onblur',
    'onchange', 'onsubmit', 'onreset', 'onselect', 'onkeydown', 'onkeyup',
    'onkeypress', 'onmousedown', 'onmouseup', 'onmousemove', 'onmouseout',
    'onmouseover', 'ondblclick', 'ondrag', 'ondrop', 'onscroll', 'onresize',
    'javascript', 'vbscript', 'data'
  ];
  
  // Check if attribute is dangerous
  if (dangerousAttributes.some(dangerous => attribute.toLowerCase().includes(dangerous))) {
    console.warn(`Attempted to set dangerous attribute: ${attribute}`);
    return false;
  }
  
  // Sanitize the value
  const sanitizedValue = escapeHtml(value);
  
  try {
    element.setAttribute(attribute, sanitizedValue);
    return true;
  } catch (error) {
    console.error('Failed to set attribute:', error);
    return false;
  }
};

/**
 * XSS Prevention Middleware for API responses
 */
export const xssPreventionMiddleware = {
  /**
   * Sanitize response data before sending to client
   */
  sanitizeResponse: (data: any): any => {
    if (typeof data === 'string') {
      return sanitizeHtml(data, 'basic');
    }
    
    if (Array.isArray(data)) {
      return data.map(item => xssPreventionMiddleware.sanitizeResponse(item));
    }
    
    if (data && typeof data === 'object') {
      const sanitized: any = {};
      for (const key in data) {
        if (data.hasOwnProperty(key)) {
          sanitized[key] = xssPreventionMiddleware.sanitizeResponse(data[key]);
        }
      }
      return sanitized;
    }
    
    return data;
  }
};