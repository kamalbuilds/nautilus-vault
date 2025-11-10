/**
 * Security Middleware
 * Custom security middleware for additional protection
 */

import crypto from 'crypto';
import { logger, securityLogger } from '../../utils/logger.js';

export function securityMiddleware(req, res, next) {
  // Add request ID for tracking
  req.id = crypto.randomUUID();

  // Add security headers
  res.set({
    'X-Request-ID': req.id,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
  });

  // Remove sensitive server information
  res.removeHeader('X-Powered-By');
  res.removeHeader('Server');

  // Validate request size
  const contentLength = parseInt(req.get('Content-Length') || '0');
  if (contentLength > 10 * 1024 * 1024) { // 10MB limit
    securityLogger.warn('Large request detected', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      contentLength,
      endpoint: req.path
    });

    return res.status(413).json({
      error: 'Request entity too large',
      maxSize: '10MB'
    });
  }

  // Check for suspicious patterns
  if (containsSuspiciousPatterns(req)) {
    securityLogger.warn('Suspicious request pattern detected', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: req.path,
      method: req.method,
      headers: sanitizeHeaders(req.headers)
    });

    return res.status(400).json({
      error: 'Invalid request format'
    });
  }

  // Validate User-Agent
  const userAgent = req.get('User-Agent');
  if (!userAgent || userAgent.length > 512) {
    securityLogger.warn('Invalid User-Agent detected', {
      ip: req.ip,
      userAgent: userAgent ? userAgent.substring(0, 100) + '...' : 'missing',
      endpoint: req.path
    });

    return res.status(400).json({
      error: 'Invalid request headers'
    });
  }

  // Check for common attack patterns
  if (containsAttackPatterns(req)) {
    securityLogger.warn('Potential attack pattern detected', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: req.path,
      method: req.method
    });

    return res.status(400).json({
      error: 'Invalid request'
    });
  }

  next();
}

function containsSuspiciousPatterns(req) {
  const suspiciousPatterns = [
    /\.\./,                    // Directory traversal
    /\/\.\./,                  // Path traversal
    /<script/i,                // XSS attempts
    /javascript:/i,            // JS injection
    /data:/i,                  // Data URI scheme
    /vbscript:/i,              // VBScript injection
    /onload=/i,                // Event handlers
    /onerror=/i,               // Event handlers
    /eval\(/i,                 // Code evaluation
    /exec\(/i,                 // Code execution
    /union\s+select/i,         // SQL injection
    /insert\s+into/i,          // SQL injection
    /delete\s+from/i,          // SQL injection
    /drop\s+table/i,           // SQL injection
    /--/,                      // SQL comments
    /\/\*/,                    // SQL comments
    /%27/i,                    // SQL quote encoding
    /%22/i,                    // Quote encoding
    /%3C/i,                    // < encoding
    /%3E/i,                    // > encoding
    /%00/i,                    // Null byte
    /\x00/,                    // Null byte
    /\x1a/                     // Substitute character
  ];

  const checkString = [
    req.url,
    req.get('Referer') || '',
    req.get('X-Forwarded-For') || '',
    JSON.stringify(req.query),
    JSON.stringify(req.params)
  ].join(' ');

  return suspiciousPatterns.some(pattern => pattern.test(checkString));
}

function containsAttackPatterns(req) {
  // Check for common attack signatures
  const attackPatterns = [
    // Web shell signatures
    /c99shell/i,
    /r57shell/i,
    /webshell/i,
    /backdoor/i,

    // Scanning tools
    /nmap/i,
    /sqlmap/i,
    /nikto/i,
    /burpsuite/i,
    /dirb/i,
    /gobuster/i,

    // Exploitation frameworks
    /metasploit/i,
    /msfconsole/i,

    // Common payloads
    /phpinfo\(\)/i,
    /system\(/i,
    /shell_exec/i,
    /passthru/i,
    /wget/i,
    /curl.*http/i
  ];

  const checkString = [
    req.get('User-Agent') || '',
    req.url,
    JSON.stringify(req.body || {}),
    JSON.stringify(req.query)
  ].join(' ');

  return attackPatterns.some(pattern => pattern.test(checkString));
}

function sanitizeHeaders(headers) {
  const sensitiveHeaders = [
    'authorization',
    'cookie',
    'x-api-key',
    'x-auth-token'
  ];

  const sanitized = { ...headers };

  sensitiveHeaders.forEach(header => {
    if (sanitized[header]) {
      sanitized[header] = '[REDACTED]';
    }
  });

  return sanitized;
}