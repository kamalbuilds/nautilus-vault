/**
 * Error Handler Middleware
 * Centralized error handling with security-aware logging
 */

import { logger, securityLogger } from '../../utils/logger.js';

export function errorHandler(err, req, res, next) {
  // Default error response
  let statusCode = err.statusCode || 500;
  let message = 'Internal Server Error';
  let details = null;

  // Handle specific error types
  if (err.name === 'ValidationError') {
    statusCode = 400;
    message = 'Validation Error';
    details = err.details || err.message;
  } else if (err.name === 'UnauthorizedError' || err.message.includes('Unauthorized')) {
    statusCode = 401;
    message = 'Unauthorized';

    // Log security event for authentication failures
    securityLogger.warn('Authentication failure', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: req.path,
      method: req.method,
      error: err.message
    });

  } else if (err.name === 'ForbiddenError' || err.message.includes('Forbidden')) {
    statusCode = 403;
    message = 'Forbidden';

    // Log security event for authorization failures
    securityLogger.warn('Authorization failure', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: req.path,
      method: req.method,
      error: err.message
    });

  } else if (err.name === 'NotFoundError' || statusCode === 404) {
    statusCode = 404;
    message = 'Not Found';

  } else if (err.name === 'TimeoutError') {
    statusCode = 408;
    message = 'Request Timeout';

  } else if (err.name === 'TooManyRequestsError' || err.message.includes('Rate limit')) {
    statusCode = 429;
    message = 'Too Many Requests';

    // Log security event for potential abuse
    securityLogger.warn('Rate limit exceeded', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: req.path,
      method: req.method
    });

  } else if (statusCode >= 500) {
    // Log server errors
    logger.error('Server error occurred', {
      error: err.message,
      stack: err.stack,
      endpoint: req.path,
      method: req.method,
      ip: req.ip
    });
  }

  // In development, include error details
  if (process.env.NODE_ENV === 'development' && statusCode >= 500) {
    details = {
      message: err.message,
      stack: err.stack
    };
  }

  // Ensure we don't expose sensitive information
  const sanitizedError = sanitizeError(err, req);

  // Send error response
  res.status(statusCode).json({
    error: {
      message,
      status: statusCode,
      timestamp: new Date().toISOString(),
      requestId: req.id || 'unknown',
      ...(details && { details })
    }
  });
}

function sanitizeError(err, req) {
  // Remove sensitive information from error objects
  const sensitiveFields = [
    'password', 'token', 'secret', 'key', 'apiKey',
    'authorization', 'cookie', 'session'
  ];

  const sanitized = { ...err };

  // Remove sensitive data from error message
  sensitiveFields.forEach(field => {
    if (sanitized.message && typeof sanitized.message === 'string') {
      sanitized.message = sanitized.message.replace(
        new RegExp(field + '\\s*[=:]\\s*[^\\s,}]+', 'gi'),
        field + '=[REDACTED]'
      );
    }
  });

  // Remove sensitive data from error details
  if (sanitized.details && typeof sanitized.details === 'object') {
    sensitiveFields.forEach(field => {
      if (sanitized.details[field]) {
        sanitized.details[field] = '[REDACTED]';
      }
    });
  }

  return sanitized;
}