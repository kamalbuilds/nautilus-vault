/**
 * Secure Logging Utility
 * Privacy-preserving structured logging
 */

import winston from 'winston';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Custom format for security-sensitive logs
const securityFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.errors({ stack: true }),
  winston.format.printf(({ timestamp, level, message, stack, ...meta }) => {
    // Sanitize sensitive information
    const sanitizedMeta = sanitizeSensitiveData(meta);

    let log = `${timestamp} [${level.toUpperCase()}]: ${message}`;

    if (Object.keys(sanitizedMeta).length > 0) {
      log += ` ${JSON.stringify(sanitizedMeta)}`;
    }

    if (stack) {
      log += `\n${stack}`;
    }

    return log;
  })
);

// Sanitize sensitive data from logs
function sanitizeSensitiveData(obj) {
  const sensitiveKeys = [
    'password', 'token', 'secret', 'key', 'apiKey', 'privateKey',
    'authorization', 'cookie', 'session', 'ssn', 'email', 'phone'
  ];

  const sanitized = { ...obj };

  for (const key in sanitized) {
    if (sensitiveKeys.some(pattern =>
      key.toLowerCase().includes(pattern.toLowerCase())
    )) {
      sanitized[key] = '[REDACTED]';
    }

    if (typeof sanitized[key] === 'object' && sanitized[key] !== null) {
      sanitized[key] = sanitizeSensitiveData(sanitized[key]);
    }
  }

  return sanitized;
}

// Create logger instance
export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: securityFormat,
  transports: [
    // Console transport for development
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        securityFormat
      )
    }),

    // File transport for production logs
    new winston.transports.File({
      filename: path.join(process.cwd(), 'logs', 'error.log'),
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5
    }),

    new winston.transports.File({
      filename: path.join(process.cwd(), 'logs', 'combined.log'),
      maxsize: 5242880, // 5MB
      maxFiles: 10
    }),

    // Separate security events log
    new winston.transports.File({
      filename: path.join(process.cwd(), 'logs', 'security.log'),
      level: 'warn',
      maxsize: 5242880, // 5MB
      maxFiles: 20
    })
  ],

  // Don't exit on handled exceptions
  exitOnError: false
});

// Create security-specific logger for audit trails
export const securityLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({
      filename: path.join(process.cwd(), 'logs', 'audit.log'),
      maxsize: 10485760, // 10MB
      maxFiles: 50
    })
  ]
});

// Performance logger for benchmarking
export const perfLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({
      filename: path.join(process.cwd(), 'logs', 'performance.log'),
      maxsize: 5242880, // 5MB
      maxFiles: 5
    })
  ]
});

// Ensure log directory exists
import fs from 'fs';
const logsDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

export default logger;