/**
 * SecurityEngine - Core security orchestration
 * Coordinates all security operations and services
 */

import crypto from 'crypto';
import { EventEmitter } from 'events';
import { logger, securityLogger } from '../utils/logger.js';
import { EncryptionManager } from './EncryptionManager.js';
import { AccessController } from './AccessController.js';

export class SecurityEngine extends EventEmitter {
  constructor() {
    super();
    this.isInitialized = false;
    this.encryptionManager = new EncryptionManager();
    this.accessController = new AccessController();
    this.securityMetrics = new Map();
    this.activeThreats = new Set();
  }

  async initialize() {
    try {
      logger.info('🔧 Initializing Security Engine...');

      // Initialize encryption subsystem
      await this.encryptionManager.initialize();
      logger.info('✅ Encryption manager initialized');

      // Initialize access control
      await this.accessController.initialize();
      logger.info('✅ Access controller initialized');

      // Setup security monitoring
      this.setupSecurityMonitoring();

      // Generate system encryption keys
      await this.generateSystemKeys();

      this.isInitialized = true;
      this.emit('initialized');

      logger.info('🛡️  Security Engine fully operational');
      return true;

    } catch (error) {
      logger.error('❌ Failed to initialize Security Engine:', error);
      throw error;
    }
  }

  async generateSystemKeys() {
    // Generate master encryption key
    const masterKey = crypto.randomBytes(32);
    this.encryptionManager.setMasterKey(masterKey);

    // Generate API key for internal services
    const apiKey = crypto.randomBytes(64).toString('hex');
    process.env.INTERNAL_API_KEY = apiKey;

    securityLogger.info('System keys generated', {
      action: 'key_generation',
      timestamp: new Date().toISOString(),
      keyCount: 2
    });
  }

  setupSecurityMonitoring() {
    // Monitor failed authentication attempts
    this.accessController.on('authFailure', (event) => {
      this.recordSecurityEvent('auth_failure', event);
    });

    // Monitor encryption failures
    this.encryptionManager.on('encryptionFailure', (event) => {
      this.recordSecurityEvent('encryption_failure', event);
    });

    // Setup metrics collection
    setInterval(() => {
      this.collectSecurityMetrics();
    }, 60000); // Every minute
  }

  recordSecurityEvent(type, data) {
    securityLogger.warn(`Security event: ${type}`, {
      type,
      timestamp: new Date().toISOString(),
      data: this.sanitizeSecurityData(data)
    });

    // Update threat tracking
    if (this.isHighRiskEvent(type, data)) {
      this.activeThreats.add(`${type}-${Date.now()}`);
      this.emit('threatDetected', { type, data });
    }
  }

  isHighRiskEvent(type, data) {
    const highRiskTypes = ['auth_failure', 'encryption_failure', 'access_denied'];
    return highRiskTypes.includes(type);
  }

  sanitizeSecurityData(data) {
    const sanitized = { ...data };
    const sensitiveKeys = ['password', 'token', 'key', 'secret'];

    for (const key of sensitiveKeys) {
      if (sanitized[key]) {
        sanitized[key] = '[REDACTED]';
      }
    }

    return sanitized;
  }

  collectSecurityMetrics() {
    const metrics = {
      timestamp: new Date().toISOString(),
      activeConnections: this.accessController.getActiveConnectionCount(),
      threatCount: this.activeThreats.size,
      encryptionOperations: this.encryptionManager.getOperationCount(),
      memory: process.memoryUsage(),
      uptime: process.uptime()
    };

    this.securityMetrics.set('current', metrics);

    // Clean up old threats (older than 1 hour)
    const oneHourAgo = Date.now() - (60 * 60 * 1000);
    for (const threat of this.activeThreats) {
      const timestamp = parseInt(threat.split('-').pop());
      if (timestamp < oneHourAgo) {
        this.activeThreats.delete(threat);
      }
    }
  }

  // Public API methods
  async encryptData(data, options = {}) {
    if (!this.isInitialized) {
      throw new Error('SecurityEngine not initialized');
    }

    return this.encryptionManager.encrypt(data, options);
  }

  async decryptData(encryptedData, options = {}) {
    if (!this.isInitialized) {
      throw new Error('SecurityEngine not initialized');
    }

    return this.encryptionManager.decrypt(encryptedData, options);
  }

  async validateAccess(credentials, resource) {
    if (!this.isInitialized) {
      throw new Error('SecurityEngine not initialized');
    }

    return this.accessController.validateAccess(credentials, resource);
  }

  getSecurityStatus() {
    return {
      initialized: this.isInitialized,
      activeThreats: this.activeThreats.size,
      encryptionStatus: this.encryptionManager.getStatus(),
      accessControlStatus: this.accessController.getStatus(),
      uptime: process.uptime(),
      lastUpdate: new Date().toISOString()
    };
  }

  async performSecurityAudit() {
    const auditResults = {
      timestamp: new Date().toISOString(),
      engine: this.getSecurityStatus(),
      encryption: await this.encryptionManager.audit(),
      accessControl: await this.accessController.audit(),
      threats: Array.from(this.activeThreats),
      recommendations: []
    };

    // Generate recommendations
    if (this.activeThreats.size > 0) {
      auditResults.recommendations.push('Review active security threats');
    }

    if (!this.encryptionManager.getStatus().healthy) {
      auditResults.recommendations.push('Check encryption service health');
    }

    securityLogger.info('Security audit completed', auditResults);
    return auditResults;
  }
}