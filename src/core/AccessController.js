/**
 * AccessController - Role-based access control and authentication
 * Implements comprehensive security policies and access management
 */

import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { EventEmitter } from 'events';
import { logger, securityLogger } from '../utils/logger.js';

export class AccessController extends EventEmitter {
  constructor() {
    super();
    this.isInitialized = false;
    this.activeConnections = new Map();
    this.authAttempts = new Map();
    this.jwtSecret = null;
    this.roles = new Map();
    this.permissions = new Map();
    this.setupDefaultRoles();
  }

  async initialize() {
    try {
      logger.info('🔐 Initializing Access Controller...');

      // Generate JWT secret
      this.jwtSecret = crypto.randomBytes(64).toString('hex');

      // Setup rate limiting for auth attempts
      this.setupAuthRateLimiting();

      // Setup session management
      this.setupSessionManagement();

      this.isInitialized = true;
      logger.info('✅ Access Controller initialized');

    } catch (error) {
      logger.error('❌ Failed to initialize Access Controller:', error);
      throw error;
    }
  }

  setupDefaultRoles() {
    // Define system roles
    this.roles.set('admin', {
      name: 'admin',
      description: 'System administrator',
      permissions: ['*'] // All permissions
    });

    this.roles.set('user', {
      name: 'user',
      description: 'Regular user',
      permissions: ['read', 'encrypt', 'decrypt', 'store']
    });

    this.roles.set('auditor', {
      name: 'auditor',
      description: 'Security auditor',
      permissions: ['read', 'audit', 'monitor']
    });

    this.roles.set('service', {
      name: 'service',
      description: 'Service account',
      permissions: ['encrypt', 'decrypt', 'store', 'verify']
    });

    // Define permissions
    const permissionList = [
      'read', 'write', 'delete', 'encrypt', 'decrypt', 'store',
      'audit', 'monitor', 'admin', 'verify', 'fraud-detect'
    ];

    permissionList.forEach(permission => {
      this.permissions.set(permission, {
        name: permission,
        description: `Permission to ${permission}`,
        resources: ['*']
      });
    });
  }

  setupAuthRateLimiting() {
    // Clean up failed auth attempts every 15 minutes
    setInterval(() => {
      const fifteenMinutesAgo = Date.now() - (15 * 60 * 1000);

      for (const [identifier, attempts] of this.authAttempts.entries()) {
        const recentAttempts = attempts.filter(time => time > fifteenMinutesAgo);
        if (recentAttempts.length === 0) {
          this.authAttempts.delete(identifier);
        } else {
          this.authAttempts.set(identifier, recentAttempts);
        }
      }
    }, 15 * 60 * 1000);
  }

  setupSessionManagement() {
    // Clean up expired sessions every hour
    setInterval(() => {
      const now = Date.now();

      for (const [sessionId, session] of this.activeConnections.entries()) {
        if (session.expiresAt < now) {
          this.activeConnections.delete(sessionId);
          securityLogger.info('Session expired', { sessionId });
        }
      }
    }, 60 * 60 * 1000);
  }

  async authenticate(credentials) {
    const { username, password, apiKey } = credentials;

    try {
      // Check rate limiting
      if (!this.checkAuthRateLimit(credentials.identifier || username)) {
        this.emit('authFailure', { reason: 'rate_limited', username });
        throw new Error('Too many authentication attempts');
      }

      let user;

      // API Key authentication
      if (apiKey) {
        user = await this.authenticateApiKey(apiKey);
      }
      // Username/password authentication
      else if (username && password) {
        user = await this.authenticatePassword(username, password);
      } else {
        throw new Error('Invalid credentials format');
      }

      // Generate JWT token
      const token = this.generateJWT(user);

      // Create session
      const session = this.createSession(user, token);

      securityLogger.info('Authentication successful', {
        userId: user.id,
        username: user.username,
        sessionId: session.id
      });

      return {
        token,
        session,
        user: this.sanitizeUser(user)
      };

    } catch (error) {
      this.recordAuthFailure(credentials.identifier || username, error.message);
      this.emit('authFailure', { username, error: error.message });
      throw error;
    }
  }

  checkAuthRateLimit(identifier) {
    const maxAttempts = 5;
    const windowMs = 15 * 60 * 1000; // 15 minutes
    const now = Date.now();

    if (!this.authAttempts.has(identifier)) {
      this.authAttempts.set(identifier, []);
    }

    const attempts = this.authAttempts.get(identifier);
    const recentAttempts = attempts.filter(time => time > now - windowMs);

    return recentAttempts.length < maxAttempts;
  }

  recordAuthFailure(identifier, reason) {
    if (!this.authAttempts.has(identifier)) {
      this.authAttempts.set(identifier, []);
    }

    const attempts = this.authAttempts.get(identifier);
    attempts.push(Date.now());
    this.authAttempts.set(identifier, attempts);

    securityLogger.warn('Authentication failure', {
      identifier,
      reason,
      attemptCount: attempts.length
    });
  }

  async authenticateApiKey(apiKey) {
    // Simulate API key validation - in production, check against database
    const hashedApiKey = crypto.createHash('sha256').update(apiKey).digest('hex');

    // For demo purposes, accept a predefined API key
    const validApiKeys = {
      'test-api-key-123': {
        id: 'api-user-1',
        username: 'api-service',
        roles: ['service'],
        type: 'api_key'
      }
    };

    if (!validApiKeys[apiKey]) {
      throw new Error('Invalid API key');
    }

    return validApiKeys[apiKey];
  }

  async authenticatePassword(username, password) {
    // Simulate user lookup - in production, check against database
    const users = {
      'admin': {
        id: 'user-1',
        username: 'admin',
        passwordHash: await bcrypt.hash('admin123', 10),
        roles: ['admin'],
        type: 'user'
      },
      'user1': {
        id: 'user-2',
        username: 'user1',
        passwordHash: await bcrypt.hash('password123', 10),
        roles: ['user'],
        type: 'user'
      }
    };

    const user = users[username];
    if (!user) {
      throw new Error('User not found');
    }

    const isValidPassword = await bcrypt.compare(password, user.passwordHash);
    if (!isValidPassword) {
      throw new Error('Invalid password');
    }

    return user;
  }

  generateJWT(user) {
    const payload = {
      userId: user.id,
      username: user.username,
      roles: user.roles,
      type: user.type,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24 hours
    };

    return jwt.sign(payload, this.jwtSecret);
  }

  createSession(user, token) {
    const sessionId = crypto.randomUUID();
    const session = {
      id: sessionId,
      userId: user.id,
      username: user.username,
      roles: user.roles,
      createdAt: Date.now(),
      expiresAt: Date.now() + (24 * 60 * 60 * 1000), // 24 hours
      lastActivity: Date.now(),
      token
    };

    this.activeConnections.set(sessionId, session);
    return session;
  }

  async validateAccess(credentials, resource) {
    try {
      let session;

      // Validate JWT token
      if (credentials.token) {
        session = await this.validateJWT(credentials.token);
      }
      // Validate session ID
      else if (credentials.sessionId) {
        session = this.validateSession(credentials.sessionId);
      } else {
        throw new Error('No valid credentials provided');
      }

      // Check permissions
      const hasPermission = await this.checkPermission(session, resource);

      if (!hasPermission) {
        this.emit('accessDenied', { session, resource });
        throw new Error('Insufficient permissions');
      }

      // Update last activity
      session.lastActivity = Date.now();
      this.activeConnections.set(session.id, session);

      return {
        authorized: true,
        session,
        permissions: this.getUserPermissions(session.roles)
      };

    } catch (error) {
      this.emit('accessDenied', { credentials, resource, error: error.message });
      throw error;
    }
  }

  async validateJWT(token) {
    try {
      const decoded = jwt.verify(token, this.jwtSecret);

      // Find active session
      for (const [sessionId, session] of this.activeConnections.entries()) {
        if (session.token === token && session.userId === decoded.userId) {
          return session;
        }
      }

      throw new Error('Session not found');

    } catch (error) {
      throw new Error('Invalid token');
    }
  }

  validateSession(sessionId) {
    const session = this.activeConnections.get(sessionId);

    if (!session) {
      throw new Error('Session not found');
    }

    if (session.expiresAt < Date.now()) {
      this.activeConnections.delete(sessionId);
      throw new Error('Session expired');
    }

    return session;
  }

  async checkPermission(session, resource) {
    const userPermissions = this.getUserPermissions(session.roles);

    // Admin has all permissions
    if (userPermissions.includes('*')) {
      return true;
    }

    // Check specific permissions
    const requiredPermission = this.getRequiredPermission(resource);
    return userPermissions.includes(requiredPermission);
  }

  getUserPermissions(roles) {
    const permissions = new Set();

    roles.forEach(roleName => {
      const role = this.roles.get(roleName);
      if (role) {
        role.permissions.forEach(permission => permissions.add(permission));
      }
    });

    return Array.from(permissions);
  }

  getRequiredPermission(resource) {
    const resourcePermissions = {
      '/api/encrypt': 'encrypt',
      '/api/decrypt': 'decrypt',
      '/api/store': 'store',
      '/api/detect': 'fraud-detect',
      '/api/verify': 'verify',
      '/api/audit': 'audit',
      '/api/admin': 'admin'
    };

    return resourcePermissions[resource] || 'read';
  }

  sanitizeUser(user) {
    return {
      id: user.id,
      username: user.username,
      roles: user.roles,
      type: user.type
    };
  }

  // Session management
  async logout(sessionId) {
    const session = this.activeConnections.get(sessionId);
    if (session) {
      this.activeConnections.delete(sessionId);
      securityLogger.info('User logged out', { sessionId, userId: session.userId });
    }
  }

  async logoutAll(userId) {
    let loggedOut = 0;
    for (const [sessionId, session] of this.activeConnections.entries()) {
      if (session.userId === userId) {
        this.activeConnections.delete(sessionId);
        loggedOut++;
      }
    }

    securityLogger.info('All sessions logged out', { userId, sessionCount: loggedOut });
    return loggedOut;
  }

  // Status and monitoring
  getActiveConnectionCount() {
    return this.activeConnections.size;
  }

  getStatus() {
    return {
      initialized: this.isInitialized,
      activeConnections: this.activeConnections.size,
      roles: this.roles.size,
      permissions: this.permissions.size,
      healthy: this.isInitialized && this.jwtSecret !== null
    };
  }

  async audit() {
    return {
      timestamp: new Date().toISOString(),
      status: this.getStatus(),
      securityMetrics: {
        activeSessions: Array.from(this.activeConnections.values()).map(session => ({
          id: session.id,
          userId: session.userId,
          roles: session.roles,
          createdAt: new Date(session.createdAt).toISOString(),
          lastActivity: new Date(session.lastActivity).toISOString()
        })),
        failedAttempts: this.authAttempts.size,
        rolesConfigured: Array.from(this.roles.keys()),
        permissionsConfigured: Array.from(this.permissions.keys())
      }
    };
  }
}