/**
 * Authentication and Authorization Unit Tests
 * Walrus Haulout Hackathon - Data Security & Privacy Track
 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');

describe('Authentication & Authorization', () => {
  let securityAudit;

  beforeAll(() => {
    securityAudit = global.securityAudit;
  });

  describe('JWT Token Security', () => {
    const JWT_SECRET = 'test-secret-key-for-walrus-security';
    const JWT_ALGORITHM = 'HS256';

    test('should create and verify JWT tokens securely', () => {
      const payload = {
        userId: 'user-123',
        role: 'user',
        permissions: ['read', 'write'],
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour
      };

      // Create token
      const token = jwt.sign(payload, JWT_SECRET, { algorithm: JWT_ALGORITHM });

      // Verify token
      const decoded = jwt.verify(token, JWT_SECRET, { algorithms: [JWT_ALGORITHM] });

      expect(decoded.userId).toBe(payload.userId);
      expect(decoded.role).toBe(payload.role);
      expect(decoded.permissions).toEqual(payload.permissions);

      securityAudit.log('jwt_token_verification', {
        tokenLength: token.length,
        algorithm: JWT_ALGORITHM,
        expiresIn: '1h'
      });
    });

    test('should reject tampered JWT tokens', () => {
      const payload = { userId: 'user-123', role: 'user' };
      const token = jwt.sign(payload, JWT_SECRET, { algorithm: JWT_ALGORITHM });

      // Tamper with token by changing one character
      const tamperedToken = token.slice(0, -1) + 'X';

      expect(() => {
        jwt.verify(tamperedToken, JWT_SECRET, { algorithms: [JWT_ALGORITHM] });
      }).toThrow();

      securityAudit.log('jwt_tampering_detection', {
        originalToken: token.slice(-10),
        tamperedToken: tamperedToken.slice(-10),
        tamperingDetected: true
      });
    });

    test('should reject expired JWT tokens', () => {
      const payload = {
        userId: 'user-123',
        exp: Math.floor(Date.now() / 1000) - 3600 // Expired 1 hour ago
      };

      const expiredToken = jwt.sign(payload, JWT_SECRET, { algorithm: JWT_ALGORITHM });

      expect(() => {
        jwt.verify(expiredToken, JWT_SECRET, { algorithms: [JWT_ALGORITHM] });
      }).toThrow('jwt expired');

      securityAudit.log('jwt_expiration_check', {
        tokenExpired: true,
        rejectedCorrectly: true
      });
    });

    test('should prevent algorithm confusion attacks', () => {
      const payload = { userId: 'user-123', role: 'admin' };

      // Create token with HMAC
      const hmacToken = jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256' });

      // Try to verify with RSA algorithm (should fail)
      expect(() => {
        jwt.verify(hmacToken, JWT_SECRET, { algorithms: ['RS256'] });
      }).toThrow();

      // Verify only with specified algorithm
      const decoded = jwt.verify(hmacToken, JWT_SECRET, { algorithms: ['HS256'] });
      expect(decoded.userId).toBe(payload.userId);

      securityAudit.log('jwt_algorithm_confusion_prevention', {
        expectedAlgorithm: 'HS256',
        attemptedAlgorithm: 'RS256',
        attackPrevented: true
      });
    });
  });

  describe('Password Security', () => {
    test('should hash passwords using bcrypt with secure parameters', async () => {
      const bcrypt = require('bcrypt');
      const password = 'UserPassword123!@#';
      const saltRounds = 12; // OWASP recommended minimum

      const timer = global.performanceTracker.start('bcrypt-hash');
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      const hashDuration = timer.end();

      // Verify password
      const verifyTimer = global.performanceTracker.start('bcrypt-verify');
      const isValid = await bcrypt.compare(password, hashedPassword);
      const verifyDuration = verifyTimer.end();

      expect(isValid).toBe(true);
      expect(hashedPassword).not.toBe(password);
      expect(hashedPassword.startsWith('$2b$12$')).toBe(true); // Bcrypt format
      expect(hashDuration).toBeGreaterThan(100); // Should take reasonable time
      expect(verifyDuration).toBeGreaterThan(50);

      securityAudit.log('password_hashing', {
        algorithm: 'bcrypt',
        saltRounds,
        hashTime: hashDuration,
        verifyTime: verifyDuration,
        hashedLength: hashedPassword.length
      });
    });

    test('should enforce strong password policies', () => {
      const passwordPolicy = {
        minLength: 12,
        requireUppercase: true,
        requireLowercase: true,
        requireNumbers: true,
        requireSymbols: true,
        forbidCommon: true,
        forbidUserInfo: true
      };

      const commonPasswords = ['password', '123456', 'qwerty', 'admin', 'password123'];

      const validatePassword = (password, userInfo = {}) => {
        const errors = [];

        if (password.length < passwordPolicy.minLength) {
          errors.push('Password too short');
        }

        if (passwordPolicy.requireUppercase && !/[A-Z]/.test(password)) {
          errors.push('Missing uppercase letter');
        }

        if (passwordPolicy.requireLowercase && !/[a-z]/.test(password)) {
          errors.push('Missing lowercase letter');
        }

        if (passwordPolicy.requireNumbers && !/\d/.test(password)) {
          errors.push('Missing number');
        }

        if (passwordPolicy.requireSymbols && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
          errors.push('Missing special character');
        }

        if (passwordPolicy.forbidCommon && commonPasswords.includes(password.toLowerCase())) {
          errors.push('Password too common');
        }

        if (passwordPolicy.forbidUserInfo) {
          Object.values(userInfo).forEach(value => {
            if (value && password.toLowerCase().includes(value.toLowerCase())) {
              errors.push('Password contains user information');
            }
          });
        }

        return { valid: errors.length === 0, errors };
      };

      const testCases = [
        { password: 'ValidPassword123!', userInfo: {}, expectedValid: true },
        { password: 'weak', userInfo: {}, expectedValid: false },
        { password: 'password123', userInfo: {}, expectedValid: false },
        { password: 'NoNumbers!', userInfo: {}, expectedValid: false },
        { password: 'john.doe123!', userInfo: { name: 'John Doe' }, expectedValid: false }
      ];

      for (const testCase of testCases) {
        const result = validatePassword(testCase.password, testCase.userInfo);
        expect(result.valid).toBe(testCase.expectedValid);

        securityAudit.log('password_policy_validation', {
          password: testCase.password.slice(0, 3) + '***',
          valid: result.valid,
          errors: result.errors
        });
      }
    });

    test('should implement account lockout after failed attempts', () => {
      const lockoutPolicy = {
        maxAttempts: 5,
        lockoutDurationMs: 300000, // 5 minutes
        progressiveLockout: true
      };

      class AccountLockout {
        constructor() {
          this.attempts = new Map();
        }

        recordFailure(userId) {
          if (!this.attempts.has(userId)) {
            this.attempts.set(userId, {
              count: 0,
              lastAttempt: Date.now(),
              lockedUntil: null
            });
          }

          const record = this.attempts.get(userId);
          record.count++;
          record.lastAttempt = Date.now();

          if (record.count >= lockoutPolicy.maxAttempts) {
            const lockoutDuration = lockoutPolicy.progressiveLockout
              ? lockoutPolicy.lockoutDurationMs * Math.pow(2, Math.floor(record.count / 5))
              : lockoutPolicy.lockoutDurationMs;

            record.lockedUntil = Date.now() + lockoutDuration;
          }
        }

        isLocked(userId) {
          const record = this.attempts.get(userId);
          if (!record || !record.lockedUntil) return false;
          return Date.now() < record.lockedUntil;
        }

        recordSuccess(userId) {
          this.attempts.delete(userId);
        }

        getRemainingLockTime(userId) {
          const record = this.attempts.get(userId);
          if (!record || !record.lockedUntil) return 0;
          return Math.max(0, record.lockedUntil - Date.now());
        }
      }

      const lockout = new AccountLockout();
      const userId = 'test-user-123';

      // Simulate multiple failed attempts
      for (let i = 0; i < 6; i++) {
        lockout.recordFailure(userId);
      }

      expect(lockout.isLocked(userId)).toBe(true);
      expect(lockout.getRemainingLockTime(userId)).toBeGreaterThan(0);

      // Test successful authentication clears lockout
      lockout.recordSuccess(userId);
      expect(lockout.isLocked(userId)).toBe(false);

      securityAudit.log('account_lockout', {
        maxAttempts: lockoutPolicy.maxAttempts,
        lockoutImplemented: true,
        progressiveLockout: lockoutPolicy.progressiveLockout
      });
    });
  });

  describe('Multi-Factor Authentication', () => {
    test('should generate and validate TOTP codes', () => {
      // Simplified TOTP implementation for testing
      const generateTOTP = (secret, timeStep = 30) => {
        const epoch = Math.floor(Date.now() / 1000);
        const counter = Math.floor(epoch / timeStep);

        const hmac = crypto.createHmac('sha1', secret);
        hmac.update(Buffer.from(counter.toString(16).padStart(16, '0'), 'hex'));
        const hash = hmac.digest();

        const offset = hash[hash.length - 1] & 0xf;
        const code = (
          ((hash[offset] & 0x7f) << 24) |
          ((hash[offset + 1] & 0xff) << 16) |
          ((hash[offset + 2] & 0xff) << 8) |
          (hash[offset + 3] & 0xff)
        ) % 1000000;

        return code.toString().padStart(6, '0');
      };

      const secret = crypto.randomBytes(20);
      const code1 = generateTOTP(secret);
      const code2 = generateTOTP(secret);

      expect(code1).toBe(code2); // Should be same within time window
      expect(code1).toMatch(/^\d{6}$/); // 6-digit code

      securityAudit.log('totp_generation', {
        codeLength: code1.length,
        format: 'numeric',
        timeWindow: 30
      });
    });

    test('should validate backup codes for MFA recovery', () => {
      const generateBackupCodes = (count = 10) => {
        const codes = [];
        for (let i = 0; i < count; i++) {
          // Generate 8-character alphanumeric codes
          const code = crypto.randomBytes(4).toString('hex').toUpperCase();
          codes.push(code);
        }
        return codes;
      };

      const backupCodes = generateBackupCodes();
      const usedCodes = new Set();

      const validateBackupCode = (inputCode) => {
        const normalizedCode = inputCode.trim().toUpperCase();

        if (usedCodes.has(normalizedCode)) {
          return { valid: false, reason: 'code_already_used' };
        }

        if (!backupCodes.includes(normalizedCode)) {
          return { valid: false, reason: 'invalid_code' };
        }

        usedCodes.add(normalizedCode);
        return { valid: true };
      };

      // Test valid code
      const validResult = validateBackupCode(backupCodes[0]);
      expect(validResult.valid).toBe(true);

      // Test reuse of same code
      const reusedResult = validateBackupCode(backupCodes[0]);
      expect(reusedResult.valid).toBe(false);
      expect(reusedResult.reason).toBe('code_already_used');

      // Test invalid code
      const invalidResult = validateBackupCode('INVALID123');
      expect(invalidResult.valid).toBe(false);
      expect(invalidResult.reason).toBe('invalid_code');

      securityAudit.log('backup_codes_validation', {
        totalCodes: backupCodes.length,
        usedCodes: usedCodes.size,
        remainingCodes: backupCodes.length - usedCodes.size
      });
    });
  });

  describe('Session Management', () => {
    test('should manage secure sessions with proper lifecycle', () => {
      class SessionManager {
        constructor() {
          this.sessions = new Map();
          this.maxAge = 3600000; // 1 hour
          this.slidingExpiration = true;
        }

        createSession(userId, deviceInfo = {}) {
          const sessionId = crypto.randomUUID();
          const now = Date.now();

          const session = {
            id: sessionId,
            userId,
            createdAt: now,
            lastActivity: now,
            expiresAt: now + this.maxAge,
            deviceInfo,
            isValid: true
          };

          this.sessions.set(sessionId, session);
          return sessionId;
        }

        validateSession(sessionId) {
          const session = this.sessions.get(sessionId);

          if (!session || !session.isValid) {
            return { valid: false, reason: 'session_not_found' };
          }

          const now = Date.now();
          if (now > session.expiresAt) {
            this.invalidateSession(sessionId);
            return { valid: false, reason: 'session_expired' };
          }

          // Update last activity and potentially extend expiration
          if (this.slidingExpiration) {
            session.lastActivity = now;
            session.expiresAt = now + this.maxAge;
          }

          return { valid: true, session };
        }

        invalidateSession(sessionId) {
          const session = this.sessions.get(sessionId);
          if (session) {
            session.isValid = false;
            session.invalidatedAt = Date.now();
          }
        }

        cleanupExpiredSessions() {
          const now = Date.now();
          let cleaned = 0;

          for (const [sessionId, session] of this.sessions.entries()) {
            if (now > session.expiresAt || !session.isValid) {
              this.sessions.delete(sessionId);
              cleaned++;
            }
          }

          return cleaned;
        }

        getUserSessions(userId) {
          const userSessions = [];
          for (const session of this.sessions.values()) {
            if (session.userId === userId && session.isValid) {
              userSessions.push({
                id: session.id,
                createdAt: session.createdAt,
                lastActivity: session.lastActivity,
                deviceInfo: session.deviceInfo
              });
            }
          }
          return userSessions;
        }
      }

      const sessionManager = new SessionManager();
      const userId = 'user-123';

      // Create session
      const sessionId = sessionManager.createSession(userId, {
        userAgent: 'Test Browser',
        ip: '192.168.1.100'
      });

      expect(sessionId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);

      // Validate session
      const validation = sessionManager.validateSession(sessionId);
      expect(validation.valid).toBe(true);
      expect(validation.session.userId).toBe(userId);

      // Test session invalidation
      sessionManager.invalidateSession(sessionId);
      const invalidValidation = sessionManager.validateSession(sessionId);
      expect(invalidValidation.valid).toBe(false);

      securityAudit.log('session_management', {
        sessionCreated: true,
        validationWorking: true,
        invalidationWorking: true,
        slidingExpiration: sessionManager.slidingExpiration
      });
    });

    test('should prevent session fixation attacks', () => {
      const preventSessionFixation = () => {
        // Always regenerate session ID after authentication
        const regenerateSessionId = (oldSessionId) => {
          return crypto.randomUUID();
        };

        // Simulate authentication flow
        const preAuthSessionId = crypto.randomUUID();
        const postAuthSessionId = regenerateSessionId(preAuthSessionId);

        return {
          preAuth: preAuthSessionId,
          postAuth: postAuthSessionId,
          regenerated: preAuthSessionId !== postAuthSessionId
        };
      };

      const result = preventSessionFixation();

      expect(result.preAuth).not.toBe(result.postAuth);
      expect(result.regenerated).toBe(true);

      securityAudit.log('session_fixation_prevention', result);
    });
  });

  describe('Role-Based Access Control (RBAC)', () => {
    test('should implement hierarchical role permissions', () => {
      const roles = {
        guest: {
          permissions: ['read_public']
        },
        user: {
          inherits: ['guest'],
          permissions: ['read_personal', 'write_personal']
        },
        moderator: {
          inherits: ['user'],
          permissions: ['read_all', 'moderate_content']
        },
        admin: {
          inherits: ['moderator'],
          permissions: ['write_all', 'delete_any', 'manage_users']
        }
      };

      const resolvePermissions = (roleName) => {
        const permissions = new Set();

        const addRolePermissions = (role) => {
          if (!roles[role]) return;

          // Add direct permissions
          roles[role].permissions.forEach(perm => permissions.add(perm));

          // Add inherited permissions
          if (roles[role].inherits) {
            roles[role].inherits.forEach(inheritedRole => {
              addRolePermissions(inheritedRole);
            });
          }
        };

        addRolePermissions(roleName);
        return Array.from(permissions);
      };

      const checkPermission = (userRole, requiredPermission) => {
        const userPermissions = resolvePermissions(userRole);
        return userPermissions.includes(requiredPermission);
      };

      // Test permission inheritance
      const adminPermissions = resolvePermissions('admin');
      const userPermissions = resolvePermissions('user');

      expect(adminPermissions).toContain('read_public'); // Inherited from guest
      expect(adminPermissions).toContain('read_personal'); // Inherited from user
      expect(adminPermissions).toContain('moderate_content'); // Inherited from moderator
      expect(adminPermissions).toContain('manage_users'); // Direct permission

      expect(userPermissions).toContain('read_public'); // Inherited from guest
      expect(userPermissions).not.toContain('manage_users'); // Not accessible

      // Test access control
      expect(checkPermission('admin', 'manage_users')).toBe(true);
      expect(checkPermission('user', 'manage_users')).toBe(false);
      expect(checkPermission('user', 'read_personal')).toBe(true);

      securityAudit.log('rbac_implementation', {
        roles: Object.keys(roles),
        adminPermissions: adminPermissions.length,
        userPermissions: userPermissions.length,
        inheritanceWorking: adminPermissions.includes('read_public')
      });
    });

    test('should implement attribute-based access control (ABAC)', () => {
      const evaluatePolicy = (subject, action, resource, environment = {}) => {
        const policies = [
          // Policy 1: Users can only access their own data
          {
            effect: 'permit',
            condition: subject.id === resource.ownerId && action === 'read'
          },
          // Policy 2: Admins can access everything
          {
            effect: 'permit',
            condition: subject.role === 'admin'
          },
          // Policy 3: Sensitive data requires elevated security
          {
            effect: 'permit',
            condition: resource.sensitivity === 'high' && subject.securityClearance >= 3
          },
          // Policy 4: Time-based access restrictions
          {
            effect: 'deny',
            condition: environment.hour < 9 || environment.hour > 17 // Business hours only
          },
          // Policy 5: Location-based restrictions
          {
            effect: 'deny',
            condition: resource.sensitivity === 'restricted' && !environment.allowedLocation
          }
        ];

        for (const policy of policies) {
          if (policy.condition) {
            return policy.effect === 'permit';
          }
        }

        return false; // Default deny
      };

      const testCases = [
        {
          subject: { id: 'user1', role: 'user', securityClearance: 2 },
          action: 'read',
          resource: { ownerId: 'user1', sensitivity: 'normal' },
          environment: { hour: 14, allowedLocation: true },
          expectedResult: true
        },
        {
          subject: { id: 'user1', role: 'user', securityClearance: 2 },
          action: 'read',
          resource: { ownerId: 'user2', sensitivity: 'normal' },
          environment: { hour: 14, allowedLocation: true },
          expectedResult: false
        },
        {
          subject: { id: 'admin1', role: 'admin', securityClearance: 5 },
          action: 'delete',
          resource: { ownerId: 'user1', sensitivity: 'high' },
          environment: { hour: 14, allowedLocation: true },
          expectedResult: true
        }
      ];

      for (const testCase of testCases) {
        const result = evaluatePolicy(
          testCase.subject,
          testCase.action,
          testCase.resource,
          testCase.environment
        );

        expect(result).toBe(testCase.expectedResult);

        securityAudit.log('abac_policy_evaluation', {
          subjectRole: testCase.subject.role,
          action: testCase.action,
          resourceSensitivity: testCase.resource.sensitivity,
          decision: result ? 'permit' : 'deny'
        });
      }
    });
  });
});