/**
 * EncryptionManager - Advanced encryption and cryptographic operations
 * Supports multiple encryption algorithms and key management
 */

import crypto from 'crypto';
import { EventEmitter } from 'events';
import { logger } from '../utils/logger.js';

export class EncryptionManager extends EventEmitter {
  constructor() {
    super();
    this.algorithms = {
      AES_256_GCM: 'aes-256-gcm',
      CHACHA20_POLY1305: 'chacha20-poly1305',
      AES_256_CBC: 'aes-256-cbc'
    };
    this.defaultAlgorithm = this.algorithms.AES_256_GCM;
    this.masterKey = null;
    this.keyCache = new Map();
    this.operationCount = 0;
    this.isInitialized = false;
  }

  async initialize() {
    try {
      logger.info('🔐 Initializing Encryption Manager...');

      // Verify crypto support
      this.verifyCryptoSupport();

      // Setup key rotation
      this.setupKeyRotation();

      this.isInitialized = true;
      logger.info('✅ Encryption Manager initialized');

    } catch (error) {
      logger.error('❌ Failed to initialize Encryption Manager:', error);
      throw error;
    }
  }

  verifyCryptoSupport() {
    // Test AES-256-GCM
    try {
      const key = crypto.randomBytes(32);
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipher('aes-256-gcm', key, { iv });
      cipher.update('test');
      cipher.final();
      cipher.getAuthTag();
    } catch (error) {
      // Try alternative approach for GCM
      try {
        const key = crypto.randomBytes(32);
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        cipher.update('test');
        cipher.final();
        cipher.getAuthTag();
      } catch (error2) {
        logger.warn('GCM mode not fully supported, using CBC mode');
        this.defaultAlgorithm = this.algorithms.AES_256_CBC;
      }
    }

    // Test ChaCha20-Poly1305 if available
    try {
      const key = crypto.randomBytes(32);
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('chacha20-poly1305', key, iv);
      cipher.update('test');
      cipher.final();
      cipher.getAuthTag();
    } catch (error) {
      logger.warn('ChaCha20-Poly1305 not available, fallback to AES');
      delete this.algorithms.CHACHA20_POLY1305;
    }

    // Test AES-256-CBC (most widely supported)
    try {
      const key = crypto.randomBytes(32);
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
      cipher.update('test');
      cipher.final();
    } catch (error) {
      throw new Error(`AES-256-CBC not supported: ${error.message}`);
    }

    logger.info('✅ Encryption algorithms verified');
    logger.info(`Default algorithm: ${this.defaultAlgorithm}`);
  }

  setupKeyRotation() {
    // Rotate keys every 24 hours
    setInterval(() => {
      this.rotateKeys();
    }, 24 * 60 * 60 * 1000);
  }

  setMasterKey(key) {
    if (!(key instanceof Buffer) || key.length !== 32) {
      throw new Error('Master key must be a 32-byte Buffer');
    }
    this.masterKey = key;
  }

  async encrypt(data, options = {}) {
    if (!this.isInitialized) {
      throw new Error('EncryptionManager not initialized');
    }

    try {
      const algorithm = options.algorithm || this.defaultAlgorithm;
      const key = options.key || this.deriveKey(options.keyId || 'default');

      const result = await this.performEncryption(data, algorithm, key);
      this.operationCount++;

      return result;

    } catch (error) {
      this.emit('encryptionFailure', { error: error.message, algorithm: options.algorithm });
      throw new Error(`Encryption failed: ${error.message}`);
    }
  }

  async decrypt(encryptedData, options = {}) {
    if (!this.isInitialized) {
      throw new Error('EncryptionManager not initialized');
    }

    try {
      const algorithm = options.algorithm || this.defaultAlgorithm;
      const key = options.key || this.deriveKey(options.keyId || 'default');

      const result = await this.performDecryption(encryptedData, algorithm, key);
      this.operationCount++;

      return result;

    } catch (error) {
      this.emit('decryptionFailure', { error: error.message, algorithm: options.algorithm });
      throw new Error(`Decryption failed: ${error.message}`);
    }
  }

  async performEncryption(data, algorithm, key) {
    const dataBuffer = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');

    switch (algorithm) {
      case this.algorithms.AES_256_GCM:
        return this.encryptAESGCM(dataBuffer, key);

      case this.algorithms.CHACHA20_POLY1305:
        return this.encryptChaCha20(dataBuffer, key);

      case this.algorithms.AES_256_CBC:
        return this.encryptAESCBC(dataBuffer, key);

      default:
        throw new Error(`Unsupported encryption algorithm: ${algorithm}`);
    }
  }

  async performDecryption(encryptedData, algorithm, key) {
    switch (algorithm) {
      case this.algorithms.AES_256_GCM:
        return this.decryptAESGCM(encryptedData, key);

      case this.algorithms.CHACHA20_POLY1305:
        return this.decryptChaCha20(encryptedData, key);

      case this.algorithms.AES_256_CBC:
        return this.decryptAESCBC(encryptedData, key);

      default:
        throw new Error(`Unsupported decryption algorithm: ${algorithm}`);
    }
  }

  encryptAESGCM(data, key) {
    try {
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

      const encrypted = Buffer.concat([
        cipher.update(data),
        cipher.final()
      ]);

      const tag = cipher.getAuthTag();

      return {
        algorithm: 'aes-256-gcm',
        encrypted: encrypted.toString('base64'),
        iv: iv.toString('base64'),
        tag: tag.toString('base64')
      };
    } catch (error) {
      // Fallback to CBC if GCM not available
      logger.warn('GCM not available, using CBC fallback');
      return this.encryptAESCBC(data, key);
    }
  }

  decryptAESGCM(encryptedData, key) {
    try {
      const { encrypted, iv, tag } = encryptedData;

      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        key,
        Buffer.from(iv, 'base64')
      );

      decipher.setAuthTag(Buffer.from(tag, 'base64'));

      const decrypted = Buffer.concat([
        decipher.update(Buffer.from(encrypted, 'base64')),
        decipher.final()
      ]);

      return decrypted;
    } catch (error) {
      // Try CBC fallback
      if (!encryptedData.tag) {
        return this.decryptAESCBC(encryptedData, key);
      }
      throw error;
    }
  }

  encryptChaCha20(data, key) {
    try {
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('chacha20-poly1305', key, iv);

      const encrypted = Buffer.concat([
        cipher.update(data),
        cipher.final()
      ]);

      const tag = cipher.getAuthTag();

      return {
        algorithm: 'chacha20-poly1305',
        encrypted: encrypted.toString('base64'),
        iv: iv.toString('base64'),
        tag: tag.toString('base64')
      };
    } catch (error) {
      // Fallback to AES if ChaCha20 not available
      logger.warn('ChaCha20 not available, using AES fallback');
      return this.encryptAESCBC(data, key);
    }
  }

  decryptChaCha20(encryptedData, key) {
    try {
      const { encrypted, iv, tag } = encryptedData;

      const decipher = crypto.createDecipheriv(
        'chacha20-poly1305',
        key,
        Buffer.from(iv, 'base64')
      );

      decipher.setAuthTag(Buffer.from(tag, 'base64'));

      const decrypted = Buffer.concat([
        decipher.update(Buffer.from(encrypted, 'base64')),
        decipher.final()
      ]);

      return decrypted;
    } catch (error) {
      // Fallback to AES
      if (!encryptedData.tag) {
        return this.decryptAESCBC(encryptedData, key);
      }
      throw error;
    }
  }

  encryptAESCBC(data, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

    const encrypted = Buffer.concat([
      cipher.update(data),
      cipher.final()
    ]);

    return {
      algorithm: 'aes-256-cbc',
      encrypted: encrypted.toString('base64'),
      iv: iv.toString('base64')
    };
  }

  decryptAESCBC(encryptedData, key) {
    const { encrypted, iv } = encryptedData;

    const decipher = crypto.createDecipheriv(
      'aes-256-cbc',
      key,
      Buffer.from(iv, 'base64')
    );

    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encrypted, 'base64')),
      decipher.final()
    ]);

    return decrypted;
  }

  deriveKey(keyId) {
    if (this.keyCache.has(keyId)) {
      return this.keyCache.get(keyId);
    }

    if (!this.masterKey) {
      throw new Error('Master key not set');
    }

    const salt = crypto.createHash('sha256').update(keyId).digest();
    const derivedKey = crypto.pbkdf2Sync(this.masterKey, salt, 100000, 32, 'sha256');

    this.keyCache.set(keyId, derivedKey);
    return derivedKey;
  }

  rotateKeys() {
    logger.info('🔄 Rotating encryption keys...');

    // Clear key cache to force regeneration
    this.keyCache.clear();

    // Generate new master key
    const newMasterKey = crypto.randomBytes(32);
    this.masterKey = newMasterKey;

    logger.info('✅ Key rotation completed');
  }

  // Utility methods
  generateRandomKey(length = 32) {
    return crypto.randomBytes(length);
  }

  hashPassword(password, salt) {
    if (!salt) {
      salt = crypto.randomBytes(32);
    }
    const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha256');
    return {
      hash: hash.toString('base64'),
      salt: salt.toString('base64')
    };
  }

  verifyPassword(password, hashedPassword, salt) {
    const { hash } = this.hashPassword(password, Buffer.from(salt, 'base64'));
    return crypto.timingSafeEqual(
      Buffer.from(hash, 'base64'),
      Buffer.from(hashedPassword, 'base64')
    );
  }

  // Status and monitoring
  getOperationCount() {
    return this.operationCount;
  }

  getStatus() {
    return {
      initialized: this.isInitialized,
      operationCount: this.operationCount,
      cachedKeys: this.keyCache.size,
      supportedAlgorithms: Object.keys(this.algorithms),
      healthy: this.isInitialized && this.masterKey !== null
    };
  }

  async audit() {
    return {
      timestamp: new Date().toISOString(),
      status: this.getStatus(),
      securityMetrics: {
        masterKeySet: this.masterKey !== null,
        keyRotationActive: true,
        algorithmsSupported: Object.keys(this.algorithms).length
      }
    };
  }
}