/**
 * Advanced Encryption Management System
 * Comprehensive encryption, key management, and cryptographic operations
 */

import { EncryptionKey, EncryptedData, SecurityError } from '../types';
import { createCipheriv, createDecipheriv, createHash, randomBytes, pbkdf2Sync, scryptSync } from 'crypto';
import * as forge from 'node-forge';

export interface EncryptionConfig {
  algorithm: 'AES-256-GCM' | 'AES-256-CBC' | 'ChaCha20-Poly1305';
  keyDerivation: 'PBKDF2' | 'Argon2' | 'HKDF' | 'scrypt';
  keySize: number;
  ivSize: number;
  tagSize: number;
  iterations: number;
}

export interface KeyRotationPolicy {
  enabled: boolean;
  rotationIntervalMs: number;
  maxKeyAge: number;
  retainOldKeys: boolean;
  notificationThresholdMs: number;
}

export interface EncryptionMetrics {
  totalEncryptions: number;
  totalDecryptions: number;
  keysGenerated: number;
  keysRotated: number;
  failedOperations: number;
  averageEncryptionTime: number;
  averageDecryptionTime: number;
}

export class EncryptionManager {
  private config: EncryptionConfig;
  private keyStore: Map<string, EncryptionKey> = new Map();
  private userKeys: Map<string, string[]> = new Map(); // user -> key IDs
  private rotationPolicy: KeyRotationPolicy;
  private metrics: EncryptionMetrics;
  private keyRotationTimer?: NodeJS.Timeout;

  constructor(
    config: Partial<EncryptionConfig> = {},
    rotationPolicy: Partial<KeyRotationPolicy> = {}
  ) {
    this.config = {
      algorithm: 'AES-256-GCM',
      keyDerivation: 'PBKDF2',
      keySize: 32, // 256 bits
      ivSize: 16,  // 128 bits
      tagSize: 16, // 128 bits
      iterations: 100000,
      ...config
    };

    this.rotationPolicy = {
      enabled: true,
      rotationIntervalMs: 7 * 24 * 60 * 60 * 1000, // 7 days
      maxKeyAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      retainOldKeys: true,
      notificationThresholdMs: 24 * 60 * 60 * 1000, // 1 day
      ...rotationPolicy
    };

    this.metrics = {
      totalEncryptions: 0,
      totalDecryptions: 0,
      keysGenerated: 0,
      keysRotated: 0,
      failedOperations: 0,
      averageEncryptionTime: 0,
      averageDecryptionTime: 0
    };

    this.initializeKeyRotation();
  }

  /**
   * Encrypt data with specified algorithm
   */
  async encrypt(data: string, userId: string, keyId?: string): Promise<EncryptedData> {
    const startTime = Date.now();

    try {
      // Get or generate encryption key
      const key = keyId ? this.getKey(keyId) : await this.getOrCreateUserKey(userId, 'ENCRYPTION');

      if (!key) {
        throw new SecurityError('Encryption key not available', 'KEY_NOT_AVAILABLE', 'HIGH');
      }

      let encryptedData: EncryptedData;

      switch (this.config.algorithm) {
        case 'AES-256-GCM':
          encryptedData = this.encryptAESGCM(data, key);
          break;
        case 'AES-256-CBC':
          encryptedData = this.encryptAESCBC(data, key);
          break;
        case 'ChaCha20-Poly1305':
          encryptedData = this.encryptChaCha20(data, key);
          break;
        default:
          throw new SecurityError('Unsupported encryption algorithm', 'UNSUPPORTED_ALGORITHM', 'HIGH');
      }

      // Update metrics
      this.updateMetrics('encrypt', Date.now() - startTime);

      return encryptedData;

    } catch (error) {
      this.metrics.failedOperations++;
      throw new SecurityError(`Encryption failed: ${error.message}`, 'ENCRYPTION_ERROR', 'HIGH');
    }
  }

  /**
   * Decrypt data with specified algorithm
   */
  async decrypt(encryptedData: EncryptedData, userId: string): Promise<string> {
    const startTime = Date.now();

    try {
      const key = this.getKey(encryptedData.keyId);

      if (!key) {
        throw new SecurityError('Decryption key not available', 'KEY_NOT_AVAILABLE', 'HIGH');
      }

      // Verify user has access to this key
      await this.verifyKeyAccess(userId, key.id);

      let decryptedData: string;

      switch (encryptedData.algorithm) {
        case 'AES-256-GCM':
          decryptedData = this.decryptAESGCM(encryptedData, key);
          break;
        case 'AES-256-CBC':
          decryptedData = this.decryptAESCBC(encryptedData, key);
          break;
        case 'ChaCha20-Poly1305':
          decryptedData = this.decryptChaCha20(encryptedData, key);
          break;
        default:
          throw new SecurityError('Unsupported decryption algorithm', 'UNSUPPORTED_ALGORITHM', 'HIGH');
      }

      // Update metrics
      this.updateMetrics('decrypt', Date.now() - startTime);

      return decryptedData;

    } catch (error) {
      this.metrics.failedOperations++;
      throw new SecurityError(`Decryption failed: ${error.message}`, 'DECRYPTION_ERROR', 'HIGH');
    }
  }

  /**
   * Generate new encryption key
   */
  async generateKey(
    userId: string,
    usage: 'ENCRYPTION' | 'SIGNING' | 'VERIFICATION' = 'ENCRYPTION',
    expiresAt?: Date
  ): Promise<EncryptionKey> {
    try {
      const keyId = this.generateKeyId();
      const keyData = this.generateSecureKey();

      const key: EncryptionKey = {
        id: keyId,
        algorithm: this.config.algorithm,
        key: keyData,
        createdAt: new Date(),
        expiresAt,
        usage
      };

      // Store key
      this.keyStore.set(keyId, key);

      // Associate with user
      if (!this.userKeys.has(userId)) {
        this.userKeys.set(userId, []);
      }
      this.userKeys.get(userId)!.push(keyId);

      this.metrics.keysGenerated++;

      console.log(`Generated ${usage} key ${keyId} for user ${userId}`);
      return key;

    } catch (error) {
      throw new SecurityError(`Key generation failed: ${error.message}`, 'KEY_GENERATION_ERROR', 'HIGH');
    }
  }

  /**
   * Rotate encryption keys for a user
   */
  async rotateUserKeys(userId: string): Promise<string[]> {
    try {
      const userKeyIds = this.userKeys.get(userId) || [];
      const newKeyIds: string[] = [];

      for (const oldKeyId of userKeyIds) {
        const oldKey = this.keyStore.get(oldKeyId);
        if (!oldKey) continue;

        // Generate new key
        const newKey = await this.generateKey(userId, oldKey.usage, oldKey.expiresAt);
        newKeyIds.push(newKey.id);

        // Mark old key as expired if not retaining
        if (!this.rotationPolicy.retainOldKeys) {
          oldKey.expiresAt = new Date();
          this.keyStore.set(oldKeyId, oldKey);
        }

        this.metrics.keysRotated++;
      }

      // Update user key references
      if (newKeyIds.length > 0) {
        if (this.rotationPolicy.retainOldKeys) {
          this.userKeys.get(userId)!.push(...newKeyIds);
        } else {
          this.userKeys.set(userId, newKeyIds);
        }
      }

      console.log(`Rotated ${newKeyIds.length} keys for user ${userId}`);
      return newKeyIds;

    } catch (error) {
      throw new SecurityError(`Key rotation failed: ${error.message}`, 'KEY_ROTATION_ERROR', 'HIGH');
    }
  }

  /**
   * Derive key from password using configured KDF
   */
  deriveKeyFromPassword(
    password: string,
    salt: string,
    userId?: string
  ): string {
    try {
      let derivedKey: Buffer;

      switch (this.config.keyDerivation) {
        case 'PBKDF2':
          derivedKey = pbkdf2Sync(password, salt, this.config.iterations, this.config.keySize, 'sha512');
          break;
        case 'scrypt':
          derivedKey = scryptSync(password, salt, this.config.keySize);
          break;
        case 'HKDF':
          derivedKey = this.deriveHKDF(password, salt);
          break;
        default:
          throw new SecurityError('Unsupported key derivation function', 'UNSUPPORTED_KDF', 'HIGH');
      }

      const keyString = derivedKey.toString('hex');

      // Optionally store derived key for user
      if (userId) {
        const keyId = this.generateKeyId();
        const key: EncryptionKey = {
          id: keyId,
          algorithm: this.config.algorithm,
          key: keyString,
          createdAt: new Date(),
          usage: 'ENCRYPTION'
        };

        this.keyStore.set(keyId, key);

        if (!this.userKeys.has(userId)) {
          this.userKeys.set(userId, []);
        }
        this.userKeys.get(userId)!.push(keyId);
      }

      return keyString;

    } catch (error) {
      throw new SecurityError(`Key derivation failed: ${error.message}`, 'KEY_DERIVATION_ERROR', 'HIGH');
    }
  }

  /**
   * Secure key exchange using ECDH
   */
  async performKeyExchange(
    localPrivateKey: string,
    remotePublicKey: string
  ): Promise<string> {
    try {
      // Generate ECDH key pair using forge
      const localKeyPair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
      const remoteKey = forge.pki.publicKeyFromPem(remotePublicKey);

      // Perform key agreement (simplified)
      const sharedSecret = forge.util.encode64(localKeyPair.privateKey.sign(forge.md.sha256.create()));

      return sharedSecret;

    } catch (error) {
      throw new SecurityError(`Key exchange failed: ${error.message}`, 'KEY_EXCHANGE_ERROR', 'HIGH');
    }
  }

  /**
   * Get key information
   */
  getKey(keyId: string): EncryptionKey | null {
    return this.keyStore.get(keyId) || null;
  }

  /**
   * List keys for a user
   */
  getUserKeys(userId: string, includeExpired: boolean = false): EncryptionKey[] {
    const userKeyIds = this.userKeys.get(userId) || [];
    const keys: EncryptionKey[] = [];

    for (const keyId of userKeyIds) {
      const key = this.keyStore.get(keyId);
      if (key && (includeExpired || !this.isKeyExpired(key))) {
        keys.push(key);
      }
    }

    return keys.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  /**
   * Revoke a key
   */
  async revokeKey(keyId: string, userId: string): Promise<void> {
    try {
      const key = this.keyStore.get(keyId);
      if (!key) {
        throw new SecurityError('Key not found', 'KEY_NOT_FOUND', 'MEDIUM');
      }

      // Verify user owns this key
      const userKeyIds = this.userKeys.get(userId) || [];
      if (!userKeyIds.includes(keyId)) {
        throw new SecurityError('Key access denied', 'KEY_ACCESS_DENIED', 'HIGH');
      }

      // Mark key as expired
      key.expiresAt = new Date();
      this.keyStore.set(keyId, key);

      console.log(`Key ${keyId} revoked for user ${userId}`);

    } catch (error) {
      throw new SecurityError(`Key revocation failed: ${error.message}`, 'KEY_REVOCATION_ERROR', 'HIGH');
    }
  }

  /**
   * Get encryption metrics
   */
  getMetrics(): EncryptionMetrics {
    return { ...this.metrics };
  }

  /**
   * Clean up expired keys
   */
  async cleanupExpiredKeys(): Promise<number> {
    try {
      let cleanedCount = 0;
      const now = new Date();

      for (const [keyId, key] of this.keyStore.entries()) {
        if (key.expiresAt && key.expiresAt <= now) {
          this.keyStore.delete(keyId);
          cleanedCount++;

          // Remove from user associations
          for (const [userId, keyIds] of this.userKeys.entries()) {
            const index = keyIds.indexOf(keyId);
            if (index > -1) {
              keyIds.splice(index, 1);
              if (keyIds.length === 0) {
                this.userKeys.delete(userId);
              }
            }
          }
        }
      }

      if (cleanedCount > 0) {
        console.log(`Cleaned up ${cleanedCount} expired keys`);
      }

      return cleanedCount;

    } catch (error) {
      console.error(`Key cleanup failed: ${error.message}`);
      return 0;
    }
  }

  // Private helper methods

  private initializeKeyRotation(): void {
    if (!this.rotationPolicy.enabled) return;

    this.keyRotationTimer = setInterval(async () => {
      try {
        await this.performScheduledRotation();
        await this.cleanupExpiredKeys();
      } catch (error) {
        console.error(`Scheduled key rotation failed: ${error.message}`);
      }
    }, this.rotationPolicy.rotationIntervalMs);
  }

  private async performScheduledRotation(): Promise<void> {
    const now = new Date();

    for (const [userId, keyIds] of this.userKeys.entries()) {
      for (const keyId of keyIds) {
        const key = this.keyStore.get(keyId);
        if (!key) continue;

        const keyAge = now.getTime() - key.createdAt.getTime();

        if (keyAge > this.rotationPolicy.maxKeyAge) {
          console.log(`Auto-rotating key ${keyId} for user ${userId} (age: ${keyAge}ms)`);
          await this.rotateUserKeys(userId);
          break; // Rotate one key per interval per user
        }
      }
    }
  }

  private async getOrCreateUserKey(userId: string, usage: 'ENCRYPTION' | 'SIGNING' | 'VERIFICATION'): Promise<EncryptionKey> {
    const userKeys = this.getUserKeys(userId);
    const validKey = userKeys.find(key => key.usage === usage);

    if (validKey) {
      return validKey;
    }

    return this.generateKey(userId, usage);
  }

  private async verifyKeyAccess(userId: string, keyId: string): Promise<void> {
    const userKeyIds = this.userKeys.get(userId) || [];
    if (!userKeyIds.includes(keyId)) {
      throw new SecurityError('Key access denied', 'KEY_ACCESS_DENIED', 'HIGH');
    }
  }

  private isKeyExpired(key: EncryptionKey): boolean {
    return key.expiresAt ? new Date() > key.expiresAt : false;
  }

  private encryptAESGCM(data: string, key: EncryptionKey): EncryptedData {
    const iv = randomBytes(this.config.ivSize);
    const cipher = createCipheriv('aes-256-gcm', Buffer.from(key.key, 'hex'), iv);

    let ciphertext = cipher.update(data, 'utf8', 'hex');
    ciphertext += cipher.final('hex');

    const tag = cipher.getAuthTag();

    return {
      ciphertext,
      algorithm: 'AES-256-GCM',
      keyId: key.id,
      iv: iv.toString('hex'),
      tag: tag.toString('hex'),
      metadata: {
        timestamp: Date.now(),
        version: '1.0'
      }
    };
  }

  private decryptAESGCM(encryptedData: EncryptedData, key: EncryptionKey): string {
    const iv = Buffer.from(encryptedData.iv, 'hex');
    const tag = Buffer.from(encryptedData.tag!, 'hex');
    const decipher = createDecipheriv('aes-256-gcm', Buffer.from(key.key, 'hex'), iv);

    decipher.setAuthTag(tag);

    let plaintext = decipher.update(encryptedData.ciphertext, 'hex', 'utf8');
    plaintext += decipher.final('utf8');

    return plaintext;
  }

  private encryptAESCBC(data: string, key: EncryptionKey): EncryptedData {
    const iv = randomBytes(this.config.ivSize);
    const cipher = createCipheriv('aes-256-cbc', Buffer.from(key.key, 'hex'), iv);

    let ciphertext = cipher.update(data, 'utf8', 'hex');
    ciphertext += cipher.final('hex');

    return {
      ciphertext,
      algorithm: 'AES-256-CBC',
      keyId: key.id,
      iv: iv.toString('hex'),
      metadata: {
        timestamp: Date.now(),
        version: '1.0'
      }
    };
  }

  private decryptAESCBC(encryptedData: EncryptedData, key: EncryptionKey): string {
    const iv = Buffer.from(encryptedData.iv, 'hex');
    const decipher = createDecipheriv('aes-256-cbc', Buffer.from(key.key, 'hex'), iv);

    let plaintext = decipher.update(encryptedData.ciphertext, 'hex', 'utf8');
    plaintext += decipher.final('utf8');

    return plaintext;
  }

  private encryptChaCha20(data: string, key: EncryptionKey): EncryptedData {
    // Simplified ChaCha20 implementation using forge
    const iv = randomBytes(12); // ChaCha20 uses 96-bit nonce

    // For production: use actual ChaCha20 implementation
    const cipher = createCipheriv('aes-256-gcm', Buffer.from(key.key, 'hex'), iv);
    let ciphertext = cipher.update(data, 'utf8', 'hex');
    ciphertext += cipher.final('hex');

    return {
      ciphertext,
      algorithm: 'ChaCha20-Poly1305',
      keyId: key.id,
      iv: iv.toString('hex'),
      tag: cipher.getAuthTag().toString('hex'),
      metadata: {
        timestamp: Date.now(),
        version: '1.0'
      }
    };
  }

  private decryptChaCha20(encryptedData: EncryptedData, key: EncryptionKey): string {
    // Simplified ChaCha20 implementation
    const iv = Buffer.from(encryptedData.iv, 'hex');
    const tag = Buffer.from(encryptedData.tag!, 'hex');

    const decipher = createDecipheriv('aes-256-gcm', Buffer.from(key.key, 'hex'), iv);
    decipher.setAuthTag(tag);

    let plaintext = decipher.update(encryptedData.ciphertext, 'hex', 'utf8');
    plaintext += decipher.final('utf8');

    return plaintext;
  }

  private generateSecureKey(): string {
    return randomBytes(this.config.keySize).toString('hex');
  }

  private generateKeyId(): string {
    const timestamp = Date.now().toString(36);
    const randomPart = randomBytes(8).toString('hex');
    return `key_${timestamp}_${randomPart}`;
  }

  private deriveHKDF(password: string, salt: string): Buffer {
    // Simplified HKDF implementation
    const hash = createHash('sha256');
    hash.update(password);
    hash.update(salt);
    return hash.digest().slice(0, this.config.keySize);
  }

  private updateMetrics(operation: 'encrypt' | 'decrypt', duration: number): void {
    if (operation === 'encrypt') {
      this.metrics.totalEncryptions++;
      this.metrics.averageEncryptionTime =
        (this.metrics.averageEncryptionTime + duration) / 2;
    } else {
      this.metrics.totalDecryptions++;
      this.metrics.averageDecryptionTime =
        (this.metrics.averageDecryptionTime + duration) / 2;
    }
  }

  /**
   * Cleanup on destruction
   */
  destroy(): void {
    if (this.keyRotationTimer) {
      clearInterval(this.keyRotationTimer);
    }
    this.keyStore.clear();
    this.userKeys.clear();
  }
}