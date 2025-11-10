/**
 * Key Manager - Cryptographic key management and lifecycle
 */

import { randomBytes, createHash } from 'crypto';
import { SecurityError } from '../types';

export interface KeyConfig {
  algorithm: 'AES-256' | 'RSA-2048' | 'RSA-4096' | 'ECDSA-P256' | 'ECDSA-P384';
  usage: 'ENCRYPTION' | 'SIGNING' | 'KEY_WRAPPING';
  exportable: boolean;
  rotationPeriod: number; // in milliseconds
}

export interface CryptoKey {
  id: string;
  algorithm: string;
  usage: string;
  created: Date;
  expires?: Date;
  status: 'ACTIVE' | 'EXPIRED' | 'REVOKED' | 'PENDING_ACTIVATION';
  metadata: Record<string, any>;
}

export class KeyManager {
  private keys: Map<string, CryptoKey> = new Map();
  private keyMaterial: Map<string, Buffer> = new Map();

  async generateKey(config: KeyConfig): Promise<string> {
    try {
      const keyId = `key_${Date.now()}_${randomBytes(8).toString('hex')}`;

      const key: CryptoKey = {
        id: keyId,
        algorithm: config.algorithm,
        usage: config.usage,
        created: new Date(),
        expires: config.rotationPeriod ? new Date(Date.now() + config.rotationPeriod) : undefined,
        status: 'ACTIVE',
        metadata: { exportable: config.exportable }
      };

      // Generate actual key material based on algorithm
      const keyMaterial = this.generateKeyMaterial(config.algorithm);

      this.keys.set(keyId, key);
      this.keyMaterial.set(keyId, keyMaterial);

      return keyId;
    } catch (error) {
      throw new SecurityError(`Failed to generate key: ${(error as Error).message}`, 'KEY_GENERATION_ERROR');
    }
  }

  async rotateKey(keyId: string): Promise<string> {
    const key = this.keys.get(keyId);
    if (!key) {
      throw new SecurityError(`Key not found: ${keyId}`, 'KEY_NOT_FOUND');
    }

    // Create new key with same configuration
    const config: KeyConfig = {
      algorithm: key.algorithm as any,
      usage: key.usage as any,
      exportable: key.metadata.exportable,
      rotationPeriod: 0
    };

    const newKeyId = await this.generateKey(config);

    // Mark old key as expired
    key.status = 'EXPIRED';
    this.keys.set(keyId, key);

    return newKeyId;
  }

  async getKey(keyId: string): Promise<CryptoKey> {
    const key = this.keys.get(keyId);
    if (!key) {
      throw new SecurityError(`Key not found: ${keyId}`, 'KEY_NOT_FOUND');
    }
    return { ...key }; // Return copy to prevent modification
  }

  async revokeKey(keyId: string): Promise<void> {
    const key = this.keys.get(keyId);
    if (!key) {
      throw new SecurityError(`Key not found: ${keyId}`, 'KEY_NOT_FOUND');
    }

    key.status = 'REVOKED';
    this.keys.set(keyId, key);
  }

  async getActiveKeys(): Promise<CryptoKey[]> {
    return Array.from(this.keys.values())
      .filter(key => key.status === 'ACTIVE')
      .map(key => ({ ...key }));
  }

  private generateKeyMaterial(algorithm: string): Buffer {
    switch (algorithm) {
      case 'AES-256':
        return randomBytes(32); // 256 bits

      case 'RSA-2048':
        // In real implementation, generate RSA key pair
        return randomBytes(256); // Mock

      case 'RSA-4096':
        return randomBytes(512); // Mock

      case 'ECDSA-P256':
        return randomBytes(32); // Mock

      case 'ECDSA-P384':
        return randomBytes(48); // Mock

      default:
        throw new SecurityError(`Unsupported algorithm: ${algorithm}`, 'UNSUPPORTED_ALGORITHM');
    }
  }
}