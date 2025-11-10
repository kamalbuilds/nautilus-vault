/**
 * Walrus Decentralized Storage Connector
 * Secure integration with Walrus storage network
 */

import { WalrusStorageConfig, EncryptedData, SecurityError } from '../types';
import { EncryptionManager } from '../security/encryption-manager';
import { VerifiableStorage } from '../storage/verifiable-storage';
import { createHash, randomBytes } from 'crypto';

export interface WalrusBlob {
  blobId: string;
  size: number;
  contentType: string;
  metadata: any;
  uploadedAt: Date;
  verified: boolean;
}

export interface StorageQuota {
  used: number;
  available: number;
  total: number;
}

export interface StorageMetrics {
  totalBlobs: number;
  totalSize: number;
  successfulReads: number;
  failedReads: number;
  averageLatency: number;
}

export class WalrusConnector {
  private config: WalrusStorageConfig;
  private encryptionManager: EncryptionManager;
  private verifiableStorage: VerifiableStorage;
  private blobIndex: Map<string, WalrusBlob> = new Map();
  private metrics: StorageMetrics;

  constructor(
    config: WalrusStorageConfig,
    encryptionManager: EncryptionManager,
    verifiableStorage: VerifiableStorage
  ) {
    this.config = config;
    this.encryptionManager = encryptionManager;
    this.verifiableStorage = verifiableStorage;
    this.metrics = {
      totalBlobs: 0,
      totalSize: 0,
      successfulReads: 0,
      failedReads: 0,
      averageLatency: 0
    };
    this.initialize();
  }

  /**
   * Initialize Walrus connection
   */
  private async initialize(): Promise<void> {
    try {
      // Validate connection to Walrus network
      await this.validateConnection();

      // Load existing blob index
      await this.loadBlobIndex();

      console.log('Walrus connector initialized successfully');
    } catch (error) {
      throw new SecurityError('Failed to initialize Walrus connector', 'WALRUS_INIT_ERROR', 'HIGH');
    }
  }

  /**
   * Store data in Walrus with encryption and verification
   */
  async storeSecure(
    data: any,
    owner: string,
    metadata: any = {},
    encryption: boolean = true
  ): Promise<string> {
    const startTime = Date.now();

    try {
      // Generate blob ID
      const blobId = this.generateBlobId();

      // Prepare data for storage
      let storeData = data;
      if (encryption) {
        const encryptedData = await this.encryptionManager.encrypt(
          JSON.stringify(data),
          owner
        );
        storeData = encryptedData;
      }

      // Create verifiable storage entry
      const verifiableBlobId = await this.verifiableStorage.store(
        storeData,
        owner,
        [`read:${owner}`, 'verify:*'],
        encryption
      );

      // Store in Walrus network
      await this.uploadToWalrus(blobId, storeData, metadata);

      // Create blob metadata
      const blob: WalrusBlob = {
        blobId,
        size: this.calculateDataSize(storeData),
        contentType: this.detectContentType(data),
        metadata: {
          ...metadata,
          owner,
          encrypted: encryption,
          verifiableBlobId,
          uploadedAt: new Date()
        },
        uploadedAt: new Date(),
        verified: true
      };

      // Update index and metrics
      this.blobIndex.set(blobId, blob);
      this.updateMetrics('store', Date.now() - startTime, blob.size);

      console.log(`Data stored successfully in Walrus with blob ID: ${blobId}`);
      return blobId;

    } catch (error) {
      this.updateMetrics('store_error', Date.now() - startTime);
      throw new SecurityError(`Failed to store data in Walrus: ${error.message}`, 'WALRUS_STORE_ERROR', 'HIGH');
    }
  }

  /**
   * Retrieve and verify data from Walrus
   */
  async retrieveSecure(blobId: string, requester: string): Promise<any> {
    const startTime = Date.now();

    try {
      // Check blob exists
      const blob = this.blobIndex.get(blobId);
      if (!blob) {
        throw new SecurityError('Blob not found', 'BLOB_NOT_FOUND', 'MEDIUM');
      }

      // Verify access permissions
      await this.verifyAccessPermissions(blob, requester);

      // Retrieve from Walrus
      const rawData = await this.downloadFromWalrus(blobId);

      // Verify data integrity
      await this.verifyDataIntegrity(blobId, rawData);

      // Retrieve from verifiable storage
      const verifiableData = await this.verifiableStorage.retrieve(
        blob.metadata.verifiableBlobId,
        requester
      );

      // Decrypt if necessary
      let data = verifiableData;
      if (blob.metadata.encrypted) {
        data = await this.encryptionManager.decrypt(
          verifiableData as EncryptedData,
          requester
        );
        data = JSON.parse(data);
      }

      // Update metrics
      this.updateMetrics('retrieve', Date.now() - startTime);
      this.metrics.successfulReads++;

      console.log(`Data retrieved successfully from Walrus with blob ID: ${blobId}`);
      return data;

    } catch (error) {
      this.updateMetrics('retrieve_error', Date.now() - startTime);
      this.metrics.failedReads++;
      throw new SecurityError(`Failed to retrieve data from Walrus: ${error.message}`, 'WALRUS_RETRIEVE_ERROR', 'HIGH');
    }
  }

  /**
   * Update existing blob with versioning
   */
  async updateBlob(
    blobId: string,
    newData: any,
    updater: string,
    createVersion: boolean = true
  ): Promise<void> {
    try {
      const blob = this.blobIndex.get(blobId);
      if (!blob) {
        throw new SecurityError('Blob not found', 'BLOB_NOT_FOUND', 'MEDIUM');
      }

      // Verify update permissions
      await this.verifyUpdatePermissions(blob, updater);

      // Create version if requested
      if (createVersion) {
        const versionId = await this.createBlobVersion(blobId);
        console.log(`Created version ${versionId} for blob ${blobId}`);
      }

      // Encrypt new data if original was encrypted
      let storeData = newData;
      if (blob.metadata.encrypted) {
        const encryptedData = await this.encryptionManager.encrypt(
          JSON.stringify(newData),
          blob.metadata.owner
        );
        storeData = encryptedData;
      }

      // Update in verifiable storage
      await this.verifiableStorage.update(blob.metadata.verifiableBlobId, storeData, updater);

      // Update in Walrus
      await this.updateInWalrus(blobId, storeData);

      // Update metadata
      blob.size = this.calculateDataSize(storeData);
      blob.metadata.updatedAt = new Date();
      blob.metadata.updatedBy = updater;

      this.blobIndex.set(blobId, blob);

      console.log(`Blob ${blobId} updated successfully`);

    } catch (error) {
      throw new SecurityError(`Failed to update blob: ${error.message}`, 'WALRUS_UPDATE_ERROR', 'HIGH');
    }
  }

  /**
   * Delete blob with secure erasure
   */
  async deleteBlob(blobId: string, requester: string): Promise<void> {
    try {
      const blob = this.blobIndex.get(blobId);
      if (!blob) {
        throw new SecurityError('Blob not found', 'BLOB_NOT_FOUND', 'MEDIUM');
      }

      // Verify deletion permissions
      await this.verifyDeletePermissions(blob, requester);

      // Delete from verifiable storage
      await this.verifiableStorage.delete(blob.metadata.verifiableBlobId, requester);

      // Delete from Walrus
      await this.deleteFromWalrus(blobId);

      // Remove from index
      this.blobIndex.delete(blobId);

      // Update metrics
      this.metrics.totalBlobs--;
      this.metrics.totalSize -= blob.size;

      console.log(`Blob ${blobId} deleted successfully`);

    } catch (error) {
      throw new SecurityError(`Failed to delete blob: ${error.message}`, 'WALRUS_DELETE_ERROR', 'HIGH');
    }
  }

  /**
   * List blobs for a user
   */
  async listBlobs(owner: string, filter: any = {}): Promise<WalrusBlob[]> {
    try {
      return Array.from(this.blobIndex.values())
        .filter(blob => {
          // Filter by owner
          if (blob.metadata.owner !== owner) return false;

          // Apply additional filters
          if (filter.contentType && blob.contentType !== filter.contentType) return false;
          if (filter.minSize && blob.size < filter.minSize) return false;
          if (filter.maxSize && blob.size > filter.maxSize) return false;
          if (filter.uploadedAfter && blob.uploadedAt < filter.uploadedAfter) return false;
          if (filter.uploadedBefore && blob.uploadedAt > filter.uploadedBefore) return false;

          return true;
        })
        .sort((a, b) => b.uploadedAt.getTime() - a.uploadedAt.getTime());

    } catch (error) {
      throw new SecurityError(`Failed to list blobs: ${error.message}`, 'WALRUS_LIST_ERROR', 'MEDIUM');
    }
  }

  /**
   * Get storage quota information
   */
  async getStorageQuota(owner: string): Promise<StorageQuota> {
    try {
      const userBlobs = await this.listBlobs(owner);
      const used = userBlobs.reduce((total, blob) => total + blob.size, 0);

      // Get quota limits from Walrus network
      const limits = await this.getQuotaLimits(owner);

      return {
        used,
        available: limits.total - used,
        total: limits.total
      };

    } catch (error) {
      throw new SecurityError(`Failed to get storage quota: ${error.message}`, 'QUOTA_ERROR', 'MEDIUM');
    }
  }

  /**
   * Get storage metrics
   */
  getMetrics(): StorageMetrics {
    return { ...this.metrics };
  }

  /**
   * Verify blob integrity
   */
  async verifyBlob(blobId: string): Promise<boolean> {
    try {
      const blob = this.blobIndex.get(blobId);
      if (!blob) return false;

      // Verify in verifiable storage
      const isVerifiableValid = await this.verifiableStorage.verify(blob.metadata.verifiableBlobId);

      // Verify in Walrus network
      const isWalrusValid = await this.verifyInWalrus(blobId);

      return isVerifiableValid && isWalrusValid;

    } catch (error) {
      console.error(`Blob verification failed: ${error.message}`);
      return false;
    }
  }

  // Private helper methods

  private async validateConnection(): Promise<void> {
    // Simulate Walrus network connection validation
    if (!this.config.endpoint) {
      throw new SecurityError('Walrus endpoint not configured', 'CONFIG_ERROR', 'HIGH');
    }

    if (!this.config.apiKey) {
      throw new SecurityError('Walrus API key not configured', 'CONFIG_ERROR', 'HIGH');
    }

    // In production: await walrusClient.ping()
    console.log('Walrus connection validated');
  }

  private async loadBlobIndex(): Promise<void> {
    // In production: load from persistent storage
    console.log('Blob index loaded');
  }

  private generateBlobId(): string {
    return createHash('sha256')
      .update(randomBytes(32))
      .digest('hex')
      .substring(0, 16);
  }

  private async uploadToWalrus(blobId: string, data: any, metadata: any): Promise<void> {
    // Simulate Walrus upload
    console.log(`Uploading blob ${blobId} to Walrus`);
    // In production: await walrusClient.upload(blobId, data, metadata)
  }

  private async downloadFromWalrus(blobId: string): Promise<any> {
    // Simulate Walrus download
    console.log(`Downloading blob ${blobId} from Walrus`);
    // In production: return await walrusClient.download(blobId)
    return { mock: 'data' };
  }

  private async updateInWalrus(blobId: string, data: any): Promise<void> {
    // Simulate Walrus update
    console.log(`Updating blob ${blobId} in Walrus`);
    // In production: await walrusClient.update(blobId, data)
  }

  private async deleteFromWalrus(blobId: string): Promise<void> {
    // Simulate Walrus deletion
    console.log(`Deleting blob ${blobId} from Walrus`);
    // In production: await walrusClient.delete(blobId)
  }

  private async verifyInWalrus(blobId: string): Promise<boolean> {
    // Simulate Walrus verification
    console.log(`Verifying blob ${blobId} in Walrus`);
    // In production: return await walrusClient.verify(blobId)
    return true;
  }

  private async verifyDataIntegrity(blobId: string, data: any): Promise<void> {
    const blob = this.blobIndex.get(blobId);
    if (!blob) return;

    const calculatedSize = this.calculateDataSize(data);
    if (calculatedSize !== blob.size) {
      throw new SecurityError('Data integrity check failed: size mismatch', 'INTEGRITY_ERROR', 'CRITICAL');
    }
  }

  private async verifyAccessPermissions(blob: WalrusBlob, requester: string): Promise<void> {
    const owner = blob.metadata.owner;
    const permissions = blob.metadata.permissions || [];

    if (owner !== requester && !permissions.includes(`read:${requester}`) && !permissions.includes('read:*')) {
      throw new SecurityError('Access denied', 'ACCESS_DENIED', 'HIGH');
    }
  }

  private async verifyUpdatePermissions(blob: WalrusBlob, updater: string): Promise<void> {
    const owner = blob.metadata.owner;
    const permissions = blob.metadata.permissions || [];

    if (owner !== updater && !permissions.includes(`write:${updater}`)) {
      throw new SecurityError('Update permission denied', 'UPDATE_DENIED', 'HIGH');
    }
  }

  private async verifyDeletePermissions(blob: WalrusBlob, requester: string): Promise<void> {
    const owner = blob.metadata.owner;
    const permissions = blob.metadata.permissions || [];

    if (owner !== requester && !permissions.includes(`delete:${requester}`)) {
      throw new SecurityError('Delete permission denied', 'DELETE_DENIED', 'HIGH');
    }
  }

  private async createBlobVersion(blobId: string): Promise<string> {
    // Create versioned copy
    const versionId = `${blobId}_v${Date.now()}`;
    // In production: implement actual versioning
    return versionId;
  }

  private calculateDataSize(data: any): number {
    return new Blob([typeof data === 'string' ? data : JSON.stringify(data)]).size;
  }

  private detectContentType(data: any): string {
    if (typeof data === 'string') {
      try {
        JSON.parse(data);
        return 'application/json';
      } catch {
        return 'text/plain';
      }
    } else if (typeof data === 'object') {
      return 'application/json';
    } else if (data instanceof ArrayBuffer) {
      return 'application/octet-stream';
    }
    return 'application/octet-stream';
  }

  private async getQuotaLimits(owner: string): Promise<{ total: number }> {
    // In production: get from Walrus network
    return { total: 1024 * 1024 * 1024 }; // 1GB default
  }

  private updateMetrics(operation: string, latency: number, size: number = 0): void {
    if (operation === 'store') {
      this.metrics.totalBlobs++;
      this.metrics.totalSize += size;
    }

    // Update average latency
    this.metrics.averageLatency = (this.metrics.averageLatency + latency) / 2;
  }
}