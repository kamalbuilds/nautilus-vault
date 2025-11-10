/**
 * Verifiable Storage System for Walrus Integration
 * Provides cryptographically verifiable storage with integrity guarantees
 */

import { VerifiableData, ZKProof, SecurityError, EncryptedData } from '../types';
import { ZKProofSystem } from '../privacy/zk-proof-system';
import { EncryptionManager } from '../security/encryption-manager';
import { createHash, randomBytes } from 'crypto';

export interface StorageMetadata {
  blobId: string;
  version: number;
  createdAt: Date;
  updatedAt: Date;
  owner: string;
  permissions: string[];
  integrity: string;
  verifiable: boolean;
}

export interface StorageProof {
  existence: ZKProof;
  integrity: ZKProof;
  ownership: ZKProof;
  timestamp: number;
}

export class VerifiableStorage {
  private zkProofSystem: ZKProofSystem;
  private encryptionManager: EncryptionManager;
  private storageIndex: Map<string, StorageMetadata> = new Map();
  private proofCache: Map<string, StorageProof> = new Map();

  constructor(
    zkProofSystem: ZKProofSystem,
    encryptionManager: EncryptionManager
  ) {
    this.zkProofSystem = zkProofSystem;
    this.encryptionManager = encryptionManager;
  }

  /**
   * Store data with verifiable proofs
   */
  async store(
    data: any,
    owner: string,
    permissions: string[] = [],
    encrypt: boolean = true
  ): Promise<string> {
    try {
      const blobId = this.generateBlobId();

      // Prepare data for storage
      let storeData = data;
      if (encrypt) {
        const encrypted = await this.encryptionManager.encrypt(JSON.stringify(data), owner);
        storeData = encrypted;
      }

      // Create verifiable data with ZK proofs
      const verifiableData = await this.createVerifiableData(storeData, owner);

      // Generate storage proofs
      const storageProof = await this.generateStorageProof(verifiableData, owner, permissions);

      // Create metadata
      const metadata: StorageMetadata = {
        blobId,
        version: 1,
        createdAt: new Date(),
        updatedAt: new Date(),
        owner,
        permissions,
        integrity: this.calculateIntegrity(verifiableData),
        verifiable: true
      };

      // Store in Walrus (simulated)
      await this.storeInWalrus(blobId, verifiableData);

      // Cache metadata and proofs
      this.storageIndex.set(blobId, metadata);
      this.proofCache.set(blobId, storageProof);

      console.log(`Data stored successfully with blob ID: ${blobId}`);
      return blobId;

    } catch (error) {
      throw new SecurityError(`Failed to store data: ${error.message}`, 'STORAGE_ERROR', 'HIGH');
    }
  }

  /**
   * Retrieve and verify stored data
   */
  async retrieve(blobId: string, requester: string): Promise<any> {
    try {
      // Check metadata and permissions
      const metadata = this.storageIndex.get(blobId);
      if (!metadata) {
        throw new SecurityError('Blob not found', 'BLOB_NOT_FOUND', 'MEDIUM');
      }

      // Verify access permissions
      if (!this.checkPermissions(metadata, requester)) {
        throw new SecurityError('Access denied', 'ACCESS_DENIED', 'HIGH');
      }

      // Retrieve from Walrus
      const verifiableData = await this.retrieveFromWalrus(blobId);

      // Verify data integrity and proofs
      await this.verifyStorageProofs(blobId, verifiableData);

      // Decrypt if necessary
      let data = verifiableData.data;
      if (this.isEncrypted(data)) {
        data = await this.encryptionManager.decrypt(data as EncryptedData, requester);
        data = JSON.parse(data);
      }

      console.log(`Data retrieved successfully for blob ID: ${blobId}`);
      return data;

    } catch (error) {
      throw new SecurityError(`Failed to retrieve data: ${error.message}`, 'RETRIEVAL_ERROR', 'HIGH');
    }
  }

  /**
   * Update stored data with new version and proofs
   */
  async update(
    blobId: string,
    newData: any,
    updater: string
  ): Promise<void> {
    try {
      const metadata = this.storageIndex.get(blobId);
      if (!metadata) {
        throw new SecurityError('Blob not found', 'BLOB_NOT_FOUND', 'MEDIUM');
      }

      // Check update permissions
      if (!this.checkUpdatePermissions(metadata, updater)) {
        throw new SecurityError('Update permission denied', 'UPDATE_DENIED', 'HIGH');
      }

      // Encrypt new data if original was encrypted
      let storeData = newData;
      if (this.wasEncrypted(metadata)) {
        const encrypted = await this.encryptionManager.encrypt(JSON.stringify(newData), metadata.owner);
        storeData = encrypted;
      }

      // Create verifiable data for update
      const verifiableData = await this.createVerifiableData(storeData, updater);

      // Generate new storage proofs
      const storageProof = await this.generateStorageProof(verifiableData, updater, metadata.permissions);

      // Update metadata
      metadata.version += 1;
      metadata.updatedAt = new Date();
      metadata.integrity = this.calculateIntegrity(verifiableData);

      // Store updated data
      await this.storeInWalrus(blobId, verifiableData);

      // Update caches
      this.storageIndex.set(blobId, metadata);
      this.proofCache.set(blobId, storageProof);

      console.log(`Data updated successfully for blob ID: ${blobId}, version: ${metadata.version}`);

    } catch (error) {
      throw new SecurityError(`Failed to update data: ${error.message}`, 'UPDATE_ERROR', 'HIGH');
    }
  }

  /**
   * Delete stored data with proof of deletion
   */
  async delete(blobId: string, requester: string): Promise<void> {
    try {
      const metadata = this.storageIndex.get(blobId);
      if (!metadata) {
        throw new SecurityError('Blob not found', 'BLOB_NOT_FOUND', 'MEDIUM');
      }

      // Check deletion permissions
      if (!this.checkDeletePermissions(metadata, requester)) {
        throw new SecurityError('Delete permission denied', 'DELETE_DENIED', 'HIGH');
      }

      // Generate proof of deletion
      const deletionProof = await this.generateDeletionProof(blobId, requester);

      // Delete from Walrus
      await this.deleteFromWalrus(blobId);

      // Remove from caches
      this.storageIndex.delete(blobId);
      this.proofCache.delete(blobId);

      console.log(`Data deleted successfully for blob ID: ${blobId}`);

    } catch (error) {
      throw new SecurityError(`Failed to delete data: ${error.message}`, 'DELETION_ERROR', 'HIGH');
    }
  }

  /**
   * Verify the integrity and authenticity of stored data
   */
  async verify(blobId: string): Promise<boolean> {
    try {
      const metadata = this.storageIndex.get(blobId);
      if (!metadata) {
        return false;
      }

      // Retrieve data and proofs
      const verifiableData = await this.retrieveFromWalrus(blobId);
      const storageProof = this.proofCache.get(blobId);

      if (!storageProof) {
        return false;
      }

      // Verify all proofs
      const existenceValid = await this.zkProofSystem.verifyProof(storageProof.existence);
      const integrityValid = await this.zkProofSystem.verifyProof(storageProof.integrity);
      const ownershipValid = await this.zkProofSystem.verifyProof(storageProof.ownership);

      // Verify data integrity
      const calculatedIntegrity = this.calculateIntegrity(verifiableData);
      const integrityMatches = calculatedIntegrity === metadata.integrity;

      return existenceValid && integrityValid && ownershipValid && integrityMatches;

    } catch (error) {
      console.error(`Verification failed for blob ${blobId}:`, error);
      return false;
    }
  }

  /**
   * Get storage metadata
   */
  getMetadata(blobId: string): StorageMetadata | null {
    return this.storageIndex.get(blobId) || null;
  }

  /**
   * List all stored blobs for a user
   */
  listBlobs(owner: string): StorageMetadata[] {
    return Array.from(this.storageIndex.values())
      .filter(metadata => metadata.owner === owner || metadata.permissions.includes(owner));
  }

  // Private helper methods

  private generateBlobId(): string {
    return createHash('sha256')
      .update(randomBytes(32))
      .digest('hex')
      .substring(0, 16);
  }

  private async createVerifiableData(data: any, owner: string): Promise<VerifiableData> {
    const privateInputs = {
      owner: this.hashString(owner),
      timestamp: Date.now(),
      randomness: randomBytes(32).toString('hex')
    };

    return this.zkProofSystem.createVerifiableData(data, 'commitment', privateInputs);
  }

  private async generateStorageProof(
    verifiableData: VerifiableData,
    owner: string,
    permissions: string[]
  ): Promise<StorageProof> {
    // Existence proof
    const existenceProof = await this.zkProofSystem.generateProof(
      'membership',
      {
        data: this.hashString(JSON.stringify(verifiableData.data)),
        owner: this.hashString(owner)
      },
      [this.hashString(owner)]
    );

    // Integrity proof
    const integrityProof = await this.zkProofSystem.generateProof(
      'commitment',
      {
        data: JSON.stringify(verifiableData.data),
        integrity: this.calculateIntegrity(verifiableData)
      },
      [this.calculateIntegrity(verifiableData)]
    );

    // Ownership proof
    const ownershipProof = await this.zkProofSystem.generateProof(
      'identity',
      {
        owner: this.hashString(owner),
        permissions: permissions.map(p => this.hashString(p))
      },
      [this.hashString(owner)]
    );

    return {
      existence: existenceProof,
      integrity: integrityProof,
      ownership: ownershipProof,
      timestamp: Date.now()
    };
  }

  private async verifyStorageProofs(blobId: string, verifiableData: VerifiableData): Promise<void> {
    const storageProof = this.proofCache.get(blobId);
    if (!storageProof) {
      throw new SecurityError('Storage proof not found', 'PROOF_NOT_FOUND', 'HIGH');
    }

    const verificationResults = await Promise.all([
      this.zkProofSystem.verifyProof(storageProof.existence),
      this.zkProofSystem.verifyProof(storageProof.integrity),
      this.zkProofSystem.verifyProof(storageProof.ownership)
    ]);

    if (!verificationResults.every(result => result)) {
      throw new SecurityError('Storage proof verification failed', 'PROOF_VERIFICATION_FAILED', 'CRITICAL');
    }

    // Verify verifiable data
    const isVerifiableValid = await this.zkProofSystem.verifyVerifiableData(verifiableData);
    if (!isVerifiableValid) {
      throw new SecurityError('Verifiable data verification failed', 'DATA_VERIFICATION_FAILED', 'CRITICAL');
    }
  }

  private async generateDeletionProof(blobId: string, requester: string): Promise<ZKProof> {
    return this.zkProofSystem.generateProof(
      'identity',
      {
        blobId: this.hashString(blobId),
        requester: this.hashString(requester),
        action: this.hashString('DELETE'),
        timestamp: Date.now()
      },
      [this.hashString(requester)]
    );
  }

  private calculateIntegrity(verifiableData: VerifiableData): string {
    const combined = JSON.stringify({
      data: verifiableData.data,
      proof: verifiableData.proof.proof,
      timestamp: verifiableData.timestamp
    });
    return createHash('sha256').update(combined).digest('hex');
  }

  private checkPermissions(metadata: StorageMetadata, requester: string): boolean {
    return metadata.owner === requester ||
           metadata.permissions.includes(requester) ||
           metadata.permissions.includes('*');
  }

  private checkUpdatePermissions(metadata: StorageMetadata, updater: string): boolean {
    return metadata.owner === updater || metadata.permissions.includes('write:' + updater);
  }

  private checkDeletePermissions(metadata: StorageMetadata, requester: string): boolean {
    return metadata.owner === requester || metadata.permissions.includes('delete:' + requester);
  }

  private isEncrypted(data: any): boolean {
    return data && typeof data === 'object' && 'ciphertext' in data && 'algorithm' in data;
  }

  private wasEncrypted(metadata: StorageMetadata): boolean {
    return metadata.permissions.includes('encrypted');
  }

  private hashString(input: string): string {
    return createHash('sha256').update(input).digest('hex');
  }

  // Walrus integration methods (simulated)

  private async storeInWalrus(blobId: string, data: any): Promise<void> {
    // Simulate Walrus storage
    console.log(`Storing data in Walrus with blob ID: ${blobId}`);
    // In production: await walrusClient.store(blobId, data);
  }

  private async retrieveFromWalrus(blobId: string): Promise<VerifiableData> {
    // Simulate Walrus retrieval
    console.log(`Retrieving data from Walrus with blob ID: ${blobId}`);
    // In production: return await walrusClient.retrieve(blobId);

    // Mock verifiable data for demonstration
    return {
      data: { mock: 'data' },
      proof: {
        proof: 'mock_proof',
        publicSignals: ['signal1', 'signal2'],
        verificationKey: 'mock_verification_key',
        circuit: 'commitment'
      },
      timestamp: Date.now(),
      signature: 'mock_signature'
    };
  }

  private async deleteFromWalrus(blobId: string): Promise<void> {
    // Simulate Walrus deletion
    console.log(`Deleting data from Walrus with blob ID: ${blobId}`);
    // In production: await walrusClient.delete(blobId);
  }
}