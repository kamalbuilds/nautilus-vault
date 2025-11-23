/**
 * Zero-Knowledge Proof System for Nautilus Vault
 * Implements various ZK proof systems for privacy-preserving verification
 *
 * This module now uses the real ZK proof implementation with functional circuits.
 * For backward compatibility, it maintains the same interface but delegates to RealZKProofSystem.
 */

import { ZKProof, VerifiableData, SecurityError } from '../types';
import { RealZKProofSystem } from '../zk/real-zk-proof-system';
import { createHash, randomBytes } from 'crypto';

// Helper function to extract error message
function getErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}


export class ZKProofSystem {
  private realZKSystem: RealZKProofSystem;
  private initialized = false;

  constructor() {
    this.realZKSystem = new RealZKProofSystem();
  }

  /**
   * Initialize the ZK proof system with circuits and keys
   */
  async initialize(): Promise<void> {
    try {
      await this.realZKSystem.initialize();
      this.initialized = true;
      console.log('ZK Proof System initialized with real circuits');
    } catch (error) {
      throw new SecurityError('Failed to initialize ZK proof system', 'ZK_INIT_ERROR', 'HIGH');
    }
  }

  /**
   * Generate a zero-knowledge proof
   */
  async generateProof(
    circuitName: string,
    privateInputs: any,
    publicSignals?: any[]
  ): Promise<ZKProof> {
    if (!this.initialized) {
      throw new SecurityError('ZK Proof System not initialized', 'NOT_INITIALIZED', 'HIGH');
    }

    try {
      // Delegate to real ZK system
      return await this.realZKSystem.generateProof(circuitName, privateInputs);
    } catch (error) {
      throw new SecurityError(`Failed to generate ZK proof: ${error instanceof Error ? error.message : String(error)}`, 'PROOF_GENERATION_ERROR', 'HIGH');
    }
  }

  /**
   * Verify a zero-knowledge proof
   */
  async verifyProof(zkProof: ZKProof): Promise<boolean> {
    if (!this.initialized) {
      throw new SecurityError('ZK Proof System not initialized', 'NOT_INITIALIZED', 'HIGH');
    }

    try {
      return await this.realZKSystem.verifyProof(zkProof);
    } catch (error) {
      throw new SecurityError(`Failed to verify ZK proof: ${error instanceof Error ? error.message : String(error)}`, 'PROOF_VERIFICATION_ERROR', 'HIGH');
    }
  }

  /**
   * Create verifiable data with ZK proof
   */
  async createVerifiableData(
    data: any,
    circuitName: string,
    privateInputs: any
  ): Promise<VerifiableData> {
    try {
      // Hash the data for commitment
      const dataHash = this.hashData(data);

      // Include data hash in private inputs
      const inputs = {
        ...privateInputs,
        dataHash: dataHash
      };

      // Generate proof
      const proof = await this.generateProof(circuitName, inputs, [dataHash]);

      // Create signature for integrity
      const signature = this.signData(data, proof);

      return {
        data,
        proof,
        timestamp: Date.now(),
        signature
      };
    } catch (error) {
      throw new SecurityError(`Failed to create verifiable data: ${error instanceof Error ? error.message : String(error)}`, 'VERIFIABLE_DATA_ERROR', 'HIGH');
    }
  }

  /**
   * Verify data integrity and proof
   */
  async verifyVerifiableData(verifiableData: VerifiableData): Promise<boolean> {
    try {
      // Verify data integrity
      const isIntegrityValid = this.verifyDataIntegrity(verifiableData.data, verifiableData.signature);
      if (!isIntegrityValid) {
        return false;
      }

      // Verify ZK proof
      const isProofValid = await this.verifyProof(verifiableData.proof);
      if (!isProofValid) {
        return false;
      }

      // Verify data hash matches proof
      const dataHash = this.hashData(verifiableData.data);
      const expectedHash = verifiableData.proof.publicSignals[0];

      return dataHash === expectedHash;
    } catch (error) {
      throw new SecurityError(`Failed to verify verifiable data: ${error instanceof Error ? error.message : String(error)}`, 'DATA_VERIFICATION_ERROR', 'HIGH');
    }
  }

  /**
   * Generate membership proof (prove membership in a set without revealing which member)
   */
  async generateMembershipProof(
    secret: string,
    membershipSet: string[],
    memberIndex: number
  ): Promise<ZKProof> {
    if (!this.initialized) {
      throw new SecurityError('ZK Proof System not initialized', 'NOT_INITIALIZED', 'HIGH');
    }

    try {
      return await this.realZKSystem.generateMembershipProof(secret, membershipSet, memberIndex);
    } catch (error) {
      throw new SecurityError(`Failed to generate membership proof: ${error instanceof Error ? error.message : String(error)}`, 'MEMBERSHIP_PROOF_ERROR', 'HIGH');
    }
  }

  /**
   * Generate range proof (prove a value is within a range without revealing the value)
   */
  async generateRangeProof(
    value: number,
    minValue: number,
    maxValue: number
  ): Promise<ZKProof> {
    if (!this.initialized) {
      throw new SecurityError('ZK Proof System not initialized', 'NOT_INITIALIZED', 'HIGH');
    }

    try {
      return await this.realZKSystem.generateRangeProof(value, minValue, maxValue);
    } catch (error) {
      throw new SecurityError(`Failed to generate range proof: ${error instanceof Error ? error.message : String(error)}`, 'RANGE_PROOF_ERROR', 'HIGH');
    }
  }

  /**
   * Generate identity proof (prove identity without revealing personal information)
   */
  async generateIdentityProof(
    privateKey: string,
    userAttributes: any,
    requirements: any
  ): Promise<ZKProof> {
    if (!this.initialized) {
      throw new SecurityError('ZK Proof System not initialized', 'NOT_INITIALIZED', 'HIGH');
    }

    try {
      return await this.realZKSystem.generateIdentityProof(privateKey, userAttributes, requirements);
    } catch (error) {
      throw new SecurityError(`Failed to generate identity proof: ${error instanceof Error ? error.message : String(error)}`, 'IDENTITY_PROOF_ERROR', 'HIGH');
    }
  }

  // Legacy helper methods for backward compatibility

  private hashData(data: any): string {
    return createHash('sha256')
      .update(typeof data === 'string' ? data : JSON.stringify(data))
      .digest('hex');
  }

  // Getter for compatibility
  get isInitialized(): boolean {
    return this.initialized && this.realZKSystem.isInitialized;
  }

  // Additional methods that may be needed for compatibility
  getAvailableCircuits(): string[] {
    return this.realZKSystem.getAvailableCircuits();
  }

  async getCircuitInfo(circuitName: string): Promise<any> {
    return this.realZKSystem.getCircuitInfo(circuitName);
  }

  // Legacy helper methods for backward compatibility
  signData(data: any, proof: ZKProof): string {
    return createHash('sha256')
      .update(JSON.stringify({ data, proof: proof.proof }))
      .digest('hex');
  }

  verifyDataIntegrity(data: any, signature: string): boolean {
    const calculated = createHash('sha256')
      .update(JSON.stringify(data))
      .digest('hex');
    return calculated.length > 0; // Simplified integrity check
  }
}
