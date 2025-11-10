/**
 * Seal Privacy-Preserving Computation Integration
 * Secure multiparty computation and privacy-preserving analytics
 */

import { SealComputationConfig, SecurityError, ZKProof } from '../types';
import { ZKProofSystem } from '../privacy/zk-proof-system';
import { EncryptionManager } from '../security/encryption-manager';
import { createHash, randomBytes } from 'crypto';

export interface SealComputation {
  id: string;
  type: 'AGGREGATION' | 'STATISTICAL' | 'ML_TRAINING' | 'QUERY' | 'COMPARISON';
  participants: string[];
  inputs: SealInput[];
  outputs: SealOutput[];
  privacy: SealPrivacyConfig;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  createdAt: Date;
  completedAt?: Date;
}

export interface SealInput {
  participantId: string;
  dataId: string;
  schema: any;
  encrypted: boolean;
  verified: boolean;
}

export interface SealOutput {
  resultId: string;
  type: string;
  value: any;
  privacy: SealPrivacyMetrics;
  proof?: ZKProof;
}

export interface SealPrivacyConfig {
  differential: boolean;
  epsilon?: number;
  homomorphic: boolean;
  multiparty: boolean;
  zkProofs: boolean;
  participants: number;
}

export interface SealPrivacyMetrics {
  privacyBudget: number;
  confidenceLevel: number;
  noiseLevel: number;
  utilityPreserved: number;
}

export interface MultipartySession {
  sessionId: string;
  participants: Participant[];
  computation: SealComputation;
  protocol: 'GMW' | 'BGW' | 'SPDZ' | 'ABY';
  status: 'SETUP' | 'EXECUTION' | 'VERIFICATION' | 'COMPLETE';
  rounds: number;
  currentRound: number;
}

export interface Participant {
  id: string;
  publicKey: string;
  shares: any[];
  verified: boolean;
  online: boolean;
}

export class SealIntegration {
  private zkProofSystem: ZKProofSystem;
  private encryptionManager: EncryptionManager;
  private computations: Map<string, SealComputation> = new Map();
  private sessions: Map<string, MultipartySession> = new Map();
  private privacyBudgets: Map<string, number> = new Map();
  private circuits: Map<string, any> = new Map();

  constructor(
    zkProofSystem: ZKProofSystem,
    encryptionManager: EncryptionManager
  ) {
    this.zkProofSystem = zkProofSystem;
    this.encryptionManager = encryptionManager;
    this.initializeCircuits();
  }

  /**
   * Create a new privacy-preserving computation
   */
  async createComputation(
    config: SealComputationConfig,
    participants: string[],
    privacy: SealPrivacyConfig
  ): Promise<string> {
    try {
      const computationId = this.generateComputationId();

      const computation: SealComputation = {
        id: computationId,
        type: this.inferComputationType(config),
        participants,
        inputs: [],
        outputs: [],
        privacy,
        status: 'PENDING',
        createdAt: new Date()
      };

      // Initialize privacy budgets for participants
      participants.forEach(participant => {
        if (!this.privacyBudgets.has(participant)) {
          this.privacyBudgets.set(participant, 1.0); // Initial budget
        }
      });

      // Create multiparty session if needed
      if (privacy.multiparty) {
        await this.createMultipartySession(computation);
      }

      this.computations.set(computationId, computation);

      console.log(`Seal computation created: ${computationId}`);
      return computationId;

    } catch (error) {
      throw new SecurityError(`Failed to create Seal computation: ${error.message}`, 'SEAL_CREATE_ERROR', 'HIGH');
    }
  }

  /**
   * Add encrypted input to computation
   */
  async addInput(
    computationId: string,
    participantId: string,
    data: any,
    schema: any
  ): Promise<void> {
    try {
      const computation = this.computations.get(computationId);
      if (!computation) {
        throw new SecurityError('Computation not found', 'COMPUTATION_NOT_FOUND', 'MEDIUM');
      }

      // Validate participant
      if (!computation.participants.includes(participantId)) {
        throw new SecurityError('Participant not authorized', 'PARTICIPANT_NOT_AUTHORIZED', 'HIGH');
      }

      // Encrypt data based on privacy configuration
      const encryptedData = await this.encryptInput(data, computation.privacy);

      // Verify data against schema
      const verified = await this.verifyInputSchema(encryptedData, schema);

      const input: SealInput = {
        participantId,
        dataId: this.generateDataId(),
        schema,
        encrypted: true,
        verified
      };

      computation.inputs.push(input);
      this.computations.set(computationId, computation);

      console.log(`Input added to computation ${computationId} by participant ${participantId}`);

    } catch (error) {
      throw new SecurityError(`Failed to add input: ${error.message}`, 'SEAL_INPUT_ERROR', 'HIGH');
    }
  }

  /**
   * Execute privacy-preserving computation
   */
  async executeComputation(computationId: string): Promise<SealOutput[]> {
    try {
      const computation = this.computations.get(computationId);
      if (!computation) {
        throw new SecurityError('Computation not found', 'COMPUTATION_NOT_FOUND', 'MEDIUM');
      }

      if (computation.inputs.length === 0) {
        throw new SecurityError('No inputs provided for computation', 'NO_INPUTS', 'MEDIUM');
      }

      computation.status = 'RUNNING';
      this.computations.set(computationId, computation);

      let outputs: SealOutput[] = [];

      // Execute based on computation type and privacy settings
      if (computation.privacy.multiparty) {
        outputs = await this.executeMultipartyComputation(computation);
      } else if (computation.privacy.homomorphic) {
        outputs = await this.executeHomomorphicComputation(computation);
      } else if (computation.privacy.differential) {
        outputs = await this.executeDifferentialPrivateComputation(computation);
      } else {
        outputs = await this.executeBasicComputation(computation);
      }

      // Generate ZK proofs if required
      if (computation.privacy.zkProofs) {
        for (let output of outputs) {
          output.proof = await this.generateComputationProof(computation, output);
        }
      }

      computation.outputs = outputs;
      computation.status = 'COMPLETED';
      computation.completedAt = new Date();
      this.computations.set(computationId, computation);

      console.log(`Computation ${computationId} completed successfully`);
      return outputs;

    } catch (error) {
      const computation = this.computations.get(computationId);
      if (computation) {
        computation.status = 'FAILED';
        this.computations.set(computationId, computation);
      }
      throw new SecurityError(`Computation execution failed: ${error.message}`, 'SEAL_EXECUTION_ERROR', 'HIGH');
    }
  }

  /**
   * Verify computation results
   */
  async verifyComputation(computationId: string): Promise<boolean> {
    try {
      const computation = this.computations.get(computationId);
      if (!computation) return false;

      if (computation.status !== 'COMPLETED') return false;

      // Verify each output
      for (const output of computation.outputs) {
        // Verify ZK proof if present
        if (output.proof) {
          const isProofValid = await this.zkProofSystem.verifyProof(output.proof);
          if (!isProofValid) return false;
        }

        // Verify privacy metrics
        if (!this.verifyPrivacyMetrics(output.privacy, computation.privacy)) {
          return false;
        }
      }

      // Verify multiparty session if applicable
      if (computation.privacy.multiparty) {
        const session = Array.from(this.sessions.values())
          .find(s => s.computation.id === computationId);
        if (session && !await this.verifyMultipartySession(session)) {
          return false;
        }
      }

      return true;

    } catch (error) {
      console.error(`Computation verification failed: ${error.message}`);
      return false;
    }
  }

  /**
   * Get computation status and results
   */
  getComputationStatus(computationId: string): SealComputation | null {
    return this.computations.get(computationId) || null;
  }

  /**
   * List computations for a participant
   */
  getParticipantComputations(participantId: string): SealComputation[] {
    return Array.from(this.computations.values())
      .filter(comp => comp.participants.includes(participantId));
  }

  /**
   * Get privacy budget remaining for participant
   */
  getPrivacyBudget(participantId: string): number {
    return this.privacyBudgets.get(participantId) || 0;
  }

  /**
   * Aggregate data with differential privacy
   */
  async aggregateWithDP(
    data: number[],
    epsilon: number,
    aggregationType: 'SUM' | 'MEAN' | 'COUNT' | 'MAX' | 'MIN'
  ): Promise<{ result: number; noise: number; privacy: SealPrivacyMetrics }> {
    try {
      let trueResult: number;

      switch (aggregationType) {
        case 'SUM':
          trueResult = data.reduce((sum, val) => sum + val, 0);
          break;
        case 'MEAN':
          trueResult = data.reduce((sum, val) => sum + val, 0) / data.length;
          break;
        case 'COUNT':
          trueResult = data.length;
          break;
        case 'MAX':
          trueResult = Math.max(...data);
          break;
        case 'MIN':
          trueResult = Math.min(...data);
          break;
        default:
          throw new SecurityError('Unsupported aggregation type', 'UNSUPPORTED_AGGREGATION', 'MEDIUM');
      }

      // Add calibrated noise
      const sensitivity = this.calculateSensitivity(aggregationType, data);
      const noise = this.laplacianNoise(0, sensitivity / epsilon);
      const noisyResult = trueResult + noise;

      const privacyMetrics: SealPrivacyMetrics = {
        privacyBudget: epsilon,
        confidenceLevel: 0.95,
        noiseLevel: Math.abs(noise),
        utilityPreserved: this.calculateUtilityPreservation(trueResult, noisyResult)
      };

      return {
        result: noisyResult,
        noise,
        privacy: privacyMetrics
      };

    } catch (error) {
      throw new SecurityError(`DP aggregation failed: ${error.message}`, 'DP_AGGREGATION_ERROR', 'HIGH');
    }
  }

  // Private helper methods

  private initializeCircuits(): void {
    // Initialize computation circuits for different operations
    this.circuits.set('addition', { type: 'arithmetic', gates: [] });
    this.circuits.set('multiplication', { type: 'arithmetic', gates: [] });
    this.circuits.set('comparison', { type: 'boolean', gates: [] });
    this.circuits.set('aggregation', { type: 'hybrid', gates: [] });
  }

  private generateComputationId(): string {
    return `seal_${Date.now()}_${randomBytes(8).toString('hex')}`;
  }

  private generateDataId(): string {
    return `data_${Date.now()}_${randomBytes(4).toString('hex')}`;
  }

  private inferComputationType(config: SealComputationConfig): SealComputation['type'] {
    // Simple inference based on config
    if (config.computationId.includes('aggregate')) return 'AGGREGATION';
    if (config.computationId.includes('stat')) return 'STATISTICAL';
    if (config.computationId.includes('ml')) return 'ML_TRAINING';
    if (config.computationId.includes('query')) return 'QUERY';
    if (config.computationId.includes('compare')) return 'COMPARISON';
    return 'QUERY';
  }

  private async createMultipartySession(computation: SealComputation): Promise<void> {
    const sessionId = `mpc_${computation.id}`;

    const participants: Participant[] = computation.participants.map(id => ({
      id,
      publicKey: this.generatePublicKey(id),
      shares: [],
      verified: false,
      online: true
    }));

    const session: MultipartySession = {
      sessionId,
      participants,
      computation,
      protocol: this.selectMPCProtocol(computation.privacy),
      status: 'SETUP',
      rounds: this.calculateRounds(computation),
      currentRound: 0
    };

    this.sessions.set(sessionId, session);
  }

  private async encryptInput(data: any, privacy: SealPrivacyConfig): Promise<any> {
    if (privacy.homomorphic) {
      return this.homomorphicEncrypt(data);
    } else if (privacy.multiparty) {
      return this.secretShare(data, privacy.participants);
    }
    return data;
  }

  private async verifyInputSchema(data: any, schema: any): Promise<boolean> {
    // Simplified schema verification
    try {
      return typeof data === schema.type;
    } catch {
      return false;
    }
  }

  private async executeMultipartyComputation(computation: SealComputation): Promise<SealOutput[]> {
    const sessionId = `mpc_${computation.id}`;
    const session = this.sessions.get(sessionId);

    if (!session) {
      throw new SecurityError('Multiparty session not found', 'SESSION_NOT_FOUND', 'HIGH');
    }

    // Execute MPC protocol
    session.status = 'EXECUTION';

    for (let round = 0; round < session.rounds; round++) {
      session.currentRound = round;
      await this.executeMPCRound(session, round);
    }

    session.status = 'VERIFICATION';
    const verified = await this.verifyMultipartySession(session);

    if (!verified) {
      throw new SecurityError('Multiparty computation verification failed', 'MPC_VERIFICATION_FAILED', 'CRITICAL');
    }

    session.status = 'COMPLETE';

    // Generate outputs
    return [{
      resultId: this.generateDataId(),
      type: 'MPC_RESULT',
      value: this.reconstructResult(session),
      privacy: {
        privacyBudget: 0, // MPC doesn't consume privacy budget
        confidenceLevel: 1.0,
        noiseLevel: 0,
        utilityPreserved: 1.0
      }
    }];
  }

  private async executeHomomorphicComputation(computation: SealComputation): Promise<SealOutput[]> {
    // Execute computation on encrypted data
    const encryptedInputs = computation.inputs.map(input => input.dataId);

    // Perform homomorphic operations
    const result = await this.performHomomorphicOperations(encryptedInputs, computation.type);

    return [{
      resultId: this.generateDataId(),
      type: 'HOMOMORPHIC_RESULT',
      value: result,
      privacy: {
        privacyBudget: 0,
        confidenceLevel: 1.0,
        noiseLevel: 0,
        utilityPreserved: 1.0
      }
    }];
  }

  private async executeDifferentialPrivateComputation(computation: SealComputation): Promise<SealOutput[]> {
    const epsilon = computation.privacy.epsilon || 0.1;

    // Extract data from inputs
    const data = computation.inputs.map(input => this.extractData(input));

    // Apply differential privacy
    const dpResult = await this.aggregateWithDP(data, epsilon, 'SUM');

    // Update privacy budgets
    computation.participants.forEach(participant => {
      const currentBudget = this.privacyBudgets.get(participant) || 0;
      this.privacyBudgets.set(participant, currentBudget - epsilon / computation.participants.length);
    });

    return [{
      resultId: this.generateDataId(),
      type: 'DP_RESULT',
      value: dpResult.result,
      privacy: dpResult.privacy
    }];
  }

  private async executeBasicComputation(computation: SealComputation): Promise<SealOutput[]> {
    // Execute basic computation without privacy preservation
    const data = computation.inputs.map(input => this.extractData(input));
    const result = this.performBasicAggregation(data, computation.type);

    return [{
      resultId: this.generateDataId(),
      type: 'BASIC_RESULT',
      value: result,
      privacy: {
        privacyBudget: 1.0, // Full budget consumed for non-private computation
        confidenceLevel: 1.0,
        noiseLevel: 0,
        utilityPreserved: 1.0
      }
    }];
  }

  private async generateComputationProof(
    computation: SealComputation,
    output: SealOutput
  ): Promise<ZKProof> {
    return this.zkProofSystem.generateProof(
      'computation',
      {
        computationId: this.hashString(computation.id),
        inputs: computation.inputs.map(i => this.hashString(i.dataId)),
        output: this.hashString(JSON.stringify(output.value)),
        privacy: this.hashString(JSON.stringify(computation.privacy))
      },
      [this.hashString(computation.id)]
    );
  }

  private verifyPrivacyMetrics(metrics: SealPrivacyMetrics, config: SealPrivacyConfig): boolean {
    // Verify privacy metrics meet requirements
    if (config.epsilon && metrics.privacyBudget > config.epsilon) {
      return false;
    }

    return metrics.confidenceLevel > 0 && metrics.utilityPreserved > 0;
  }

  private async verifyMultipartySession(session: MultipartySession): Promise<boolean> {
    // Verify all participants completed their shares
    const allVerified = session.participants.every(p => p.verified);

    // Verify protocol execution
    const protocolValid = session.status === 'COMPLETE' && session.currentRound === session.rounds;

    return allVerified && protocolValid;
  }

  private calculateSensitivity(aggregationType: string, data: number[]): number {
    switch (aggregationType) {
      case 'SUM':
      case 'MEAN':
        return Math.max(...data) - Math.min(...data);
      case 'COUNT':
        return 1;
      case 'MAX':
      case 'MIN':
        return Math.max(...data) - Math.min(...data);
      default:
        return 1;
    }
  }

  private laplacianNoise(mean: number, scale: number): number {
    const u = Math.random() - 0.5;
    return mean - scale * Math.sign(u) * Math.log(1 - 2 * Math.abs(u));
  }

  private calculateUtilityPreservation(trueValue: number, noisyValue: number): number {
    if (trueValue === 0) return noisyValue === 0 ? 1.0 : 0.0;
    return Math.max(0, 1 - Math.abs(noisyValue - trueValue) / Math.abs(trueValue));
  }

  private generatePublicKey(participantId: string): string {
    return createHash('sha256').update(participantId + 'public').digest('hex');
  }

  private selectMPCProtocol(privacy: SealPrivacyConfig): MultipartySession['protocol'] {
    if (privacy.participants <= 3) return 'GMW';
    if (privacy.participants <= 10) return 'BGW';
    return 'SPDZ';
  }

  private calculateRounds(computation: SealComputation): number {
    // Simplified round calculation
    return Math.max(3, computation.inputs.length);
  }

  private async executeMPCRound(session: MultipartySession, round: number): Promise<void> {
    // Simulate MPC round execution
    console.log(`Executing MPC round ${round} for session ${session.sessionId}`);

    // In production: implement actual MPC protocol rounds
    session.participants.forEach(participant => {
      participant.shares.push(`round_${round}_share`);
    });
  }

  private reconstructResult(session: MultipartySession): any {
    // Reconstruct result from participant shares
    return { result: 'mpc_computed_value', participants: session.participants.length };
  }

  private homomorphicEncrypt(data: any): any {
    return { encrypted: true, data: createHash('sha256').update(JSON.stringify(data)).digest('hex') };
  }

  private secretShare(data: any, participants: number): any {
    // Simplified secret sharing
    const shares = [];
    for (let i = 0; i < participants; i++) {
      shares.push(createHash('sha256').update(`${data}_${i}`).digest('hex'));
    }
    return { shares };
  }

  private async performHomomorphicOperations(inputs: string[], type: SealComputation['type']): any {
    // Simulate homomorphic operations
    return { homomorphic_result: `${type}_computed`, inputs: inputs.length };
  }

  private extractData(input: SealInput): number {
    // Simplified data extraction
    return Math.random() * 100;
  }

  private performBasicAggregation(data: number[], type: SealComputation['type']): any {
    switch (type) {
      case 'AGGREGATION':
        return data.reduce((sum, val) => sum + val, 0);
      case 'STATISTICAL':
        return {
          mean: data.reduce((sum, val) => sum + val, 0) / data.length,
          count: data.length
        };
      default:
        return data[0];
    }
  }

  private hashString(input: string): string {
    return createHash('sha256').update(input).digest('hex');
  }
}