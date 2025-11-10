/**
 * Security Manager - Central security orchestration and management
 */

import { EncryptionManager } from './encryption-manager';
import { FraudDetector } from './fraud-detector';
import { MLSecurityAnalyzer } from './ml-security-analyzer';
import { SecurityError } from '../types';

export interface SecurityConfig {
  encryptionLevel: 'STANDARD' | 'HIGH' | 'QUANTUM_RESISTANT';
  fraudDetectionEnabled: boolean;
  mlAnalysisEnabled: boolean;
  auditLogging: boolean;
  rateLimit: number;
}

export class SecurityManager {
  private encryptionManager: EncryptionManager;
  private fraudDetector: FraudDetector;
  private mlAnalyzer: MLSecurityAnalyzer;
  private config: SecurityConfig;

  constructor(config: SecurityConfig) {
    this.config = config;
    this.encryptionManager = new EncryptionManager();
    this.fraudDetector = new FraudDetector();
    this.mlAnalyzer = new MLSecurityAnalyzer();
  }

  async initialize(): Promise<void> {
    try {
      await this.encryptionManager.initialize();
      if (this.config.fraudDetectionEnabled) {
        await this.fraudDetector.initialize();
      }
      if (this.config.mlAnalysisEnabled) {
        await this.mlAnalyzer.initialize();
      }
    } catch (error) {
      throw new SecurityError(`Failed to initialize security manager: ${(error as Error).message}`, 'INITIALIZATION_ERROR');
    }
  }

  async secureOperation<T>(operation: () => Promise<T>, context: any): Promise<T> {
    try {
      // Pre-operation security checks
      if (this.config.fraudDetectionEnabled) {
        const fraudCheck = await this.fraudDetector.analyzeBehavior(context);
        if (fraudCheck.riskScore > 0.8) {
          throw new SecurityError('High fraud risk detected', 'FRAUD_RISK');
        }
      }

      // Execute operation with security monitoring
      const result = await operation();

      // Post-operation analysis
      if (this.config.mlAnalysisEnabled) {
        await this.mlAnalyzer.analyzeUserBehavior(context);
      }

      return result;
    } catch (error) {
      throw new SecurityError(`Secure operation failed: ${(error as Error).message}`, 'OPERATION_ERROR');
    }
  }

  getSecurityMetrics() {
    return {
      encryptionStatus: this.encryptionManager.getStatus(),
      fraudDetectionMetrics: this.fraudDetector.getMetrics(),
      mlAnalysisMetrics: this.mlAnalyzer.getPerformanceMetrics(),
      config: this.config
    };
  }
}