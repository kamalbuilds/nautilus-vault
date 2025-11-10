/**
 * Type definitions for Walrus Security Suite
 */

// Core Security Types
export interface SecurityConfig {
  encryptionAlgorithm: 'AES-256-GCM' | 'ChaCha20-Poly1305';
  keyDerivation: 'PBKDF2' | 'Argon2';
  zkProofSystem: 'Groth16' | 'PLONK' | 'STARK';
  fraudDetectionThreshold: number;
  privacyLevel: 'MINIMAL' | 'STANDARD' | 'MAXIMUM';
}

export interface PrivacySettings {
  dataMinimization: boolean;
  anonymization: boolean;
  consentRequired: boolean;
  auditLogging: boolean;
  dataRetentionDays: number;
}

export interface ZKProof {
  proof: string;
  publicSignals: string[];
  verificationKey: string;
  circuit: string;
}

export interface VerifiableData {
  data: any;
  proof: ZKProof;
  timestamp: number;
  signature: string;
}

// Walrus Integration Types
export interface WalrusStorageConfig {
  endpoint: string;
  apiKey: string;
  blobId?: string;
  encryption: boolean;
}

export interface SealComputationConfig {
  computationId: string;
  inputs: any[];
  privacy: boolean;
  verification: boolean;
}

export interface NautilusFlowConfig {
  flowId: string;
  nodes: FlowNode[];
  privacy: boolean;
  audit: boolean;
}

export interface FlowNode {
  id: string;
  type: 'input' | 'processing' | 'output' | 'verification';
  data: any;
  privacy: boolean;
}

// Fraud Detection Types
export interface FraudIndicator {
  type: 'ANOMALY' | 'PATTERN' | 'THRESHOLD' | 'ML_PREDICTION';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number;
  description: string;
  metadata: any;
}

export interface MLModel {
  id: string;
  type: 'CLASSIFICATION' | 'REGRESSION' | 'CLUSTERING' | 'ANOMALY_DETECTION';
  version: string;
  accuracy: number;
  lastTrained: Date;
}

// Privacy Types
export interface ConsentRecord {
  userId: string;
  purpose: string;
  granted: boolean;
  timestamp: Date;
  expiresAt?: Date;
  metadata: any;
}

export interface DataSubject {
  id: string;
  pseudonym: string;
  consents: ConsentRecord[];
  preferences: PrivacyPreferences;
}

export interface PrivacyPreferences {
  shareData: boolean;
  allowProfiling: boolean;
  marketingConsent: boolean;
  dataRetention: number;
  anonymization: boolean;
}

// Security Infrastructure Types
export interface AccessToken {
  token: string;
  type: 'BEARER' | 'API_KEY' | 'JWT';
  permissions: string[];
  expiresAt: Date;
  userId: string;
}

export interface SecurityEvent {
  id: string;
  type: 'LOGIN' | 'ACCESS' | 'MODIFICATION' | 'THREAT' | 'INCIDENT';
  severity: 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL';
  timestamp: Date;
  userId?: string;
  details: any;
}

export interface ThreatIndicator {
  type: 'IP_REPUTATION' | 'PATTERN_MATCH' | 'BEHAVIORAL' | 'SIGNATURE';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number;
  source: string;
  details: any;
}

// Encryption Types
export interface EncryptionKey {
  id: string;
  algorithm: string;
  key: string;
  createdAt: Date;
  expiresAt?: Date;
  usage: 'ENCRYPTION' | 'SIGNING' | 'VERIFICATION';
}

export interface EncryptedData {
  ciphertext: string;
  algorithm: string;
  keyId: string;
  iv: string;
  tag?: string;
  metadata: any;
}

// Sui Move Contract Types
export interface MoveTransaction {
  digest: string;
  sender: string;
  gasUsed: number;
  status: 'SUCCESS' | 'FAILURE';
  timestamp: Date;
}

export interface DataGovernancePolicy {
  id: string;
  owner: string;
  rules: GovernanceRule[];
  active: boolean;
  createdAt: Date;
}

export interface GovernanceRule {
  type: 'ACCESS' | 'RETENTION' | 'SHARING' | 'DELETION';
  condition: string;
  action: string;
  metadata: any;
}

// Audit and Compliance Types
export interface AuditLog {
  id: string;
  action: string;
  actor: string;
  resource: string;
  timestamp: Date;
  outcome: 'SUCCESS' | 'FAILURE';
  details: any;
}

export interface ComplianceReport {
  framework: 'GDPR' | 'CCPA' | 'HIPAA' | 'SOX';
  status: 'COMPLIANT' | 'NON_COMPLIANT' | 'PARTIAL';
  issues: ComplianceIssue[];
  generatedAt: Date;
}

export interface ComplianceIssue {
  rule: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  recommendation: string;
}

// Error Types
export class SecurityError extends Error {
  constructor(
    message: string,
    public code: string,
    public severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'MEDIUM'
  ) {
    super(message);
    this.name = 'SecurityError';
  }
}

export class PrivacyError extends Error {
  constructor(
    message: string,
    public code: string,
    public complianceFramework?: string
  ) {
    super(message);
    this.name = 'PrivacyError';
  }
}

export class VerificationError extends Error {
  constructor(
    message: string,
    public proofId?: string,
    public expected?: any,
    public actual?: any
  ) {
    super(message);
    this.name = 'VerificationError';
  }
}