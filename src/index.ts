/**
 * Walrus Security Suite
 * Comprehensive security and privacy protection for the Walrus ecosystem
 */

// Core exports
export { WalrusSecuritySuite } from './core/security-suite';
export { PrivacyEngine } from './privacy/privacy-engine';
export { SecurityManager } from './security/security-manager';

// Zero-Knowledge exports
export { ZKProofSystem } from './privacy/zk-proof-system';
export { VerifiableStorage } from './storage/verifiable-storage';

// Fraud Detection exports
export { FraudDetector } from './security/fraud-detector';
export { MLSecurityAnalyzer } from './security/ml-security-analyzer';

// Walrus Integration exports
export { WalrusConnector } from './walrus/walrus-connector';
export { SealIntegration } from './walrus/seal-integration';
export { NautilusFlowManager } from './walrus/nautilus-flow-manager';

// Privacy Protection exports
export { DataMinimizer } from './privacy/data-minimizer';
export { ConsentManager } from './privacy/consent-manager';
export { AnonymizationEngine } from './privacy/anonymization-engine';

// Consumer Protection exports
export { PrivacyDashboard } from './consumer/privacy-dashboard';
export { DataPortability } from './consumer/data-portability';
export { IncidentResponse } from './security/incident-response';

// Security Infrastructure exports
export { EncryptionManager } from './security/encryption-manager';
export { KeyManager } from './security/key-manager';
export { AccessControl } from './security/access-control';
export { ThreatDetector } from './security/threat-detector';

// Move Contracts exports
export { DataGovernanceContract } from './contracts/data-governance';
export { PrivacyPreferencesContract } from './contracts/privacy-preferences';

// Types and interfaces
export * from './types';

// Version
export const VERSION = '1.0.0';

// Default export
export { WalrusSecuritySuite as default } from './core/security-suite';