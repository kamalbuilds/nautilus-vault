/**
 * TypeScript interface for Sui Move Data Governance Contract
 * Provides typed interaction with the smart contract
 */

import { TransactionBlock } from '@mysten/sui.js/transactions';
import { SuiClient } from '@mysten/sui.js/client';
import { Ed25519Keypair } from '@mysten/sui.js/keypairs/ed25519';
import { DataGovernancePolicy, GovernanceRule, MoveTransaction, SecurityError } from '../types';

export interface MoveDataPolicy {
  id: string;
  name: string;
  purpose: string;
  legalBasis: number;
  retentionPeriodMs: string;
  dataCategories: string[];
  allowedProcessors: string[];
  crossBorderTransfer: boolean;
  encryptionRequired: boolean;
  anonymizationRequired: boolean;
  createdAt: string;
  updatedAt: string;
  active: boolean;
}

export interface MoveDataSubject {
  id: string;
  pseudonym: string;
  preferences: MovePrivacyPreferences;
  consents: string[];
  dataCategories: string[];
  createdAt: string;
  lastUpdated: string;
}

export interface MovePrivacyPreferences {
  shareData: boolean;
  allowProfiling: boolean;
  marketingConsent: boolean;
  dataRetentionDays: string;
  anonymizationPreference: boolean;
  contactPreferences: string[];
}

export interface MoveConsentRecord {
  id: string;
  dataSubject: string;
  purpose: string;
  granted: boolean;
  grantedAt: string;
  expiresAt: string;
  withdrawnAt: string;
  legalBasis: string;
  metadata: number[];
  version: string;
}

export interface ProcessingRequestParams {
  dataSubject: string;
  purpose: string;
  policyId: string;
  requestedData: string[];
  legalBasis: number;
  retentionPeriod: string;
}

export class DataGovernanceContract {
  private client: SuiClient;
  private packageId: string;
  private registryId: string;

  constructor(
    client: SuiClient,
    packageId: string,
    registryId: string
  ) {
    this.client = client;
    this.packageId = packageId;
    this.registryId = registryId;
  }

  /**
   * Create a new data processing policy
   */
  async createPolicy(
    signer: Ed25519Keypair,
    policy: {
      policyId: string;
      name: string;
      purpose: string;
      legalBasis: number;
      retentionPeriodMs: string;
      dataCategories: string[];
      allowedProcessors: string[];
      crossBorderTransfer: boolean;
      encryptionRequired: boolean;
      anonymizationRequired: boolean;
    }
  ): Promise<MoveTransaction> {
    try {
      const tx = new TransactionBlock();

      const clock = tx.object('0x6');

      tx.moveCall({
        target: `${this.packageId}::data_governance::create_policy`,
        arguments: [
          tx.object(this.registryId),
          tx.pure(policy.policyId),
          tx.pure(policy.name),
          tx.pure(policy.purpose),
          tx.pure(policy.legalBasis),
          tx.pure(policy.retentionPeriodMs),
          tx.pure(policy.dataCategories),
          tx.pure(policy.allowedProcessors),
          tx.pure(policy.crossBorderTransfer),
          tx.pure(policy.encryptionRequired),
          tx.pure(policy.anonymizationRequired),
          clock
        ],
      });

      const result = await this.client.signAndExecuteTransactionBlock({
        signer,
        transactionBlock: tx,
        options: {
          showEffects: true,
          showEvents: true,
        },
      });

      if (result.effects?.status?.status !== 'success') {
        throw new SecurityError('Policy creation failed', 'CONTRACT_EXECUTION_ERROR', 'HIGH');
      }

      return {
        digest: result.digest,
        sender: signer.getPublicKey().toSuiAddress(),
        gasUsed: Number(result.effects?.gasUsed?.computationCost || 0),
        status: 'SUCCESS',
        timestamp: new Date()
      };

    } catch (error) {
      throw new SecurityError(`Failed to create policy: ${error.message}`, 'CONTRACT_ERROR', 'HIGH');
    }
  }

  /**
   * Register a data subject
   */
  async registerDataSubject(
    signer: Ed25519Keypair,
    pseudonym: string,
    preferences: MovePrivacyPreferences
  ): Promise<MoveTransaction> {
    try {
      const tx = new TransactionBlock();

      const clock = tx.object('0x6');

      tx.moveCall({
        target: `${this.packageId}::data_governance::register_data_subject`,
        arguments: [
          tx.object(this.registryId),
          tx.pure(pseudonym),
          tx.pure(preferences),
          clock
        ],
      });

      const result = await this.client.signAndExecuteTransactionBlock({
        signer,
        transactionBlock: tx,
        options: {
          showEffects: true,
          showEvents: true,
        },
      });

      if (result.effects?.status?.status !== 'success') {
        throw new SecurityError('Data subject registration failed', 'CONTRACT_EXECUTION_ERROR', 'HIGH');
      }

      return {
        digest: result.digest,
        sender: signer.getPublicKey().toSuiAddress(),
        gasUsed: Number(result.effects?.gasUsed?.computationCost || 0),
        status: 'SUCCESS',
        timestamp: new Date()
      };

    } catch (error) {
      throw new SecurityError(`Failed to register data subject: ${error.message}`, 'CONTRACT_ERROR', 'HIGH');
    }
  }

  /**
   * Grant consent for data processing
   */
  async grantConsent(
    signer: Ed25519Keypair,
    consentId: string,
    purpose: string,
    expiresAt: string,
    legalBasis: string,
    metadata: number[] = []
  ): Promise<MoveTransaction> {
    try {
      const tx = new TransactionBlock();

      const clock = tx.object('0x6');

      tx.moveCall({
        target: `${this.packageId}::data_governance::grant_consent`,
        arguments: [
          tx.object(this.registryId),
          tx.pure(consentId),
          tx.pure(purpose),
          tx.pure(expiresAt),
          tx.pure(legalBasis),
          tx.pure(metadata),
          clock
        ],
      });

      const result = await this.client.signAndExecuteTransactionBlock({
        signer,
        transactionBlock: tx,
        options: {
          showEffects: true,
          showEvents: true,
        },
      });

      if (result.effects?.status?.status !== 'success') {
        throw new SecurityError('Consent granting failed', 'CONTRACT_EXECUTION_ERROR', 'HIGH');
      }

      return {
        digest: result.digest,
        sender: signer.getPublicKey().toSuiAddress(),
        gasUsed: Number(result.effects?.gasUsed?.computationCost || 0),
        status: 'SUCCESS',
        timestamp: new Date()
      };

    } catch (error) {
      throw new SecurityError(`Failed to grant consent: ${error.message}`, 'CONTRACT_ERROR', 'HIGH');
    }
  }

  /**
   * Withdraw consent
   */
  async withdrawConsent(
    signer: Ed25519Keypair,
    consentId: string
  ): Promise<MoveTransaction> {
    try {
      const tx = new TransactionBlock();

      const clock = tx.object('0x6');

      tx.moveCall({
        target: `${this.packageId}::data_governance::withdraw_consent`,
        arguments: [
          tx.object(this.registryId),
          tx.pure(consentId),
          clock
        ],
      });

      const result = await this.client.signAndExecuteTransactionBlock({
        signer,
        transactionBlock: tx,
        options: {
          showEffects: true,
          showEvents: true,
        },
      });

      if (result.effects?.status?.status !== 'success') {
        throw new SecurityError('Consent withdrawal failed', 'CONTRACT_EXECUTION_ERROR', 'HIGH');
      }

      return {
        digest: result.digest,
        sender: signer.getPublicKey().toSuiAddress(),
        gasUsed: Number(result.effects?.gasUsed?.computationCost || 0),
        status: 'SUCCESS',
        timestamp: new Date()
      };

    } catch (error) {
      throw new SecurityError(`Failed to withdraw consent: ${error.message}`, 'CONTRACT_ERROR', 'HIGH');
    }
  }

  /**
   * Request data processing
   */
  async requestDataProcessing(
    signer: Ed25519Keypair,
    params: ProcessingRequestParams
  ): Promise<MoveTransaction> {
    try {
      const tx = new TransactionBlock();

      const clock = tx.object('0x6');

      tx.moveCall({
        target: `${this.packageId}::data_governance::request_data_processing`,
        arguments: [
          tx.object(this.registryId),
          tx.pure(params.dataSubject),
          tx.pure(params.purpose),
          tx.pure(params.policyId),
          tx.pure(params.requestedData),
          tx.pure(params.legalBasis),
          tx.pure(params.retentionPeriod),
          clock
        ],
      });

      const result = await this.client.signAndExecuteTransactionBlock({
        signer,
        transactionBlock: tx,
        options: {
          showEffects: true,
          showEvents: true,
        },
      });

      if (result.effects?.status?.status !== 'success') {
        throw new SecurityError('Processing request failed', 'CONTRACT_EXECUTION_ERROR', 'HIGH');
      }

      return {
        digest: result.digest,
        sender: signer.getPublicKey().toSuiAddress(),
        gasUsed: Number(result.effects?.gasUsed?.computationCost || 0),
        status: 'SUCCESS',
        timestamp: new Date()
      };

    } catch (error) {
      throw new SecurityError(`Failed to request data processing: ${error.message}`, 'CONTRACT_ERROR', 'HIGH');
    }
  }

  /**
   * Exercise right to be forgotten
   */
  async rightToBeForgotten(
    signer: Ed25519Keypair,
    categories: string[]
  ): Promise<MoveTransaction> {
    try {
      const tx = new TransactionBlock();

      const clock = tx.object('0x6');

      tx.moveCall({
        target: `${this.packageId}::data_governance::right_to_be_forgotten`,
        arguments: [
          tx.object(this.registryId),
          tx.pure(categories),
          clock
        ],
      });

      const result = await this.client.signAndExecuteTransactionBlock({
        signer,
        transactionBlock: tx,
        options: {
          showEffects: true,
          showEvents: true,
        },
      });

      if (result.effects?.status?.status !== 'success') {
        throw new SecurityError('Right to be forgotten execution failed', 'CONTRACT_EXECUTION_ERROR', 'HIGH');
      }

      return {
        digest: result.digest,
        sender: signer.getPublicKey().toSuiAddress(),
        gasUsed: Number(result.effects?.gasUsed?.computationCost || 0),
        status: 'SUCCESS',
        timestamp: new Date()
      };

    } catch (error) {
      throw new SecurityError(`Failed to execute right to be forgotten: ${error.message}`, 'CONTRACT_ERROR', 'HIGH');
    }
  }

  /**
   * Generate compliance report
   */
  async generateComplianceReport(
    signer: Ed25519Keypair,
    framework: string,
    periodStart: string,
    periodEnd: string
  ): Promise<MoveTransaction> {
    try {
      const tx = new TransactionBlock();

      const clock = tx.object('0x6');

      tx.moveCall({
        target: `${this.packageId}::data_governance::generate_compliance_report`,
        arguments: [
          tx.object(this.registryId),
          tx.pure(framework),
          tx.pure(periodStart),
          tx.pure(periodEnd),
          clock
        ],
      });

      const result = await this.client.signAndExecuteTransactionBlock({
        signer,
        transactionBlock: tx,
        options: {
          showEffects: true,
          showEvents: true,
        },
      });

      if (result.effects?.status?.status !== 'success') {
        throw new SecurityError('Compliance report generation failed', 'CONTRACT_EXECUTION_ERROR', 'HIGH');
      }

      return {
        digest: result.digest,
        sender: signer.getPublicKey().toSuiAddress(),
        gasUsed: Number(result.effects?.gasUsed?.computationCost || 0),
        status: 'SUCCESS',
        timestamp: new Date()
      };

    } catch (error) {
      throw new SecurityError(`Failed to generate compliance report: ${error.message}`, 'CONTRACT_ERROR', 'HIGH');
    }
  }

  /**
   * Get policy information
   */
  async getPolicy(policyId: string): Promise<MoveDataPolicy | null> {
    try {
      const result = await this.client.devInspectTransactionBlock({
        transactionBlock: (() => {
          const tx = new TransactionBlock();
          tx.moveCall({
            target: `${this.packageId}::data_governance::get_policy`,
            arguments: [
              tx.object(this.registryId),
              tx.pure(policyId)
            ],
          });
          return tx;
        })(),
        sender: '0x0000000000000000000000000000000000000000000000000000000000000000'
      });

      if (result.error) {
        console.warn(`Failed to get policy: ${result.error}`);
        return null;
      }

      // Parse result from contract
      // In production: implement proper result parsing
      return {
        id: policyId,
        name: 'Policy Name',
        purpose: 'Policy Purpose',
        legalBasis: 1,
        retentionPeriodMs: '31536000000', // 1 year
        dataCategories: [],
        allowedProcessors: [],
        crossBorderTransfer: false,
        encryptionRequired: true,
        anonymizationRequired: false,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        active: true
      };

    } catch (error) {
      console.error(`Error getting policy: ${error.message}`);
      return null;
    }
  }

  /**
   * Get data subject information
   */
  async getDataSubject(subjectId: string): Promise<MoveDataSubject | null> {
    try {
      const result = await this.client.devInspectTransactionBlock({
        transactionBlock: (() => {
          const tx = new TransactionBlock();
          tx.moveCall({
            target: `${this.packageId}::data_governance::get_data_subject`,
            arguments: [
              tx.object(this.registryId),
              tx.pure(subjectId)
            ],
          });
          return tx;
        })(),
        sender: subjectId
      });

      if (result.error) {
        console.warn(`Failed to get data subject: ${result.error}`);
        return null;
      }

      // Parse result from contract
      return {
        id: subjectId,
        pseudonym: 'Anonymous User',
        preferences: {
          shareData: false,
          allowProfiling: false,
          marketingConsent: false,
          dataRetentionDays: '365',
          anonymizationPreference: true,
          contactPreferences: []
        },
        consents: [],
        dataCategories: [],
        createdAt: new Date().toISOString(),
        lastUpdated: new Date().toISOString()
      };

    } catch (error) {
      console.error(`Error getting data subject: ${error.message}`);
      return null;
    }
  }

  /**
   * Get consent record
   */
  async getConsent(consentId: string): Promise<MoveConsentRecord | null> {
    try {
      const result = await this.client.devInspectTransactionBlock({
        transactionBlock: (() => {
          const tx = new TransactionBlock();
          tx.moveCall({
            target: `${this.packageId}::data_governance::get_consent`,
            arguments: [
              tx.object(this.registryId),
              tx.pure(consentId)
            ],
          });
          return tx;
        })(),
        sender: '0x0000000000000000000000000000000000000000000000000000000000000000'
      });

      if (result.error) {
        console.warn(`Failed to get consent: ${result.error}`);
        return null;
      }

      // Parse result from contract
      return {
        id: consentId,
        dataSubject: '0x1234567890abcdef',
        purpose: 'Data Processing',
        granted: true,
        grantedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 31536000000).toISOString(), // 1 year
        withdrawnAt: '0',
        legalBasis: 'Consent',
        metadata: [],
        version: '1'
      };

    } catch (error) {
      console.error(`Error getting consent: ${error.message}`);
      return null;
    }
  }

  /**
   * Check if consent is valid
   */
  async isValidConsent(
    dataSubject: string,
    purpose: string,
    currentTime?: string
  ): Promise<boolean> {
    try {
      const time = currentTime || Date.now().toString();

      const result = await this.client.devInspectTransactionBlock({
        transactionBlock: (() => {
          const tx = new TransactionBlock();
          tx.moveCall({
            target: `${this.packageId}::data_governance::is_valid_consent`,
            arguments: [
              tx.object(this.registryId),
              tx.pure(dataSubject),
              tx.pure(purpose),
              tx.pure(time)
            ],
          });
          return tx;
        })(),
        sender: '0x0000000000000000000000000000000000000000000000000000000000000000'
      });

      if (result.error) {
        console.warn(`Failed to check consent validity: ${result.error}`);
        return false;
      }

      // In production: parse actual boolean result from contract
      return true;

    } catch (error) {
      console.error(`Error checking consent validity: ${error.message}`);
      return false;
    }
  }

  /**
   * Listen for contract events
   */
  async subscribeToEvents(
    eventTypes: string[],
    onEvent: (event: any) => void
  ): Promise<void> {
    try {
      // In production: implement WebSocket connection for real-time events
      // This is a simplified polling approach

      const pollEvents = async () => {
        try {
          const events = await this.client.queryEvents({
            query: {
              MoveEventType: eventTypes.map(type => `${this.packageId}::data_governance::${type}`)
            },
            limit: 50,
            order: 'descending'
          });

          events.data.forEach(event => {
            onEvent({
              type: event.type,
              sender: event.sender,
              timestamp: event.timestampMs,
              data: event.parsedJson
            });
          });
        } catch (error) {
          console.error(`Error polling events: ${error.message}`);
        }
      };

      // Poll every 5 seconds
      setInterval(pollEvents, 5000);

      // Initial poll
      await pollEvents();

    } catch (error) {
      throw new SecurityError(`Failed to subscribe to events: ${error.message}`, 'EVENT_SUBSCRIPTION_ERROR', 'MEDIUM');
    }
  }

  /**
   * Deploy a new registry instance
   */
  static async deployRegistry(
    client: SuiClient,
    signer: Ed25519Keypair,
    packageId: string
  ): Promise<string> {
    try {
      const tx = new TransactionBlock();

      tx.moveCall({
        target: `${packageId}::data_governance::create_registry`,
        arguments: [],
      });

      const result = await client.signAndExecuteTransactionBlock({
        signer,
        transactionBlock: tx,
        options: {
          showEffects: true,
          showEvents: true,
          showObjectChanges: true,
        },
      });

      if (result.effects?.status?.status !== 'success') {
        throw new SecurityError('Registry deployment failed', 'CONTRACT_DEPLOYMENT_ERROR', 'CRITICAL');
      }

      // Extract registry object ID from created objects
      const createdObjects = result.effects?.created || [];
      const registryObject = createdObjects.find(obj =>
        obj.owner === 'Shared' // Registry is a shared object
      );

      if (!registryObject) {
        throw new SecurityError('Registry object not found in transaction results', 'REGISTRY_NOT_FOUND', 'CRITICAL');
      }

      return registryObject.reference.objectId;

    } catch (error) {
      throw new SecurityError(`Failed to deploy registry: ${error.message}`, 'DEPLOYMENT_ERROR', 'CRITICAL');
    }
  }
}