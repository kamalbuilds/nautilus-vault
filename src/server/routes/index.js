/**
 * API Routes - Main routing configuration
 * Implements secure API endpoints for the Walrus Security Suite
 */

import { Router } from 'express';
import { logger } from '../../utils/logger.js';

export function createRoutes(services) {
  const router = Router();
  const { securityEngine, privacyManager, fraudDetector, walrusClient } = services;

  // Health and status endpoints
  router.get('/health', async (req, res) => {
    try {
      const status = {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        services: {
          security: securityEngine.getSecurityStatus(),
          privacy: privacyManager.getStatus(),
          fraudDetection: fraudDetector.getStatus(),
          walrus: walrusClient.getStatus()
        }
      };

      res.json(status);

    } catch (error) {
      logger.error('Health check failed:', error);
      res.status(500).json({
        status: 'unhealthy',
        error: error.message
      });
    }
  });

  // Encryption endpoints
  router.post('/encrypt', async (req, res) => {
    try {
      const { data, options = {} } = req.body;

      if (!data) {
        return res.status(400).json({
          error: 'Data field is required'
        });
      }

      const encrypted = await securityEngine.encryptData(data, options);

      res.json({
        success: true,
        encrypted,
        algorithm: options.algorithm || 'aes-256-gcm',
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Encryption failed:', error);
      res.status(500).json({
        error: 'Encryption failed',
        message: error.message
      });
    }
  });

  router.post('/decrypt', async (req, res) => {
    try {
      const { encryptedData, options = {} } = req.body;

      if (!encryptedData) {
        return res.status(400).json({
          error: 'EncryptedData field is required'
        });
      }

      const decrypted = await securityEngine.decryptData(encryptedData, options);

      res.json({
        success: true,
        decrypted: decrypted.toString(),
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Decryption failed:', error);
      res.status(500).json({
        error: 'Decryption failed',
        message: error.message
      });
    }
  });

  // Storage endpoints
  router.post('/store', async (req, res) => {
    try {
      const { data, options = {} } = req.body;

      if (!data) {
        return res.status(400).json({
          error: 'Data field is required'
        });
      }

      const result = await walrusClient.store(data, options);

      res.json({
        success: true,
        storeId: result.storeId,
        proof: result.proof,
        metadata: result.metadata,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Storage failed:', error);
      res.status(500).json({
        error: 'Storage failed',
        message: error.message
      });
    }
  });

  router.get('/retrieve/:storeId', async (req, res) => {
    try {
      const { storeId } = req.params;
      const options = req.query;

      if (!storeId) {
        return res.status(400).json({
          error: 'StoreId parameter is required'
        });
      }

      const data = await walrusClient.retrieve(storeId, options);

      res.json({
        success: true,
        data: data.toString(),
        storeId,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Retrieval failed:', error);
      res.status(404).json({
        error: 'Retrieval failed',
        message: error.message
      });
    }
  });

  router.delete('/store/:storeId', async (req, res) => {
    try {
      const { storeId } = req.params;
      const options = req.body || {};

      const result = await walrusClient.delete(storeId, options);

      res.json({
        success: true,
        storeId: result.storeId,
        deletedShards: result.deletedShards,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Deletion failed:', error);
      res.status(500).json({
        error: 'Deletion failed',
        message: error.message
      });
    }
  });

  // Fraud detection endpoints
  router.post('/detect', async (req, res) => {
    try {
      const { transactionData, userContext = {} } = req.body;

      if (!transactionData) {
        return res.status(400).json({
          error: 'TransactionData field is required'
        });
      }

      const result = await fraudDetector.detectFraud(transactionData, userContext);

      res.json({
        success: true,
        detection: {
          detectionId: result.detectionId,
          riskScore: result.riskScore,
          riskLevel: result.riskLevel,
          confidence: result.confidence,
          recommendations: result.recommendations
        },
        metadata: result.metadata,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Fraud detection failed:', error);
      res.status(500).json({
        error: 'Fraud detection failed',
        message: error.message
      });
    }
  });

  // Privacy endpoints
  router.post('/privacy/consent', async (req, res) => {
    try {
      const { subjectId, consentData } = req.body;

      if (!subjectId || !consentData) {
        return res.status(400).json({
          error: 'SubjectId and consentData fields are required'
        });
      }

      const consent = await privacyManager.recordConsent(subjectId, consentData);

      res.json({
        success: true,
        consent: {
          id: consent.id,
          subjectId: consent.subjectId,
          purposes: consent.purposes,
          timestamp: new Date(consent.timestamp).toISOString()
        }
      });

    } catch (error) {
      logger.error('Consent recording failed:', error);
      res.status(500).json({
        error: 'Consent recording failed',
        message: error.message
      });
    }
  });

  router.post('/privacy/zk-proof', async (req, res) => {
    try {
      const { data, statement, witness } = req.body;

      if (!data || !statement || !witness) {
        return res.status(400).json({
          error: 'Data, statement, and witness fields are required'
        });
      }

      const zkProof = await privacyManager.generateZKProof(data, statement, witness);

      res.json({
        success: true,
        proof: {
          id: zkProof.id,
          statement: zkProof.statement,
          commitment: zkProof.commitment,
          metadata: zkProof.metadata
        },
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('ZK proof generation failed:', error);
      res.status(500).json({
        error: 'ZK proof generation failed',
        message: error.message
      });
    }
  });

  router.post('/privacy/verify-proof', async (req, res) => {
    try {
      const { proof, statement, publicInputs } = req.body;

      if (!proof || !statement || !publicInputs) {
        return res.status(400).json({
          error: 'Proof, statement, and publicInputs fields are required'
        });
      }

      const verification = await privacyManager.verifyZKProof(proof, statement, publicInputs);

      res.json({
        success: true,
        verification: {
          valid: verification.valid,
          proofId: verification.proofId,
          verifiedAt: new Date(verification.verifiedAt).toISOString()
        }
      });

    } catch (error) {
      logger.error('ZK proof verification failed:', error);
      res.status(500).json({
        error: 'ZK proof verification failed',
        message: error.message
      });
    }
  });

  router.post('/privacy/anonymize', async (req, res) => {
    try {
      const { data, anonymizationType = 'k-anonymity' } = req.body;

      if (!data) {
        return res.status(400).json({
          error: 'Data field is required'
        });
      }

      const result = await privacyManager.anonymizeData(data, anonymizationType);

      res.json({
        success: true,
        anonymization: {
          id: result.id,
          method: result.method,
          anonymizedData: result.anonymizedData,
          metadata: result.metadata
        },
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Data anonymization failed:', error);
      res.status(500).json({
        error: 'Data anonymization failed',
        message: error.message
      });
    }
  });

  router.post('/privacy/differential', async (req, res) => {
    try {
      const { data, queryType } = req.body;

      if (!data || !queryType) {
        return res.status(400).json({
          error: 'Data and queryType fields are required'
        });
      }

      const result = await privacyManager.applyDifferentialPrivacy(data, queryType);

      res.json({
        success: true,
        result: {
          noisyResult: result.noisyResult,
          queryType: result.queryType,
          epsilon: result.epsilon,
          mechanism: result.mechanism
        },
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Differential privacy failed:', error);
      res.status(500).json({
        error: 'Differential privacy failed',
        message: error.message
      });
    }
  });

  // Security audit endpoints
  router.get('/audit/security', async (req, res) => {
    try {
      const audit = await securityEngine.performSecurityAudit();

      res.json({
        success: true,
        audit,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Security audit failed:', error);
      res.status(500).json({
        error: 'Security audit failed',
        message: error.message
      });
    }
  });

  router.get('/audit/privacy', async (req, res) => {
    try {
      const audit = await privacyManager.audit();

      res.json({
        success: true,
        audit,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Privacy audit failed:', error);
      res.status(500).json({
        error: 'Privacy audit failed',
        message: error.message
      });
    }
  });

  router.get('/audit/fraud', async (req, res) => {
    try {
      const audit = await fraudDetector.audit();

      res.json({
        success: true,
        audit,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Fraud detection audit failed:', error);
      res.status(500).json({
        error: 'Fraud detection audit failed',
        message: error.message
      });
    }
  });

  router.get('/audit/walrus', async (req, res) => {
    try {
      const audit = await walrusClient.audit();

      res.json({
        success: true,
        audit,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Walrus audit failed:', error);
      res.status(500).json({
        error: 'Walrus audit failed',
        message: error.message
      });
    }
  });

  // Demo endpoints
  router.post('/demo/complete-workflow', async (req, res) => {
    try {
      const { data = 'Hello, Walrus Security Suite!' } = req.body;

      // 1. Encrypt data
      const encrypted = await securityEngine.encryptData(data);

      // 2. Store encrypted data
      const stored = await walrusClient.store(encrypted);

      // 3. Retrieve data
      const retrieved = await walrusClient.retrieve(stored.storeId);

      // 4. Decrypt data
      const decrypted = await securityEngine.decryptData(retrieved);

      // 5. Generate ZK proof
      const zkProof = await privacyManager.generateZKProof(
        { originalData: data },
        { type: 'data_integrity', version: '1.0' },
        { hash: crypto.createHash('sha256').update(data).digest('hex') }
      );

      // 6. Run fraud detection
      const fraudResult = await fraudDetector.detectFraud({
        id: 'demo-tx-' + Date.now(),
        amount: Math.random() * 1000,
        type: 'demo'
      });

      res.json({
        success: true,
        workflow: {
          originalData: data,
          encryption: { success: true, algorithm: 'aes-256-gcm' },
          storage: { storeId: stored.storeId, success: true },
          retrieval: { success: true },
          decryption: { decrypted: decrypted.toString(), success: true },
          zkProof: { id: zkProof.id, success: true },
          fraudDetection: {
            riskLevel: fraudResult.riskLevel,
            riskScore: fraudResult.riskScore,
            success: true
          }
        },
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Demo workflow failed:', error);
      res.status(500).json({
        error: 'Demo workflow failed',
        message: error.message
      });
    }
  });

  return router;
}