/**
 * Blockchain API Server
 * Production API endpoints for real smart contract interactions
 */

import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { RealSuiBlockchainService, PrivacyPreferences, BlockchainTransaction } from './real-sui-blockchain-service';

// Helper function to extract error message
function getErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

const app = express();

// Security middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});

app.use('/api/', limiter);

// Initialize blockchain service
const blockchainService = new RealSuiBlockchainService('testnet');

// Global error handler
const asyncHandler = (fn: Function) => (req: any, res: any, next: any) =>
  Promise.resolve(fn(req, res, next)).catch(next);

// =============== API ENDPOINTS ===============

/**
 * GET /api/blockchain/status
 * Get blockchain service status and network info
 */
app.get('/api/blockchain/status', asyncHandler(async (req: any, res: any) => {
  const networkInfo = await blockchainService.getNetworkInfo();
  const transactionHistory = blockchainService.getTransactionHistory();

  res.json({
    success: true,
    data: {
      ...networkInfo,
      statistics: {
        totalTransactions: transactionHistory.length,
        confirmedTransactions: transactionHistory.filter(tx => tx.status === 'CONFIRMED').length,
        totalGasUsed: transactionHistory.reduce((sum, tx) => sum + tx.gasUsed, 0),
      },
      lastUpdated: new Date().toISOString()
    }
  });
}));

/**
 * POST /api/blockchain/initialize-registry
 * Initialize the data governance registry (one-time setup)
 */
app.post('/api/blockchain/initialize-registry', asyncHandler(async (req: any, res: any) => {
  try {
    const registryId = await blockchainService.initializeRegistry();

    res.json({
      success: true,
      data: {
        registryId,
        transactionUrl: `https://testnet.suivision.xyz/object/${registryId}`,
        message: 'Data governance registry successfully initialized'
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: getErrorMessage(error),
      code: 'REGISTRY_INIT_FAILED'
    });
  }
}));

/**
 * POST /api/blockchain/register-data-subject
 * Register a data subject with privacy preferences
 */
app.post('/api/blockchain/register-data-subject', asyncHandler(async (req: any, res: any) => {
  const { pseudonym, preferences } = req.body;

  if (!pseudonym || !preferences) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields: pseudonym, preferences',
      code: 'INVALID_INPUT'
    });
  }

  try {
    const transaction = await blockchainService.registerDataSubject(pseudonym, preferences);

    res.json({
      success: true,
      data: {
        transaction,
        explorerUrl: transaction.explorerUrl,
        message: `Data subject '${pseudonym}' registered successfully`
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: getErrorMessage(error),
      code: 'SUBJECT_REGISTRATION_FAILED'
    });
  }
}));

/**
 * POST /api/blockchain/grant-consent
 * Grant consent for data processing
 */
app.post('/api/blockchain/grant-consent', asyncHandler(async (req: any, res: any) => {
  const { consentId, purpose, expiresAt, legalBasis, metadata } = req.body;

  if (!consentId || !purpose || !legalBasis) {
    return res.status(400).json({
      success: false,
      error: 'Missing required fields: consentId, purpose, legalBasis',
      code: 'INVALID_INPUT'
    });
  }

  try {
    const transaction = await blockchainService.grantConsent(
      consentId,
      purpose,
      expiresAt || (Date.now() + (365 * 24 * 60 * 60 * 1000)), // Default 1 year
      legalBasis,
      metadata || {}
    );

    res.json({
      success: true,
      data: {
        transaction,
        explorerUrl: transaction.explorerUrl,
        message: `Consent granted for purpose: ${purpose}`
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: getErrorMessage(error),
      code: 'CONSENT_GRANT_FAILED'
    });
  }
}));

/**
 * POST /api/blockchain/withdraw-consent
 * Withdraw previously granted consent
 */
app.post('/api/blockchain/withdraw-consent', asyncHandler(async (req: any, res: any) => {
  const { consentId } = req.body;

  if (!consentId) {
    return res.status(400).json({
      success: false,
      error: 'Missing required field: consentId',
      code: 'INVALID_INPUT'
    });
  }

  try {
    const transaction = await blockchainService.withdrawConsent(consentId);

    res.json({
      success: true,
      data: {
        transaction,
        explorerUrl: transaction.explorerUrl,
        message: `Consent ${consentId} withdrawn successfully`
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: getErrorMessage(error),
      code: 'CONSENT_WITHDRAW_FAILED'
    });
  }
}));

/**
 * POST /api/blockchain/right-to-be-forgotten
 * Exercise right to be forgotten (data erasure)
 */
app.post('/api/blockchain/right-to-be-forgotten', asyncHandler(async (req: any, res: any) => {
  const { categories } = req.body;

  if (!categories || !Array.isArray(categories)) {
    return res.status(400).json({
      success: false,
      error: 'Missing or invalid field: categories (must be array)',
      code: 'INVALID_INPUT'
    });
  }

  try {
    const transaction = await blockchainService.rightToBeForgotten(categories);

    res.json({
      success: true,
      data: {
        transaction,
        explorerUrl: transaction.explorerUrl,
        message: `Right to be forgotten exercised for categories: ${categories.join(', ')}`
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: getErrorMessage(error),
      code: 'ERASURE_REQUEST_FAILED'
    });
  }
}));

/**
 * POST /api/blockchain/generate-compliance-report
 * Generate a compliance report for a specific framework
 */
app.post('/api/blockchain/generate-compliance-report', asyncHandler(async (req: any, res: any) => {
  const { framework, periodStart, periodEnd } = req.body;

  if (!framework) {
    return res.status(400).json({
      success: false,
      error: 'Missing required field: framework',
      code: 'INVALID_INPUT'
    });
  }

  const start = periodStart || (Date.now() - (30 * 24 * 60 * 60 * 1000)); // Default 30 days ago
  const end = periodEnd || Date.now();

  try {
    const transaction = await blockchainService.generateComplianceReport(framework, start, end);

    res.json({
      success: true,
      data: {
        transaction,
        explorerUrl: transaction.explorerUrl,
        report: {
          framework,
          periodStart: new Date(start).toISOString(),
          periodEnd: new Date(end).toISOString(),
        },
        message: `${framework} compliance report generated successfully`
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: getErrorMessage(error),
      code: 'REPORT_GENERATION_FAILED'
    });
  }
}));

/**
 * GET /api/blockchain/transaction/:digest
 * Get transaction status and verify on blockchain
 */
app.get('/api/blockchain/transaction/:digest', asyncHandler(async (req: any, res: any) => {
  const { digest } = req.params;

  if (!digest) {
    return res.status(400).json({
      success: false,
      error: 'Missing transaction digest',
      code: 'INVALID_INPUT'
    });
  }

  try {
    const [transaction, verification] = await Promise.all([
      blockchainService.getTransactionStatus(digest),
      blockchainService.verifyTransaction(digest)
    ]);

    if (!transaction) {
      return res.status(404).json({
        success: false,
        error: 'Transaction not found',
        code: 'TRANSACTION_NOT_FOUND'
      });
    }

    res.json({
      success: true,
      data: {
        transaction,
        verification,
        explorerUrl: `https://testnet.suivision.xyz/txblock/${digest}`
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: getErrorMessage(error),
      code: 'TRANSACTION_LOOKUP_FAILED'
    });
  }
}));

/**
 * GET /api/blockchain/transactions
 * Get transaction history
 */
app.get('/api/blockchain/transactions', asyncHandler(async (req: any, res: any) => {
  const { limit = 10, type, status } = req.query;

  let transactions = blockchainService.getTransactionHistory();

  // Apply filters
  if (type) {
    transactions = transactions.filter(tx => tx.type === type);
  }
  if (status) {
    transactions = transactions.filter(tx => tx.status === status);
  }

  // Apply limit
  transactions = transactions.slice(0, parseInt(limit));

  res.json({
    success: true,
    data: {
      transactions,
      total: transactions.length,
      filters: { type, status, limit }
    }
  });
}));

/**
 * POST /api/blockchain/demo-workflow
 * Run complete demonstration workflow
 */
app.post('/api/blockchain/demo-workflow', asyncHandler(async (req: any, res: any) => {
  try {
    const result = await blockchainService.demonstrateWorkflow();

    res.json({
      success: true,
      data: {
        ...result,
        message: 'Complete blockchain workflow demonstrated successfully',
        explorerLinks: result.transactions.map(tx => ({
          type: tx.type,
          digest: tx.digest,
          url: tx.explorerUrl
        }))
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: getErrorMessage(error),
      code: 'WORKFLOW_DEMO_FAILED'
    });
  }
}));

/**
 * GET /api/blockchain/verify/:digest
 * Verify transaction on blockchain and provide proof
 */
app.get('/api/blockchain/verify/:digest', asyncHandler(async (req: any, res: any) => {
  const { digest } = req.params;

  if (!digest) {
    return res.status(400).json({
      success: false,
      error: 'Missing transaction digest',
      code: 'INVALID_INPUT'
    });
  }

  try {
    const verification = await blockchainService.verifyTransaction(digest);

    res.json({
      success: true,
      data: {
        digest,
        verification,
        timestamp: new Date().toISOString(),
        explorerUrl: `https://testnet.suivision.xyz/txblock/${digest}`,
        proof: {
          verified: verification.verified,
          onChain: verification.onChain,
          networkConfirmed: verification.onChain && verification.verified,
          details: verification.details
        }
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: getErrorMessage(error),
      code: 'VERIFICATION_FAILED'
    });
  }
}));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'Blockchain API Server is running',
    timestamp: new Date().toISOString(),
    service: 'walrus-security-blockchain-api'
  });
});

// Error handling middleware
app.use((error: any, req: any, res: any, next: any) => {
  console.error('API Error:', error);

  res.status(error.status || 500).json({
    success: false,
    error: getErrorMessage(error) || 'Internal server error',
    code: error.code || 'INTERNAL_ERROR',
    ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    code: 'ENDPOINT_NOT_FOUND',
    availableEndpoints: [
      'GET /api/blockchain/status',
      'POST /api/blockchain/initialize-registry',
      'POST /api/blockchain/register-data-subject',
      'POST /api/blockchain/grant-consent',
      'POST /api/blockchain/withdraw-consent',
      'POST /api/blockchain/right-to-be-forgotten',
      'POST /api/blockchain/generate-compliance-report',
      'GET /api/blockchain/transaction/:digest',
      'GET /api/blockchain/transactions',
      'POST /api/blockchain/demo-workflow',
      'GET /api/blockchain/verify/:digest',
      'GET /health'
    ]
  });
});

const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
  console.log(`🚀 Blockchain API Server running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🔗 Blockchain status: http://localhost:${PORT}/api/blockchain/status`);
});

export default app;