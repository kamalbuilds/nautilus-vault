// Global test setup for Walrus Security Suite
const crypto = require('crypto');
const { performance } = require('perf_hooks');

// Security test environment setup
global.securityTestConfig = {
  cryptoLevel: 'high',
  strictMode: true,
  auditMode: true,
  performanceTracking: true
};

// Set up secure random number generation for tests
if (!global.crypto) {
  global.crypto = {
    getRandomValues: (array) => crypto.randomFillSync(array),
    randomUUID: crypto.randomUUID
  };
}

// Performance monitoring utilities
global.performanceTracker = {
  start: (operation) => {
    const start = performance.now();
    return {
      end: () => {
        const end = performance.now();
        const duration = end - start;
        console.log(`[PERF] ${operation}: ${duration.toFixed(2)}ms`);
        return duration;
      }
    };
  }
};

// Security test helpers
global.securityHelpers = {
  // Generate secure test keys
  generateTestKey: (algorithm = 'aes-256-gcm') => {
    switch (algorithm) {
      case 'aes-256-gcm':
        return crypto.randomBytes(32);
      case 'aes-128-gcm':
        return crypto.randomBytes(16);
      case 'chacha20-poly1305':
        return crypto.randomBytes(32);
      default:
        throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  },

  // Generate secure test data
  generateTestData: (size = 1024) => {
    return crypto.randomBytes(size);
  },

  // Generate test nonce/IV
  generateNonce: (size = 12) => {
    return crypto.randomBytes(size);
  },

  // Timing attack resistant comparison
  constantTimeEqual: (a, b) => {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result === 0;
  },

  // Memory usage tracking
  trackMemory: (label) => {
    const usage = process.memoryUsage();
    console.log(`[MEMORY] ${label}:`, {
      heapUsed: `${Math.round(usage.heapUsed / 1024 / 1024)}MB`,
      heapTotal: `${Math.round(usage.heapTotal / 1024 / 1024)}MB`,
      external: `${Math.round(usage.external / 1024 / 1024)}MB`
    });
    return usage;
  }
};

// Mock external services for security testing
global.mockServices = {
  // Mock Walrus service
  walrus: {
    isHealthy: () => true,
    store: jest.fn().mockResolvedValue({ blobId: 'mock-blob-id' }),
    retrieve: jest.fn().mockResolvedValue(Buffer.from('mock-data'))
  },

  // Mock Seal service
  seal: {
    encrypt: jest.fn().mockResolvedValue({
      encryptedData: 'mock-encrypted',
      metadata: { keyId: 'mock-key' }
    }),
    decrypt: jest.fn().mockResolvedValue(Buffer.from('mock-decrypted'))
  },

  // Mock Nautilus enclave
  nautilus: {
    attest: jest.fn().mockResolvedValue({ attestation: 'mock-attestation' }),
    verify: jest.fn().mockResolvedValue(true),
    computeSecure: jest.fn().mockResolvedValue({ result: 'mock-result' })
  },

  // Mock Sui blockchain
  sui: {
    executeTransaction: jest.fn().mockResolvedValue({
      transactionHash: 'mock-tx-hash',
      success: true
    }),
    queryObject: jest.fn().mockResolvedValue({ data: {} })
  }
};

// Test data fixtures
global.testFixtures = {
  // Sample encryption keys
  keys: {
    aes256: Buffer.from('01234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef', 'hex'),
    aes128: Buffer.from('01234567890abcdef01234567890abcdef', 'hex'),
    rsa: {
      public: '-----BEGIN PUBLIC KEY-----\nMOCK_PUBLIC_KEY\n-----END PUBLIC KEY-----',
      private: '-----BEGIN PRIVATE KEY-----\nMOCK_PRIVATE_KEY\n-----END PRIVATE KEY-----'
    }
  },

  // Sample test data
  data: {
    small: Buffer.from('Hello, Walrus!'),
    medium: Buffer.alloc(1024, 'a'),
    large: Buffer.alloc(1024 * 1024, 'b'), // 1MB
    sensitive: {
      personalData: {
        name: 'John Doe',
        email: 'john@example.com',
        ssn: '123-45-6789'
      },
      financialData: {
        accountNumber: '1234567890',
        routingNumber: '987654321',
        balance: 1000.00
      }
    }
  },

  // Sample configurations
  configs: {
    encryption: {
      algorithm: 'aes-256-gcm',
      keyLength: 32,
      ivLength: 12,
      tagLength: 16
    },
    walrus: {
      epochs: 3,
      redundancy: 4,
      availability: 0.99
    }
  }
};

// Security audit logging
global.securityAudit = {
  logs: [],
  log: (event, details) => {
    const entry = {
      timestamp: new Date().toISOString(),
      event,
      details,
      testName: expect.getState().currentTestName || 'unknown'
    };
    global.securityAudit.logs.push(entry);
    if (global.securityTestConfig.auditMode) {
      console.log('[SECURITY AUDIT]', entry);
    }
  },
  clear: () => {
    global.securityAudit.logs = [];
  },
  export: () => {
    return JSON.stringify(global.securityAudit.logs, null, 2);
  }
};

// Test environment validation
beforeAll(() => {
  // Ensure we're in test environment
  if (process.env.NODE_ENV !== 'test') {
    throw new Error('Security tests must run in test environment');
  }

  // Validate crypto availability
  if (!crypto.constants || !crypto.randomBytes) {
    throw new Error('Crypto module not properly initialized');
  }

  // Clear any existing audit logs
  global.securityAudit.clear();

  console.log('[SETUP] Security test environment initialized');
  console.log('[SETUP] Crypto level:', global.securityTestConfig.cryptoLevel);
  console.log('[SETUP] Strict mode:', global.securityTestConfig.strictMode);
});

// Cleanup after each test
afterEach(() => {
  // Clear sensitive data from memory
  if (global.gc) {
    global.gc();
  }

  // Reset mock call counts
  jest.clearAllMocks();
});

// Global error handling for security tests
process.on('uncaughtException', (error) => {
  global.securityAudit.log('uncaught_exception', {
    message: error.message,
    stack: error.stack
  });
  console.error('[SECURITY ERROR] Uncaught exception:', error);
});

process.on('unhandledRejection', (reason, promise) => {
  global.securityAudit.log('unhandled_rejection', {
    reason: reason.toString(),
    promise: promise.toString()
  });
  console.error('[SECURITY ERROR] Unhandled rejection:', reason);
});