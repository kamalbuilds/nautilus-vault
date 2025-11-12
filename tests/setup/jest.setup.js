/**
 * Jest Test Setup
 * Configures global test environment and mocks
 */

// Security Audit Mock for consistent logging
class SecurityAuditMock {
  constructor() {
    this.logs = [];
    this.startTime = Date.now();
  }

  log(event, data = {}) {
    this.logs.push({
      timestamp: Date.now(),
      event,
      data,
      sessionId: 'test-session'
    });
  }

  clear() {
    this.logs = [];
  }

  getStats() {
    return {
      totalLogs: this.logs.length,
      events: [...new Set(this.logs.map(l => l.event))],
      duration: Date.now() - this.startTime
    };
  }

  findLogs(eventType) {
    return this.logs.filter(log => log.event === eventType);
  }
}

// Global setup
global.securityAudit = new SecurityAuditMock();

// Environment variables for testing
process.env.NODE_ENV = 'test';
process.env.WALRUS_ENDPOINT = 'http://localhost:31415';
process.env.SUI_NETWORK = 'testnet';
process.env.SEAL_ENDPOINT = 'http://localhost:8080';

// Mock crypto functions to avoid real cryptographic operations in tests
global.mockCrypto = {
  randomBytes: (size) => Buffer.alloc(size, 0xaa),
  createHash: (algorithm) => ({
    update: () => ({ digest: () => 'mockedhash' }),
  }),
  createHmac: (algorithm, key) => ({
    update: () => ({ digest: () => 'mockedhmac' })
  })
};

// Test utilities
global.testUtils = {
  createMockUser: (overrides = {}) => ({
    id: 'test-user-123',
    email: 'test@example.com',
    role: 'user',
    ...overrides
  }),

  createMockTransaction: (overrides = {}) => ({
    id: 'txn-' + Math.random().toString(36).substr(2, 9),
    amount: 1000,
    currency: 'USD',
    timestamp: new Date(),
    userId: 'test-user-123',
    ...overrides
  }),

  waitFor: (ms) => new Promise(resolve => setTimeout(resolve, ms)),

  expectWithRetry: async (assertion, maxRetries = 3, delay = 100) => {
    let lastError;
    for (let i = 0; i < maxRetries; i++) {
      try {
        await assertion();
        return;
      } catch (error) {
        lastError = error;
        await global.testUtils.waitFor(delay);
      }
    }
    throw lastError;
  }
};

// Cleanup after each test
afterEach(() => {
  global.securityAudit.clear();
});