/**
 * Global Jest Setup
 * Runs once before all tests
 */

const fs = require('fs').promises;
const path = require('path');

module.exports = async () => {
  console.log('🚀 Setting up test environment...');

  // Create test directories if they don't exist
  const testDirs = [
    'tests/temp',
    'tests/fixtures',
    'tests/logs'
  ];

  for (const dir of testDirs) {
    try {
      await fs.mkdir(path.join(__dirname, '../..', dir), { recursive: true });
    } catch (error) {
      // Directory might already exist, ignore
    }
  }

  // Set up test fixtures
  const fixtures = {
    'sample-data.json': JSON.stringify({
      users: [
        { id: 'user-1', email: 'alice@example.com', role: 'admin' },
        { id: 'user-2', email: 'bob@example.com', role: 'user' }
      ],
      transactions: [
        { id: 'txn-1', userId: 'user-1', amount: 1000, currency: 'USD' },
        { id: 'txn-2', userId: 'user-2', amount: 500, currency: 'EUR' }
      ]
    }, null, 2),

    'test-keys.json': JSON.stringify({
      encryptionKey: 'test-key-12345',
      signingKey: 'test-signing-key-67890',
      walrusEndpoint: 'http://localhost:31415',
      sealEndpoint: 'http://localhost:8080'
    }, null, 2)
  };

  for (const [filename, content] of Object.entries(fixtures)) {
    try {
      await fs.writeFile(
        path.join(__dirname, '../fixtures', filename),
        content
      );
    } catch (error) {
      console.warn(`Warning: Could not create fixture ${filename}:`, error.message);
    }
  }

  // Initialize test database schema
  global.__TEST_START_TIME__ = Date.now();

  console.log('✅ Test environment setup complete');
};