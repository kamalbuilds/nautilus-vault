/** @type {import('jest').Config} */
module.exports = {
  // Basic configuration
  testEnvironment: 'node',
  verbose: true,
  collectCoverage: true,
  coverageReporters: ['text', 'lcov', 'html', 'json'],

  // Test patterns
  testMatch: [
    '<rootDir>/tests/**/*.test.{js,ts}',
    '<rootDir>/tests/**/*.spec.{js,ts}'
  ],

  // Coverage configuration
  coverageDirectory: '<rootDir>/tests/reports/coverage',
  collectCoverageFrom: [
    'src/**/*.{js,ts}',
    '!src/**/*.d.ts',
    '!src/**/*.test.{js,ts}',
    '!src/**/index.{js,ts}'
  ],

  // Coverage thresholds for security-critical code
  coverageThreshold: {
    global: {
      branches: 85,
      functions: 90,
      lines: 90,
      statements: 90
    },
    './src/crypto/': {
      branches: 95,
      functions: 95,
      lines: 95,
      statements: 95
    },
    './src/auth/': {
      branches: 90,
      functions: 95,
      lines: 90,
      statements: 90
    }
  },

  // Setup and teardown
  setupFilesAfterEnv: ['<rootDir>/tests/config/setup.js'],
  globalSetup: '<rootDir>/tests/config/global-setup.js',
  globalTeardown: '<rootDir>/tests/config/global-teardown.js',

  // TypeScript support
  preset: 'ts-jest',
  transform: {
    '^.+\\.tsx?$': 'ts-jest',
    '^.+\\.jsx?$': 'babel-jest'
  },

  // Module resolution
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@tests/(.*)$': '<rootDir>/tests/$1',
    '^@fixtures/(.*)$': '<rootDir>/tests/fixtures/$1',
    '^@mocks/(.*)$': '<rootDir>/tests/mocks/$1'
  },

  // Test timeouts for security tests
  testTimeout: 30000, // 30 seconds for crypto operations

  // Reporters for security testing
  reporters: [
    'default',
    ['jest-html-reporters', {
      publicPath: './tests/reports/html',
      filename: 'security-test-report.html',
      expand: true
    }],
    ['jest-junit', {
      outputDirectory: './tests/reports/junit',
      outputName: 'security-tests.xml'
    }],
    ['jest-sonar', {
      outputDirectory: './tests/reports/sonar',
      outputName: 'test-report.xml'
    }]
  ],

  // Security-specific test environment variables
  testEnvironmentOptions: {
    NODE_ENV: 'test',
    CRYPTO_LEVEL: 'high',
    SECURITY_MODE: 'strict'
  },

  // Mock configuration for external services
  clearMocks: true,
  resetMocks: true,
  restoreMocks: true,

  // Error handling for security tests
  errorOnDeprecated: true,

  // Performance monitoring
  detectOpenHandles: true,
  detectLeaks: true,

  // Test organization
  projects: [
    {
      displayName: 'Unit Tests - Crypto',
      testMatch: ['<rootDir>/tests/unit/crypto/**/*.test.{js,ts}']
    },
    {
      displayName: 'Unit Tests - Auth',
      testMatch: ['<rootDir>/tests/unit/auth/**/*.test.{js,ts}']
    },
    {
      displayName: 'Integration Tests',
      testMatch: ['<rootDir>/tests/integration/**/*.test.{js,ts}'],
      testTimeout: 60000
    },
    {
      displayName: 'Security Tests',
      testMatch: ['<rootDir>/tests/security/**/*.test.{js,ts}'],
      testTimeout: 120000
    },
    {
      displayName: 'Performance Tests',
      testMatch: ['<rootDir>/tests/performance/**/*.test.{js,ts}'],
      testTimeout: 300000,
      maxWorkers: 1 // Run performance tests serially
    }
  ]
};