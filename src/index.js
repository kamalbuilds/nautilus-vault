#!/usr/bin/env node

/**
 * Walrus Security Suite - Main Entry Point
 * Comprehensive security and privacy protection for the Walrus ecosystem
 *
 * Hackathon: Walrus Haulout 2024
 * Track: Data Security & Privacy
 */

import { createServer } from './server/app.js';
import { logger } from './utils/logger.js';
import { SecurityEngine } from './core/SecurityEngine.js';
import { PrivacyManager } from './core/PrivacyManager.js';
import { FraudDetector } from './security/FraudDetector.js';
import { WalrusClient } from './integrations/WalrusClient.js';

const PORT = process.env.PORT || 3000;

async function bootstrap() {
  try {
    logger.info('🚀 Initializing Walrus Security Suite...');

    // Initialize core components
    const securityEngine = new SecurityEngine();
    const privacyManager = new PrivacyManager();
    const fraudDetector = new FraudDetector();
    const walrusClient = new WalrusClient();

    // Initialize services
    await securityEngine.initialize();
    await privacyManager.initialize();
    await fraudDetector.initialize();
    await walrusClient.initialize();

    logger.info('✅ Core components initialized');

    // Create and start server
    const app = createServer({
      securityEngine,
      privacyManager,
      fraudDetector,
      walrusClient
    });

    const server = app.listen(PORT, () => {
      logger.info(`🛡️  Walrus Security Suite running on port ${PORT}`);
      logger.info('📋 Available endpoints:');
      logger.info('   GET  /health        - Health check');
      logger.info('   POST /api/encrypt   - Data encryption');
      logger.info('   POST /api/decrypt   - Data decryption');
      logger.info('   POST /api/store     - Secure storage');
      logger.info('   POST /api/detect    - Fraud detection');
      logger.info('   POST /api/verify    - Zero-knowledge verification');
      logger.info('   GET  /api/privacy   - Privacy dashboard');
      logger.info('   POST /api/consent   - Consent management');
    });

    // Graceful shutdown
    process.on('SIGTERM', () => {
      logger.info('🔄 Shutting down gracefully...');
      server.close(() => {
        logger.info('✅ Server closed');
        process.exit(0);
      });
    });

  } catch (error) {
    logger.error('❌ Failed to start Walrus Security Suite:', error);
    process.exit(1);
  }
}

// Start the application
if (import.meta.url === `file://${process.argv[1]}`) {
  bootstrap();
}

export { bootstrap };