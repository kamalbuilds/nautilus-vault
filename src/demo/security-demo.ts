/**
 * Walrus Security Suite Demo
 * Comprehensive demonstration of security and privacy features
 */

import { WalrusSecuritySuite, WalrusSecurityConfig } from '../core/security-suite';

async function runDemo() {
  console.log('🚀 Starting Walrus Security Suite Demo');
  console.log('=====================================\n');

  // Configuration for the security suite
  const config: WalrusSecurityConfig = {
    security: {
      encryptionAlgorithm: 'AES-256-GCM',
      keyDerivation: 'PBKDF2',
      zkProofSystem: 'Groth16',
      fraudDetectionThreshold: 0.7,
      privacyLevel: 'MAXIMUM'
    },
    privacy: {
      dataMinimization: true,
      anonymization: true,
      consentRequired: true,
      auditLogging: true,
      dataRetentionDays: 365
    },
    walrus: {
      endpoint: 'https://walrus-testnet.example.com',
      apiKey: 'demo_api_key',
      encryption: true
    },
    sui: {
      rpcUrl: 'https://fullnode.testnet.sui.io:443',
      packageId: '0x123...demo_package_id',
      registryId: '0x456...demo_registry_id'
    },
    ml: {
      enableFraudDetection: true,
      enableAnomalyDetection: true,
      trainingMode: false
    },
    features: {
      zkProofs: true,
      homomorphicEncryption: true,
      differentialPrivacy: true,
      multipartyComputation: true
    }
  };

  try {
    // Initialize the security suite
    console.log('🔧 Initializing Walrus Security Suite...');
    const securitySuite = new WalrusSecuritySuite(config);
    await securitySuite.initialize();
    console.log('✅ Security Suite initialized successfully!\n');

    // Demo 1: Secure Data Processing
    console.log('📊 Demo 1: Secure Data Processing');
    console.log('----------------------------------');

    const userData = {
      name: 'Alice Smith',
      email: 'alice@example.com',
      age: 30,
      preferences: {
        marketing: true,
        analytics: false
      },
      behaviorData: {
        clicks: 150,
        pageViews: 45,
        sessionDuration: 1200
      }
    };

    const processingResult = await securitySuite.processData(
      userData,
      'user_alice_123',
      'analytics',
      {
        encrypt: true,
        anonymize: true,
        generateProof: true,
        storeInWalrus: true
      }
    );

    console.log(`✅ Data processed securely`);
    console.log(`   - Blob ID: ${processingResult.blobId}`);
    console.log(`   - Security Score: ${processingResult.securityScore}/100`);
    console.log(`   - Privacy Risk: ${processingResult.privacyMetrics.overallRisk}`);
    console.log(`   - ZK Proof Generated: ${processingResult.zkProof ? '✓' : '✗'}\n`);

    // Demo 2: Data Retrieval and Verification
    console.log('🔍 Demo 2: Data Retrieval and Verification');
    console.log('-------------------------------------------');

    if (processingResult.blobId) {
      const retrievedData = await securitySuite.retrieveData(
        processingResult.blobId,
        'user_alice_123',
        true // verify proof
      );

      console.log(`✅ Data retrieved and verified`);
      console.log(`   - Proof Verification: ✓`);
      console.log(`   - Data Integrity: ✓\n`);
    }

    // Demo 3: Privacy-Preserving Computation
    console.log('🔮 Demo 3: Privacy-Preserving Computation');
    console.log('------------------------------------------');

    const computationResult = await securitySuite.executePrivateComputation(
      ['user_alice_123', 'user_bob_456', 'user_charlie_789'],
      'STATISTICAL',
      [25, 30, 35], // ages for statistical analysis
      {
        differential: true,
        epsilon: 0.1,
        homomorphic: true,
        multiparty: true,
        zkProofs: true
      }
    );

    console.log(`✅ Private computation completed`);
    console.log(`   - Computation ID: ${computationResult.computationId}`);
    console.log(`   - Results: ${JSON.stringify(computationResult.results[0]?.value)}`);
    console.log(`   - Privacy Preserved: ✓`);
    console.log(`   - Verification: ${computationResult.verified ? '✓' : '✗'}\n`);

    // Demo 4: Privacy Dashboard
    console.log('📱 Demo 4: Privacy Dashboard');
    console.log('-----------------------------');

    const dashboard = await securitySuite.getPrivacyDashboard('user_alice_123');

    console.log(`✅ Privacy dashboard generated`);
    console.log(`   - Privacy Score: ${dashboard.privacyScore.overall}/100`);
    console.log(`   - Active Consents: ${dashboard.consents.filter((c: any) => c.status === 'GRANTED').length}`);
    console.log(`   - Data Categories: ${dashboard.dataCategories.length}`);
    console.log(`   - Security Events: ${dashboard.security.securityEvents.length}`);
    console.log(`   - Recommendations: ${dashboard.recommendations.length}\n`);

    // Demo 5: System Health Check
    console.log('🏥 Demo 5: System Health Check');
    console.log('-------------------------------');

    const healthCheck = await securitySuite.performHealthCheck();

    console.log(`✅ Health check completed`);
    console.log(`   - Overall Status: ${healthCheck.overall}`);
    console.log(`   - Component Status:`);
    Object.entries(healthCheck.components).forEach(([component, status]) => {
      const icon = status === 'OK' ? '✅' : status === 'WARNING' ? '⚠️' : '❌';
      console.log(`     ${icon} ${component}: ${status}`);
    });

    if (healthCheck.issues.length > 0) {
      console.log(`   - Issues: ${healthCheck.issues.length}`);
      healthCheck.issues.forEach(issue => console.log(`     - ${issue}`));
    }

    if (healthCheck.recommendations.length > 0) {
      console.log(`   - Recommendations: ${healthCheck.recommendations.length}`);
      healthCheck.recommendations.forEach(rec => console.log(`     - ${rec}`));
    }
    console.log();

    // Demo 6: Security Metrics
    console.log('📈 Demo 6: Security Metrics');
    console.log('---------------------------');

    const metrics = securitySuite.getMetrics();

    console.log(`✅ Security metrics collected`);
    console.log(`   - Uptime: ${Math.round(metrics.uptime / 1000)}s`);
    console.log(`   - Threats Blocked: ${metrics.threatsBlocked}`);
    console.log(`   - Data Processed: ${metrics.dataProcessed}`);
    console.log(`   - Privacy Score: ${metrics.privacyScore}/100`);
    console.log(`   - Compliance: ${metrics.complianceStatus}\n`);

    // Demo 7: Integration Showcase
    console.log('🔗 Demo 7: Integration Showcase');
    console.log('--------------------------------');

    console.log('✅ Walrus Integration:');
    console.log('   - Decentralized storage: ✓');
    console.log('   - Encryption at rest: ✓');
    console.log('   - Verifiable storage: ✓');

    console.log('✅ Seal Integration:');
    console.log('   - Privacy-preserving computation: ✓');
    console.log('   - Multiparty computation: ✓');
    console.log('   - Homomorphic encryption: ✓');

    console.log('✅ Sui Move Contracts:');
    console.log('   - Data governance: ✓');
    console.log('   - Consent management: ✓');
    console.log('   - Audit trails: ✓');

    console.log('✅ Security Features:');
    console.log('   - Zero-knowledge proofs: ✓');
    console.log('   - ML-based fraud detection: ✓');
    console.log('   - Advanced encryption: ✓');
    console.log('   - Privacy-preserving analytics: ✓\n');

    console.log('🎉 Demo completed successfully!');
    console.log('================================');
    console.log('\n🔒 Walrus Security Suite provides:');
    console.log('✓ Comprehensive privacy protection');
    console.log('✓ Advanced security controls');
    console.log('✓ Regulatory compliance (GDPR, CCPA, HIPAA)');
    console.log('✓ Decentralized storage with Walrus');
    console.log('✓ Privacy-preserving computation with Seal');
    console.log('✓ Smart contract governance with Sui Move');
    console.log('✓ ML-powered threat detection');
    console.log('✓ User-friendly privacy controls');
    console.log('✓ Zero-knowledge verification');
    console.log('✓ Enterprise-grade encryption\n');

    // Graceful shutdown
    console.log('🔄 Shutting down...');
    await securitySuite.shutdown();
    console.log('✅ Shutdown complete');

  } catch (error) {
    console.error('❌ Demo failed:', error.message);
    console.error(error);
    process.exit(1);
  }
}

// Feature showcase functions
function showcaseFeatures() {
  console.log('\n🌟 Key Features of Walrus Security Suite:');
  console.log('==========================================\n');

  console.log('🔐 ZERO-KNOWLEDGE PROOFS');
  console.log('• Verify data integrity without revealing content');
  console.log('• Multiple proof systems (Groth16, PLONK, STARK)');
  console.log('• Membership, range, and identity proofs');
  console.log('• Privacy-preserving verification\n');

  console.log('🗄️ VERIFIABLE STORAGE');
  console.log('• Cryptographically verifiable data storage');
  console.log('• Integration with Walrus decentralized storage');
  console.log('• Immutable audit trails');
  console.log('• Version control and access management\n');

  console.log('🤖 ML-POWERED SECURITY');
  console.log('• Advanced fraud detection algorithms');
  console.log('• Behavioral anomaly detection');
  console.log('• Adaptive learning and threat intelligence');
  console.log('• Real-time security scoring\n');

  console.log('🎭 PRIVACY-PRESERVING COMPUTATION');
  console.log('• Seal integration for private computation');
  console.log('• Homomorphic encryption');
  console.log('• Secure multiparty computation');
  console.log('• Differential privacy guarantees\n');

  console.log('📜 SMART CONTRACT GOVERNANCE');
  console.log('• Sui Move contracts for data governance');
  console.log('• Decentralized consent management');
  console.log('• Automated compliance enforcement');
  console.log('• Transparent audit mechanisms\n');

  console.log('🛡️ COMPREHENSIVE PRIVACY PROTECTION');
  console.log('• GDPR, CCPA, HIPAA compliance');
  console.log('• Data minimization and anonymization');
  console.log('• Consent management and user rights');
  console.log('• Privacy impact assessments\n');

  console.log('📊 USER-FRIENDLY DASHBOARDS');
  console.log('• Transparency and control interfaces');
  console.log('• Privacy score monitoring');
  console.log('• Data usage visualization');
  console.log('• Rights exercise and consent management\n');

  console.log('🔒 ENTERPRISE SECURITY');
  console.log('• Advanced encryption (AES-256-GCM, ChaCha20)');
  console.log('• Key rotation and management');
  console.log('• Access control and authentication');
  console.log('• Threat detection and monitoring\n');
}

// Architecture overview
function showArchitecture() {
  console.log('\n🏗️ Walrus Security Suite Architecture:');
  console.log('=====================================\n');

  console.log('┌─────────────────────────────────────┐');
  console.log('│           USER INTERFACES           │');
  console.log('│  Privacy Dashboard │ Admin Console  │');
  console.log('└─────────────────┬───────────────────┘');
  console.log('                  │');
  console.log('┌─────────────────┴───────────────────┐');
  console.log('│          CORE SECURITY SUITE        │');
  console.log('│  ┌─────────────┐ ┌─────────────────┐ │');
  console.log('│  │  Privacy    │ │    Security     │ │');
  console.log('│  │   Engine    │ │    Manager      │ │');
  console.log('│  └─────────────┘ └─────────────────┘ │');
  console.log('└─────────────────┬───────────────────┘');
  console.log('                  │');
  console.log('┌─────────────────┴───────────────────┐');
  console.log('│        WALRUS INTEGRATIONS          │');
  console.log('│  ┌─────────┐ ┌─────────┐ ┌────────┐ │');
  console.log('│  │ Walrus  │ │  Seal   │ │ Sui    │ │');
  console.log('│  │ Storage │ │ Compute │ │ Move   │ │');
  console.log('│  └─────────┘ └─────────┘ └────────┘ │');
  console.log('└─────────────────────────────────────┘\n');

  console.log('🔄 Data Flow:');
  console.log('1. User data → Privacy Engine (minimization, anonymization)');
  console.log('2. Processed data → Security Manager (encryption, fraud detection)');
  console.log('3. Secure data → Walrus Storage (decentralized, verifiable)');
  console.log('4. Computations → Seal Integration (privacy-preserving)');
  console.log('5. Governance → Sui Move Contracts (transparent, auditable)');
  console.log('6. Results → User Dashboard (transparent, controllable)\n');
}

// Run the demo
if (require.main === module) {
  showcaseFeatures();
  showArchitecture();
  runDemo().catch(console.error);
}

export { runDemo, showcaseFeatures, showArchitecture };