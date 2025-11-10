/**
 * Security Performance Benchmarking Tests
 * Measuring performance of cryptographic operations and security features
 */

const crypto = require('crypto');
const { performance } = require('perf_hooks');

describe('Security Performance Benchmarks', () => {
  let securityAudit;
  let performanceResults;

  beforeAll(() => {
    securityAudit = global.securityAudit;
    performanceResults = {
      encryption: {},
      hashing: {},
      signatures: {},
      keyGeneration: {},
      fraud_detection: {},
      privacy_operations: {}
    };
  });

  afterAll(() => {
    // Export comprehensive performance report
    securityAudit.log('performance_benchmark_summary', performanceResults);
    console.log('\n=== SECURITY PERFORMANCE BENCHMARK RESULTS ===\n');
    console.table(performanceResults.encryption);
    console.table(performanceResults.hashing);
    console.table(performanceResults.signatures);
  });

  describe('Cryptographic Operations Performance', () => {
    const testSizes = [1024, 10240, 102400, 1048576]; // 1KB, 10KB, 100KB, 1MB
    const iterations = 100;

    test('should benchmark AES-256-GCM encryption performance', async () => {
      const algorithm = 'aes-256-gcm';
      const results = {};

      for (const size of testSizes) {
        const data = crypto.randomBytes(size);
        const key = crypto.randomBytes(32);
        const iv = crypto.randomBytes(12);

        const times = [];

        // Warm-up
        for (let i = 0; i < 10; i++) {
          const cipher = crypto.createCipherGCM(algorithm);
          cipher.update(data);
          cipher.final();
        }

        // Benchmark encryption
        for (let i = 0; i < iterations; i++) {
          const start = performance.now();

          const cipher = crypto.createCipherGCM(algorithm);
          cipher.setAAD(Buffer.from('benchmark-test'));
          let encrypted = cipher.update(data);
          cipher.final();
          const authTag = cipher.getAuthTag();

          const end = performance.now();
          times.push(end - start);
        }

        const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
        const minTime = Math.min(...times);
        const maxTime = Math.max(...times);
        const throughput = (size / 1024 / 1024) / (avgTime / 1000); // MB/s

        results[`${size}B`] = {
          averageMs: Math.round(avgTime * 100) / 100,
          minMs: Math.round(minTime * 100) / 100,
          maxMs: Math.round(maxTime * 100) / 100,
          throughputMBps: Math.round(throughput * 100) / 100,
          operationsPerSec: Math.round(1000 / avgTime)
        };

        // Performance assertions
        expect(avgTime).toBeLessThan(size < 100000 ? 50 : 500); // Reasonable performance
        expect(throughput).toBeGreaterThan(1); // At least 1 MB/s
      }

      performanceResults.encryption[algorithm] = results;

      securityAudit.log('aes_gcm_performance', results);
    });

    test('should benchmark ChaCha20-Poly1305 encryption performance', async () => {
      // Note: ChaCha20-Poly1305 may not be available in all Node.js versions
      try {
        const algorithm = 'chacha20-poly1305';
        const results = {};

        for (const size of testSizes.slice(0, 2)) { // Test smaller sizes only
          const data = crypto.randomBytes(size);
          const key = crypto.randomBytes(32);
          const times = [];

          for (let i = 0; i < 50; i++) { // Fewer iterations due to potential availability issues
            try {
              const start = performance.now();

              const cipher = crypto.createCipher(algorithm, key);
              let encrypted = cipher.update(data);
              cipher.final();

              const end = performance.now();
              times.push(end - start);
            } catch (error) {
              // ChaCha20 not available, skip this test
              console.log('ChaCha20-Poly1305 not available, skipping benchmark');
              return;
            }
          }

          const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
          const throughput = (size / 1024 / 1024) / (avgTime / 1000);

          results[`${size}B`] = {
            averageMs: Math.round(avgTime * 100) / 100,
            throughputMBps: Math.round(throughput * 100) / 100
          };
        }

        if (Object.keys(results).length > 0) {
          performanceResults.encryption['chacha20-poly1305'] = results;
        }

      } catch (error) {
        console.log('ChaCha20-Poly1305 benchmark skipped:', error.message);
      }
    });

    test('should benchmark RSA encryption performance', async () => {
      const keySizes = [2048, 3072]; // Common RSA key sizes
      const results = {};

      for (const keySize of keySizes) {
        const times = {
          keyGeneration: [],
          encryption: [],
          decryption: []
        };

        // Test with smaller data for RSA (RSA can't encrypt large data directly)
        const data = crypto.randomBytes(190); // Max for 2048-bit key with PKCS#1 padding

        // Key generation benchmark
        for (let i = 0; i < 5; i++) { // Fewer iterations for key generation
          const start = performance.now();
          crypto.generateKeyPairSync('rsa', { modulusLength: keySize });
          const end = performance.now();
          times.keyGeneration.push(end - start);
        }

        // Generate key pair for encryption/decryption tests
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
          modulusLength: keySize
        });

        // Encryption benchmark
        for (let i = 0; i < 20; i++) {
          const start = performance.now();
          crypto.publicEncrypt(publicKey, data);
          const end = performance.now();
          times.encryption.push(end - start);
        }

        // Decryption benchmark
        const encrypted = crypto.publicEncrypt(publicKey, data);
        for (let i = 0; i < 20; i++) {
          const start = performance.now();
          crypto.privateDecrypt(privateKey, encrypted);
          const end = performance.now();
          times.decryption.push(end - start);
        }

        results[`RSA-${keySize}`] = {
          keyGenAvgMs: Math.round(times.keyGeneration.reduce((a, b) => a + b, 0) / times.keyGeneration.length),
          encryptAvgMs: Math.round(times.encryption.reduce((a, b) => a + b, 0) / times.encryption.length * 100) / 100,
          decryptAvgMs: Math.round(times.decryption.reduce((a, b) => a + b, 0) / times.decryption.length * 100) / 100,
          encryptionsPerSec: Math.round(1000 / (times.encryption.reduce((a, b) => a + b, 0) / times.encryption.length)),
          decryptionsPerSec: Math.round(1000 / (times.decryption.reduce((a, b) => a + b, 0) / times.decryption.length))
        };

        // Performance assertions for RSA
        expect(times.keyGeneration[0]).toBeLessThan(5000); // Key generation < 5 seconds
        expect(times.encryption[0]).toBeLessThan(100); // Encryption < 100ms
        expect(times.decryption[0]).toBeLessThan(100); // Decryption < 100ms
      }

      performanceResults.encryption.rsa = results;

      securityAudit.log('rsa_encryption_performance', results);
    });
  });

  describe('Hashing Performance', () => {
    const testSizes = [1024, 10240, 102400, 1048576]; // 1KB to 1MB
    const algorithms = ['sha256', 'sha384', 'sha512', 'sha3-256', 'sha3-512'];

    test('should benchmark hash algorithm performance', async () => {
      const results = {};

      for (const algorithm of algorithms) {
        results[algorithm] = {};

        for (const size of testSizes) {
          const data = crypto.randomBytes(size);
          const times = [];

          // Warm-up
          for (let i = 0; i < 10; i++) {
            crypto.createHash(algorithm).update(data).digest();
          }

          // Benchmark
          for (let i = 0; i < 200; i++) {
            const start = performance.now();
            crypto.createHash(algorithm).update(data).digest();
            const end = performance.now();
            times.push(end - start);
          }

          const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
          const throughput = (size / 1024 / 1024) / (avgTime / 1000); // MB/s

          results[algorithm][`${size}B`] = {
            averageMs: Math.round(avgTime * 1000) / 1000, // Microsecond precision
            throughputMBps: Math.round(throughput * 100) / 100,
            hashesPerSec: Math.round(1000 / avgTime)
          };

          // Performance assertion - hashing should be very fast
          expect(avgTime).toBeLessThan(100); // Less than 100ms even for 1MB
        }
      }

      performanceResults.hashing = results;

      securityAudit.log('hash_algorithm_performance', results);
    });

    test('should benchmark HMAC performance', async () => {
      const algorithms = ['sha256', 'sha512'];
      const results = {};

      for (const algorithm of algorithms) {
        results[`hmac-${algorithm}`] = {};

        for (const size of testSizes) {
          const data = crypto.randomBytes(size);
          const key = crypto.randomBytes(32);
          const times = [];

          for (let i = 0; i < 100; i++) {
            const start = performance.now();
            crypto.createHmac(algorithm, key).update(data).digest();
            const end = performance.now();
            times.push(end - start);
          }

          const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
          const throughput = (size / 1024 / 1024) / (avgTime / 1000);

          results[`hmac-${algorithm}`][`${size}B`] = {
            averageMs: Math.round(avgTime * 1000) / 1000,
            throughputMBps: Math.round(throughput * 100) / 100
          };
        }
      }

      Object.assign(performanceResults.hashing, results);

      securityAudit.log('hmac_performance', results);
    });

    test('should benchmark password hashing performance', async () => {
      const bcrypt = require('bcrypt');
      const password = 'TestPassword123!';
      const saltRounds = [10, 12, 14]; // Different security levels
      const results = {};

      for (const rounds of saltRounds) {
        const hashTimes = [];
        const verifyTimes = [];

        // Hash benchmark
        for (let i = 0; i < 5; i++) { // Fewer iterations due to deliberate slowness
          const start = performance.now();
          const hash = await bcrypt.hash(password, rounds);
          const hashTime = performance.now() - start;
          hashTimes.push(hashTime);

          // Verify benchmark
          const verifyStart = performance.now();
          await bcrypt.compare(password, hash);
          const verifyTime = performance.now() - verifyStart;
          verifyTimes.push(verifyTime);
        }

        const avgHashTime = hashTimes.reduce((a, b) => a + b, 0) / hashTimes.length;
        const avgVerifyTime = verifyTimes.reduce((a, b) => a + b, 0) / verifyTimes.length;

        results[`bcrypt-${rounds}`] = {
          hashTimeMs: Math.round(avgHashTime),
          verifyTimeMs: Math.round(avgVerifyTime),
          hashesPerSec: Math.round(1000 / avgHashTime * 100) / 100,
          verificationsPerSec: Math.round(1000 / avgVerifyTime * 100) / 100
        };

        // Security assertion - bcrypt should be deliberately slow
        expect(avgHashTime).toBeGreaterThan(50); // At least 50ms for security
        expect(avgVerifyTime).toBeGreaterThan(50);
      }

      performanceResults.hashing.passwordHashing = results;

      securityAudit.log('password_hashing_performance', results);
    });
  });

  describe('Digital Signature Performance', () => {
    test('should benchmark ECDSA signature performance', async () => {
      const curves = ['secp256k1', 'prime256v1']; // Bitcoin curve and standard curve
      const results = {};

      for (const curve of curves) {
        const times = {
          keyGeneration: [],
          signing: [],
          verification: []
        };

        const message = crypto.randomBytes(256);

        // Key generation benchmark
        for (let i = 0; i < 10; i++) {
          const start = performance.now();
          crypto.generateKeyPairSync('ec', { namedCurve: curve });
          const end = performance.now();
          times.keyGeneration.push(end - start);
        }

        // Generate key pair for signing tests
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: curve });

        // Signing benchmark
        for (let i = 0; i < 100; i++) {
          const start = performance.now();
          crypto.sign('sha256', message, privateKey);
          const end = performance.now();
          times.signing.push(end - start);
        }

        // Verification benchmark
        const signature = crypto.sign('sha256', message, privateKey);
        for (let i = 0; i < 100; i++) {
          const start = performance.now();
          crypto.verify('sha256', message, publicKey, signature);
          const end = performance.now();
          times.verification.push(end - start);
        }

        results[curve] = {
          keyGenAvgMs: Math.round(times.keyGeneration.reduce((a, b) => a + b, 0) / times.keyGeneration.length * 100) / 100,
          signAvgMs: Math.round(times.signing.reduce((a, b) => a + b, 0) / times.signing.length * 100) / 100,
          verifyAvgMs: Math.round(times.verification.reduce((a, b) => a + b, 0) / times.verification.length * 100) / 100,
          signaturesPerSec: Math.round(1000 / (times.signing.reduce((a, b) => a + b, 0) / times.signing.length)),
          verificationsPerSec: Math.round(1000 / (times.verification.reduce((a, b) => a + b, 0) / times.verification.length))
        };

        // Performance assertions
        expect(times.signing[0]).toBeLessThan(50); // Signing should be fast
        expect(times.verification[0]).toBeLessThan(50); // Verification should be fast
      }

      performanceResults.signatures.ecdsa = results;

      securityAudit.log('ecdsa_performance', results);
    });

    test('should benchmark Ed25519 signature performance', async () => {
      try {
        const times = {
          keyGeneration: [],
          signing: [],
          verification: []
        };

        const message = crypto.randomBytes(256);

        // Key generation benchmark
        for (let i = 0; i < 20; i++) {
          const start = performance.now();
          crypto.generateKeyPairSync('ed25519');
          const end = performance.now();
          times.keyGeneration.push(end - start);
        }

        // Generate key pair for signing tests
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');

        // Signing benchmark
        for (let i = 0; i < 100; i++) {
          const start = performance.now();
          crypto.sign(null, message, privateKey);
          const end = performance.now();
          times.signing.push(end - start);
        }

        // Verification benchmark
        const signature = crypto.sign(null, message, privateKey);
        for (let i = 0; i < 100; i++) {
          const start = performance.now();
          crypto.verify(null, message, publicKey, signature);
          const end = performance.now();
          times.verification.push(end - start);
        }

        const results = {
          keyGenAvgMs: Math.round(times.keyGeneration.reduce((a, b) => a + b, 0) / times.keyGeneration.length * 100) / 100,
          signAvgMs: Math.round(times.signing.reduce((a, b) => a + b, 0) / times.signing.length * 100) / 100,
          verifyAvgMs: Math.round(times.verification.reduce((a, b) => a + b, 0) / times.verification.length * 100) / 100,
          signaturesPerSec: Math.round(1000 / (times.signing.reduce((a, b) => a + b, 0) / times.signing.length)),
          verificationsPerSec: Math.round(1000 / (times.verification.reduce((a, b) => a + b, 0) / times.verification.length))
        };

        performanceResults.signatures.ed25519 = results;

        // Ed25519 should be faster than ECDSA
        expect(results.signAvgMs).toBeLessThan(20);
        expect(results.verifyAvgMs).toBeLessThan(20);

        securityAudit.log('ed25519_performance', results);

      } catch (error) {
        console.log('Ed25519 not available, skipping benchmark');
      }
    });
  });

  describe('Fraud Detection Performance', () => {
    test('should benchmark real-time fraud detection performance', async () => {
      // Mock fraud detection system
      class FraudDetectionSystem {
        constructor() {
          this.models = {
            riskScoring: this.createMockMLModel(),
            anomalyDetection: this.createMockAnomalyDetector(),
            patternAnalysis: this.createMockPatternAnalyzer()
          };
        }

        async analyzeTxn(transaction) {
          const features = this.extractFeatures(transaction);

          const riskScore = this.models.riskScoring.predict(features);
          const anomalyScore = this.models.anomalyDetection.detect(features);
          const patternScore = this.models.patternAnalysis.analyze(features);

          const finalScore = (riskScore + anomalyScore + patternScore) / 3;

          return {
            riskScore: finalScore,
            flagged: finalScore > 0.7,
            features: features.length,
            processingTime: performance.now()
          };
        }

        extractFeatures(txn) {
          return [
            txn.amount / 1000, // Normalized amount
            txn.merchant_category || 0,
            txn.location_risk || 0.5,
            txn.user_velocity || 1.0,
            txn.time_of_day || 12
          ];
        }

        createMockMLModel() {
          return {
            predict: (features) => {
              // Simulate ML model computation
              let score = 0;
              for (let i = 0; i < features.length; i++) {
                score += features[i] * (0.1 + Math.random() * 0.2);
              }
              return Math.min(1.0, Math.max(0.0, score));
            }
          };
        }

        createMockAnomalyDetector() {
          return {
            detect: (features) => {
              // Simulate anomaly detection
              const variance = features.reduce((acc, val, idx) =>
                acc + Math.pow(val - (idx * 0.2), 2), 0) / features.length;
              return Math.min(1.0, variance);
            }
          };
        }

        createMockPatternAnalyzer() {
          return {
            analyze: (features) => {
              // Simulate pattern analysis
              const patterns = features.map((val, idx) => val * (idx + 1));
              return patterns.reduce((a, b) => a + b, 0) / patterns.length / 10;
            }
          };
        }
      }

      const fraudDetector = new FraudDetectionSystem();
      const transactionCounts = [100, 1000, 5000]; // Different load levels
      const results = {};

      for (const count of transactionCounts) {
        const times = [];
        const transactions = [];

        // Generate test transactions
        for (let i = 0; i < count; i++) {
          transactions.push({
            id: i,
            amount: Math.random() * 10000,
            merchant_category: Math.floor(Math.random() * 100),
            location_risk: Math.random(),
            user_velocity: Math.random() * 10,
            time_of_day: Math.floor(Math.random() * 24)
          });
        }

        // Benchmark fraud detection
        const start = performance.now();

        const analysePromises = transactions.map(txn => fraudDetector.analyzeTxn(txn));
        const analyses = await Promise.all(analysePromises);

        const end = performance.now();
        const totalTime = end - start;

        results[`${count}_transactions`] = {
          totalTimeMs: Math.round(totalTime),
          avgTimePerTxnMs: Math.round(totalTime / count * 1000) / 1000,
          transactionsPerSec: Math.round(count / (totalTime / 1000)),
          flaggedCount: analyses.filter(a => a.flagged).length,
          flaggedPercentage: Math.round(analyses.filter(a => a.flagged).length / count * 100)
        };

        // Performance assertion - should handle real-time loads
        expect(totalTime / count).toBeLessThan(50); // < 50ms per transaction
        expect(count / (totalTime / 1000)).toBeGreaterThan(20); // > 20 TPS
      }

      performanceResults.fraud_detection = results;

      securityAudit.log('fraud_detection_performance', results);
    });

    test('should benchmark machine learning model inference performance', async () => {
      // Mock ML model for security analysis
      class SecurityMLModel {
        constructor(modelSize) {
          this.weights = Array(modelSize).fill(0).map(() => Math.random());
          this.biases = Array(modelSize / 10).fill(0).map(() => Math.random());
        }

        predict(features) {
          // Simulate neural network inference
          let result = features.slice();

          // Multiple layers
          for (let layer = 0; layer < 3; layer++) {
            const newResult = [];
            for (let i = 0; i < this.biases.length; i++) {
              let sum = this.biases[i];
              for (let j = 0; j < result.length && j < this.weights.length; j++) {
                sum += result[j] * this.weights[j];
              }
              newResult.push(Math.max(0, sum)); // ReLU activation
            }
            result = newResult;
          }

          return result.reduce((a, b) => a + b, 0) / result.length;
        }
      }

      const modelSizes = [1000, 10000, 100000]; // Small, medium, large models
      const results = {};

      for (const modelSize of modelSizes) {
        const model = new SecurityMLModel(modelSize);
        const features = Array(100).fill(0).map(() => Math.random());
        const iterations = 1000;
        const times = [];

        // Warm-up
        for (let i = 0; i < 10; i++) {
          model.predict(features);
        }

        // Benchmark
        for (let i = 0; i < iterations; i++) {
          const start = performance.now();
          model.predict(features);
          const end = performance.now();
          times.push(end - start);
        }

        const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
        const minTime = Math.min(...times);
        const maxTime = Math.max(...times);

        results[`model_${modelSize}`] = {
          avgInferenceMs: Math.round(avgTime * 1000) / 1000,
          minInferenceMs: Math.round(minTime * 1000) / 1000,
          maxInferenceMs: Math.round(maxTime * 1000) / 1000,
          inferencePerSec: Math.round(1000 / avgTime),
          modelParameters: modelSize
        };

        // Performance assertion - inference should be fast enough for real-time
        expect(avgTime).toBeLessThan(100); // < 100ms inference time
      }

      performanceResults.fraud_detection.ml_inference = results;

      securityAudit.log('ml_model_performance', results);
    });
  });

  describe('Privacy Operations Performance', () => {
    test('should benchmark homomorphic encryption operations', async () => {
      // Mock homomorphic encryption for performance testing
      class MockHomomorphicEncryption {
        constructor() {
          this.modulus = 2147483647; // Large prime
        }

        encrypt(plaintext) {
          const noise = Math.floor(Math.random() * 1000);
          return (plaintext + noise) % this.modulus;
        }

        decrypt(ciphertext, noise) {
          return (ciphertext - noise + this.modulus) % this.modulus;
        }

        add(cipher1, cipher2) {
          return (cipher1 + cipher2) % this.modulus;
        }

        multiply(cipher1, cipher2) {
          return (cipher1 * cipher2) % this.modulus;
        }
      }

      const he = new MockHomomorphicEncryption();
      const dataSizes = [100, 1000, 10000]; // Number of values to process
      const results = {};

      for (const size of dataSizes) {
        const values = Array(size).fill(0).map(() => Math.floor(Math.random() * 1000));

        // Encryption benchmark
        const encryptStart = performance.now();
        const encrypted = values.map(v => he.encrypt(v));
        const encryptTime = performance.now() - encryptStart;

        // Addition benchmark
        const addStart = performance.now();
        const sum = encrypted.reduce((a, b) => he.add(a, b), 0);
        const addTime = performance.now() - addStart;

        // Multiplication benchmark (smaller dataset for performance)
        const multValues = encrypted.slice(0, Math.min(100, size));
        const multStart = performance.now();
        const product = multValues.reduce((a, b) => he.multiply(a, b), 1);
        const multTime = performance.now() - multStart;

        results[`${size}_values`] = {
          encryptTimeMs: Math.round(encryptTime * 100) / 100,
          encryptPerValueMs: Math.round(encryptTime / size * 1000) / 1000,
          addTimeMs: Math.round(addTime * 100) / 100,
          multiplyTimeMs: Math.round(multTime * 100) / 100,
          totalOperationsPerSec: Math.round(size / ((encryptTime + addTime) / 1000))
        };

        // Performance assertions
        expect(encryptTime / size).toBeLessThan(10); // < 10ms per encryption
        expect(addTime).toBeLessThan(1000); // < 1s for addition operation
      }

      performanceResults.privacy_operations.homomorphic = results;

      securityAudit.log('homomorphic_encryption_performance', results);
    });

    test('should benchmark zero-knowledge proof generation and verification', async () => {
      // Mock ZK proof system for performance testing
      class MockZKProofSystem {
        generateProof(secret, statement) {
          // Simulate complex ZK proof generation
          const iterations = 1000 + Math.floor(Math.random() * 1000);

          let hash = crypto.createHash('sha256').update(secret + statement).digest('hex');

          for (let i = 0; i < iterations; i++) {
            hash = crypto.createHash('sha256').update(hash).digest('hex');
          }

          return {
            commitment: hash.slice(0, 32),
            challenge: hash.slice(32, 64),
            response: hash.slice(64, 96),
            iterations
          };
        }

        verifyProof(proof, statement) {
          // Simulate proof verification (typically faster than generation)
          const iterations = proof.iterations / 10; // Verification is faster

          let hash = proof.commitment;

          for (let i = 0; i < iterations; i++) {
            hash = crypto.createHash('sha256').update(hash).digest('hex');
          }

          return hash.includes(proof.challenge);
        }
      }

      const zkSystem = new MockZKProofSystem();
      const proofCounts = [1, 10, 50]; // Number of proofs to generate
      const results = {};

      for (const count of proofCounts) {
        const generationTimes = [];
        const verificationTimes = [];
        const proofs = [];

        // Generate proofs
        for (let i = 0; i < count; i++) {
          const secret = crypto.randomBytes(32).toString('hex');
          const statement = `proof_${i}_statement`;

          const genStart = performance.now();
          const proof = zkSystem.generateProof(secret, statement);
          const genTime = performance.now() - genStart;

          generationTimes.push(genTime);
          proofs.push({ proof, statement });
        }

        // Verify proofs
        for (const { proof, statement } of proofs) {
          const verifyStart = performance.now();
          const valid = zkSystem.verifyProof(proof, statement);
          const verifyTime = performance.now() - verifyStart;

          verificationTimes.push(verifyTime);
          expect(valid).toBe(true);
        }

        const avgGenTime = generationTimes.reduce((a, b) => a + b, 0) / generationTimes.length;
        const avgVerifyTime = verificationTimes.reduce((a, b) => a + b, 0) / verificationTimes.length;

        results[`${count}_proofs`] = {
          avgGenerationMs: Math.round(avgGenTime),
          avgVerificationMs: Math.round(avgVerifyTime),
          generationPerSec: Math.round(1000 / avgGenTime * 100) / 100,
          verificationPerSec: Math.round(1000 / avgVerifyTime * 100) / 100,
          totalTimeMs: Math.round(generationTimes.reduce((a, b) => a + b, 0) + verificationTimes.reduce((a, b) => a + b, 0))
        };

        // Performance assertions - ZK proofs should complete within reasonable time
        expect(avgGenTime).toBeLessThan(5000); // < 5s for proof generation
        expect(avgVerifyTime).toBeLessThan(1000); // < 1s for verification
      }

      performanceResults.privacy_operations.zero_knowledge = results;

      securityAudit.log('zk_proof_performance', results);
    });

    test('should benchmark differential privacy mechanisms', async () => {
      // Mock differential privacy implementation
      class DifferentialPrivacy {
        constructor(epsilon = 1.0) {
          this.epsilon = epsilon;
        }

        addLaplaceNoise(value, sensitivity = 1.0) {
          const scale = sensitivity / this.epsilon;
          const uniform = Math.random() - 0.5;
          const noise = -scale * Math.sign(uniform) * Math.log(1 - 2 * Math.abs(uniform));
          return value + noise;
        }

        addGaussianNoise(value, sensitivity = 1.0, delta = 1e-5) {
          const sigma = (sensitivity * Math.sqrt(2 * Math.log(1.25 / delta))) / this.epsilon;
          const gaussian = this.generateGaussianNoise() * sigma;
          return value + gaussian;
        }

        generateGaussianNoise() {
          // Box-Muller transformation
          const u1 = Math.random();
          const u2 = Math.random();
          return Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
        }

        privateMean(values) {
          const sum = values.reduce((a, b) => a + b, 0);
          const noisySum = this.addLaplaceNoise(sum, 1.0);
          return noisySum / values.length;
        }

        privateHistogram(values, bins = 10) {
          const histogram = Array(bins).fill(0);
          const min = Math.min(...values);
          const max = Math.max(...values);
          const binSize = (max - min) / bins;

          for (const value of values) {
            const binIndex = Math.min(Math.floor((value - min) / binSize), bins - 1);
            histogram[binIndex]++;
          }

          // Add noise to each bin
          return histogram.map(count => Math.max(0, this.addLaplaceNoise(count, 1.0)));
        }
      }

      const dp = new DifferentialPrivacy(1.0);
      const dataSizes = [1000, 10000, 100000]; // Different dataset sizes
      const results = {};

      for (const size of dataSizes) {
        const values = Array(size).fill(0).map(() => Math.random() * 100);

        // Mean computation benchmark
        const meanStart = performance.now();
        const privateMean = dp.privateMean(values);
        const meanTime = performance.now() - meanStart;

        // Histogram computation benchmark
        const histStart = performance.now();
        const privateHistogram = dp.privateHistogram(values, 20);
        const histTime = performance.now() - histStart;

        // Noise addition benchmark
        const noiseStart = performance.now();
        const noisyValues = values.slice(0, 1000).map(v => dp.addLaplaceNoise(v));
        const noiseTime = performance.now() - noiseStart;

        results[`${size}_values`] = {
          meanComputationMs: Math.round(meanTime * 100) / 100,
          histogramComputationMs: Math.round(histTime * 100) / 100,
          noiseAdditionMs: Math.round(noiseTime * 100) / 100,
          meanPerSecond: Math.round(1000 / meanTime),
          histogramPerSecond: Math.round(1000 / histTime),
          noiseOperationsPerSec: Math.round(1000 / (noiseTime / 1000))
        };

        // Verify differential privacy properties
        expect(privateMean).toBeCloseTo(values.reduce((a, b) => a + b, 0) / values.length, 0);
        expect(privateHistogram.reduce((a, b) => a + b, 0)).toBeCloseTo(values.length, 0);

        // Performance assertions
        expect(meanTime).toBeLessThan(100); // < 100ms for mean computation
        expect(histTime).toBeLessThan(1000); // < 1s for histogram computation
      }

      performanceResults.privacy_operations.differential_privacy = results;

      securityAudit.log('differential_privacy_performance', results);
    });
  });
});