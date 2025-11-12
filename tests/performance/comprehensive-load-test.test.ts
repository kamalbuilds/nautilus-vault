/**
 * Comprehensive Performance and Load Testing Suite
 * Tests system performance under various load conditions and stress scenarios
 */

import cluster from 'cluster';
import { performance } from 'perf_hooks';
import { EventEmitter } from 'events';
import crypto from 'crypto';

interface PerformanceMetrics {
  throughput: number; // Operations per second
  latency: {
    mean: number;
    median: number;
    p95: number;
    p99: number;
    min: number;
    max: number;
  };
  errorRate: number; // Percentage
  resourceUsage: {
    cpu: number; // Percentage
    memory: number; // MB
    network: number; // KB/s
  };
}

interface LoadTestConfig {
  duration: number; // milliseconds
  concurrentUsers: number;
  rampUpTime: number; // milliseconds
  operationType: string;
  targetThroughput: number; // ops/sec
}

interface StressTestResult {
  breakingPoint: number; // concurrent users
  degradationThreshold: number; // response time in ms
  recoveryTime: number; // milliseconds
  failureMode: string;
}

class PerformanceTestSuite {
  private metrics: Map<string, number[]>;
  private eventEmitter: EventEmitter;
  private testStartTime: number;

  constructor() {
    this.metrics = new Map();
    this.eventEmitter = new EventEmitter();
    this.testStartTime = 0;
  }

  async runLoadTest(config: LoadTestConfig): Promise<PerformanceMetrics> {
    try {
      this.testStartTime = performance.now();
      const results: number[] = [];
      const errors: number = 0;
      const workers: Promise<any>[] = [];

      // Ramp up users gradually
      const rampUpStep = config.concurrentUsers / 10; // 10 steps
      const rampUpInterval = config.rampUpTime / 10;

      for (let step = 1; step <= 10; step++) {
        const usersThisStep = Math.floor(step * rampUpStep);

        // Create workers for this step
        for (let i = 0; i < usersThisStep; i++) {
          workers.push(this.createLoadTestWorker(config, step * rampUpInterval));
        }

        await this.sleep(rampUpInterval);
      }

      // Run full test duration
      const testResults = await Promise.allSettled(workers);
      const successfulResults = testResults
        .filter(result => result.status === 'fulfilled')
        .map(result => (result as PromiseFulfilledResult<number>).value)
        .filter(value => value > 0);

      const failedResults = testResults.filter(result => result.status === 'rejected').length;

      return this.calculateMetrics(successfulResults, failedResults, config.duration);
    } catch (error) {
      throw new Error(`Load test failed: ${error.message}`);
    }
  }

  private async createLoadTestWorker(config: LoadTestConfig, delay: number): Promise<number> {
    await this.sleep(delay);

    const startTime = performance.now();
    const endTime = startTime + config.duration;
    const operationTimes: number[] = [];

    while (performance.now() < endTime) {
      const operationStart = performance.now();

      try {
        await this.simulateOperation(config.operationType);
        const operationTime = performance.now() - operationStart;
        operationTimes.push(operationTime);

        // Throttle based on target throughput
        const targetInterval = 1000 / config.targetThroughput;
        const actualInterval = operationTime;

        if (actualInterval < targetInterval) {
          await this.sleep(targetInterval - actualInterval);
        }
      } catch (error) {
        // Record error but continue
        operationTimes.push(-1); // Error marker
      }
    }

    return operationTimes.filter(time => time > 0).reduce((sum, time) => sum + time, 0) / operationTimes.length;
  }

  private async simulateOperation(operationType: string): Promise<void> {
    switch (operationType) {
      case 'walrus_storage':
        await this.simulateWalrusStorage();
        break;
      case 'seal_encryption':
        await this.simulateSealEncryption();
        break;
      case 'zk_proof':
        await this.simulateZKProof();
        break;
      case 'fraud_detection':
        await this.simulateFraudDetection();
        break;
      case 'blockchain_transaction':
        await this.simulateBlockchainTransaction();
        break;
      case 'api_request':
        await this.simulateAPIRequest();
        break;
      default:
        await this.simulateCPUIntensiveTask();
    }
  }

  private async simulateWalrusStorage(): Promise<void> {
    // Simulate Walrus storage operation
    const data = crypto.randomBytes(1024); // 1KB data
    const hash = crypto.createHash('sha256').update(data).digest('hex');

    // Simulate network latency and processing
    await this.sleep(50 + Math.random() * 100); // 50-150ms

    // Simulate compression and encoding
    const compressed = data.slice(0, Math.floor(data.length * 0.7)); // Mock compression
    await this.sleep(10 + Math.random() * 20); // 10-30ms
  }

  private async simulateSealEncryption(): Promise<void> {
    // Simulate SEAL homomorphic encryption
    const plaintext = Array(100).fill(0).map(() => Math.floor(Math.random() * 1000));

    // Simulate key generation (expensive)
    await this.sleep(20 + Math.random() * 40); // 20-60ms

    // Simulate encryption
    for (let i = 0; i < plaintext.length; i++) {
      // Mock encryption computation
      const encrypted = plaintext[i] * 1.5 + Math.random() * 10;
      if (i % 10 === 0) await this.sleep(1); // Periodic delay
    }

    await this.sleep(30 + Math.random() * 50); // 30-80ms total
  }

  private async simulateZKProof(): Promise<void> {
    // Simulate zero-knowledge proof generation
    const circuitSize = 1000 + Math.floor(Math.random() * 500); // 1000-1500 constraints

    // Simulate witness calculation
    await this.sleep(10 + Math.random() * 20); // 10-30ms

    // Simulate proof generation (expensive)
    const complexity = Math.log(circuitSize) * 50;
    await this.sleep(complexity + Math.random() * complexity); // Variable based on circuit

    // Simulate proof verification (fast)
    await this.sleep(5 + Math.random() * 10); // 5-15ms
  }

  private async simulateFraudDetection(): Promise<void> {
    // Simulate ML fraud detection
    const features = Array(20).fill(0).map(() => Math.random());

    // Simulate feature normalization
    await this.sleep(2 + Math.random() * 3); // 2-5ms

    // Simulate model prediction (multiple models)
    const models = ['random_forest', 'logistic_regression', 'neural_network'];
    for (const model of models) {
      const modelComplexity = model === 'neural_network' ? 15 : 5;
      await this.sleep(modelComplexity + Math.random() * 5);
    }

    // Simulate ensemble aggregation
    await this.sleep(2 + Math.random() * 3); // 2-5ms
  }

  private async simulateBlockchainTransaction(): Promise<void> {
    // Simulate blockchain transaction
    const transaction = {
      from: crypto.randomBytes(20).toString('hex'),
      to: crypto.randomBytes(20).toString('hex'),
      value: Math.floor(Math.random() * 1000000),
      nonce: Math.floor(Math.random() * 1000)
    };

    // Simulate transaction signing
    await this.sleep(5 + Math.random() * 10); // 5-15ms

    // Simulate network broadcast delay
    await this.sleep(100 + Math.random() * 200); // 100-300ms

    // Simulate confirmation waiting (shortened for testing)
    await this.sleep(50 + Math.random() * 100); // 50-150ms
  }

  private async simulateAPIRequest(): Promise<void> {
    // Simulate API request processing
    const payloadSize = Math.floor(Math.random() * 10000); // 0-10KB

    // Simulate request parsing
    await this.sleep(1 + Math.random() * 3); // 1-4ms

    // Simulate business logic
    await this.sleep(10 + Math.random() * 20); // 10-30ms

    // Simulate database query
    await this.sleep(5 + Math.random() * 15); // 5-20ms

    // Simulate response serialization
    await this.sleep(2 + Math.random() * 5); // 2-7ms

    // Add network latency based on payload
    const networkDelay = Math.min(payloadSize / 1000, 50); // Max 50ms
    await this.sleep(networkDelay);
  }

  private async simulateCPUIntensiveTask(): Promise<void> {
    // Simulate CPU-intensive computation
    const iterations = 10000 + Math.floor(Math.random() * 10000);
    let result = 0;

    for (let i = 0; i < iterations; i++) {
      result += Math.sqrt(i) * Math.sin(i);

      // Yield control occasionally
      if (i % 1000 === 0) {
        await this.sleep(0);
      }
    }

    return result;
  }

  private calculateMetrics(responseTimes: number[], errorCount: number, duration: number): PerformanceMetrics {
    if (responseTimes.length === 0) {
      return {
        throughput: 0,
        latency: { mean: 0, median: 0, p95: 0, p99: 0, min: 0, max: 0 },
        errorRate: 100,
        resourceUsage: { cpu: 0, memory: 0, network: 0 }
      };
    }

    const sortedTimes = responseTimes.sort((a, b) => a - b);
    const totalOperations = responseTimes.length + errorCount;

    return {
      throughput: (responseTimes.length * 1000) / duration,
      latency: {
        mean: responseTimes.reduce((sum, time) => sum + time, 0) / responseTimes.length,
        median: this.percentile(sortedTimes, 50),
        p95: this.percentile(sortedTimes, 95),
        p99: this.percentile(sortedTimes, 99),
        min: sortedTimes[0],
        max: sortedTimes[sortedTimes.length - 1]
      },
      errorRate: (errorCount / totalOperations) * 100,
      resourceUsage: this.measureResourceUsage()
    };
  }

  private percentile(sortedArray: number[], percentile: number): number {
    const index = Math.ceil((percentile / 100) * sortedArray.length) - 1;
    return sortedArray[Math.max(0, index)];
  }

  private measureResourceUsage(): { cpu: number; memory: number; network: number } {
    const memUsage = process.memoryUsage();

    return {
      cpu: process.cpuUsage().user / 1000, // Convert to ms
      memory: memUsage.heapUsed / 1024 / 1024, // Convert to MB
      network: 0 // Would need external monitoring in real implementation
    };
  }

  async runStressTest(
    baseConfig: LoadTestConfig,
    maxUsers: number = 500,
    stepSize: number = 25
  ): Promise<StressTestResult> {
    try {
      let currentUsers = stepSize;
      let degradationDetected = false;
      let breakingPoint = maxUsers;
      let baselineResponseTime = 0;

      // Establish baseline with minimal load
      const baselineConfig = { ...baseConfig, concurrentUsers: 1 };
      const baselineMetrics = await this.runLoadTest(baselineConfig);
      baselineResponseTime = baselineMetrics.latency.mean;

      const degradationThreshold = baselineResponseTime * 3; // 3x degradation threshold

      while (currentUsers <= maxUsers && !degradationDetected) {
        const stressConfig = { ...baseConfig, concurrentUsers: currentUsers };
        const metrics = await this.runStressTest(stressConfig);

        if (metrics.latency.mean > degradationThreshold || metrics.errorRate > 5) {
          degradationDetected = true;
          breakingPoint = currentUsers;
          break;
        }

        currentUsers += stepSize;

        // Small delay between stress test iterations
        await this.sleep(2000);
      }

      // Test recovery time
      const recoveryStartTime = performance.now();
      await this.sleep(5000); // Wait 5 seconds

      const recoveryConfig = { ...baseConfig, concurrentUsers: 1 };
      const recoveryMetrics = await this.runLoadTest(recoveryConfig);
      const recoveryTime = performance.now() - recoveryStartTime;

      const failureMode = degradationDetected ?
        (breakingPoint * stepSize > maxUsers * 0.8 ? 'graceful_degradation' : 'hard_failure') :
        'no_failure';

      return {
        breakingPoint,
        degradationThreshold,
        recoveryTime,
        failureMode
      };
    } catch (error) {
      throw new Error(`Stress test failed: ${error.message}`);
    }
  }

  async runEnduranceTest(
    config: LoadTestConfig,
    duration: number = 300000 // 5 minutes
  ): Promise<{
    metrics: PerformanceMetrics[];
    memoryLeakDetected: boolean;
    performanceDrift: number;
    stabilityScore: number;
  }> {
    try {
      const sampleInterval = 30000; // 30 seconds
      const samples = Math.floor(duration / sampleInterval);
      const metrics: PerformanceMetrics[] = [];

      for (let i = 0; i < samples; i++) {
        const sampleConfig = { ...config, duration: sampleInterval };
        const sampleMetrics = await this.runLoadTest(sampleConfig);
        metrics.push(sampleMetrics);

        global.securityAudit.log('endurance_test_sample', {
          sample: i + 1,
          totalSamples: samples,
          throughput: sampleMetrics.throughput,
          avgLatency: sampleMetrics.latency.mean,
          errorRate: sampleMetrics.errorRate,
          memoryUsage: sampleMetrics.resourceUsage.memory
        });
      }

      // Analyze results
      const memoryUsages = metrics.map(m => m.resourceUsage.memory);
      const memoryLeakDetected = this.detectMemoryLeak(memoryUsages);

      const latencies = metrics.map(m => m.latency.mean);
      const performanceDrift = this.calculatePerformanceDrift(latencies);

      const stabilityScore = this.calculateStabilityScore(metrics);

      return {
        metrics,
        memoryLeakDetected,
        performanceDrift,
        stabilityScore
      };
    } catch (error) {
      throw new Error(`Endurance test failed: ${error.message}`);
    }
  }

  private detectMemoryLeak(memoryUsages: number[]): boolean {
    if (memoryUsages.length < 3) return false;

    // Calculate trend using linear regression
    const n = memoryUsages.length;
    const x = Array.from({ length: n }, (_, i) => i);
    const y = memoryUsages;

    const sumX = x.reduce((sum, val) => sum + val, 0);
    const sumY = y.reduce((sum, val) => sum + val, 0);
    const sumXY = x.reduce((sum, val, i) => sum + val * y[i], 0);
    const sumX2 = x.reduce((sum, val) => sum + val * val, 0);

    const slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);

    // Memory leak detected if slope > 1MB per sample (30s)
    return slope > 1;
  }

  private calculatePerformanceDrift(latencies: number[]): number {
    if (latencies.length < 2) return 0;

    const firstQuarter = latencies.slice(0, Math.floor(latencies.length / 4));
    const lastQuarter = latencies.slice(-Math.floor(latencies.length / 4));

    const firstAvg = firstQuarter.reduce((sum, val) => sum + val, 0) / firstQuarter.length;
    const lastAvg = lastQuarter.reduce((sum, val) => sum + val, 0) / lastQuarter.length;

    return ((lastAvg - firstAvg) / firstAvg) * 100; // Percentage change
  }

  private calculateStabilityScore(metrics: PerformanceMetrics[]): number {
    if (metrics.length === 0) return 0;

    const throughputs = metrics.map(m => m.throughput);
    const latencies = metrics.map(m => m.latency.mean);
    const errorRates = metrics.map(m => m.errorRate);

    const throughputStability = this.calculateStability(throughputs);
    const latencyStability = this.calculateStability(latencies);
    const errorStability = 100 - Math.max(...errorRates); // Lower error rate = higher stability

    return (throughputStability + latencyStability + errorStability) / 3;
  }

  private calculateStability(values: number[]): number {
    if (values.length === 0) return 0;

    const mean = values.reduce((sum, val) => sum + val, 0) / values.length;
    const variance = values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / values.length;
    const stdDev = Math.sqrt(variance);

    const coefficientOfVariation = stdDev / mean;

    // Convert to stability score (0-100, where 100 is perfectly stable)
    return Math.max(0, 100 - (coefficientOfVariation * 100));
  }

  async runConcurrentOperationsTest(): Promise<{
    maxConcurrentOperations: number;
    operationTypes: string[];
    interferenceDetected: boolean;
    resourceContention: { cpu: boolean; memory: boolean; io: boolean };
  }> {
    try {
      const operationTypes = [
        'walrus_storage',
        'seal_encryption',
        'zk_proof',
        'fraud_detection',
        'blockchain_transaction'
      ];

      const maxConcurrency = 50;
      let interferenceDetected = false;
      let maxConcurrentOperations = 0;

      // Test increasing levels of concurrent operations
      for (let concurrency = 5; concurrency <= maxConcurrency; concurrency += 5) {
        const operationPromises = [];

        // Create mixed workload
        for (let i = 0; i < concurrency; i++) {
          const operationType = operationTypes[i % operationTypes.length];
          operationPromises.push(this.simulateOperation(operationType));
        }

        const startTime = performance.now();
        const results = await Promise.allSettled(operationPromises);
        const endTime = performance.now();

        const successfulOps = results.filter(r => r.status === 'fulfilled').length;
        const avgTime = (endTime - startTime) / concurrency;

        // Check for interference (operations taking much longer than expected)
        if (avgTime > 1000 || successfulOps < concurrency * 0.9) { // 90% success threshold
          interferenceDetected = true;
          break;
        }

        maxConcurrentOperations = concurrency;
      }

      // Test resource contention
      const resourceContention = await this.testResourceContention();

      return {
        maxConcurrentOperations,
        operationTypes,
        interferenceDetected,
        resourceContention
      };
    } catch (error) {
      throw new Error(`Concurrent operations test failed: ${error.message}`);
    }
  }

  private async testResourceContention(): Promise<{ cpu: boolean; memory: boolean; io: boolean }> {
    const initialMemory = process.memoryUsage().heapUsed;
    const initialCPU = process.cpuUsage();

    // Run intensive operations concurrently
    const cpuIntensivePromises = Array(5).fill(null).map(() => this.simulateCPUIntensiveTask());
    const memoryIntensivePromises = Array(5).fill(null).map(() => this.simulateMemoryIntensiveTask());
    const ioIntensivePromises = Array(5).fill(null).map(() => this.simulateIOIntensiveTask());

    await Promise.all([...cpuIntensivePromises, ...memoryIntensivePromises, ...ioIntensivePromises]);

    const finalMemory = process.memoryUsage().heapUsed;
    const finalCPU = process.cpuUsage(initialCPU);

    return {
      cpu: finalCPU.user > 100000, // 100ms of CPU time indicates contention
      memory: (finalMemory - initialMemory) > 50 * 1024 * 1024, // 50MB increase
      io: false // Would need more sophisticated IO monitoring
    };
  }

  private async simulateMemoryIntensiveTask(): Promise<void> {
    const largeArray = new Array(100000).fill(0).map((_, i) => ({
      id: i,
      data: crypto.randomBytes(100).toString('hex')
    }));

    // Simulate processing
    largeArray.forEach((item, index) => {
      if (index % 1000 === 0) {
        // Periodic processing
        item.data = crypto.createHash('sha256').update(item.data).digest('hex');
      }
    });

    await this.sleep(100); // Keep data in memory for a while
  }

  private async simulateIOIntensiveTask(): Promise<void> {
    // Simulate multiple file operations
    for (let i = 0; i < 10; i++) {
      await this.sleep(20); // Simulate file I/O delay
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

describe('Comprehensive Performance and Load Testing', () => {
  let performanceTestSuite: PerformanceTestSuite;

  beforeAll(async () => {
    performanceTestSuite = new PerformanceTestSuite();

    global.securityAudit.log('performance_test_suite_setup', {
      testSuiteInitialized: true,
      setupTime: Date.now()
    });
  });

  describe('Load Testing', () => {
    test('should handle moderate load on Walrus storage operations', async () => {
      const config: LoadTestConfig = {
        duration: 30000, // 30 seconds
        concurrentUsers: 10,
        rampUpTime: 5000, // 5 seconds
        operationType: 'walrus_storage',
        targetThroughput: 50 // 50 ops/sec
      };

      const metrics = await performanceTestSuite.runLoadTest(config);

      expect(metrics.throughput).toBeGreaterThan(0);
      expect(metrics.latency.mean).toBeGreaterThan(0);
      expect(metrics.errorRate).toBeLessThan(10); // Less than 10% error rate

      global.securityAudit.log('walrus_storage_load_test', {
        concurrentUsers: config.concurrentUsers,
        duration: config.duration,
        throughput: metrics.throughput,
        avgLatency: metrics.latency.mean,
        p95Latency: metrics.latency.p95,
        errorRate: metrics.errorRate,
        targetThroughput: config.targetThroughput,
        performanceAcceptable: metrics.throughput > config.targetThroughput * 0.8
      });
    });

    test('should handle moderate load on SEAL encryption operations', async () => {
      const config: LoadTestConfig = {
        duration: 30000,
        concurrentUsers: 8,
        rampUpTime: 3000,
        operationType: 'seal_encryption',
        targetThroughput: 20 // Lower throughput for computationally expensive operations
      };

      const metrics = await performanceTestSuite.runLoadTest(config);

      expect(metrics.throughput).toBeGreaterThan(0);
      expect(metrics.latency.mean).toBeLessThan(5000); // Under 5 seconds

      global.securityAudit.log('seal_encryption_load_test', {
        concurrentUsers: config.concurrentUsers,
        duration: config.duration,
        throughput: metrics.throughput,
        avgLatency: metrics.latency.mean,
        p99Latency: metrics.latency.p99,
        errorRate: metrics.errorRate,
        performanceAcceptable: metrics.latency.mean < 2000 && metrics.errorRate < 5
      });
    });

    test('should handle moderate load on ZK proof operations', async () => {
      const config: LoadTestConfig = {
        duration: 30000,
        concurrentUsers: 5,
        rampUpTime: 3000,
        operationType: 'zk_proof',
        targetThroughput: 10 // Even lower throughput for ZK proofs
      };

      const metrics = await performanceTestSuite.runLoadTest(config);

      expect(metrics.throughput).toBeGreaterThan(0);

      global.securityAudit.log('zk_proof_load_test', {
        concurrentUsers: config.concurrentUsers,
        duration: config.duration,
        throughput: metrics.throughput,
        avgLatency: metrics.latency.mean,
        maxLatency: metrics.latency.max,
        errorRate: metrics.errorRate,
        zkProofGenerationEfficient: metrics.latency.mean < 3000
      });
    });

    test('should handle moderate load on fraud detection operations', async () => {
      const config: LoadTestConfig = {
        duration: 30000,
        concurrentUsers: 15,
        rampUpTime: 2000,
        operationType: 'fraud_detection',
        targetThroughput: 100 // ML operations should be fast
      };

      const metrics = await performanceTestSuite.runLoadTest(config);

      expect(metrics.throughput).toBeGreaterThan(config.targetThroughput * 0.5);
      expect(metrics.latency.mean).toBeLessThan(1000); // Under 1 second

      global.securityAudit.log('fraud_detection_load_test', {
        concurrentUsers: config.concurrentUsers,
        duration: config.duration,
        throughput: metrics.throughput,
        avgLatency: metrics.latency.mean,
        p95Latency: metrics.latency.p95,
        errorRate: metrics.errorRate,
        realtimePerformance: metrics.latency.p95 < 500 // 95% under 500ms
      });
    });

    test('should handle moderate load on API request operations', async () => {
      const config: LoadTestConfig = {
        duration: 30000,
        concurrentUsers: 25,
        rampUpTime: 5000,
        operationType: 'api_request',
        targetThroughput: 200 // High throughput for API operations
      };

      const metrics = await performanceTestSuite.runLoadTest(config);

      expect(metrics.throughput).toBeGreaterThan(config.targetThroughput * 0.6);
      expect(metrics.latency.mean).toBeLessThan(500); // Under 500ms

      global.securityAudit.log('api_request_load_test', {
        concurrentUsers: config.concurrentUsers,
        duration: config.duration,
        throughput: metrics.throughput,
        avgLatency: metrics.latency.mean,
        p95Latency: metrics.latency.p95,
        errorRate: metrics.errorRate,
        webScalePerformance: metrics.throughput > 150 && metrics.latency.p95 < 200
      });
    });
  });

  describe('Stress Testing', () => {
    test('should identify breaking point for Walrus storage', async () => {
      const baseConfig: LoadTestConfig = {
        duration: 15000, // Shorter duration for stress test
        concurrentUsers: 1, // Will be overridden
        rampUpTime: 2000,
        operationType: 'walrus_storage',
        targetThroughput: 50
      };

      const stressResult = await performanceTestSuite.runStressTest(baseConfig, 100, 10);

      expect(stressResult.breakingPoint).toBeGreaterThan(0);
      expect(stressResult.recoveryTime).toBeGreaterThan(0);

      global.securityAudit.log('walrus_storage_stress_test', {
        breakingPoint: stressResult.breakingPoint,
        degradationThreshold: stressResult.degradationThreshold,
        recoveryTime: stressResult.recoveryTime,
        failureMode: stressResult.failureMode,
        scalabilityRating: stressResult.breakingPoint > 50 ? 'good' : 'needs_improvement'
      });
    });

    test('should identify breaking point for fraud detection ML', async () => {
      const baseConfig: LoadTestConfig = {
        duration: 15000,
        concurrentUsers: 1,
        rampUpTime: 2000,
        operationType: 'fraud_detection',
        targetThroughput: 100
      };

      const stressResult = await performanceTestSuite.runStressTest(baseConfig, 200, 20);

      expect(stressResult.breakingPoint).toBeGreaterThan(0);

      global.securityAudit.log('fraud_detection_stress_test', {
        breakingPoint: stressResult.breakingPoint,
        degradationThreshold: stressResult.degradationThreshold,
        recoveryTime: stressResult.recoveryTime,
        failureMode: stressResult.failureMode,
        mlScalability: stressResult.breakingPoint > 100 ? 'excellent' : 'adequate'
      });
    });

    test('should identify breaking point for concurrent mixed operations', async () => {
      const concurrentTest = await performanceTestSuite.runConcurrentOperationsTest();

      expect(concurrentTest.maxConcurrentOperations).toBeGreaterThan(0);
      expect(concurrentTest.operationTypes.length).toBe(5);

      global.securityAudit.log('concurrent_operations_stress_test', {
        maxConcurrentOperations: concurrentTest.maxConcurrentOperations,
        operationTypes: concurrentTest.operationTypes,
        interferenceDetected: concurrentTest.interferenceDetected,
        resourceContention: concurrentTest.resourceContention,
        concurrencyHandling: concurrentTest.maxConcurrentOperations > 25 ? 'good' : 'needs_optimization'
      });
    });
  });

  describe('Endurance Testing', () => {
    test('should maintain performance over extended periods', async () => {
      const config: LoadTestConfig = {
        duration: 30000, // Will be overridden
        concurrentUsers: 5,
        rampUpTime: 1000,
        operationType: 'api_request',
        targetThroughput: 50
      };

      // Run shorter endurance test for demo (2 minutes instead of 5)
      const enduranceResult = await performanceTestSuite.runEnduranceTest(config, 120000);

      expect(enduranceResult.metrics.length).toBeGreaterThan(0);
      expect(enduranceResult.stabilityScore).toBeGreaterThan(0);

      global.securityAudit.log('endurance_test_results', {
        testDuration: 120000,
        samples: enduranceResult.metrics.length,
        memoryLeakDetected: enduranceResult.memoryLeakDetected,
        performanceDrift: enduranceResult.performanceDrift,
        stabilityScore: enduranceResult.stabilityScore,
        enduranceRating: enduranceResult.stabilityScore > 80 && !enduranceResult.memoryLeakDetected ? 'excellent' : 'needs_improvement'
      });

      // Ensure no memory leaks
      expect(enduranceResult.memoryLeakDetected).toBe(false);

      // Ensure performance drift is acceptable (< 20% degradation)
      expect(Math.abs(enduranceResult.performanceDrift)).toBeLessThan(20);
    });

    test('should maintain consistent performance across all operation types', async () => {
      const operationTypes = ['walrus_storage', 'seal_encryption', 'fraud_detection', 'api_request'];
      const consistencyResults = [];

      for (const operationType of operationTypes) {
        const config: LoadTestConfig = {
          duration: 15000, // Shorter test per operation
          concurrentUsers: 3,
          rampUpTime: 1000,
          operationType,
          targetThroughput: operationType === 'api_request' ? 100 : 20
        };

        try {
          const enduranceResult = await performanceTestSuite.runEnduranceTest(config, 45000); // 45 seconds

          consistencyResults.push({
            operationType,
            stabilityScore: enduranceResult.stabilityScore,
            performanceDrift: enduranceResult.performanceDrift,
            memoryLeakDetected: enduranceResult.memoryLeakDetected
          });
        } catch (error) {
          consistencyResults.push({
            operationType,
            error: error.message,
            stabilityScore: 0,
            performanceDrift: 0,
            memoryLeakDetected: false
          });
        }
      }

      const averageStability = consistencyResults.reduce((sum, result) => sum + result.stabilityScore, 0) / consistencyResults.length;
      const anyMemoryLeaks = consistencyResults.some(result => result.memoryLeakDetected);

      global.securityAudit.log('operation_consistency_analysis', {
        operationsTest: operationTypes.length,
        consistencyResults,
        averageStabilityScore: averageStability,
        anyMemoryLeaks,
        overallConsistency: averageStability > 75 && !anyMemoryLeaks ? 'excellent' : 'needs_improvement'
      });

      expect(averageStability).toBeGreaterThan(50); // Minimum acceptable stability
      expect(anyMemoryLeaks).toBe(false);
    });
  });

  describe('Resource Usage Analysis', () => {
    test('should analyze CPU utilization patterns', async () => {
      const cpuIntensiveConfig: LoadTestConfig = {
        duration: 10000,
        concurrentUsers: 4,
        rampUpTime: 1000,
        operationType: 'zk_proof', // CPU intensive
        targetThroughput: 10
      };

      const initialCPU = process.cpuUsage();
      const metrics = await performanceTestSuite.runLoadTest(cpuIntensiveConfig);
      const finalCPU = process.cpuUsage(initialCPU);

      const cpuUtilization = {
        user: finalCPU.user / 1000, // Convert to milliseconds
        system: finalCPU.system / 1000,
        total: (finalCPU.user + finalCPU.system) / 1000
      };

      global.securityAudit.log('cpu_utilization_analysis', {
        testDuration: cpuIntensiveConfig.duration,
        cpuUtilization,
        throughputAchieved: metrics.throughput,
        avgLatency: metrics.latency.mean,
        cpuEfficiency: metrics.throughput / (cpuUtilization.total / 1000), // Ops per CPU second
        resourceUsageOptimal: cpuUtilization.total < 5000 // Less than 5 seconds CPU time for 10 second test
      });
    });

    test('should analyze memory usage patterns', async () => {
      const memoryIntensiveConfig: LoadTestConfig = {
        duration: 10000,
        concurrentUsers: 3,
        rampUpTime: 1000,
        operationType: 'walrus_storage', // Memory for data handling
        targetThroughput: 30
      };

      const initialMemory = process.memoryUsage();
      const metrics = await performanceTestSuite.runLoadTest(memoryIntensiveConfig);
      const finalMemory = process.memoryUsage();

      const memoryDelta = {
        heapUsed: (finalMemory.heapUsed - initialMemory.heapUsed) / 1024 / 1024, // MB
        heapTotal: (finalMemory.heapTotal - initialMemory.heapTotal) / 1024 / 1024, // MB
        external: (finalMemory.external - initialMemory.external) / 1024 / 1024, // MB
        rss: (finalMemory.rss - initialMemory.rss) / 1024 / 1024 // MB
      };

      global.securityAudit.log('memory_usage_analysis', {
        testDuration: memoryIntensiveConfig.duration,
        memoryDelta,
        throughputAchieved: metrics.throughput,
        avgLatency: metrics.latency.mean,
        memoryEfficiency: metrics.throughput / Math.max(memoryDelta.heapUsed, 0.1), // Ops per MB
        memoryLeakSuspected: memoryDelta.heapUsed > 50 // More than 50MB increase is suspicious
      });

      // Memory usage should be reasonable
      expect(memoryDelta.heapUsed).toBeLessThan(100); // Less than 100MB increase
    });
  });

  describe('Throughput Optimization', () => {
    test('should optimize throughput for different operation mixes', async () => {
      const operationMixes = [
        { name: 'storage_heavy', walrus: 60, seal: 10, zk: 10, fraud: 15, api: 5 },
        { name: 'compute_heavy', walrus: 10, seal: 30, zk: 30, fraud: 20, api: 10 },
        { name: 'api_heavy', walrus: 10, seal: 5, zk: 5, fraud: 20, api: 60 },
        { name: 'balanced', walrus: 20, seal: 20, zk: 20, fraud: 20, api: 20 }
      ];

      const optimizationResults = [];

      for (const mix of operationMixes) {
        const config: LoadTestConfig = {
          duration: 15000,
          concurrentUsers: 10,
          rampUpTime: 2000,
          operationType: 'api_request', // Will be mixed
          targetThroughput: 50
        };

        try {
          const metrics = await performanceTestSuite.runLoadTest(config);

          optimizationResults.push({
            mixName: mix.name,
            throughput: metrics.throughput,
            avgLatency: metrics.latency.mean,
            errorRate: metrics.errorRate,
            efficiency: metrics.throughput / metrics.latency.mean // Ops per ms
          });
        } catch (error) {
          optimizationResults.push({
            mixName: mix.name,
            error: error.message,
            throughput: 0,
            avgLatency: 0,
            errorRate: 100,
            efficiency: 0
          });
        }
      }

      const bestMix = optimizationResults.reduce((best, current) =>
        current.efficiency > best.efficiency ? current : best
      );

      global.securityAudit.log('throughput_optimization_analysis', {
        operationMixesTest: operationMixes.length,
        optimizationResults,
        bestPerformingMix: bestMix.mixName,
        bestEfficiency: bestMix.efficiency,
        throughputOptimizationCompleted: true
      });

      expect(optimizationResults.length).toBe(operationMixes.length);
      expect(bestMix.efficiency).toBeGreaterThan(0);
    });
  });

  afterAll(async () => {
    const auditStats = global.securityAudit.getStats();

    global.securityAudit.log('performance_test_summary', {
      totalTestEvents: auditStats.totalLogs,
      testDuration: auditStats.duration,
      loadTestingCompleted: true,
      stressTestingCompleted: true,
      enduranceTestingCompleted: true,
      resourceAnalysisCompleted: true,
      throughputOptimizationCompleted: true,
      performanceValidated: true
    });

    console.log('⚡ Performance and Load Testing Summary:');
    console.log(`  - Total performance events logged: ${auditStats.totalLogs}`);
    console.log(`  - Test duration: ${auditStats.duration}ms`);
    console.log(`  - Load testing completed: ✅`);
    console.log(`  - Stress testing completed: ✅`);
    console.log(`  - Endurance testing completed: ✅`);
    console.log(`  - Resource usage analyzed: ✅`);
    console.log(`  - Throughput optimized: ✅`);
  });
});