/**
 * Comprehensive Fraud Detection Tests
 * Validates that the ML fraud detection system returns proper risk scores
 */

import { FraudDetector } from '../src/security/fraud-detector';
import { MLSecurityAnalyzer } from '../src/security/ml-security-analyzer';
import { SecurityEvent } from '../src/types';

describe('Enhanced Fraud Detection System', () => {
  let fraudDetector: FraudDetector;
  let mlAnalyzer: MLSecurityAnalyzer;

  beforeEach(async () => {
    mlAnalyzer = new MLSecurityAnalyzer();
    await mlAnalyzer.initialize();
    fraudDetector = new FraudDetector(mlAnalyzer);
  });

  describe('High Risk Transaction Scenarios', () => {
    it('should detect high-risk transaction with score >= 0.4', async () => {
      const suspiciousEvent: SecurityEvent = {
        id: 'test-1',
        type: 'transaction',
        timestamp: new Date('2024-01-15T02:30:00Z'), // 2:30 AM - suspicious time
        userId: 'user123',
        details: {
          sessionDuration: 30000 // Very short session
        }
      };

      const suspiciousContext = {
        transaction: {
          amount: 15000, // High amount
          currency: 'BTC', // Crypto currency
          recipient: 'temp@10minutemail.com' // Temp email
        },
        location: {
          country: 'AF', // High-risk country (Afghanistan)
          ip: '185.220.100.240', // Tor exit node
          timezoneOffset: 8
        },
        network: {
          ip: '185.220.100.240',
          riskScore: 0.8,
          connectionSpeed: 100
        },
        device: {
          isNewDevice: true,
          isMobile: false,
          isJailbroken: true,
          cookiesEnabled: false
        }
      };

      const result = await fraudDetector.detectFraud(suspiciousEvent, suspiciousContext);

      console.log('High-risk transaction result:', {
        overall: result.riskScore.overall,
        transactional: result.riskScore.transactional,
        network: result.riskScore.network,
        isFraud: result.isFraud,
        indicatorCount: result.indicators.length
      });

      // Should detect as fraud with high confidence
      expect(result.riskScore.overall).toBeGreaterThanOrEqual(0.4);
      expect(result.isFraud).toBe(true);
      expect(result.indicators.length).toBeGreaterThan(0);
    });

    it('should detect VPN/Tor usage with elevated risk', async () => {
      const torEvent: SecurityEvent = {
        id: 'test-2',
        type: 'transaction',
        timestamp: new Date(),
        userId: 'user456',
        details: {}
      };

      const torContext = {
        transaction: {
          amount: 5000,
          currency: 'USD'
        },
        location: {
          country: 'US',
          ip: '185.220.100.241' // Another Tor exit node
        },
        network: {
          ip: '185.220.100.241',
          riskScore: 0.6
        },
        device: {
          isNewDevice: false,
          isMobile: true
        }
      };

      const result = await fraudDetector.detectFraud(torEvent, torContext);

      console.log('Tor usage result:', {
        overall: result.riskScore.overall,
        network: result.riskScore.network,
        isFraud: result.isFraud
      });

      expect(result.riskScore.network).toBeGreaterThan(0.3);
      expect(result.riskScore.overall).toBeGreaterThan(0.2);
    });

    it('should detect unusual transaction amount patterns', async () => {
      const highAmountEvent: SecurityEvent = {
        id: 'test-3',
        type: 'transaction',
        timestamp: new Date(),
        userId: 'user789',
        details: {}
      };

      const highAmountContext = {
        transaction: {
          amount: 50000, // Very high amount
          currency: 'USD'
        },
        location: {
          country: 'US',
          ip: '192.168.1.1'
        },
        network: {
          ip: '192.168.1.1',
          riskScore: 0.1
        },
        device: {
          isNewDevice: true, // New device with high amount
          isMobile: false
        }
      };

      const result = await fraudDetector.detectFraud(highAmountEvent, highAmountContext);

      console.log('High amount result:', {
        overall: result.riskScore.overall,
        transactional: result.riskScore.transactional,
        isFraud: result.isFraud
      });

      expect(result.riskScore.transactional).toBeGreaterThan(0.3);
      expect(result.riskScore.overall).toBeGreaterThan(0.2);
    });
  });

  describe('Low Risk Transaction Scenarios', () => {
    it('should allow normal transactions with low risk scores', async () => {
      const normalEvent: SecurityEvent = {
        id: 'test-4',
        type: 'transaction',
        timestamp: new Date('2024-01-15T14:30:00Z'), // 2:30 PM - business hours
        userId: 'user999',
        details: {
          sessionDuration: 300000 // 5 minutes - normal session
        }
      };

      const normalContext = {
        transaction: {
          amount: 100, // Small amount
          currency: 'USD',
          recipient: 'user@gmail.com'
        },
        location: {
          country: 'US', // Low-risk country
          ip: '74.125.224.72', // Google IP - legitimate
          timezoneOffset: -5
        },
        network: {
          ip: '74.125.224.72',
          riskScore: 0.1,
          connectionSpeed: 50
        },
        device: {
          isNewDevice: false,
          isMobile: true,
          cookiesEnabled: true
        }
      };

      const result = await fraudDetector.detectFraud(normalEvent, normalContext);

      console.log('Normal transaction result:', {
        overall: result.riskScore.overall,
        isFraud: result.isFraud,
        indicatorCount: result.indicators.length
      });

      expect(result.riskScore.overall).toBeLessThan(0.3);
      expect(result.isFraud).toBe(false);
    });
  });

  describe('ML Model Feature Engineering', () => {
    it('should extract proper number of features', async () => {
      const testEvent: SecurityEvent = {
        id: 'test-5',
        type: 'transaction',
        timestamp: new Date(),
        userId: 'feature-test',
        details: {}
      };

      const testContext = {
        transaction: { amount: 1000, currency: 'USD' },
        location: { country: 'US', ip: '1.2.3.4' },
        network: { ip: '1.2.3.4', riskScore: 0.2 },
        device: { isNewDevice: false, isMobile: true }
      };

      // Access private method through type assertion
      const fraudDetectorAny = fraudDetector as any;
      const features = fraudDetectorAny.extractFeatures(testEvent, testContext);

      console.log('Extracted features count:', features.length);
      console.log('Sample features:', features.slice(0, 10));

      // Should extract 20+ features for comprehensive analysis
      expect(features).toBeDefined();
      expect(features.length).toBeGreaterThanOrEqual(20);
      expect(features.every(f => typeof f === 'number')).toBe(true);
    });
  });

  describe('Risk Score Validation', () => {
    it('should return realistic risk scores for various scenarios', async () => {
      const scenarios = [
        {
          name: 'Multiple risk factors',
          event: {
            id: 'multi-risk',
            type: 'transaction',
            timestamp: new Date('2024-01-15T03:00:00Z'),
            userId: 'risky-user',
            details: { sessionDuration: 10000 }
          },
          context: {
            transaction: { amount: 25000, currency: 'BTC' },
            location: { country: 'IR', ip: '185.220.100.240' },
            network: { ip: '185.220.100.240', riskScore: 0.9 },
            device: { isNewDevice: true, isJailbroken: true }
          },
          expectedMinRisk: 0.5
        },
        {
          name: 'Medium risk scenario',
          event: {
            id: 'medium-risk',
            type: 'transaction',
            timestamp: new Date(),
            userId: 'medium-user',
            details: {}
          },
          context: {
            transaction: { amount: 8000, currency: 'USD' },
            location: { country: 'PK', ip: '192.168.1.1' },
            network: { ip: '192.168.1.1', riskScore: 0.4 },
            device: { isNewDevice: true }
          },
          expectedMinRisk: 0.25
        }
      ];

      for (const scenario of scenarios) {
        const result = await fraudDetector.detectFraud(scenario.event, scenario.context);

        console.log(`${scenario.name} risk score:`, result.riskScore.overall);

        expect(result.riskScore.overall).toBeGreaterThanOrEqual(scenario.expectedMinRisk);
        expect(result.riskScore.overall).toBeLessThanOrEqual(1.0);
      }
    });
  });
});