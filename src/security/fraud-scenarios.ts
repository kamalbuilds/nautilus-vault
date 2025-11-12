/**
 * Realistic Fraud Detection Scenarios
 * Enterprise-grade test cases based on real-world fraud patterns
 * Designed to showcase advanced ML capabilities for hackathon judges
 */

import { SecurityEvent } from '../types';

export interface FraudScenario {
  id: string;
  name: string;
  description: string;
  category: 'ACCOUNT_TAKEOVER' | 'PAYMENT_FRAUD' | 'SYNTHETIC_IDENTITY' | 'MONEY_LAUNDERING' | 'INSIDER_THREAT' | 'SOCIAL_ENGINEERING';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  expectedRiskScore: number;
  event: SecurityEvent;
  context: any;
  indicators: string[];
  businessImpact: string;
  mitigation: string[];
}

export class FraudScenarioGenerator {
  private static readonly HIGH_RISK_COUNTRIES = [
    'North Korea', 'Syria', 'Iran', 'Afghanistan', 'Somalia'
  ];

  private static readonly VPN_IP_RANGES = [
    '185.220.100.240', '192.42.116.16', '199.87.154.255', '144.217.7.124'
  ];

  private static readonly SUSPICIOUS_USER_AGENTS = [
    'Mozilla/5.0 (compatible; automated-tool/1.0)',
    'curl/7.68.0',
    'python-requests/2.25.1'
  ];

  /**
   * Generate comprehensive fraud scenarios for testing
   */
  static generateAllScenarios(): FraudScenario[] {
    return [
      ...this.generateAccountTakeoverScenarios(),
      ...this.generatePaymentFraudScenarios(),
      ...this.generateSyntheticIdentityScenarios(),
      ...this.generateMoneyLaunderingScenarios(),
      ...this.generateInsiderThreatScenarios(),
      ...this.generateSocialEngineeringScenarios()
    ];
  }

  /**
   * Account Takeover Scenarios
   */
  private static generateAccountTakeoverScenarios(): FraudScenario[] {
    return [
      {
        id: 'ATO_001',
        name: 'Credential Stuffing Attack',
        description: 'Multiple failed login attempts followed by successful login from new device',
        category: 'ACCOUNT_TAKEOVER',
        severity: 'HIGH',
        expectedRiskScore: 0.85,
        event: {
          id: 'evt_credential_stuffing',
          type: 'ACCESS',
          severity: 'HIGH',
          timestamp: new Date(),
          userId: 'user_victim_001',
          details: {
            action: 'login_success',
            previousFailures: 47,
            timeToSuccess: 180000, // 3 minutes of attempts
            newDevice: true
          }
        },
        context: {
          location: { country: 'Romania', city: 'Bucharest', lat: 44.4268, lng: 26.1025 },
          device: {
            fingerprint: 'unknown_device_fingerprint',
            os: 'Linux',
            browser: 'Chrome/91.0 (Headless)',
            isHeadless: true,
            risk: 0.9
          },
          network: {
            ipAddress: '185.220.100.240',
            isVPN: true,
            isTor: false,
            ipRisk: 0.8,
            geoRisk: 0.7
          },
          session: {
            duration: 45000, // Very short session
            pageViews: 2,
            mouseMovements: 0, // Automated behavior
            keyboardPattern: 'automated'
          }
        },
        indicators: [
          'MULTIPLE_FAILED_LOGINS',
          'NEW_DEVICE_LOGIN',
          'VPN_USAGE',
          'HEADLESS_BROWSER',
          'SHORT_SESSION_DURATION',
          'NO_MOUSE_ACTIVITY',
          'AUTOMATED_BEHAVIOR'
        ],
        businessImpact: 'Account compromise leading to unauthorized transactions and data theft',
        mitigation: [
          'Implement CAPTCHA after 3 failed attempts',
          'Require device verification for new logins',
          'Monitor for headless browser indicators',
          'Implement behavioral biometrics'
        ]
      },

      {
        id: 'ATO_002',
        name: 'Impossible Travel Detection',
        description: 'Login from geographically impossible location within short time frame',
        category: 'ACCOUNT_TAKEOVER',
        severity: 'CRITICAL',
        expectedRiskScore: 0.95,
        event: {
          id: 'evt_impossible_travel',
          type: 'ACCESS',
          severity: 'CRITICAL',
          timestamp: new Date(),
          userId: 'user_traveler_001',
          details: {
            action: 'login_success',
            previousLocation: { country: 'USA', city: 'New York' },
            currentLocation: { country: 'Russia', city: 'Moscow' },
            timeDifference: 1800000 // 30 minutes
          }
        },
        context: {
          location: { country: 'Russia', city: 'Moscow', lat: 55.7558, lng: 37.6176 },
          previousLocation: { country: 'USA', city: 'New York', lat: 40.7128, lng: -74.0060 },
          previousTimestamp: new Date(Date.now() - 1800000),
          travelTime: {
            required: 28800000, // 8 hours minimum flight time
            actual: 1800000, // 30 minutes actual
            isImpossible: true
          },
          network: {
            ipAddress: '77.88.55.60',
            isVPN: false,
            country: 'Russia',
            geoRisk: 0.8
          }
        },
        indicators: [
          'IMPOSSIBLE_TRAVEL_TIME',
          'HIGH_RISK_GEOLOCATION',
          'RAPID_LOCATION_CHANGE',
          'SUSPICIOUS_TIMING_PATTERN'
        ],
        businessImpact: 'Potential account takeover with immediate financial risk',
        mitigation: [
          'Block login and require identity verification',
          'Implement geolocation-based controls',
          'Alert security team immediately',
          'Freeze account temporarily'
        ]
      },

      {
        id: 'ATO_003',
        name: 'Session Hijacking via WiFi',
        description: 'Session token compromise through public WiFi interception',
        category: 'ACCOUNT_TAKEOVER',
        severity: 'HIGH',
        expectedRiskScore: 0.78,
        event: {
          id: 'evt_session_hijack',
          type: 'ACCESS',
          severity: 'HIGH',
          timestamp: new Date(),
          userId: 'user_cafe_victim',
          details: {
            action: 'session_takeover',
            originalSession: 'session_123_cafe',
            newSession: 'session_456_hacker',
            networkChange: true
          }
        },
        context: {
          location: { country: 'USA', city: 'San Francisco', lat: 37.7749, lng: -122.4194 },
          network: {
            ipAddress: '192.168.1.100',
            networkName: 'Starbucks_WiFi',
            isPublicWiFi: true,
            encryptionType: 'WEP', // Weak encryption
            ipRisk: 0.6
          },
          session: {
            originalIP: '192.168.1.85',
            newIP: '192.168.1.100',
            sessionTransfer: true,
            timeGap: 300000 // 5 minutes
          }
        },
        indicators: [
          'PUBLIC_WIFI_USAGE',
          'SESSION_IP_CHANGE',
          'WEAK_NETWORK_ENCRYPTION',
          'RAPID_SESSION_TRANSFER'
        ],
        businessImpact: 'Session compromise allowing unauthorized access to user data',
        mitigation: [
          'Require re-authentication on IP change',
          'Warn users about public WiFi risks',
          'Implement session binding to device fingerprints',
          'Use secure session tokens'
        ]
      }
    ];
  }

  /**
   * Payment Fraud Scenarios
   */
  private static generatePaymentFraudScenarios(): FraudScenario[] {
    return [
      {
        id: 'PAY_001',
        name: 'Card Testing Attack',
        description: 'Small value transactions to test stolen card validity',
        category: 'PAYMENT_FRAUD',
        severity: 'MEDIUM',
        expectedRiskScore: 0.72,
        event: {
          id: 'evt_card_testing',
          type: 'TRANSACTION',
          severity: 'MEDIUM',
          timestamp: new Date(),
          userId: 'user_card_tester',
          details: {
            transactionCount: 15,
            timeWindow: 600000, // 10 minutes
            amounts: [1.00, 1.50, 2.00, 0.99, 1.25], // Small test amounts
            successRate: 0.2
          }
        },
        context: {
          transaction: {
            amount: 1.00,
            currency: 'USD',
            merchant: 'online_store_xyz',
            cardBin: '4532',
            cardType: 'visa'
          },
          velocity: {
            transactionsPerMinute: 5,
            failureRate: 0.8,
            pattern: 'sequential_small_amounts'
          },
          network: {
            ipAddress: '144.217.7.124',
            isVPN: true,
            country: 'Canada',
            actualCountry: 'Unknown'
          }
        },
        indicators: [
          'HIGH_TRANSACTION_VELOCITY',
          'SMALL_ROUND_AMOUNTS',
          'HIGH_DECLINE_RATE',
          'VPN_MASKING_LOCATION',
          'SEQUENTIAL_TESTING_PATTERN'
        ],
        businessImpact: 'Card fraud leading to chargebacks and merchant penalties',
        mitigation: [
          'Implement velocity controls per card BIN',
          'Block small round amount patterns',
          'Monitor decline rates by IP/device',
          'Use advanced card validation'
        ]
      },

      {
        id: 'PAY_002',
        name: 'Money Mule Network',
        description: 'Rapid money movement through connected accounts',
        category: 'MONEY_LAUNDERING',
        severity: 'HIGH',
        expectedRiskScore: 0.88,
        event: {
          id: 'evt_money_mule',
          type: 'TRANSACTION',
          severity: 'HIGH',
          timestamp: new Date(),
          userId: 'user_mule_central',
          details: {
            inboundAmount: 50000,
            outboundAmount: 47500, // Keeping small commission
            transferTime: 1800000, // 30 minutes
            recipientCount: 8
          }
        },
        context: {
          transaction: {
            amount: 50000,
            type: 'wire_transfer',
            source: 'international',
            destination: 'domestic_multiple'
          },
          network: {
            connectedAccounts: [
              'user_mule_001', 'user_mule_002', 'user_mule_003',
              'user_mule_004', 'user_mule_005'
            ],
            transferPattern: 'hub_and_spoke',
            geographicSpread: 'international'
          },
          timing: {
            rapidSuccession: true,
            offHours: true,
            weekendActivity: true
          }
        },
        indicators: [
          'RAPID_MONEY_MOVEMENT',
          'INTERNATIONAL_TO_DOMESTIC',
          'MULTIPLE_CONNECTED_ACCOUNTS',
          'OFF_HOURS_ACTIVITY',
          'COMMISSION_PATTERN',
          'HUB_SPOKE_TOPOLOGY'
        ],
        businessImpact: 'Money laundering facilitating criminal proceeds movement',
        mitigation: [
          'Monitor account connection graphs',
          'Flag rapid large transfers',
          'Implement layering detection',
          'Report to financial intelligence unit'
        ]
      },

      {
        id: 'PAY_003',
        name: 'Synthetic Identity Buildup',
        description: 'Long-term account cultivation for major fraud',
        category: 'SYNTHETIC_IDENTITY',
        severity: 'CRITICAL',
        expectedRiskScore: 0.92,
        event: {
          id: 'evt_synthetic_bust_out',
          type: 'TRANSACTION',
          severity: 'CRITICAL',
          timestamp: new Date(),
          userId: 'user_synthetic_001',
          details: {
            accountAge: 365, // 1 year old
            cultivationPeriod: true,
            suddenVelocityIncrease: 500, // 5x increase
            maxOutAttempt: true
          }
        },
        context: {
          account: {
            age: 365,
            previousAverageTransaction: 500,
            currentTransaction: 25000,
            creditLimit: 30000,
            utilizationJump: 0.95 // Suddenly maxed out
          },
          identity: {
            syntheticMarkers: [
              'ssn_issued_after_birth_date',
              'address_commercial_mail_drop',
              'phone_voip_service',
              'email_disposable_domain'
            ],
            verificationGaps: true
          },
          behavior: {
            dormancyPeriod: 330, // Days of minimal activity
            suddenActivation: true,
            aggressiveSpending: true
          }
        },
        indicators: [
          'SYNTHETIC_IDENTITY_MARKERS',
          'SUDDEN_BEHAVIOR_CHANGE',
          'DORMANCY_THEN_ACTIVATION',
          'CREDIT_LIMIT_MAXING',
          'IDENTITY_VERIFICATION_GAPS',
          'CULTIVATION_PATTERN'
        ],
        businessImpact: 'Large financial loss from synthetic identity bust-out',
        mitigation: [
          'Enhanced identity verification at onboarding',
          'Monitor for synthetic identity indicators',
          'Track behavior consistency over time',
          'Implement bust-out prediction models'
        ]
      }
    ];
  }

  /**
   * Synthetic Identity Scenarios
   */
  private static generateSyntheticIdentityScenarios(): FraudScenario[] {
    return [
      {
        id: 'SYN_001',
        name: 'SSN Manipulation Fraud',
        description: 'Creating fake identity using manipulated Social Security Numbers',
        category: 'SYNTHETIC_IDENTITY',
        severity: 'HIGH',
        expectedRiskScore: 0.84,
        event: {
          id: 'evt_ssn_manipulation',
          type: 'IDENTITY_CREATION',
          severity: 'HIGH',
          timestamp: new Date(),
          userId: 'user_synthetic_ssn',
          details: {
            ssnIssuanceDate: new Date('2022-01-15'),
            dobClaimedDate: new Date('1985-03-10'),
            temporalInconsistency: true
          }
        },
        context: {
          identity: {
            ssn: '987-65-4321',
            ssnIssued: '2022-01-15',
            dateOfBirth: '1985-03-10',
            ageWhenSSNIssued: 37, // Suspicious - SSN issued to adult
            ssnState: 'Nevada',
            birthState: 'California'
          },
          verification: {
            creditFileAge: 45, // Very thin credit file
            addressHistory: 'minimal',
            employmentVerification: 'failed',
            phoneVerification: 'voip_service'
          },
          riskFactors: {
            recentSSNIssuance: true,
            inconsistentHistory: true,
            thinCreditFile: true
          }
        },
        indicators: [
          'RECENT_SSN_ISSUANCE_FOR_ADULT',
          'INCONSISTENT_TEMPORAL_DATA',
          'THIN_CREDIT_FILE',
          'VOIP_PHONE_SERVICE',
          'MINIMAL_VERIFICATION_HISTORY'
        ],
        businessImpact: 'Credit fraud and identity theft enabling multiple fraudulent accounts',
        mitigation: [
          'Cross-reference SSN issuance dates with claimed age',
          'Require additional identity verification for recent SSNs',
          'Monitor for temporal inconsistencies',
          'Implement synthetic identity scoring models'
        ]
      }
    ];
  }

  /**
   * Money Laundering Scenarios
   */
  private static generateMoneyLaunderingScenarios(): FraudScenario[] {
    return [
      {
        id: 'ML_001',
        name: 'Structuring via Smurfing',
        description: 'Breaking large amounts into smaller transactions to avoid reporting',
        category: 'MONEY_LAUNDERING',
        severity: 'HIGH',
        expectedRiskScore: 0.87,
        event: {
          id: 'evt_structuring',
          type: 'TRANSACTION',
          severity: 'HIGH',
          timestamp: new Date(),
          userId: 'user_smurf_coordinator',
          details: {
            originalAmount: 100000,
            structuredAmounts: [9500, 9800, 9700, 9600, 9900],
            reportingThreshold: 10000,
            coordinatedAccounts: 5
          }
        },
        context: {
          pattern: {
            amounts: [9500, 9800, 9700, 9600, 9900, 9750, 9850],
            allBelowThreshold: true,
            totalAmount: 68500,
            timeWindow: 86400000, // 24 hours
            accountPattern: 'coordinated'
          },
          accounts: [
            { id: 'smurf_001', relationship: 'family' },
            { id: 'smurf_002', relationship: 'employee' },
            { id: 'smurf_003', relationship: 'associate' }
          ],
          coordination: {
            sameBankBranch: true,
            sequentialTiming: true,
            similarAmounts: true
          }
        },
        indicators: [
          'AMOUNTS_JUST_BELOW_REPORTING_THRESHOLD',
          'COORDINATED_MULTIPLE_ACCOUNTS',
          'SEQUENTIAL_TIMING_PATTERN',
          'RELATED_PARTY_TRANSACTIONS',
          'STRUCTURING_PATTERN'
        ],
        businessImpact: 'Money laundering enabling tax evasion and crime proceeds cleaning',
        mitigation: [
          'Monitor for patterns just below reporting thresholds',
          'Aggregate related account transactions',
          'Flag coordinated timing across accounts',
          'Implement suspicious activity reporting'
        ]
      }
    ];
  }

  /**
   * Insider Threat Scenarios
   */
  private static generateInsiderThreatScenarios(): FraudScenario[] {
    return [
      {
        id: 'INT_001',
        name: 'Privileged Access Abuse',
        description: 'Employee using privileged access for unauthorized data extraction',
        category: 'INSIDER_THREAT',
        severity: 'CRITICAL',
        expectedRiskScore: 0.91,
        event: {
          id: 'evt_insider_abuse',
          type: 'DATA_ACCESS',
          severity: 'CRITICAL',
          timestamp: new Date(),
          userId: 'employee_admin_001',
          details: {
            dataAccessed: 'customer_pii_database',
            recordsAccessed: 50000,
            normalAccess: 200, // Usually accesses ~200 records
            timeOfAccess: '02:30:00' // Off hours
          }
        },
        context: {
          employee: {
            role: 'database_administrator',
            clearanceLevel: 'high',
            employmentStatus: 'notice_period', // Recently resigned
            recentEvents: 'resignation_submitted'
          },
          access: {
            recordsAccessed: 50000,
            normalVolume: 200,
            volumeIncrease: 250, // 250x normal
            offHoursAccess: true,
            weekendAccess: true
          },
          behavior: {
            recentPerformanceReview: 'negative',
            financialStress: 'detected',
            competitorContact: 'suspected'
          }
        },
        indicators: [
          'MASSIVE_DATA_ACCESS_INCREASE',
          'OFF_HOURS_ACCESS',
          'EMPLOYEE_RESIGNATION_PERIOD',
          'NEGATIVE_PERFORMANCE_SIGNALS',
          'PRIVILEGED_ACCESS_ABUSE'
        ],
        businessImpact: 'Data breach, competitive intelligence theft, regulatory violations',
        mitigation: [
          'Monitor privileged access usage patterns',
          'Implement data loss prevention controls',
          'Restrict access during notice periods',
          'Alert on unusual volume increases'
        ]
      }
    ];
  }

  /**
   * Social Engineering Scenarios
   */
  private static generateSocialEngineeringScenarios(): FraudScenario[] {
    return [
      {
        id: 'SOC_001',
        name: 'Business Email Compromise',
        description: 'CEO impersonation for wire transfer authorization',
        category: 'SOCIAL_ENGINEERING',
        severity: 'CRITICAL',
        expectedRiskScore: 0.89,
        event: {
          id: 'evt_bec_attack',
          type: 'AUTHORIZATION',
          severity: 'CRITICAL',
          timestamp: new Date(),
          userId: 'finance_manager_001',
          details: {
            requestType: 'wire_transfer',
            amount: 250000,
            urgency: 'immediate',
            requestor: 'CEO_impersonation'
          }
        },
        context: {
          communication: {
            emailHeader: 'spoofed_ceo_domain',
            urgencyLanguage: true,
            outsideNormalChannels: true,
            phoneVerificationSkipped: true
          },
          timing: {
            ceOActuallyTraveling: true,
            requestDuringTravel: true,
            phoneUnavailable: 'claimed'
          },
          transaction: {
            amount: 250000,
            recipient: 'new_vendor',
            destinationCountry: 'Hong Kong',
            paymentMethod: 'wire_transfer'
          }
        },
        indicators: [
          'EXECUTIVE_IMPERSONATION',
          'UNUSUAL_COMMUNICATION_CHANNEL',
          'URGENCY_PRESSURE_TACTICS',
          'LARGE_AMOUNT_AUTHORIZATION',
          'NEW_RECIPIENT_ACCOUNT',
          'INTERNATIONAL_DESTINATION'
        ],
        businessImpact: 'Large financial loss through fraudulent wire transfer',
        mitigation: [
          'Implement dual authorization for large transfers',
          'Verify executive requests through secondary channels',
          'Train employees on BEC tactics',
          'Use email authentication protocols'
        ]
      }
    ];
  }

  /**
   * Generate random realistic scenario for testing
   */
  static generateRandomScenario(): FraudScenario {
    const allScenarios = this.generateAllScenarios();
    return allScenarios[Math.floor(Math.random() * allScenarios.length)];
  }

  /**
   * Generate scenario by risk level
   */
  static generateScenarioByRisk(severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'): FraudScenario {
    const allScenarios = this.generateAllScenarios();
    const filteredScenarios = allScenarios.filter(s => s.severity === severity);

    if (filteredScenarios.length === 0) {
      return this.generateRandomScenario();
    }

    return filteredScenarios[Math.floor(Math.random() * filteredScenarios.length)];
  }

  /**
   * Generate scenario by category
   */
  static generateScenarioByCategory(category: FraudScenario['category']): FraudScenario {
    const allScenarios = this.generateAllScenarios();
    const filteredScenarios = allScenarios.filter(s => s.category === category);

    if (filteredScenarios.length === 0) {
      return this.generateRandomScenario();
    }

    return filteredScenarios[Math.floor(Math.random() * filteredScenarios.length)];
  }

  /**
   * Generate benchmark dataset for ML model evaluation
   */
  static generateBenchmarkDataset(size: number = 1000): FraudScenario[] {
    const scenarios: FraudScenario[] = [];
    const allScenarios = this.generateAllScenarios();

    for (let i = 0; i < size; i++) {
      const baseScenario = allScenarios[Math.floor(Math.random() * allScenarios.length)];

      // Create variations of the scenario
      const variation = {
        ...baseScenario,
        id: `${baseScenario.id}_var_${i}`,
        event: {
          ...baseScenario.event,
          id: `${baseScenario.event.id}_${i}`,
          timestamp: new Date(Date.now() - Math.random() * 86400000 * 30), // Last 30 days
        }
      };

      // Add some randomization to make it more realistic
      this.addVariationToScenario(variation);
      scenarios.push(variation);
    }

    return scenarios;
  }

  /**
   * Add realistic variations to scenarios
   */
  private static addVariationToScenario(scenario: FraudScenario): void {
    // Randomize amounts slightly
    if (scenario.context.transaction?.amount) {
      const variation = 0.8 + Math.random() * 0.4; // ±20% variation
      scenario.context.transaction.amount *= variation;
    }

    // Randomize timing
    const timeVariation = Math.random() * 7200000; // ±2 hours
    scenario.event.timestamp = new Date(scenario.event.timestamp.getTime() + timeVariation);

    // Randomize risk scores slightly
    scenario.expectedRiskScore += (Math.random() - 0.5) * 0.1;
    scenario.expectedRiskScore = Math.max(0, Math.min(1, scenario.expectedRiskScore));
  }

  /**
   * Generate live demo scenarios for dashboard
   */
  static generateLiveDemoScenarios(): FraudScenario[] {
    return [
      this.generateScenarioByCategory('ACCOUNT_TAKEOVER'),
      this.generateScenarioByCategory('PAYMENT_FRAUD'),
      this.generateScenarioByCategory('MONEY_LAUNDERING'),
      this.generateScenarioByRisk('CRITICAL'),
      this.generateScenarioByRisk('HIGH')
    ];
  }
}

export default FraudScenarioGenerator;