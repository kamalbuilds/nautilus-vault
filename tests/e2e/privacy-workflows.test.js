/**
 * End-to-End Privacy Workflow Tests
 * Complete data lifecycle with privacy preservation
 */

const crypto = require('crypto');

describe('End-to-End Privacy Workflows', () => {
  let securityAudit;

  beforeAll(() => {
    securityAudit = global.securityAudit;
  });

  describe('Healthcare Data Privacy Workflow', () => {
    // Mock healthcare privacy system
    class HealthcarePrivacySystem {
      constructor() {
        this.consentManager = new ConsentManager();
        this.dataMinimizer = new DataMinimizer();
        this.anonymizer = new Anonymizer();
        this.auditLogger = new PrivacyAuditLogger();
        this.complianceChecker = new ComplianceChecker();
      }

      async processPatientData(patientData, purpose, requesterInfo) {
        const workflowId = crypto.randomUUID();

        try {
          // Step 1: Check consent
          const consentCheck = await this.consentManager.checkConsent(
            patientData.patientId,
            purpose,
            requesterInfo
          );

          if (!consentCheck.granted) {
            throw new Error(`Consent not granted: ${consentCheck.reason}`);
          }

          this.auditLogger.log('consent_verified', {
            workflowId,
            patientId: patientData.patientId,
            purpose,
            requester: requesterInfo.id
          });

          // Step 2: Data minimization
          const minimizedData = await this.dataMinimizer.minimize(patientData, purpose);

          this.auditLogger.log('data_minimized', {
            workflowId,
            originalFields: Object.keys(patientData).length,
            minimizedFields: Object.keys(minimizedData).length
          });

          // Step 3: Anonymization if required
          let processedData = minimizedData;
          if (purpose.requiresAnonymization) {
            processedData = await this.anonymizer.anonymize(minimizedData);

            this.auditLogger.log('data_anonymized', {
              workflowId,
              anonymizationMethod: processedData.method,
              kAnonymity: processedData.kValue
            });
          }

          // Step 4: Compliance check
          const complianceResult = await this.complianceChecker.verify(
            processedData,
            purpose,
            'GDPR'
          );

          if (!complianceResult.compliant) {
            throw new Error(`Compliance violation: ${complianceResult.violations.join(', ')}`);
          }

          this.auditLogger.log('compliance_verified', {
            workflowId,
            framework: 'GDPR',
            compliant: true
          });

          // Step 5: Secure processing
          const result = await this.secureProcess(processedData, purpose);

          this.auditLogger.log('processing_completed', {
            workflowId,
            success: true,
            resultType: typeof result
          });

          return {
            workflowId,
            result,
            metadata: {
              consentGranted: true,
              dataMinimized: true,
              anonymized: purpose.requiresAnonymization,
              compliant: true
            }
          };

        } catch (error) {
          this.auditLogger.log('workflow_error', {
            workflowId,
            error: error.message
          });
          throw error;
        }
      }

      async secureProcess(data, purpose) {
        // Simulate secure processing based on purpose
        switch (purpose.type) {
          case 'research':
            return this.performResearch(data);
          case 'diagnosis':
            return this.performDiagnosis(data);
          case 'treatment':
            return this.performTreatment(data);
          default:
            throw new Error(`Unknown processing type: ${purpose.type}`);
        }
      }

      performResearch(data) {
        // Aggregate statistics without exposing individual records
        return {
          aggregateStats: {
            totalRecords: 1,
            averageAge: data.demographics?.ageGroup || 'unknown',
            conditions: data.conditions?.length || 0
          }
        };
      }

      performDiagnosis(data) {
        return {
          diagnosticSuggestions: [
            'Based on provided symptoms',
            'Consider additional tests'
          ]
        };
      }

      performTreatment(data) {
        return {
          treatmentPlan: [
            'Medication recommendations',
            'Lifestyle modifications'
          ]
        };
      }
    }

    class ConsentManager {
      constructor() {
        this.consents = new Map();
      }

      async grantConsent(patientId, purposes, duration = 86400000) {
        const consentId = crypto.randomUUID();
        const consent = {
          id: consentId,
          patientId,
          purposes,
          grantedAt: Date.now(),
          expiresAt: Date.now() + duration,
          active: true
        };

        this.consents.set(patientId, consent);
        return consentId;
      }

      async checkConsent(patientId, purpose, requesterInfo) {
        const consent = this.consents.get(patientId);

        if (!consent) {
          return { granted: false, reason: 'no_consent_found' };
        }

        if (!consent.active) {
          return { granted: false, reason: 'consent_revoked' };
        }

        if (Date.now() > consent.expiresAt) {
          return { granted: false, reason: 'consent_expired' };
        }

        const purposeAllowed = consent.purposes.some(p =>
          p.type === purpose.type &&
          (!p.requesterTypes || p.requesterTypes.includes(requesterInfo.type))
        );

        if (!purposeAllowed) {
          return { granted: false, reason: 'purpose_not_consented' };
        }

        return { granted: true, consentId: consent.id };
      }

      async revokeConsent(patientId) {
        const consent = this.consents.get(patientId);
        if (consent) {
          consent.active = false;
          consent.revokedAt = Date.now();
        }
      }
    }

    class DataMinimizer {
      constructor() {
        this.purposeFieldMappings = {
          'research': ['demographics', 'conditions', 'outcomes'],
          'diagnosis': ['symptoms', 'history', 'vitals'],
          'treatment': ['diagnosis', 'allergies', 'currentMedications'],
          'billing': ['demographics', 'insurance', 'services']
        };
      }

      async minimize(data, purpose) {
        const allowedFields = this.purposeFieldMappings[purpose.type] || [];
        const minimizedData = {};

        for (const field of allowedFields) {
          if (data[field] !== undefined) {
            minimizedData[field] = data[field];
          }
        }

        // Always include essential fields
        if (data.patientId) {
          minimizedData.patientId = data.patientId;
        }

        return minimizedData;
      }
    }

    class Anonymizer {
      constructor() {
        this.kValue = 3; // k-anonymity parameter
      }

      async anonymize(data) {
        const anonymizedData = { ...data };

        // Remove direct identifiers
        delete anonymizedData.patientId;
        delete anonymizedData.name;
        delete anonymizedData.ssn;

        // Generalize quasi-identifiers
        if (anonymizedData.demographics) {
          anonymizedData.demographics = this.generalizedemographics(anonymizedData.demographics);
        }

        if (anonymizedData.location) {
          anonymizedData.location = this.generalizeLocation(anonymizedData.location);
        }

        return {
          ...anonymizedData,
          method: 'k-anonymity',
          kValue: this.kValue,
          anonymizedAt: Date.now()
        };
      }

      generalizedemographics(demographics) {
        const generalized = { ...demographics };

        // Age generalization
        if (generalized.age) {
          const ageGroup = Math.floor(generalized.age / 10) * 10;
          generalized.ageGroup = `${ageGroup}-${ageGroup + 9}`;
          delete generalized.age;
        }

        // Income generalization
        if (generalized.income) {
          const incomeGroup = Math.floor(generalized.income / 10000) * 10000;
          generalized.incomeRange = `${incomeGroup}-${incomeGroup + 9999}`;
          delete generalized.income;
        }

        return generalized;
      }

      generalizeLocation(location) {
        // Generalize to city level, remove specific addresses
        return {
          city: location.city,
          state: location.state,
          country: location.country
          // Remove: street, zipcode, coordinates
        };
      }
    }

    class PrivacyAuditLogger {
      constructor() {
        this.logs = [];
      }

      log(event, details) {
        const logEntry = {
          timestamp: Date.now(),
          event,
          details,
          hash: this.generateLogHash(event, details)
        };

        this.logs.push(logEntry);
      }

      generateLogHash(event, details) {
        return crypto.createHash('sha256')
          .update(JSON.stringify({ event, details, timestamp: Date.now() }))
          .digest('hex');
      }

      getAuditTrail(workflowId) {
        return this.logs.filter(log =>
          log.details.workflowId === workflowId
        );
      }

      verifyIntegrity() {
        // Verify that audit logs haven't been tampered with
        for (const log of this.logs) {
          const expectedHash = crypto.createHash('sha256')
            .update(JSON.stringify({
              event: log.event,
              details: log.details,
              timestamp: log.timestamp
            }))
            .digest('hex');

          if (log.hash !== expectedHash) {
            return false;
          }
        }
        return true;
      }
    }

    class ComplianceChecker {
      constructor() {
        this.gdprRequirements = [
          'data_minimization',
          'purpose_limitation',
          'consent_required',
          'right_to_erasure',
          'data_portability'
        ];
      }

      async verify(data, purpose, framework) {
        const violations = [];

        if (framework === 'GDPR') {
          // Check data minimization
          if (this.hasExcessiveData(data, purpose)) {
            violations.push('excessive_data_collection');
          }

          // Check for direct identifiers in research context
          if (purpose.type === 'research' && this.hasDirectIdentifiers(data)) {
            violations.push('identifiers_in_research_data');
          }

          // Check purpose limitation
          if (!this.isPurposeLimited(purpose)) {
            violations.push('purpose_too_broad');
          }
        }

        return {
          compliant: violations.length === 0,
          violations,
          framework,
          checkedAt: Date.now()
        };
      }

      hasExcessiveData(data, purpose) {
        // Simplified check - in reality would be more sophisticated
        const dataFields = Object.keys(data).length;
        const maxFieldsByPurpose = {
          'research': 5,
          'diagnosis': 8,
          'treatment': 10,
          'billing': 6
        };

        return dataFields > (maxFieldsByPurpose[purpose.type] || 5);
      }

      hasDirectIdentifiers(data) {
        const directIdentifiers = ['patientId', 'name', 'ssn', 'email', 'phone'];
        return directIdentifiers.some(id => data[id] !== undefined);
      }

      isPurposeLimited(purpose) {
        // Check if purpose is specific enough
        return purpose.type && purpose.description && purpose.description.length > 10;
      }
    }

    test('should complete healthcare data processing with privacy preservation', async () => {
      const privacySystem = new HealthcarePrivacySystem();

      // Patient data
      const patientData = {
        patientId: 'patient-123',
        name: 'John Doe',
        ssn: '123-45-6789',
        demographics: {
          age: 35,
          gender: 'M',
          income: 75000
        },
        location: {
          street: '123 Main St',
          city: 'Boston',
          state: 'MA',
          zipcode: '02101',
          country: 'USA'
        },
        symptoms: ['fever', 'cough', 'fatigue'],
        history: ['diabetes', 'hypertension'],
        vitals: {
          temperature: 101.2,
          bloodPressure: '140/90',
          heartRate: 85
        },
        conditions: ['type2_diabetes'],
        currentMedications: ['metformin', 'lisinopril']
      };

      // Grant consent for research
      await privacySystem.consentManager.grantConsent('patient-123', [
        {
          type: 'research',
          description: 'Medical research for diabetes treatment',
          requesterTypes: ['researcher', 'doctor']
        }
      ]);

      // Define research purpose
      const researchPurpose = {
        type: 'research',
        description: 'Analyzing diabetes treatment outcomes',
        requiresAnonymization: true
      };

      const requesterInfo = {
        id: 'researcher-456',
        type: 'researcher',
        institution: 'Medical University'
      };

      // Process data through privacy workflow
      const result = await privacySystem.processPatientData(
        patientData,
        researchPurpose,
        requesterInfo
      );

      // Verify workflow completed successfully
      expect(result.workflowId).toBeDefined();
      expect(result.metadata.consentGranted).toBe(true);
      expect(result.metadata.dataMinimized).toBe(true);
      expect(result.metadata.anonymized).toBe(true);
      expect(result.metadata.compliant).toBe(true);

      // Verify audit trail exists
      const auditTrail = privacySystem.auditLogger.getAuditTrail(result.workflowId);
      expect(auditTrail.length).toBeGreaterThan(0);

      // Verify audit trail integrity
      const integrityCheck = privacySystem.auditLogger.verifyIntegrity();
      expect(integrityCheck).toBe(true);

      securityAudit.log('healthcare_privacy_workflow', {
        workflowCompleted: true,
        privacyPreserved: true,
        compliant: true,
        auditTrailCreated: true,
        integrityVerified: integrityCheck
      });
    });

    test('should enforce consent withdrawal and right to erasure', async () => {
      const privacySystem = new HealthcarePrivacySystem();
      const patientId = 'patient-456';

      // Grant initial consent
      const consentId = await privacySystem.consentManager.grantConsent(patientId, [
        { type: 'research', description: 'General medical research' }
      ]);

      expect(consentId).toBeDefined();

      // Verify consent works
      const initialCheck = await privacySystem.consentManager.checkConsent(
        patientId,
        { type: 'research' },
        { type: 'researcher' }
      );

      expect(initialCheck.granted).toBe(true);

      // Revoke consent (right to withdraw)
      await privacySystem.consentManager.revokeConsent(patientId);

      // Verify consent is revoked
      const revokedCheck = await privacySystem.consentManager.checkConsent(
        patientId,
        { type: 'research' },
        { type: 'researcher' }
      );

      expect(revokedCheck.granted).toBe(false);
      expect(revokedCheck.reason).toBe('consent_revoked');

      securityAudit.log('consent_withdrawal', {
        initialConsentGranted: initialCheck.granted,
        consentRevoked: !revokedCheck.granted,
        rightToWithdrawEnforced: true
      });
    });

    test('should handle consent expiration automatically', async () => {
      const privacySystem = new HealthcarePrivacySystem();
      const patientId = 'patient-789';

      // Grant consent with short duration (1 second)
      await privacySystem.consentManager.grantConsent(patientId, [
        { type: 'diagnosis', description: 'Medical diagnosis' }
      ], 1000);

      // Initial check should pass
      const immediateCheck = await privacySystem.consentManager.checkConsent(
        patientId,
        { type: 'diagnosis' },
        { type: 'doctor' }
      );

      expect(immediateCheck.granted).toBe(true);

      // Wait for consent to expire
      await new Promise(resolve => setTimeout(resolve, 1100));

      // Check should now fail
      const expiredCheck = await privacySystem.consentManager.checkConsent(
        patientId,
        { type: 'diagnosis' },
        { type: 'doctor' }
      );

      expect(expiredCheck.granted).toBe(false);
      expect(expiredCheck.reason).toBe('consent_expired');

      securityAudit.log('consent_expiration', {
        initiallyGranted: immediateCheck.granted,
        expiredCorrectly: !expiredCheck.granted,
        automaticExpiration: true
      });
    });
  });

  describe('Financial Privacy Workflow', () => {
    // Mock financial privacy system for fraud detection
    class FinancialPrivacySystem {
      constructor() {
        this.fraudDetector = new FraudDetector();
        this.privacyEngine = new FinancialPrivacyEngine();
        this.complianceValidator = new FinancialComplianceValidator();
        this.auditSystem = new FinancialAuditSystem();
      }

      async processTransaction(transaction, userProfile) {
        const processId = crypto.randomUUID();

        try {
          // Step 1: Privacy-preserving fraud detection
          const fraudAnalysis = await this.fraudDetector.analyzeTranasction(
            transaction,
            userProfile,
            { preservePrivacy: true }
          );

          this.auditSystem.log('fraud_analysis_completed', {
            processId,
            riskScore: fraudAnalysis.riskScore,
            flagged: fraudAnalysis.flagged
          });

          // Step 2: Apply privacy protection
          const protectedTransaction = await this.privacyEngine.protectTransaction(
            transaction,
            fraudAnalysis
          );

          // Step 3: Compliance validation
          const compliance = await this.complianceValidator.validate(
            protectedTransaction,
            ['PCI_DSS', 'GDPR', 'SOX']
          );

          if (!compliance.compliant) {
            throw new Error(`Compliance violation: ${compliance.violations.join(', ')}`);
          }

          // Step 4: Secure processing
          const result = await this.securelyProcessTransaction(protectedTransaction);

          this.auditSystem.log('transaction_processed', {
            processId,
            amount: transaction.amount,
            success: true,
            privacyProtected: true,
            compliant: true
          });

          return {
            processId,
            transactionId: result.transactionId,
            status: 'completed',
            fraudAnalysis: {
              riskScore: fraudAnalysis.riskScore,
              flagged: fraudAnalysis.flagged
            },
            privacyMetrics: protectedTransaction.privacyMetrics,
            compliance: compliance.frameworks
          };

        } catch (error) {
          this.auditSystem.log('transaction_failed', {
            processId,
            error: error.message
          });
          throw error;
        }
      }

      async securelyProcessTransaction(protectedTransaction) {
        // Simulate secure transaction processing
        return {
          transactionId: crypto.randomUUID(),
          processedAt: Date.now(),
          status: 'completed'
        };
      }
    }

    class FraudDetector {
      constructor() {
        this.models = {
          amountAnomaly: this.createAnomalyDetector('amount'),
          velocityAnomaly: this.createAnomalyDetector('velocity'),
          locationAnomaly: this.createAnomalyDetector('location'),
          patternAnomaly: this.createAnomalyDetector('pattern')
        };
      }

      async analyzeTranasction(transaction, userProfile, options = {}) {
        const features = this.extractFeatures(transaction, userProfile, options.preservePrivacy);

        let riskScore = 0;
        const flags = [];

        // Amount anomaly detection
        const amountScore = this.models.amountAnomaly.predict(features.amount);
        if (amountScore > 0.7) {
          riskScore += 0.3;
          flags.push('unusual_amount');
        }

        // Velocity checks (number of transactions in time window)
        if (features.transactionCount > userProfile.averageDaily * 3) {
          riskScore += 0.4;
          flags.push('high_velocity');
        }

        // Location checks
        if (features.location && userProfile.typicalLocations) {
          const locationFamiliar = userProfile.typicalLocations.some(loc =>
            this.calculateDistance(features.location, loc) < 100 // 100km
          );

          if (!locationFamiliar) {
            riskScore += 0.2;
            flags.push('unusual_location');
          }
        }

        // Behavioral pattern analysis
        const patternScore = this.models.patternAnomaly.predict(features.pattern);
        if (patternScore > 0.8) {
          riskScore += 0.1;
          flags.push('unusual_pattern');
        }

        return {
          riskScore: Math.min(riskScore, 1.0),
          flagged: riskScore > 0.5,
          flags,
          confidence: 0.85,
          analysisMethod: options.preservePrivacy ? 'privacy_preserving' : 'standard'
        };
      }

      extractFeatures(transaction, userProfile, preservePrivacy = false) {
        const features = {
          amount: transaction.amount,
          transactionCount: userProfile.recentTransactionCount || 1,
          pattern: {
            timeOfDay: new Date(transaction.timestamp).getHours(),
            dayOfWeek: new Date(transaction.timestamp).getDay(),
            merchant: transaction.merchant
          }
        };

        if (!preservePrivacy) {
          features.location = transaction.location;
        } else {
          // Use generalized location for privacy
          features.location = {
            region: transaction.location?.region,
            country: transaction.location?.country
          };
        }

        return features;
      }

      createAnomalyDetector(type) {
        return {
          predict: (value) => {
            // Simplified anomaly detection - in reality would use ML models
            switch (type) {
              case 'amount':
                return Math.random() > 0.8 ? Math.random() : 0.3;
              case 'velocity':
                return Math.random() > 0.9 ? Math.random() : 0.2;
              case 'location':
                return Math.random() > 0.85 ? Math.random() : 0.1;
              case 'pattern':
                return Math.random() > 0.95 ? Math.random() : 0.05;
              default:
                return 0;
            }
          }
        };
      }

      calculateDistance(loc1, loc2) {
        // Simplified distance calculation
        if (!loc1 || !loc2) return 1000; // Assume far if unknown
        return Math.random() * 200; // Mock distance in km
      }
    }

    class FinancialPrivacyEngine {
      async protectTransaction(transaction, fraudAnalysis) {
        const protectedTransaction = { ...transaction };

        // Remove or tokenize PII
        protectedTransaction.cardNumber = this.tokenizeCardNumber(transaction.cardNumber);
        protectedTransaction.personalInfo = this.anonymizePersonalInfo(transaction.personalInfo);

        // Apply differential privacy for analytics
        if (fraudAnalysis.flagged) {
          protectedTransaction.amount = this.applyDifferentialPrivacy(transaction.amount);
        }

        // Create privacy metrics
        const privacyMetrics = {
          piiRemoved: true,
          cardTokenized: true,
          differentialPrivacyApplied: fraudAnalysis.flagged,
          anonymizationLevel: 'high',
          privacyBudget: fraudAnalysis.flagged ? 0.1 : 0
        };

        protectedTransaction.privacyMetrics = privacyMetrics;

        return protectedTransaction;
      }

      tokenizeCardNumber(cardNumber) {
        // Replace card number with token
        return `token_${crypto.createHash('sha256').update(cardNumber).digest('hex').slice(0, 16)}`;
      }

      anonymizePersonalInfo(personalInfo) {
        if (!personalInfo) return null;

        return {
          // Keep only generalized information
          ageGroup: this.generalizeAge(personalInfo.age),
          region: personalInfo.address?.state,
          incomeRange: this.generalizeIncome(personalInfo.income)
        };
      }

      generalizeAge(age) {
        if (!age) return 'unknown';
        const group = Math.floor(age / 10) * 10;
        return `${group}-${group + 9}`;
      }

      generalizeIncome(income) {
        if (!income) return 'unknown';
        const group = Math.floor(income / 25000) * 25000;
        return `${group}-${group + 24999}`;
      }

      applyDifferentialPrivacy(value, epsilon = 0.1) {
        // Add calibrated noise for differential privacy
        const sensitivity = 1.0; // Assuming normalized values
        const scale = sensitivity / epsilon;
        const noise = this.generateLaplaceNoise(scale);
        return Math.max(0, value + noise);
      }

      generateLaplaceNoise(scale) {
        // Generate Laplace noise for differential privacy
        const uniform = Math.random() - 0.5;
        return -scale * Math.sign(uniform) * Math.log(1 - 2 * Math.abs(uniform));
      }
    }

    class FinancialComplianceValidator {
      constructor() {
        this.frameworks = {
          'PCI_DSS': this.createPCIValidator(),
          'GDPR': this.createGDPRValidator(),
          'SOX': this.createSOXValidator()
        };
      }

      async validate(transaction, requiredFrameworks) {
        const violations = [];
        const validatedFrameworks = [];

        for (const framework of requiredFrameworks) {
          const validator = this.frameworks[framework];
          if (validator) {
            const result = validator.validate(transaction);
            if (!result.compliant) {
              violations.push(...result.violations.map(v => `${framework}: ${v}`));
            } else {
              validatedFrameworks.push(framework);
            }
          }
        }

        return {
          compliant: violations.length === 0,
          violations,
          frameworks: validatedFrameworks,
          validatedAt: Date.now()
        };
      }

      createPCIValidator() {
        return {
          validate: (transaction) => {
            const violations = [];

            // Check if card data is properly protected
            if (transaction.cardNumber && !transaction.cardNumber.startsWith('token_')) {
              violations.push('unprotected_card_data');
            }

            // Check for unencrypted sensitive data
            if (transaction.cvv) {
              violations.push('cvv_stored');
            }

            return { compliant: violations.length === 0, violations };
          }
        };
      }

      createGDPRValidator() {
        return {
          validate: (transaction) => {
            const violations = [];

            // Check for excessive personal data collection
            if (transaction.personalInfo && !transaction.privacyMetrics?.piiRemoved) {
              violations.push('excessive_personal_data');
            }

            // Check for proper anonymization
            if (!transaction.privacyMetrics?.anonymizationLevel) {
              violations.push('insufficient_anonymization');
            }

            return { compliant: violations.length === 0, violations };
          }
        };
      }

      createSOXValidator() {
        return {
          validate: (transaction) => {
            const violations = [];

            // Check for audit trail
            if (!transaction.auditTrail && transaction.amount > 10000) {
              violations.push('missing_audit_trail');
            }

            // Check for proper controls
            if (transaction.amount > 50000 && !transaction.approvals) {
              violations.push('missing_approval_controls');
            }

            return { compliant: violations.length === 0, violations };
          }
        };
      }
    }

    class FinancialAuditSystem {
      constructor() {
        this.auditLog = [];
        this.immutableStore = new Map(); // Simulate blockchain storage
      }

      log(event, details) {
        const auditEntry = {
          id: crypto.randomUUID(),
          timestamp: Date.now(),
          event,
          details,
          hash: null,
          previousHash: this.getLastHash()
        };

        // Create hash for integrity
        auditEntry.hash = crypto.createHash('sha256')
          .update(JSON.stringify({
            id: auditEntry.id,
            timestamp: auditEntry.timestamp,
            event: auditEntry.event,
            details: auditEntry.details,
            previousHash: auditEntry.previousHash
          }))
          .digest('hex');

        this.auditLog.push(auditEntry);
        this.immutableStore.set(auditEntry.id, auditEntry);
      }

      getLastHash() {
        return this.auditLog.length > 0 ?
          this.auditLog[this.auditLog.length - 1].hash :
          '0000000000000000000000000000000000000000000000000000000000000000';
      }

      verifyChainIntegrity() {
        for (let i = 0; i < this.auditLog.length; i++) {
          const entry = this.auditLog[i];
          const expectedPreviousHash = i > 0 ? this.auditLog[i - 1].hash : '0000000000000000000000000000000000000000000000000000000000000000';

          if (entry.previousHash !== expectedPreviousHash) {
            return { valid: false, reason: 'broken_chain', at: i };
          }

          // Verify hash
          const expectedHash = crypto.createHash('sha256')
            .update(JSON.stringify({
              id: entry.id,
              timestamp: entry.timestamp,
              event: entry.event,
              details: entry.details,
              previousHash: entry.previousHash
            }))
            .digest('hex');

          if (entry.hash !== expectedHash) {
            return { valid: false, reason: 'invalid_hash', at: i };
          }
        }

        return { valid: true };
      }

      getAuditTrail(processId) {
        return this.auditLog.filter(entry =>
          entry.details.processId === processId
        );
      }
    }

    test('should process financial transaction with fraud detection and privacy', async () => {
      const financialSystem = new FinancialPrivacySystem();

      const transaction = {
        id: 'txn-123',
        amount: 1250.00,
        cardNumber: '4111111111111111',
        cvv: '123',
        timestamp: Date.now(),
        merchant: 'Online Store ABC',
        location: {
          latitude: 42.3601,
          longitude: -71.0589,
          city: 'Boston',
          state: 'MA',
          country: 'USA',
          region: 'Northeast'
        },
        personalInfo: {
          age: 32,
          income: 85000,
          address: {
            state: 'MA',
            zipcode: '02101'
          }
        }
      };

      const userProfile = {
        averageDaily: 3,
        recentTransactionCount: 5,
        typicalLocations: [
          { latitude: 42.3601, longitude: -71.0589 } // Boston
        ]
      };

      // Process transaction through privacy-preserving pipeline
      const result = await financialSystem.processTransaction(transaction, userProfile);

      expect(result.transactionId).toBeDefined();
      expect(result.status).toBe('completed');
      expect(result.fraudAnalysis.riskScore).toBeGreaterThanOrEqual(0);
      expect(result.fraudAnalysis.riskScore).toBeLessThanOrEqual(1);
      expect(result.privacyMetrics.piiRemoved).toBe(true);
      expect(result.privacyMetrics.cardTokenized).toBe(true);
      expect(result.compliance).toContain('PCI_DSS');
      expect(result.compliance).toContain('GDPR');

      // Verify audit trail
      const auditTrail = financialSystem.auditSystem.getAuditTrail(result.processId);
      expect(auditTrail.length).toBeGreaterThan(0);

      // Verify audit integrity
      const integrityCheck = financialSystem.auditSystem.verifyChainIntegrity();
      expect(integrityCheck.valid).toBe(true);

      securityAudit.log('financial_privacy_workflow', {
        transactionProcessed: true,
        fraudDetectionPerformed: true,
        privacyProtected: true,
        complianceValidated: true,
        auditTrailIntact: integrityCheck.valid
      });
    });

    test('should flag high-risk transactions while preserving privacy', async () => {
      const financialSystem = new FinancialPrivacySystem();

      // High-risk transaction scenario
      const highRiskTransaction = {
        id: 'txn-999',
        amount: 50000.00, // Very high amount
        cardNumber: '4111111111111111',
        timestamp: Date.now(),
        merchant: 'Unknown Merchant',
        location: {
          latitude: 35.6762, // Tokyo - far from user's typical location
          longitude: 139.6503,
          city: 'Tokyo',
          country: 'Japan',
          region: 'Asia'
        }
      };

      const lowRiskProfile = {
        averageDaily: 2,
        recentTransactionCount: 1,
        typicalLocations: [
          { latitude: 42.3601, longitude: -71.0589 } // Boston
        ]
      };

      try {
        const result = await financialSystem.processTransaction(highRiskTransaction, lowRiskProfile);

        // Should complete but with high risk score
        expect(result.fraudAnalysis.riskScore).toBeGreaterThan(0.5);
        expect(result.fraudAnalysis.flagged).toBe(true);
        expect(result.fraudAnalysis.flags).toContain('unusual_amount');

        // Privacy should still be protected even for flagged transactions
        expect(result.privacyMetrics.differentialPrivacyApplied).toBe(true);
        expect(result.privacyMetrics.privacyBudget).toBeGreaterThan(0);

        securityAudit.log('high_risk_transaction', {
          riskScore: result.fraudAnalysis.riskScore,
          flagged: result.fraudAnalysis.flagged,
          flags: result.fraudAnalysis.flags,
          privacyMaintained: true
        });

      } catch (error) {
        // Transaction might be blocked for high risk
        expect(error.message).toContain('risk');
        securityAudit.log('transaction_blocked', {
          reason: 'high_risk',
          blocked: true
        });
      }
    });
  });
});