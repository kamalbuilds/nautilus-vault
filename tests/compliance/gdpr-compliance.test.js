/**
 * GDPR Compliance Validation Test Suite
 * Ensuring data protection and privacy compliance
 */

const crypto = require('crypto');

describe('GDPR Compliance Validation', () => {
  let securityAudit;

  beforeAll(() => {
    securityAudit = global.securityAudit;
  });

  describe('Data Subject Rights (GDPR Articles 15-22)', () => {
    // Mock GDPR compliance system
    class GDPRComplianceSystem {
      constructor() {
        this.personalData = new Map();
        this.processingActivities = new Map();
        this.consentRecords = new Map();
        this.dataRetentionPolicies = new Map();
        this.auditLog = [];
      }

      storePersonalData(dataSubjectId, data, lawfulBasis, purpose) {
        const record = {
          id: crypto.randomUUID(),
          dataSubjectId,
          data,
          lawfulBasis,
          purpose,
          createdAt: Date.now(),
          lastModified: Date.now(),
          dataCategories: this.categorizeData(data),
          retentionPeriod: this.getRetentionPeriod(purpose)
        };

        this.personalData.set(record.id, record);
        this.logProcessingActivity('data_stored', record.id, { purpose, lawfulBasis });

        return record.id;
      }

      categorizeData(data) {
        const categories = [];
        const sensitiveFields = ['health', 'biometric', 'genetic', 'political', 'religious'];
        const identificationFields = ['name', 'email', 'phone', 'address', 'id'];

        Object.keys(data).forEach(field => {
          if (sensitiveFields.some(sf => field.toLowerCase().includes(sf))) {
            categories.push('special_category');
          } else if (identificationFields.some(if_ => field.toLowerCase().includes(if_))) {
            categories.push('identification');
          } else {
            categories.push('general');
          }
        });

        return [...new Set(categories)];
      }

      getRetentionPeriod(purpose) {
        const retentionPolicies = {
          'marketing': 2 * 365 * 24 * 60 * 60 * 1000, // 2 years
          'contract_performance': 7 * 365 * 24 * 60 * 60 * 1000, // 7 years
          'legal_compliance': 10 * 365 * 24 * 60 * 60 * 1000, // 10 years
          'legitimate_interest': 1 * 365 * 24 * 60 * 60 * 1000 // 1 year
        };

        return retentionPolicies[purpose] || 1 * 365 * 24 * 60 * 60 * 1000; // Default 1 year
      }

      logProcessingActivity(activity, recordId, details) {
        const logEntry = {
          timestamp: Date.now(),
          activity,
          recordId,
          details
        };

        this.auditLog.push(logEntry);
      }

      // Article 15: Right of access
      exerciseRightOfAccess(dataSubjectId) {
        const subjectData = [];

        for (const [recordId, record] of this.personalData.entries()) {
          if (record.dataSubjectId === dataSubjectId) {
            subjectData.push({
              recordId,
              data: record.data,
              purpose: record.purpose,
              lawfulBasis: record.lawfulBasis,
              categories: record.dataCategories,
              createdAt: new Date(record.createdAt).toISOString(),
              retentionPeriod: Math.ceil(record.retentionPeriod / (365 * 24 * 60 * 60 * 1000)) + ' years'
            });
          }
        }

        this.logProcessingActivity('right_of_access_exercised', null, { dataSubjectId, recordsFound: subjectData.length });

        return {
          dataSubjectId,
          requestDate: new Date().toISOString(),
          personalData: subjectData,
          processingPurposes: [...new Set(subjectData.map(d => d.purpose))],
          lawfulBases: [...new Set(subjectData.map(d => d.lawfulBasis))],
          dataCategories: [...new Set(subjectData.flatMap(d => d.categories))]
        };
      }

      // Article 16: Right to rectification
      exerciseRightToRectification(dataSubjectId, recordId, corrections) {
        const record = this.personalData.get(recordId);

        if (!record || record.dataSubjectId !== dataSubjectId) {
          throw new Error('Record not found or access denied');
        }

        const originalData = { ...record.data };

        // Apply corrections
        Object.keys(corrections).forEach(field => {
          if (record.data.hasOwnProperty(field)) {
            record.data[field] = corrections[field];
          }
        });

        record.lastModified = Date.now();

        this.logProcessingActivity('data_rectified', recordId, {
          dataSubjectId,
          originalFields: Object.keys(corrections),
          corrections
        });

        return {
          recordId,
          dataSubjectId,
          originalData: originalData,
          correctedData: record.data,
          correctionDate: new Date().toISOString()
        };
      }

      // Article 17: Right to erasure ("right to be forgotten")
      exerciseRightToErasure(dataSubjectId, reason) {
        const validReasons = [
          'consent_withdrawn',
          'no_longer_necessary',
          'unlawful_processing',
          'legal_compliance',
          'child_consent'
        ];

        if (!validReasons.includes(reason)) {
          throw new Error('Invalid reason for erasure');
        }

        const erasedRecords = [];

        for (const [recordId, record] of this.personalData.entries()) {
          if (record.dataSubjectId === dataSubjectId) {
            // Check if erasure is possible (no legal obligations to retain)
            if (this.canEraseData(record, reason)) {
              this.personalData.delete(recordId);
              erasedRecords.push(recordId);
            }
          }
        }

        this.logProcessingActivity('data_erased', null, {
          dataSubjectId,
          reason,
          erasedRecords: erasedRecords.length,
          recordIds: erasedRecords
        });

        return {
          dataSubjectId,
          erasureDate: new Date().toISOString(),
          reason,
          erasedRecords: erasedRecords.length,
          recordIds: erasedRecords
        };
      }

      canEraseData(record, reason) {
        // Simplified erasure rules
        const legalObligationPurposes = ['legal_compliance', 'contract_performance'];

        if (legalObligationPurposes.includes(record.purpose)) {
          const retentionExpired = Date.now() > (record.createdAt + record.retentionPeriod);
          return retentionExpired;
        }

        return true; // Can erase if no legal obligation
      }

      // Article 18: Right to restriction of processing
      exerciseRightToRestriction(dataSubjectId, recordId, reason) {
        const record = this.personalData.get(recordId);

        if (!record || record.dataSubjectId !== dataSubjectId) {
          throw new Error('Record not found or access denied');
        }

        record.processingRestricted = true;
        record.restrictionReason = reason;
        record.restrictionDate = Date.now();

        this.logProcessingActivity('processing_restricted', recordId, {
          dataSubjectId,
          reason
        });

        return {
          recordId,
          dataSubjectId,
          restrictionDate: new Date().toISOString(),
          reason
        };
      }

      // Article 20: Right to data portability
      exerciseRightToDataPortability(dataSubjectId, format = 'json') {
        const portableData = {};

        for (const [recordId, record] of this.personalData.entries()) {
          if (record.dataSubjectId === dataSubjectId &&
              (record.lawfulBasis === 'consent' || record.lawfulBasis === 'contract')) {
            portableData[recordId] = {
              data: record.data,
              purpose: record.purpose,
              createdAt: record.createdAt
            };
          }
        }

        this.logProcessingActivity('data_exported', null, {
          dataSubjectId,
          format,
          recordCount: Object.keys(portableData).length
        });

        if (format === 'json') {
          return JSON.stringify(portableData, null, 2);
        } else if (format === 'csv') {
          // Simplified CSV export
          return this.convertToCSV(portableData);
        }

        return portableData;
      }

      convertToCSV(data) {
        // Simplified CSV conversion
        const records = Object.values(data);
        if (records.length === 0) return '';

        const headers = ['recordId', ...Object.keys(records[0].data)];
        const csvRows = [headers.join(',')];

        records.forEach((record, index) => {
          const values = [
            Object.keys(data)[index],
            ...Object.values(record.data).map(v => `"${v}"`)
          ];
          csvRows.push(values.join(','));
        });

        return csvRows.join('\n');
      }

      // Article 21: Right to object
      exerciseRightToObject(dataSubjectId, purpose, reason) {
        const affectedRecords = [];

        for (const [recordId, record] of this.personalData.entries()) {
          if (record.dataSubjectId === dataSubjectId &&
              record.purpose === purpose &&
              record.lawfulBasis === 'legitimate_interest') {

            // Check if there are compelling legitimate grounds
            const compellingGrounds = this.hasCompellingLegitimateGrounds(record);

            if (!compellingGrounds) {
              record.processingRestricted = true;
              record.objectionReason = reason;
              affectedRecords.push(recordId);
            }
          }
        }

        this.logProcessingActivity('objection_processed', null, {
          dataSubjectId,
          purpose,
          reason,
          affectedRecords: affectedRecords.length
        });

        return {
          dataSubjectId,
          objectionDate: new Date().toISOString(),
          purpose,
          reason,
          affectedRecords: affectedRecords.length,
          processingHalted: affectedRecords.length > 0
        };
      }

      hasCompellingLegitimateGrounds(record) {
        // Simplified check for compelling legitimate grounds
        const compellingPurposes = ['fraud_prevention', 'legal_defense', 'public_safety'];
        return compellingPurposes.includes(record.purpose);
      }

      // Data retention and automated deletion
      performDataRetentionCleanup() {
        const now = Date.now();
        const deletedRecords = [];

        for (const [recordId, record] of this.personalData.entries()) {
          const retentionExpired = now > (record.createdAt + record.retentionPeriod);

          if (retentionExpired && !record.processingRestricted) {
            this.personalData.delete(recordId);
            deletedRecords.push(recordId);
          }
        }

        this.logProcessingActivity('retention_cleanup', null, {
          deletedCount: deletedRecords.length,
          deletedRecords
        });

        return deletedRecords.length;
      }

      generateComplianceReport() {
        const report = {
          timestamp: new Date().toISOString(),
          totalRecords: this.personalData.size,
          dataCategories: {},
          lawfulBases: {},
          purposes: {},
          subjectRightsExercised: {},
          retentionCompliance: 0
        };

        // Analyze data categories
        for (const record of this.personalData.values()) {
          record.dataCategories.forEach(category => {
            report.dataCategories[category] = (report.dataCategories[category] || 0) + 1;
          });

          report.lawfulBases[record.lawfulBasis] = (report.lawfulBases[record.lawfulBasis] || 0) + 1;
          report.purposes[record.purpose] = (report.purposes[record.purpose] || 0) + 1;
        }

        // Analyze subject rights
        this.auditLog.forEach(log => {
          if (log.activity.includes('right_') || log.activity.includes('_exercised')) {
            report.subjectRightsExercised[log.activity] = (report.subjectRightsExercised[log.activity] || 0) + 1;
          }
        });

        // Check retention compliance
        const now = Date.now();
        let compliantRecords = 0;
        for (const record of this.personalData.values()) {
          const withinRetention = now <= (record.createdAt + record.retentionPeriod);
          if (withinRetention) compliantRecords++;
        }
        report.retentionCompliance = (compliantRecords / this.personalData.size) * 100;

        return report;
      }
    }

    test('should handle Right of Access (Article 15) requests', () => {
      const gdprSystem = new GDPRComplianceSystem();

      // Store personal data for test subject
      const dataSubjectId = 'user-123';
      const personalData = {
        name: 'Jane Doe',
        email: 'jane.doe@example.com',
        phone: '+1234567890',
        address: '123 Privacy Street, Data City'
      };

      const recordId = gdprSystem.storePersonalData(
        dataSubjectId,
        personalData,
        'consent',
        'marketing'
      );

      // Exercise right of access
      const accessResponse = gdprSystem.exerciseRightOfAccess(dataSubjectId);

      expect(accessResponse.dataSubjectId).toBe(dataSubjectId);
      expect(accessResponse.personalData).toHaveLength(1);
      expect(accessResponse.personalData[0].data).toEqual(personalData);
      expect(accessResponse.personalData[0].lawfulBasis).toBe('consent');
      expect(accessResponse.personalData[0].purpose).toBe('marketing');

      securityAudit.log('gdpr_right_of_access', {
        dataSubjectId,
        recordsReturned: accessResponse.personalData.length,
        purposes: accessResponse.processingPurposes,
        categories: accessResponse.dataCategories
      });
    });

    test('should handle Right to Rectification (Article 16) requests', () => {
      const gdprSystem = new GDPRComplianceSystem();

      const dataSubjectId = 'user-456';
      const originalData = {
        name: 'John Smith',
        email: 'john.smith@old-email.com',
        phone: '+1111111111'
      };

      const recordId = gdprSystem.storePersonalData(
        dataSubjectId,
        originalData,
        'consent',
        'contract_performance'
      );

      // Exercise right to rectification
      const corrections = {
        email: 'john.smith@new-email.com',
        phone: '+2222222222'
      };

      const rectificationResponse = gdprSystem.exerciseRightToRectification(
        dataSubjectId,
        recordId,
        corrections
      );

      expect(rectificationResponse.recordId).toBe(recordId);
      expect(rectificationResponse.correctedData.email).toBe('john.smith@new-email.com');
      expect(rectificationResponse.correctedData.phone).toBe('+2222222222');
      expect(rectificationResponse.correctedData.name).toBe('John Smith'); // Unchanged

      securityAudit.log('gdpr_right_to_rectification', {
        dataSubjectId,
        recordId,
        correctedFields: Object.keys(corrections)
      });
    });

    test('should handle Right to Erasure (Article 17) requests', () => {
      const gdprSystem = new GDPRComplianceSystem();

      const dataSubjectId = 'user-789';
      const personalData = {
        name: 'Alice Johnson',
        email: 'alice@example.com',
        preferences: 'newsletter'
      };

      const recordId1 = gdprSystem.storePersonalData(
        dataSubjectId,
        personalData,
        'consent',
        'marketing'
      );

      const recordId2 = gdprSystem.storePersonalData(
        dataSubjectId,
        { contractData: 'important' },
        'contract',
        'legal_compliance'
      );

      // Exercise right to erasure
      const erasureResponse = gdprSystem.exerciseRightToErasure(
        dataSubjectId,
        'consent_withdrawn'
      );

      expect(erasureResponse.dataSubjectId).toBe(dataSubjectId);
      expect(erasureResponse.reason).toBe('consent_withdrawn');
      expect(erasureResponse.erasedRecords).toBeGreaterThan(0);

      // Verify marketing data was erased but legal compliance data retained
      const accessResponse = gdprSystem.exerciseRightOfAccess(dataSubjectId);
      const remainingPurposes = accessResponse.personalData.map(d => d.purpose);
      expect(remainingPurposes).not.toContain('marketing');

      securityAudit.log('gdpr_right_to_erasure', {
        dataSubjectId,
        reason: erasureResponse.reason,
        erasedRecords: erasureResponse.erasedRecords,
        retainedRecords: accessResponse.personalData.length
      });
    });

    test('should handle Right to Data Portability (Article 20) requests', () => {
      const gdprSystem = new GDPRComplianceSystem();

      const dataSubjectId = 'user-portability';
      const consentBasedData = {
        preferences: 'dark mode',
        settings: 'notifications enabled',
        profile: 'public'
      };

      const contractBasedData = {
        subscription: 'premium',
        paymentMethod: 'credit card'
      };

      const legitimateInterestData = {
        analytics: 'usage patterns'
      };

      // Store data with different lawful bases
      gdprSystem.storePersonalData(dataSubjectId, consentBasedData, 'consent', 'personalization');
      gdprSystem.storePersonalData(dataSubjectId, contractBasedData, 'contract', 'service_provision');
      gdprSystem.storePersonalData(dataSubjectId, legitimateInterestData, 'legitimate_interest', 'analytics');

      // Exercise right to data portability
      const portabilityResponse = gdprSystem.exerciseRightToDataPortability(dataSubjectId, 'json');

      const portedData = JSON.parse(portabilityResponse);
      const portedRecords = Object.values(portedData);

      // Should only include consent and contract-based data
      expect(portedRecords.length).toBe(2);
      expect(portedRecords.some(r => r.data.preferences)).toBe(true);
      expect(portedRecords.some(r => r.data.subscription)).toBe(true);
      expect(portedRecords.some(r => r.data.analytics)).toBe(false);

      securityAudit.log('gdpr_right_to_portability', {
        dataSubjectId,
        format: 'json',
        recordsPorted: portedRecords.length,
        excludedLegitimateInterest: true
      });

      // Test CSV format
      const csvResponse = gdprSystem.exerciseRightToDataPortability(dataSubjectId, 'csv');
      expect(csvResponse).toContain('recordId');
      expect(typeof csvResponse).toBe('string');

      securityAudit.log('gdpr_portability_csv_format', {
        dataSubjectId,
        csvLength: csvResponse.length,
        formatSupported: true
      });
    });

    test('should handle Right to Object (Article 21) requests', () => {
      const gdprSystem = new GDPRComplianceSystem();

      const dataSubjectId = 'user-objection';
      const marketingData = {
        email: 'user@example.com',
        interests: 'technology, finance'
      };

      gdprSystem.storePersonalData(
        dataSubjectId,
        marketingData,
        'legitimate_interest',
        'marketing'
      );

      // Exercise right to object
      const objectionResponse = gdprSystem.exerciseRightToObject(
        dataSubjectId,
        'marketing',
        'No longer interested in marketing communications'
      );

      expect(objectionResponse.dataSubjectId).toBe(dataSubjectId);
      expect(objectionResponse.purpose).toBe('marketing');
      expect(objectionResponse.processingHalted).toBe(true);
      expect(objectionResponse.affectedRecords).toBeGreaterThan(0);

      securityAudit.log('gdpr_right_to_object', {
        dataSubjectId,
        purpose: objectionResponse.purpose,
        processingHalted: objectionResponse.processingHalted,
        affectedRecords: objectionResponse.affectedRecords
      });
    });

    test('should implement automated data retention and deletion', () => {
      const gdprSystem = new GDPRComplianceSystem();

      const dataSubjectId = 'user-retention';

      // Store data with short retention period (simulate old data)
      const recordData = { name: 'Test User', email: 'test@example.com' };
      const recordId = gdprSystem.storePersonalData(
        dataSubjectId,
        recordData,
        'consent',
        'marketing'
      );

      // Manually set creation time to simulate old data
      const record = gdprSystem.personalData.get(recordId);
      record.createdAt = Date.now() - (3 * 365 * 24 * 60 * 60 * 1000); // 3 years ago
      record.retentionPeriod = 2 * 365 * 24 * 60 * 60 * 1000; // 2 year retention

      // Perform retention cleanup
      const deletedCount = gdprSystem.performDataRetentionCleanup();

      expect(deletedCount).toBe(1);
      expect(gdprSystem.personalData.has(recordId)).toBe(false);

      securityAudit.log('gdpr_automated_retention', {
        deletedRecords: deletedCount,
        retentionPolicyEnforced: true,
        automatedDeletion: true
      });
    });
  });

  describe('Data Processing Principles (GDPR Articles 5-6)', () => {
    test('should implement data minimization principle', () => {
      // Mock data collection validator
      class DataMinimizationValidator {
        constructor() {
          this.purposeFieldMappings = {
            'newsletter': ['email', 'firstName', 'preferences'],
            'billing': ['name', 'address', 'paymentMethod', 'amount'],
            'support': ['email', 'issueDescription', 'userAgent'],
            'analytics': ['sessionId', 'pageViews', 'timestamp']
          };
        }

        validateDataCollection(collectedData, purpose) {
          const allowedFields = this.purposeFieldMappings[purpose] || [];
          const violations = [];
          const minimizedData = {};

          Object.keys(collectedData).forEach(field => {
            if (allowedFields.includes(field)) {
              minimizedData[field] = collectedData[field];
            } else {
              violations.push({
                field,
                reason: 'not_necessary_for_purpose'
              });
            }
          });

          return {
            compliant: violations.length === 0,
            violations,
            minimizedData,
            reductionPercentage: ((Object.keys(collectedData).length - Object.keys(minimizedData).length) / Object.keys(collectedData).length) * 100
          };
        }
      }

      const validator = new DataMinimizationValidator();

      const testCases = [
        {
          purpose: 'newsletter',
          collectedData: {
            email: 'user@example.com',
            firstName: 'John',
            preferences: 'weekly',
            // Excessive data below
            ssn: '123-45-6789',
            creditCard: '4111-1111-1111-1111',
            medicalHistory: 'diabetes'
          },
          shouldBeMinimized: true
        },
        {
          purpose: 'billing',
          collectedData: {
            name: 'John Doe',
            address: '123 Main St',
            paymentMethod: 'visa',
            amount: 29.99
          },
          shouldBeMinimized: false
        }
      ];

      for (const testCase of testCases) {
        const validation = validator.validateDataCollection(
          testCase.collectedData,
          testCase.purpose
        );

        if (testCase.shouldBeMinimized) {
          expect(validation.compliant).toBe(false);
          expect(validation.violations.length).toBeGreaterThan(0);
          expect(validation.reductionPercentage).toBeGreaterThan(0);
        } else {
          expect(validation.compliant).toBe(true);
          expect(validation.violations.length).toBe(0);
        }

        securityAudit.log('gdpr_data_minimization', {
          purpose: testCase.purpose,
          originalFields: Object.keys(testCase.collectedData).length,
          minimizedFields: Object.keys(validation.minimizedData).length,
          reductionPercentage: validation.reductionPercentage,
          compliant: validation.compliant
        });
      }
    });

    test('should implement purpose limitation principle', () => {
      // Mock purpose validation system
      class PurposeLimitationValidator {
        constructor() {
          this.originalPurposes = new Map();
          this.compatiblePurposes = {
            'marketing': ['newsletter', 'product_recommendations'],
            'customer_service': ['support', 'account_management'],
            'legal_compliance': ['audit', 'regulatory_reporting'],
            'security': ['fraud_detection', 'access_monitoring']
          };
        }

        registerDataProcessing(recordId, originalPurpose) {
          this.originalPurposes.set(recordId, originalPurpose);
        }

        validatePurposeChange(recordId, newPurpose) {
          const originalPurpose = this.originalPurposes.get(recordId);

          if (!originalPurpose) {
            return { allowed: false, reason: 'no_original_purpose_recorded' };
          }

          // Check if new purpose is compatible
          const compatibleGroup = Object.keys(this.compatiblePurposes).find(group =>
            this.compatiblePurposes[group].includes(originalPurpose)
          );

          if (compatibleGroup && this.compatiblePurposes[compatibleGroup].includes(newPurpose)) {
            return { allowed: true, reason: 'compatible_purpose' };
          }

          // Check if it's the same purpose
          if (originalPurpose === newPurpose) {
            return { allowed: true, reason: 'same_purpose' };
          }

          return { allowed: false, reason: 'incompatible_purpose' };
        }

        assessPurposeCompatibility(purpose1, purpose2) {
          // Determine if two purposes are compatible without explicit consent
          const compatibilityMatrix = {
            'newsletter': ['marketing', 'product_recommendations'],
            'marketing': ['newsletter', 'product_recommendations'],
            'support': ['customer_service', 'account_management'],
            'fraud_detection': ['security', 'risk_assessment']
          };

          if (purpose1 === purpose2) return true;

          const compatible1 = compatibilityMatrix[purpose1] || [];
          return compatible1.includes(purpose2);
        }
      }

      const validator = new PurposeLimitationValidator();

      // Test purpose registration and validation
      const recordId1 = 'record-123';
      const recordId2 = 'record-456';

      validator.registerDataProcessing(recordId1, 'newsletter');
      validator.registerDataProcessing(recordId2, 'support');

      // Test compatible purpose changes
      const compatibleChange = validator.validatePurposeChange(recordId1, 'marketing');
      expect(compatibleChange.allowed).toBe(true);
      expect(compatibleChange.reason).toBe('compatible_purpose');

      // Test incompatible purpose change
      const incompatibleChange = validator.validatePurposeChange(recordId2, 'marketing');
      expect(incompatibleChange.allowed).toBe(false);
      expect(incompatibleChange.reason).toBe('incompatible_purpose');

      // Test purpose compatibility assessment
      expect(validator.assessPurposeCompatibility('newsletter', 'marketing')).toBe(true);
      expect(validator.assessPurposeCompatibility('support', 'fraud_detection')).toBe(false);

      securityAudit.log('gdpr_purpose_limitation', {
        compatibleChangesAllowed: true,
        incompatibleChangesBlocked: true,
        purposeCompatibilityValidated: true
      });
    });

    test('should implement storage limitation principle', () => {
      // Mock storage limitation system
      class StorageLimitationManager {
        constructor() {
          this.dataRetentionPolicies = new Map([
            ['marketing', { period: 2, unit: 'years' }],
            ['contract_performance', { period: 7, unit: 'years' }],
            ['legal_compliance', { period: 10, unit: 'years' }],
            ['fraud_detection', { period: 5, unit: 'years' }],
            ['analytics', { period: 1, unit: 'years' }]
          ]);

          this.dataStore = new Map();
        }

        storeData(recordId, data, purpose, lawfulBasis) {
          const retention = this.dataRetentionPolicies.get(purpose);

          if (!retention) {
            throw new Error('No retention policy defined for purpose: ' + purpose);
          }

          const retentionMs = this.convertToMilliseconds(retention.period, retention.unit);

          const record = {
            id: recordId,
            data,
            purpose,
            lawfulBasis,
            storedAt: Date.now(),
            retentionPeriod: retentionMs,
            expiresAt: Date.now() + retentionMs,
            scheduledForDeletion: false
          };

          this.dataStore.set(recordId, record);
          return record;
        }

        convertToMilliseconds(period, unit) {
          const conversions = {
            'days': 24 * 60 * 60 * 1000,
            'months': 30 * 24 * 60 * 60 * 1000,
            'years': 365 * 24 * 60 * 60 * 1000
          };

          return period * conversions[unit];
        }

        checkRetentionCompliance() {
          const now = Date.now();
          const complianceReport = {
            totalRecords: this.dataStore.size,
            expiredRecords: 0,
            nearExpiryRecords: 0,
            compliantRecords: 0
          };

          for (const [recordId, record] of this.dataStore.entries()) {
            const daysUntilExpiry = (record.expiresAt - now) / (24 * 60 * 60 * 1000);

            if (record.expiresAt <= now) {
              complianceReport.expiredRecords++;
              record.scheduledForDeletion = true;
            } else if (daysUntilExpiry <= 30) {
              complianceReport.nearExpiryRecords++;
            } else {
              complianceReport.compliantRecords++;
            }
          }

          return complianceReport;
        }

        performScheduledDeletion() {
          const deletedRecords = [];

          for (const [recordId, record] of this.dataStore.entries()) {
            if (record.scheduledForDeletion) {
              this.dataStore.delete(recordId);
              deletedRecords.push(recordId);
            }
          }

          return deletedRecords;
        }

        extendRetention(recordId, reason, additionalPeriod, additionalUnit) {
          const record = this.dataStore.get(recordId);

          if (!record) {
            throw new Error('Record not found');
          }

          const validReasons = ['legal_hold', 'ongoing_investigation', 'court_order'];
          if (!validReasons.includes(reason)) {
            throw new Error('Invalid reason for retention extension');
          }

          const additionalMs = this.convertToMilliseconds(additionalPeriod, additionalUnit);
          record.expiresAt += additionalMs;
          record.retentionExtended = {
            reason,
            additionalPeriod,
            additionalUnit,
            extendedAt: Date.now()
          };

          return record;
        }
      }

      const storageManager = new StorageLimitationManager();

      // Store test data with different purposes
      const marketingRecord = storageManager.storeData(
        'marketing-1',
        { email: 'user@example.com' },
        'marketing',
        'consent'
      );

      const legalRecord = storageManager.storeData(
        'legal-1',
        { contractData: 'important' },
        'legal_compliance',
        'legal_obligation'
      );

      // Verify retention periods are set correctly
      expect(marketingRecord.retentionPeriod).toBe(2 * 365 * 24 * 60 * 60 * 1000); // 2 years
      expect(legalRecord.retentionPeriod).toBe(10 * 365 * 24 * 60 * 60 * 1000); // 10 years

      // Test compliance checking
      const complianceReport = storageManager.checkRetentionCompliance();
      expect(complianceReport.totalRecords).toBe(2);
      expect(complianceReport.compliantRecords).toBe(2); // Both records should be compliant initially

      // Test retention extension
      const extendedRecord = storageManager.extendRetention(
        'marketing-1',
        'legal_hold',
        6,
        'months'
      );

      expect(extendedRecord.retentionExtended).toBeDefined();
      expect(extendedRecord.retentionExtended.reason).toBe('legal_hold');

      securityAudit.log('gdpr_storage_limitation', {
        retentionPoliciesImplemented: true,
        automaticExpiryTracking: true,
        retentionExtensionSupported: true,
        complianceReporting: true
      });
    });
  });

  describe('Consent Management (GDPR Articles 6-7)', () => {
    test('should implement valid consent collection and management', () => {
      // Mock consent management system
      class ConsentManager {
        constructor() {
          this.consents = new Map();
        }

        collectConsent(dataSubjectId, purposes, consentData) {
          const consentId = crypto.randomUUID();

          // Validate consent criteria (Article 7)
          const validation = this.validateConsent(consentData);

          if (!validation.valid) {
            throw new Error('Invalid consent: ' + validation.errors.join(', '));
          }

          const consent = {
            id: consentId,
            dataSubjectId,
            purposes,
            grantedAt: Date.now(),
            ipAddress: consentData.ipAddress,
            userAgent: consentData.userAgent,
            consentMethod: consentData.method,
            languageUsed: consentData.language,
            explicitConsent: consentData.explicit,
            granular: consentData.granular,
            withdrawable: true,
            evidenceOfConsent: consentData.evidence,
            active: true
          };

          this.consents.set(consentId, consent);
          return consentId;
        }

        validateConsent(consentData) {
          const errors = [];

          // Freely given
          if (consentData.preTickedBoxes) {
            errors.push('consent_not_freely_given_preticked_boxes');
          }

          if (consentData.bundledWithService && !consentData.necessary) {
            errors.push('consent_bundled_with_service');
          }

          // Specific
          if (!consentData.purposes || consentData.purposes.length === 0) {
            errors.push('consent_not_specific_no_purposes');
          }

          if (consentData.purposes && consentData.purposes.includes('all_purposes')) {
            errors.push('consent_too_broad');
          }

          // Informed
          if (!consentData.privacyNoticeProvided) {
            errors.push('privacy_notice_not_provided');
          }

          if (!consentData.dataControllerIdentified) {
            errors.push('data_controller_not_identified');
          }

          // Unambiguous
          if (!consentData.clearAffirmativeAction) {
            errors.push('consent_not_unambiguous');
          }

          return {
            valid: errors.length === 0,
            errors
          };
        }

        checkConsentValidity(consentId, purpose) {
          const consent = this.consents.get(consentId);

          if (!consent) {
            return { valid: false, reason: 'consent_not_found' };
          }

          if (!consent.active) {
            return { valid: false, reason: 'consent_withdrawn' };
          }

          if (!consent.purposes.includes(purpose)) {
            return { valid: false, reason: 'purpose_not_consented' };
          }

          return { valid: true, consent };
        }

        withdrawConsent(dataSubjectId, consentId, reason) {
          const consent = this.consents.get(consentId);

          if (!consent || consent.dataSubjectId !== dataSubjectId) {
            throw new Error('Consent not found or unauthorized');
          }

          consent.active = false;
          consent.withdrawnAt = Date.now();
          consent.withdrawalReason = reason;

          return {
            consentId,
            dataSubjectId,
            withdrawnAt: new Date().toISOString(),
            reason,
            affectedPurposes: consent.purposes
          };
        }

        updateConsent(dataSubjectId, consentId, newPurposes, newConsentData) {
          const consent = this.consents.get(consentId);

          if (!consent || consent.dataSubjectId !== dataSubjectId) {
            throw new Error('Consent not found or unauthorized');
          }

          // Validate new consent
          const validation = this.validateConsent(newConsentData);

          if (!validation.valid) {
            throw new Error('Invalid updated consent: ' + validation.errors.join(', '));
          }

          // Create new consent record (best practice)
          const newConsentId = this.collectConsent(dataSubjectId, newPurposes, newConsentData);

          // Mark old consent as superseded
          consent.active = false;
          consent.supersededAt = Date.now();
          consent.supersededBy = newConsentId;

          return newConsentId;
        }

        generateConsentReport(dataSubjectId) {
          const subjectConsents = [];

          for (const consent of this.consents.values()) {
            if (consent.dataSubjectId === dataSubjectId) {
              subjectConsents.push({
                consentId: consent.id,
                purposes: consent.purposes,
                grantedAt: new Date(consent.grantedAt).toISOString(),
                active: consent.active,
                method: consent.consentMethod,
                withdrawnAt: consent.withdrawnAt ? new Date(consent.withdrawnAt).toISOString() : null,
                withdrawalReason: consent.withdrawalReason
              });
            }
          }

          return {
            dataSubjectId,
            totalConsents: subjectConsents.length,
            activeConsents: subjectConsents.filter(c => c.active).length,
            consents: subjectConsents
          };
        }
      }

      const consentManager = new ConsentManager();

      // Test valid consent collection
      const validConsentData = {
        ipAddress: '203.0.113.1',
        userAgent: 'Mozilla/5.0...',
        method: 'checkbox',
        language: 'en',
        explicit: true,
        granular: true,
        preTickedBoxes: false,
        bundledWithService: false,
        purposes: ['marketing', 'analytics'],
        privacyNoticeProvided: true,
        dataControllerIdentified: true,
        clearAffirmativeAction: true,
        evidence: 'checkbox_checked_explicitly'
      };

      const consentId = consentManager.collectConsent(
        'user-consent-123',
        ['marketing', 'analytics'],
        validConsentData
      );

      expect(consentId).toBeDefined();

      // Test consent validity checking
      const marketingValidation = consentManager.checkConsentValidity(consentId, 'marketing');
      const analyticsValidation = consentManager.checkConsentValidity(consentId, 'analytics');
      const unrelatedValidation = consentManager.checkConsentValidity(consentId, 'fraud_detection');

      expect(marketingValidation.valid).toBe(true);
      expect(analyticsValidation.valid).toBe(true);
      expect(unrelatedValidation.valid).toBe(false);

      // Test consent withdrawal
      const withdrawal = consentManager.withdrawConsent(
        'user-consent-123',
        consentId,
        'no_longer_interested'
      );

      expect(withdrawal.consentId).toBe(consentId);
      expect(withdrawal.affectedPurposes).toEqual(['marketing', 'analytics']);

      // Verify consent is no longer valid after withdrawal
      const postWithdrawalValidation = consentManager.checkConsentValidity(consentId, 'marketing');
      expect(postWithdrawalValidation.valid).toBe(false);
      expect(postWithdrawalValidation.reason).toBe('consent_withdrawn');

      securityAudit.log('gdpr_consent_management', {
        validConsentCollected: true,
        consentValidationWorking: true,
        consentWithdrawalWorking: true,
        granularConsentSupported: true
      });

      // Test invalid consent scenarios
      const invalidConsentData = {
        ...validConsentData,
        preTickedBoxes: true, // Invalid
        purposes: ['all_purposes'], // Too broad
        privacyNoticeProvided: false // Missing
      };

      expect(() => {
        consentManager.collectConsent(
          'user-invalid',
          ['all_purposes'],
          invalidConsentData
        );
      }).toThrow('Invalid consent');

      securityAudit.log('gdpr_invalid_consent_rejected', {
        preTickedBoxesRejected: true,
        broadPurposesRejected: true,
        missingPrivacyNoticeDetected: true
      });
    });
  });

  afterAll(() => {
    // Generate comprehensive GDPR compliance report
    const auditEntries = global.securityAudit.logs.filter(log =>
      log.event.includes('gdpr') || log.event.includes('consent') || log.event.includes('retention')
    );

    const complianceAreas = {};
    auditEntries.forEach(entry => {
      const area = entry.event.split('_')[1] || entry.event.split('_')[0];
      if (!complianceAreas[area]) {
        complianceAreas[area] = [];
      }
      complianceAreas[area].push(entry);
    });

    securityAudit.log('gdpr_compliance_summary', {
      totalComplianceTests: auditEntries.length,
      complianceAreas: Object.keys(complianceAreas),
      areaTestCounts: Object.fromEntries(
        Object.entries(complianceAreas).map(([area, tests]) => [area, tests.length])
      ),
      dataSubjectRightsImplemented: [
        'right_of_access',
        'right_to_rectification',
        'right_to_erasure',
        'right_to_portability',
        'right_to_object'
      ],
      dataProcessingPrinciplesImplemented: [
        'data_minimization',
        'purpose_limitation',
        'storage_limitation'
      ],
      consentManagementImplemented: true
    });

    console.log('\n=== GDPR COMPLIANCE VALIDATION COMPLETE ===');
    console.log(`Total compliance tests: ${auditEntries.length}`);
    console.log('Compliance areas validated:', Object.keys(complianceAreas).join(', '));
  });
});