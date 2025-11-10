/**
 * Data Minimization Engine
 * Implements GDPR-compliant data minimization techniques
 */

import { SecurityError, PrivacyError } from '../types';
import { createHash } from 'crypto';

export interface MinimizationConfig {
  purpose: string;
  retention: number; // retention period in milliseconds
  necessity: 'MINIMAL' | 'STANDARD' | 'EXTENDED';
  dataTypes: DataTypeConfig[];
}

export interface DataTypeConfig {
  type: string;
  necessity: 'REQUIRED' | 'OPTIONAL' | 'PROHIBITED';
  transformation?: 'HASH' | 'TRUNCATE' | 'GENERALIZE' | 'SUPPRESS';
  retentionOverride?: number;
}

export interface MinimizationResult {
  originalFields: string[];
  retainedFields: string[];
  transformedFields: string[];
  suppressedFields: string[];
  data: any;
  justification: MinimizationJustification;
}

export interface MinimizationJustification {
  purpose: string;
  legalBasis: string;
  necessityAssessment: Record<string, string>;
  retentionReason: string;
}

export interface DataClassification {
  field: string;
  category: 'PERSONAL' | 'SENSITIVE' | 'BIOMETRIC' | 'BEHAVIORAL' | 'DERIVED';
  sensitivity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  identifiable: boolean;
  protected: boolean;
}

export class DataMinimizer {
  private purposeConfigs: Map<string, MinimizationConfig> = new Map();
  private dataClassifications: Map<string, DataClassification> = new Map();
  private minimizationHistory: MinimizationResult[] = [];

  constructor() {
    this.initializeDefaultConfigs();
    this.initializeDataClassifications();
  }

  /**
   * Minimize data according to purpose and legal basis
   */
  async minimizeData(
    data: any,
    config: MinimizationConfig
  ): Promise<MinimizationResult> {
    try {
      // Validate configuration
      this.validateConfig(config);

      // Analyze data structure
      const dataFields = this.extractDataFields(data);

      // Classify data fields
      const classifications = await this.classifyDataFields(dataFields);

      // Determine necessity for each field
      const necessityAssessment = this.assessFieldNecessity(classifications, config);

      // Apply minimization techniques
      const minimizedData = await this.applyMinimization(data, necessityAssessment, config);

      // Generate justification
      const justification = this.generateJustification(config, necessityAssessment);

      const result: MinimizationResult = {
        originalFields: dataFields,
        retainedFields: Object.keys(minimizedData),
        transformedFields: this.getTransformedFields(necessityAssessment),
        suppressedFields: this.getSuppressedFields(necessityAssessment),
        data: minimizedData,
        justification
      };

      // Store for audit trail
      this.minimizationHistory.push(result);

      console.log(`Data minimized for purpose: ${config.purpose}`);
      return result;

    } catch (error) {
      throw new PrivacyError(`Data minimization failed: ${error.message}`, 'MINIMIZATION_ERROR');
    }
  }

  /**
   * Configure minimization rules for a specific purpose
   */
  configurePurpose(purpose: string, config: MinimizationConfig): void {
    this.validateConfig(config);
    this.purposeConfigs.set(purpose, config);
    console.log(`Configured minimization rules for purpose: ${purpose}`);
  }

  /**
   * Get minimization configuration for a purpose
   */
  getPurposeConfig(purpose: string): MinimizationConfig | null {
    return this.purposeConfigs.get(purpose) || null;
  }

  /**
   * Add data field classification
   */
  addDataClassification(field: string, classification: DataClassification): void {
    this.dataClassifications.set(field, classification);
    console.log(`Added classification for field: ${field}`);
  }

  /**
   * Assess if data collection is proportionate
   */
  async assessProportionality(
    requestedData: string[],
    purpose: string,
    legalBasis: string
  ): Promise<{
    proportionate: boolean;
    excessiveFields: string[];
    recommendations: string[];
  }> {
    try {
      const config = this.purposeConfigs.get(purpose);
      if (!config) {
        throw new PrivacyError(`No configuration found for purpose: ${purpose}`, 'CONFIG_NOT_FOUND');
      }

      const excessiveFields: string[] = [];
      const recommendations: string[] = [];

      for (const field of requestedData) {
        const classification = this.dataClassifications.get(field);
        if (!classification) continue;

        const typeConfig = config.dataTypes.find(dt => dt.type === classification.category);
        if (!typeConfig) continue;

        // Check if field is prohibited for this purpose
        if (typeConfig.necessity === 'PROHIBITED') {
          excessiveFields.push(field);
          recommendations.push(`Remove ${field}: prohibited for purpose ${purpose}`);
          continue;
        }

        // Check if sensitive data is really necessary
        if (classification.sensitivity === 'CRITICAL' && typeConfig.necessity !== 'REQUIRED') {
          excessiveFields.push(field);
          recommendations.push(`Consider removing ${field}: critical sensitivity but not required`);
        }

        // Check for over-collection of biometric data
        if (classification.category === 'BIOMETRIC' && legalBasis !== 'CONSENT') {
          recommendations.push(`Ensure explicit consent for biometric data: ${field}`);
        }
      }

      const proportionate = excessiveFields.length === 0;

      if (!proportionate) {
        recommendations.push('Review data collection scope to ensure proportionality');
        recommendations.push('Consider alternative data sources or derived data');
      }

      return {
        proportionate,
        excessiveFields,
        recommendations
      };

    } catch (error) {
      throw new PrivacyError(`Proportionality assessment failed: ${error.message}`, 'ASSESSMENT_ERROR');
    }
  }

  /**
   * Apply retention policies and auto-deletion
   */
  async applyRetentionPolicy(
    dataStore: Map<string, any>,
    purpose: string
  ): Promise<{
    retained: number;
    deleted: number;
    expiringSoon: number;
  }> {
    try {
      const config = this.purposeConfigs.get(purpose);
      if (!config) {
        throw new PrivacyError(`No retention policy for purpose: ${purpose}`, 'NO_RETENTION_POLICY');
      }

      let retained = 0;
      let deleted = 0;
      let expiringSoon = 0;
      const now = Date.now();
      const warningThreshold = 7 * 24 * 60 * 60 * 1000; // 7 days

      for (const [key, record] of dataStore.entries()) {
        const createdAt = record.timestamp || record.createdAt || now;
        const age = now - createdAt;

        if (age > config.retention) {
          // Data has exceeded retention period
          dataStore.delete(key);
          deleted++;
          console.log(`Deleted expired data: ${key}`);
        } else if (age > config.retention - warningThreshold) {
          // Data will expire soon
          expiringSoon++;
          console.log(`Data expiring soon: ${key}`);
        } else {
          retained++;
        }
      }

      console.log(`Retention policy applied: ${retained} retained, ${deleted} deleted, ${expiringSoon} expiring soon`);

      return { retained, deleted, expiringSoon };

    } catch (error) {
      throw new PrivacyError(`Retention policy application failed: ${error.message}`, 'RETENTION_ERROR');
    }
  }

  /**
   * Generate data minimization report
   */
  generateMinimizationReport(
    period: { start: Date; end: Date }
  ): {
    totalMinimizations: number;
    dataReduction: number;
    topPurposes: string[];
    complianceIssues: string[];
  } {
    const relevantResults = this.minimizationHistory.filter(result =>
      // Filter by period if timestamps were available
      true // Simplified for this implementation
    );

    const totalMinimizations = relevantResults.length;

    // Calculate average data reduction
    const dataReduction = relevantResults.reduce((avg, result) => {
      const reduction = (result.originalFields.length - result.retainedFields.length) / result.originalFields.length;
      return avg + reduction;
    }, 0) / (totalMinimizations || 1);

    // Get top purposes by usage
    const purposeCounts = new Map<string, number>();
    relevantResults.forEach(result => {
      const purpose = result.justification.purpose;
      purposeCounts.set(purpose, (purposeCounts.get(purpose) || 0) + 1);
    });

    const topPurposes = Array.from(purposeCounts.entries())
      .sort(([,a], [,b]) => b - a)
      .slice(0, 5)
      .map(([purpose]) => purpose);

    // Identify compliance issues
    const complianceIssues: string[] = [];

    if (dataReduction < 0.1) {
      complianceIssues.push('Low data reduction rate - review minimization effectiveness');
    }

    const excessiveRetention = relevantResults.filter(result =>
      result.justification.necessityAssessment['retention'] === 'EXCESSIVE'
    );

    if (excessiveRetention.length > 0) {
      complianceIssues.push(`${excessiveRetention.length} instances of potentially excessive retention`);
    }

    return {
      totalMinimizations,
      dataReduction: Math.round(dataReduction * 100) / 100,
      topPurposes,
      complianceIssues
    };
  }

  // Private helper methods

  private initializeDefaultConfigs(): void {
    // Marketing purpose
    this.purposeConfigs.set('marketing', {
      purpose: 'marketing',
      retention: 24 * 30 * 24 * 60 * 60 * 1000, // 2 years
      necessity: 'STANDARD',
      dataTypes: [
        { type: 'PERSONAL', necessity: 'REQUIRED' },
        { type: 'BEHAVIORAL', necessity: 'OPTIONAL', transformation: 'GENERALIZE' },
        { type: 'SENSITIVE', necessity: 'PROHIBITED' },
        { type: 'BIOMETRIC', necessity: 'PROHIBITED' }
      ]
    });

    // Analytics purpose
    this.purposeConfigs.set('analytics', {
      purpose: 'analytics',
      retention: 36 * 30 * 24 * 60 * 60 * 1000, // 3 years
      necessity: 'MINIMAL',
      dataTypes: [
        { type: 'PERSONAL', necessity: 'OPTIONAL', transformation: 'HASH' },
        { type: 'BEHAVIORAL', necessity: 'REQUIRED', transformation: 'GENERALIZE' },
        { type: 'SENSITIVE', necessity: 'PROHIBITED' },
        { type: 'BIOMETRIC', necessity: 'PROHIBITED' }
      ]
    });

    // Service delivery purpose
    this.purposeConfigs.set('service', {
      purpose: 'service',
      retention: 12 * 30 * 24 * 60 * 60 * 1000, // 1 year
      necessity: 'STANDARD',
      dataTypes: [
        { type: 'PERSONAL', necessity: 'REQUIRED' },
        { type: 'BEHAVIORAL', necessity: 'OPTIONAL' },
        { type: 'SENSITIVE', necessity: 'OPTIONAL' },
        { type: 'BIOMETRIC', necessity: 'PROHIBITED' }
      ]
    });
  }

  private initializeDataClassifications(): void {
    // Personal data classifications
    this.addDataClassification('email', {
      field: 'email',
      category: 'PERSONAL',
      sensitivity: 'MEDIUM',
      identifiable: true,
      protected: true
    });

    this.addDataClassification('name', {
      field: 'name',
      category: 'PERSONAL',
      sensitivity: 'MEDIUM',
      identifiable: true,
      protected: true
    });

    this.addDataClassification('phone', {
      field: 'phone',
      category: 'PERSONAL',
      sensitivity: 'MEDIUM',
      identifiable: true,
      protected: true
    });

    this.addDataClassification('address', {
      field: 'address',
      category: 'PERSONAL',
      sensitivity: 'HIGH',
      identifiable: true,
      protected: true
    });

    // Sensitive data classifications
    this.addDataClassification('ssn', {
      field: 'ssn',
      category: 'SENSITIVE',
      sensitivity: 'CRITICAL',
      identifiable: true,
      protected: true
    });

    this.addDataClassification('health', {
      field: 'health',
      category: 'SENSITIVE',
      sensitivity: 'CRITICAL',
      identifiable: false,
      protected: true
    });

    // Behavioral data classifications
    this.addDataClassification('clickstream', {
      field: 'clickstream',
      category: 'BEHAVIORAL',
      sensitivity: 'MEDIUM',
      identifiable: false,
      protected: false
    });

    this.addDataClassification('preferences', {
      field: 'preferences',
      category: 'BEHAVIORAL',
      sensitivity: 'LOW',
      identifiable: false,
      protected: false
    });
  }

  private validateConfig(config: MinimizationConfig): void {
    if (!config.purpose) {
      throw new PrivacyError('Purpose is required for data minimization', 'INVALID_CONFIG');
    }

    if (config.retention <= 0) {
      throw new PrivacyError('Retention period must be positive', 'INVALID_CONFIG');
    }

    if (!config.dataTypes || config.dataTypes.length === 0) {
      throw new PrivacyError('Data type configurations are required', 'INVALID_CONFIG');
    }
  }

  private extractDataFields(data: any): string[] {
    if (typeof data !== 'object' || data === null) {
      return [];
    }

    const fields: string[] = [];

    const traverse = (obj: any, prefix: string = '') => {
      for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
          const fullKey = prefix ? `${prefix}.${key}` : key;
          fields.push(fullKey);

          if (typeof obj[key] === 'object' && obj[key] !== null && !Array.isArray(obj[key])) {
            traverse(obj[key], fullKey);
          }
        }
      }
    };

    traverse(data);
    return fields;
  }

  private async classifyDataFields(fields: string[]): Promise<Map<string, DataClassification>> {
    const classifications = new Map<string, DataClassification>();

    for (const field of fields) {
      let classification = this.dataClassifications.get(field);

      if (!classification) {
        // Auto-classify based on field name patterns
        classification = this.autoClassifyField(field);
      }

      classifications.set(field, classification);
    }

    return classifications;
  }

  private autoClassifyField(field: string): DataClassification {
    const fieldLower = field.toLowerCase();

    // Personal data patterns
    if (fieldLower.includes('email') || fieldLower.includes('mail')) {
      return {
        field,
        category: 'PERSONAL',
        sensitivity: 'MEDIUM',
        identifiable: true,
        protected: true
      };
    }

    if (fieldLower.includes('name') || fieldLower.includes('firstname') || fieldLower.includes('lastname')) {
      return {
        field,
        category: 'PERSONAL',
        sensitivity: 'MEDIUM',
        identifiable: true,
        protected: true
      };
    }

    if (fieldLower.includes('phone') || fieldLower.includes('mobile') || fieldLower.includes('tel')) {
      return {
        field,
        category: 'PERSONAL',
        sensitivity: 'MEDIUM',
        identifiable: true,
        protected: true
      };
    }

    // Sensitive data patterns
    if (fieldLower.includes('ssn') || fieldLower.includes('social') || fieldLower.includes('tax')) {
      return {
        field,
        category: 'SENSITIVE',
        sensitivity: 'CRITICAL',
        identifiable: true,
        protected: true
      };
    }

    if (fieldLower.includes('health') || fieldLower.includes('medical') || fieldLower.includes('diagnosis')) {
      return {
        field,
        category: 'SENSITIVE',
        sensitivity: 'CRITICAL',
        identifiable: false,
        protected: true
      };
    }

    // Behavioral data patterns
    if (fieldLower.includes('click') || fieldLower.includes('view') || fieldLower.includes('behavior')) {
      return {
        field,
        category: 'BEHAVIORAL',
        sensitivity: 'MEDIUM',
        identifiable: false,
        protected: false
      };
    }

    // Default classification
    return {
      field,
      category: 'DERIVED',
      sensitivity: 'LOW',
      identifiable: false,
      protected: false
    };
  }

  private assessFieldNecessity(
    classifications: Map<string, DataClassification>,
    config: MinimizationConfig
  ): Map<string, { necessity: string; transformation?: string; action: 'RETAIN' | 'TRANSFORM' | 'SUPPRESS' }> {
    const assessment = new Map();

    for (const [field, classification] of classifications) {
      const typeConfig = config.dataTypes.find(dt => dt.type === classification.category);

      if (!typeConfig) {
        // No specific rule, apply default based on sensitivity
        assessment.set(field, {
          necessity: classification.sensitivity === 'CRITICAL' ? 'QUESTIONABLE' : 'ACCEPTABLE',
          action: classification.sensitivity === 'CRITICAL' ? 'SUPPRESS' : 'RETAIN'
        });
        continue;
      }

      let action: 'RETAIN' | 'TRANSFORM' | 'SUPPRESS';
      let necessity: string;

      switch (typeConfig.necessity) {
        case 'REQUIRED':
          action = 'RETAIN';
          necessity = 'NECESSARY';
          break;
        case 'OPTIONAL':
          action = typeConfig.transformation ? 'TRANSFORM' : 'RETAIN';
          necessity = 'JUSTIFIED';
          break;
        case 'PROHIBITED':
          action = 'SUPPRESS';
          necessity = 'PROHIBITED';
          break;
        default:
          action = 'RETAIN';
          necessity = 'UNKNOWN';
      }

      assessment.set(field, {
        necessity,
        transformation: typeConfig.transformation,
        action
      });
    }

    return assessment;
  }

  private async applyMinimization(
    data: any,
    assessment: Map<string, any>,
    config: MinimizationConfig
  ): Promise<any> {
    const minimized = JSON.parse(JSON.stringify(data)); // Deep copy

    for (const [field, fieldAssessment] of assessment) {
      const value = this.getNestedValue(minimized, field);
      if (value === undefined) continue;

      switch (fieldAssessment.action) {
        case 'SUPPRESS':
          this.setNestedValue(minimized, field, undefined);
          break;

        case 'TRANSFORM':
          const transformed = await this.transformValue(value, fieldAssessment.transformation);
          this.setNestedValue(minimized, field, transformed);
          break;

        case 'RETAIN':
          // Keep as-is
          break;
      }
    }

    return this.cleanUndefinedValues(minimized);
  }

  private async transformValue(value: any, transformation?: string): Promise<any> {
    if (!transformation) return value;

    const valueStr = String(value);

    switch (transformation) {
      case 'HASH':
        return createHash('sha256').update(valueStr).digest('hex').substring(0, 8);

      case 'TRUNCATE':
        return valueStr.length > 10 ? valueStr.substring(0, 10) + '...' : valueStr;

      case 'GENERALIZE':
        // Simple generalization examples
        if (typeof value === 'number') {
          // Round to nearest 10
          return Math.round(value / 10) * 10;
        }
        if (valueStr.includes('@')) {
          // Email domain only
          const parts = valueStr.split('@');
          return `***@${parts[1]}`;
        }
        return '***';

      default:
        return value;
    }
  }

  private generateJustification(
    config: MinimizationConfig,
    assessment: Map<string, any>
  ): MinimizationJustification {
    const necessityAssessment: Record<string, string> = {};

    for (const [field, fieldAssessment] of assessment) {
      necessityAssessment[field] = fieldAssessment.necessity;
    }

    return {
      purpose: config.purpose,
      legalBasis: this.inferLegalBasis(config.purpose),
      necessityAssessment,
      retentionReason: this.getRetentionReason(config)
    };
  }

  private inferLegalBasis(purpose: string): string {
    switch (purpose) {
      case 'marketing':
        return 'Consent';
      case 'service':
        return 'Contract';
      case 'analytics':
        return 'Legitimate Interest';
      default:
        return 'Not Specified';
    }
  }

  private getRetentionReason(config: MinimizationConfig): string {
    const years = Math.round(config.retention / (365 * 24 * 60 * 60 * 1000));
    return `Retained for ${years} year(s) for ${config.purpose} purposes`;
  }

  private getTransformedFields(assessment: Map<string, any>): string[] {
    return Array.from(assessment.entries())
      .filter(([, fieldAssessment]) => fieldAssessment.action === 'TRANSFORM')
      .map(([field]) => field);
  }

  private getSuppressedFields(assessment: Map<string, any>): string[] {
    return Array.from(assessment.entries())
      .filter(([, fieldAssessment]) => fieldAssessment.action === 'SUPPRESS')
      .map(([field]) => field);
  }

  private getNestedValue(obj: any, path: string): any {
    return path.split('.').reduce((current, key) => current && current[key], obj);
  }

  private setNestedValue(obj: any, path: string, value: any): void {
    const keys = path.split('.');
    const lastKey = keys.pop()!;
    const target = keys.reduce((current, key) => {
      if (!current[key]) current[key] = {};
      return current[key];
    }, obj);

    if (value === undefined) {
      delete target[lastKey];
    } else {
      target[lastKey] = value;
    }
  }

  private cleanUndefinedValues(obj: any): any {
    if (Array.isArray(obj)) {
      return obj.map(item => this.cleanUndefinedValues(item)).filter(item => item !== undefined);
    }

    if (typeof obj === 'object' && obj !== null) {
      const cleaned: any = {};
      for (const key in obj) {
        if (obj[key] !== undefined) {
          cleaned[key] = this.cleanUndefinedValues(obj[key]);
        }
      }
      return cleaned;
    }

    return obj;
  }
}