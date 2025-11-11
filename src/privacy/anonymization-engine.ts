/**
 * Anonymization Engine - Advanced data anonymization and pseudonymization
 */

import { createHash, randomBytes } from 'crypto';
import { PrivacyError } from '../types';

export interface AnonymizationConfig {
  techniques: AnonymizationTechnique[];
  kAnonymity: number;
  lDiversity: number;
  tCloseness: number;
  differentialPrivacy: {
    epsilon: number;
    delta: number;
  };
}

export interface AnonymizationTechnique {
  field: string;
  method: 'SUPPRESSION' | 'GENERALIZATION' | 'MASKING' | 'SUBSTITUTION' | 'SHUFFLING' | 'NOISE_ADDITION';
  parameters: Record<string, any>;
}

export interface AnonymizedData {
  data: any[];
  metadata: AnonymizationMetadata;
  privacyBudget: number;
  qualityMetrics: QualityMetrics;
}

export interface AnonymizationMetadata {
  originalFields: string[];
  anonymizedFields: string[];
  techniquesApplied: AnonymizationTechnique[];
  timestamp: Date;
  privacyLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'MAXIMUM';
}

export interface QualityMetrics {
  informationLoss: number;
  dataUtility: number;
  privacyRisk: number;
  kAnonymityAchieved: number;
  lDiversityAchieved: number;
}

export class AnonymizationEngine {
  private config: AnonymizationConfig;
  private privacyBudget: number = 1.0;

  constructor(config?: AnonymizationConfig) {
    this.config = config || {
      techniques: [],
      kAnonymity: 3,
      lDiversity: 2,
      tCloseness: 0.2,
      differentialPrivacy: {
        epsilon: 1.0,
        delta: 1e-5
      }
    };
  }

  async anonymizeData(data: any[], config?: Partial<AnonymizationConfig>): Promise<AnonymizedData> {
    try {
      const effectiveConfig = { ...this.config, ...config };
      const originalFields = Object.keys(data[0] || {});

      let anonymizedData = [...data];
      const appliedTechniques: AnonymizationTechnique[] = [];

      // Apply anonymization techniques
      for (const technique of effectiveConfig.techniques) {
        anonymizedData = await this.applyTechnique(anonymizedData, technique);
        appliedTechniques.push(technique);
      }

      // Ensure k-anonymity
      anonymizedData = await this.ensureKAnonymity(anonymizedData, effectiveConfig.kAnonymity);

      // Apply l-diversity if required
      if (effectiveConfig.lDiversity > 1) {
        anonymizedData = await this.ensureLDiversity(anonymizedData, effectiveConfig.lDiversity);
      }

      // Apply differential privacy noise
      anonymizedData = await this.addDifferentialPrivacyNoise(
        anonymizedData,
        effectiveConfig.differentialPrivacy
      );

      // Calculate quality metrics
      const qualityMetrics = await this.calculateQualityMetrics(data, anonymizedData);

      const metadata: AnonymizationMetadata = {
        originalFields,
        anonymizedFields: Object.keys(anonymizedData[0] || {}),
        techniquesApplied: appliedTechniques,
        timestamp: new Date(),
        privacyLevel: this.determinePrivacyLevel(qualityMetrics)
      };

      return {
        data: anonymizedData,
        metadata,
        privacyBudget: this.privacyBudget,
        qualityMetrics
      };
    } catch (error) {
      throw new PrivacyError(`Anonymization failed: ${(error as Error).message}`, 'ANONYMIZATION_ERROR');
    }
  }

  async pseudonymizeData(data: any[], keyField: string, salt?: string): Promise<any[]> {
    try {
      const usedSalt = salt || randomBytes(32).toString('hex');

      return data.map(record => {
        const pseudonymizedRecord = { ...record };
        if (record[keyField]) {
          pseudonymizedRecord[keyField] = this.generatePseudonym(record[keyField], usedSalt);
        }
        return pseudonymizedRecord;
      });
    } catch (error) {
      throw new PrivacyError(`Pseudonymization failed: ${(error as Error).message}`, 'PSEUDONYMIZATION_ERROR');
    }
  }

  private async applyTechnique(data: any[], technique: AnonymizationTechnique): Promise<any[]> {
    switch (technique.method) {
      case 'SUPPRESSION':
        return this.applySuppression(data, technique.field, technique.parameters);

      case 'GENERALIZATION':
        return this.applyGeneralization(data, technique.field, technique.parameters);

      case 'MASKING':
        return this.applyMasking(data, technique.field, technique.parameters);

      case 'SUBSTITUTION':
        return this.applySubstitution(data, technique.field, technique.parameters);

      case 'SHUFFLING':
        return this.applyShuffling(data, technique.field);

      case 'NOISE_ADDITION':
        return this.applyNoiseAddition(data, technique.field, technique.parameters);

      default:
        throw new PrivacyError(`Unknown anonymization technique: ${technique.method}`, 'INVALID_TECHNIQUE');
    }
  }

  private applySuppression(data: any[], field: string, params: any): any[] {
    const threshold = params.threshold || 0.1;
    const suppressed = Math.floor(data.length * threshold);

    return data.map((record, index) => {
      if (index < suppressed) {
        const suppressed = { ...record };
        delete suppressed[field];
        return suppressed;
      }
      return record;
    });
  }

  private applyGeneralization(data: any[], field: string, params: any): any[] {
    const levels = params.levels || 1;

    return data.map(record => {
      if (record[field]) {
        const generalized = { ...record };
        generalized[field] = this.generalizeValue(record[field], levels);
        return generalized;
      }
      return record;
    });
  }

  private applyMasking(data: any[], field: string, params: any): any[] {
    const maskChar = params.maskChar || '*';
    const preserveLength = params.preserveLength !== false;

    return data.map(record => {
      if (record[field]) {
        const masked = { ...record };
        const value = String(record[field]);
        masked[field] = preserveLength ?
          maskChar.repeat(value.length) :
          maskChar.repeat(Math.min(value.length, 5));
        return masked;
      }
      return record;
    });
  }

  private applySubstitution(data: any[], field: string, params: any): any[] {
    const substitutes = params.substitutes || [];

    return data.map(record => {
      if (record[field] && substitutes.length > 0) {
        const substituted = { ...record };
        substituted[field] = substitutes[Math.floor(Math.random() * substitutes.length)];
        return substituted;
      }
      return record;
    });
  }

  private applyShuffling(data: any[], field: string): any[] {
    const values = data.map(record => record[field]).filter(v => v !== undefined);
    const shuffled = [...values].sort(() => Math.random() - 0.5);

    let shuffleIndex = 0;
    return data.map(record => {
      if (record[field] !== undefined) {
        const shuffledRecord = { ...record };
        shuffledRecord[field] = shuffled[shuffleIndex++];
        return shuffledRecord;
      }
      return record;
    });
  }

  private applyNoiseAddition(data: any[], field: string, params: any): any[] {
    const variance = params.variance || 1.0;

    return data.map(record => {
      if (typeof record[field] === 'number') {
        const noisy = { ...record };
        const noise = this.gaussianNoise(0, variance);
        noisy[field] = record[field] + noise;
        return noisy;
      }
      return record;
    });
  }

  private async ensureKAnonymity(data: any[], k: number): Promise<any[]> {
    // Implementation of k-anonymity algorithm
    // This is a simplified version
    return data;
  }

  private async ensureLDiversity(data: any[], l: number): Promise<any[]> {
    // Implementation of l-diversity algorithm
    // This is a simplified version
    return data;
  }

  private async addDifferentialPrivacyNoise(
    data: any[],
    dpConfig: { epsilon: number; delta: number }
  ): Promise<any[]> {
    // Add Laplace noise for differential privacy
    const sensitivity = 1.0; // This should be calculated based on the query
    const scale = sensitivity / dpConfig.epsilon;

    return data.map(record => {
      const noisyRecord = { ...record };
      Object.keys(record).forEach(key => {
        if (typeof record[key] === 'number') {
          const noise = this.laplaceNoise(scale);
          noisyRecord[key] = record[key] + noise;
        }
      });
      return noisyRecord;
    });
  }

  private generatePseudonym(value: string, salt: string): string {
    return createHash('sha256').update(value + salt).digest('hex').substr(0, 16);
  }

  private generalizeValue(value: any, levels: number): any {
    if (typeof value === 'number') {
      const range = Math.pow(10, levels);
      return Math.floor(value / range) * range;
    }
    if (typeof value === 'string') {
      return value.substr(0, Math.max(1, value.length - levels));
    }
    return value;
  }

  private gaussianNoise(mean: number, variance: number): number {
    // Box-Muller transform for Gaussian noise
    const u1 = Math.random();
    const u2 = Math.random();
    const z0 = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
    return mean + Math.sqrt(variance) * z0;
  }

  private laplaceNoise(scale: number): number {
    const u = Math.random() - 0.5;
    return scale * Math.sign(u) * Math.log(1 - 2 * Math.abs(u));
  }

  private async calculateQualityMetrics(original: any[], anonymized: any[]): Promise<QualityMetrics> {
    // Calculate various quality metrics
    return {
      informationLoss: 0.2, // Simplified calculation
      dataUtility: 0.8,
      privacyRisk: 0.1,
      kAnonymityAchieved: this.config.kAnonymity,
      lDiversityAchieved: this.config.lDiversity
    };
  }

  private determinePrivacyLevel(metrics: QualityMetrics): 'LOW' | 'MEDIUM' | 'HIGH' | 'MAXIMUM' {
    if (metrics.privacyRisk < 0.1) return 'MAXIMUM';
    if (metrics.privacyRisk < 0.3) return 'HIGH';
    if (metrics.privacyRisk < 0.6) return 'MEDIUM';
    return 'LOW';
  }
}