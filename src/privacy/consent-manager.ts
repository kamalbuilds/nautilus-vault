/**
 * Advanced Consent Management System
 * GDPR, CCPA, and CPRA compliant consent collection and management
 */

import { ConsentRecord, DataSubject, PrivacyPreferences, SecurityError, PrivacyError } from '../types';
import { createHash, randomBytes } from 'crypto';

// Helper function to extract error message
function getErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}


export interface ConsentRequest {
  id: string;
  dataSubjectId: string;
  purposes: ConsentPurpose[];
  requiredConsents: string[];
  optionalConsents: string[];
  legalBasis: 'CONSENT' | 'LEGITIMATE_INTEREST' | 'CONTRACT' | 'LEGAL_OBLIGATION';
  dataController: string;
  requestedAt: Date;
  expiresAt?: Date;
  locale: string;
  consentNotice: string;
}

export interface ConsentPurpose {
  id: string;
  name: string;
  description: string;
  category: 'FUNCTIONAL' | 'ANALYTICS' | 'MARKETING' | 'PERSONALIZATION' | 'THIRD_PARTY';
  required: boolean;
  dataTypes: string[];
  recipients: string[];
  retentionPeriod: number;
  crossBorderTransfer: boolean;
  thirdParties: ThirdPartyProcessor[];
}

export interface ThirdPartyProcessor {
  name: string;
  purpose: string;
  privacyPolicy: string;
  adequacyDecision?: boolean;
  safeguards?: string[];
}

export interface ConsentResponse {
  requestId: string;
  dataSubjectId: string;
  consents: ConsentDecision[];
  responseMethod: 'EXPLICIT' | 'IMPLIED' | 'OPT_OUT' | 'WITHDRAWN';
  consentProof: ConsentProof;
  respondedAt: Date;
  ipAddress?: string;
  userAgent?: string;
  locale: string;
}

export interface ConsentDecision {
  purposeId: string;
  granted: boolean;
  granularity: 'PURPOSE' | 'CATEGORY' | 'VENDOR' | 'DATA_TYPE';
  conditions?: string[];
  expiresAt?: Date;
}

export interface ConsentProof {
  method: 'CHECKBOX' | 'BUTTON' | 'SIGNATURE' | 'BIOMETRIC' | 'VOICE';
  timestamp: Date;
  evidence: string; // Hash of consent evidence
  witness?: string;
  auditTrail: ConsentAuditEvent[];
}

export interface ConsentAuditEvent {
  timestamp: Date;
  action: 'REQUESTED' | 'GRANTED' | 'WITHDRAWN' | 'RENEWED' | 'MODIFIED' | 'EXPIRED';
  actor: string;
  context: any;
  evidence?: string;
}

export interface ConsentStatus {
  dataSubjectId: string;
  purposes: Map<string, ConsentStatusDetail>;
  overallStatus: 'VALID' | 'PARTIAL' | 'EXPIRED' | 'WITHDRAWN' | 'INSUFFICIENT';
  lastUpdated: Date;
  renewalRequired: boolean;
  warnings: string[];
}

export interface ConsentStatusDetail {
  purposeId: string;
  granted: boolean;
  grantedAt?: Date;
  expiresAt?: Date;
  withdrawnAt?: Date;
  renewalDue?: Date;
  valid: boolean;
  conditions: string[];
}

interface ConsentSummary {
  totalConsents: number;
  grantedConsents: number;
  expiredConsents: number;
  lastActivity: Date;
}

interface ConsentPurposeInfo {
  id: string;
  name: string;
  description: string;
  category: string;
  granted: boolean;
  grantedAt: Date;
  expiresAt?: Date;
  dataTypes: string[];
  thirdParties: ThirdPartyProcessor[];
}

interface ConsentHistoryItem {
  timestamp: Date;
  action: string;
  purposeId?: string;
  details: string;
}

export class ConsentManager {
  private consentRequests: Map<string, ConsentRequest> = new Map();
  private consentResponses: Map<string, ConsentResponse> = new Map();
  private dataSubjects: Map<string, DataSubject> = new Map();
  private auditLog: ConsentAuditEvent[] = [];
  private purposes: Map<string, ConsentPurpose> = new Map();
  private expirationCheckInterval?: NodeJS.Timeout;

  constructor() {
    this.initializeDefaultPurposes();
    this.startExpirationChecking();
  }

  /**
   * Create a new consent request
   */
  async createConsentRequest(
    dataSubjectId: string,
    purposes: string[],
    requiredConsents: string[],
    optionalConsents: string[],
    legalBasis: ConsentRequest['legalBasis'],
    dataController: string,
    locale: string = 'en-US',
    expirationDays?: number
  ): Promise<ConsentRequest> {
    try {
      const requestId = this.generateRequestId();
      const now = new Date();
      const expiresAt = expirationDays ? new Date(now.getTime() + expirationDays * 24 * 60 * 60 * 1000) : undefined;

      // Validate purposes
      const requestPurposes = purposes.map(purposeId => {
        const purpose = this.purposes.get(purposeId);
        if (!purpose) {
          throw new PrivacyError(`Purpose not found: ${purposeId}`, 'PURPOSE_NOT_FOUND');
        }
        return purpose;
      });

      // Generate consent notice
      const consentNotice = this.generateConsentNotice(requestPurposes, locale, dataController);

      const request: ConsentRequest = {
        id: requestId,
        dataSubjectId,
        purposes: requestPurposes,
        requiredConsents,
        optionalConsents,
        legalBasis,
        dataController,
        requestedAt: now,
        expiresAt,
        locale,
        consentNotice
      };

      this.consentRequests.set(requestId, request);

      // Log audit event
      this.logAuditEvent({
        timestamp: now,
        action: 'REQUESTED',
        actor: dataController,
        context: {
          requestId,
          dataSubjectId,
          purposes: purposes,
          legalBasis
        }
      });

      console.log(`Created consent request ${requestId} for subject ${dataSubjectId}`);
      return request;

    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new PrivacyError(`Failed to create consent request: ${message}`, 'CONSENT_REQUEST_ERROR');
    }
  }

  /**
   * Process consent response from data subject
   */
  async processConsentResponse(
    requestId: string,
    decisions: ConsentDecision[],
    responseMethod: ConsentResponse['responseMethod'],
    proofMethod: ConsentProof['method'],
    evidence: string,
    context: {
      ipAddress?: string;
      userAgent?: string;
      locale?: string;
    } = {}
  ): Promise<ConsentResponse> {
    try {
      const request = this.consentRequests.get(requestId);
      if (!request) {
        throw new PrivacyError('Consent request not found', 'REQUEST_NOT_FOUND');
      }

      // Check if request has expired
      if (request.expiresAt && new Date() > request.expiresAt) {
        throw new PrivacyError('Consent request has expired', 'REQUEST_EXPIRED');
      }

      const now = new Date();

      // Validate decisions against required consents
      this.validateConsentDecisions(decisions, request);

      // Generate proof
      const proof = this.generateConsentProof(proofMethod, evidence, now);

      const response: ConsentResponse = {
        requestId,
        dataSubjectId: request.dataSubjectId,
        consents: decisions,
        responseMethod,
        consentProof: proof,
        respondedAt: now,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        locale: context.locale || request.locale
      };

      this.consentResponses.set(requestId, response);

      // Update data subject records
      await this.updateDataSubjectConsents(request.dataSubjectId, decisions, now);

      // Log audit events
      decisions.forEach(decision => {
        this.logAuditEvent({
          timestamp: now,
          action: decision.granted ? 'GRANTED' : 'WITHDRAWN',
          actor: request.dataSubjectId,
          context: {
            purposeId: decision.purposeId,
            method: responseMethod,
            requestId
          },
          evidence: proof.evidence
        });
      });

      console.log(`Processed consent response for request ${requestId}`);
      return response;

    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new PrivacyError(`Failed to process consent response: ${message}`, 'CONSENT_RESPONSE_ERROR');
    }
  }

  /**
   * Check if valid consent exists for a purpose
   */
  async hasValidConsent(
    dataSubjectId: string,
    purposeId: string,
    currentTime: Date = new Date()
  ): Promise<boolean> {
    try {
      const status = await this.getConsentStatus(dataSubjectId);
      const purposeStatus = status.purposes.get(purposeId);

      if (!purposeStatus) {
        return false;
      }

      // Check if consent is granted and not expired
      return purposeStatus.granted &&
             purposeStatus.valid &&
             (!purposeStatus.expiresAt || purposeStatus.expiresAt > currentTime) &&
             !purposeStatus.withdrawnAt;

    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`Error checking consent validity: ${message}`);
      return false;
    }
  }

  /**
   * Withdraw consent for specific purposes
   */
  async withdrawConsent(
    dataSubjectId: string,
    purposeIds: string[],
    reason?: string
  ): Promise<void> {
    try {
      const dataSubject = this.dataSubjects.get(dataSubjectId);
      if (!dataSubject) {
        throw new PrivacyError('Data subject not found', 'DATA_SUBJECT_NOT_FOUND');
      }

      const now = new Date();

      // Update consent records
      for (const purposeId of purposeIds) {
        const consentRecord = dataSubject.consents.find(c =>
          this.getConsentRecord(c.userId, c.purpose)?.purpose === purposeId
        );

        if (consentRecord) {
          consentRecord.granted = false;
          consentRecord.metadata = { ...consentRecord.metadata, withdrawnAt: now.toISOString(), reason };
        }

        // Log audit event
        this.logAuditEvent({
          timestamp: now,
          action: 'WITHDRAWN',
          actor: dataSubjectId,
          context: {
            purposeId,
            reason: reason || 'User requested withdrawal'
          }
        });
      }

      this.dataSubjects.set(dataSubjectId, dataSubject);

      console.log(`Withdrew consent for purposes ${purposeIds.join(', ')} for subject ${dataSubjectId}`);

    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new PrivacyError(`Failed to withdraw consent: ${message}`, 'CONSENT_WITHDRAWAL_ERROR');
    }
  }

  /**
   * Get comprehensive consent status for a data subject
   */
  async getConsentStatus(dataSubjectId: string): Promise<ConsentStatus> {
    try {
      const dataSubject = this.dataSubjects.get(dataSubjectId);
      if (!dataSubject) {
        throw new PrivacyError('Data subject not found', 'DATA_SUBJECT_NOT_FOUND');
      }

      const now = new Date();
      const purposes = new Map<string, ConsentStatusDetail>();
      const warnings: string[] = [];
      let validConsents = 0;
      let totalConsents = 0;

      // Analyze each consent record
      for (const consentRecord of dataSubject.consents) {
        totalConsents++;
        const purposeId = consentRecord.purpose;

        const isValid = consentRecord.granted &&
                       (!consentRecord.expiresAt || new Date(consentRecord.expiresAt) > now);

        if (isValid) validConsents++;

        // Check for upcoming expirations
        if (consentRecord.expiresAt) {
          const daysUntilExpiration = (new Date(consentRecord.expiresAt).getTime() - now.getTime()) / (24 * 60 * 60 * 1000);
          if (daysUntilExpiration <= 30 && daysUntilExpiration > 0) {
            warnings.push(`Consent for ${purposeId} expires in ${Math.round(daysUntilExpiration)} days`);
          }
        }

        purposes.set(purposeId, {
          purposeId,
          granted: consentRecord.granted,
          grantedAt: new Date(consentRecord.timestamp),
          expiresAt: consentRecord.expiresAt ? new Date(consentRecord.expiresAt) : undefined,
          valid: isValid,
          conditions: [],
          renewalDue: this.calculateRenewalDate(consentRecord)
        });
      }

      // Determine overall status
      let overallStatus: ConsentStatus['overallStatus'];
      if (validConsents === 0) {
        overallStatus = 'INSUFFICIENT';
      } else if (validConsents === totalConsents) {
        overallStatus = 'VALID';
      } else {
        overallStatus = 'PARTIAL';
      }

      // Check for expired consents
      const expiredConsents = Array.from(purposes.values()).filter(p =>
        p.expiresAt && p.expiresAt <= now
      );
      if (expiredConsents.length > 0) {
        overallStatus = 'EXPIRED';
        warnings.push(`${expiredConsents.length} consent(s) have expired`);
      }

      const renewalRequired = Array.from(purposes.values()).some(p =>
        p.renewalDue && p.renewalDue <= now
      );

      return {
        dataSubjectId,
        purposes,
        overallStatus,
        lastUpdated: new Date(),
        renewalRequired,
        warnings
      };

    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new PrivacyError(`Failed to get consent status: ${message}`, 'STATUS_ERROR');
    }
  }

  /**
   * Get consent record by ID
   */
  getConsent(dataSubjectId: string, purpose: string): ConsentRecord | null {
    const dataSubject = this.dataSubjects.get(dataSubjectId);
    if (!dataSubject) return null;

    return dataSubject.consents.find(c => c.purpose === purpose) || null;
  }

  /**
   * Renew expiring consents
   */
  async renewConsent(
    dataSubjectId: string,
    purposeIds: string[],
    newExpirationDate?: Date
  ): Promise<ConsentRequest> {
    try {
      const dataSubject = this.dataSubjects.get(dataSubjectId);
      if (!dataSubject) {
        throw new PrivacyError('Data subject not found', 'DATA_SUBJECT_NOT_FOUND');
      }

      // Create renewal request
      const renewalRequest = await this.createConsentRequest(
        dataSubjectId,
        purposeIds,
        purposeIds, // All purposes are required for renewal
        [],
        'CONSENT',
        'system_renewal',
        dataSubject.preferences?.marketingConsent ? 'en-US' : 'en-US',
        newExpirationDate ? Math.round((newExpirationDate.getTime() - Date.now()) / (24 * 60 * 60 * 1000)) : 365
      );

      console.log(`Created consent renewal request for subject ${dataSubjectId}`);
      return renewalRequest;

    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new PrivacyError(`Failed to renew consent: ${message}`, 'CONSENT_RENEWAL_ERROR');
    }
  }

  /**
   * Generate consent management dashboard data
   */
  generateConsentDashboard(
    dataSubjectId: string
  ): {
    summary: ConsentSummary;
    purposes: ConsentPurposeInfo[];
    history: ConsentHistoryItem[];
    recommendations: string[];
  } {
    try {
      const dataSubject = this.dataSubjects.get(dataSubjectId);
      if (!dataSubject) {
        throw new PrivacyError('Data subject not found', 'DATA_SUBJECT_NOT_FOUND');
      }

      // Generate summary
      const grantedConsents = dataSubject.consents.filter(c => c.granted).length;
      const totalConsents = dataSubject.consents.length;
      const expiredConsents = dataSubject.consents.filter(c =>
        c.expiresAt && new Date(c.expiresAt) <= new Date()
      ).length;

      const summary: ConsentSummary = {
        totalConsents,
        grantedConsents,
        expiredConsents,
        lastActivity: new Date(Math.max(...dataSubject.consents.map(c => c.timestamp.getTime())))
      };

      // Generate purpose information
      const purposes: ConsentPurposeInfo[] = dataSubject.consents.map(consent => {
        const purpose = this.purposes.get(consent.purpose);
        return {
          id: consent.purpose,
          name: purpose?.name || 'Unknown Purpose',
          description: purpose?.description || 'No description available',
          category: purpose?.category || 'FUNCTIONAL',
          granted: consent.granted,
          grantedAt: consent.timestamp,
          expiresAt: consent.expiresAt ? new Date(consent.expiresAt) : undefined,
          dataTypes: purpose?.dataTypes || [],
          thirdParties: purpose?.thirdParties || []
        };
      });

      // Generate history
      const history: ConsentHistoryItem[] = this.auditLog
        .filter(event => event.context?.dataSubjectId === dataSubjectId)
        .slice(-20) // Last 20 events
        .map(event => ({
          timestamp: event.timestamp,
          action: event.action,
          purposeId: event.context?.purposeId,
          details: this.formatAuditEventForHistory(event)
        }));

      // Generate recommendations
      const recommendations = this.generateConsentRecommendations(dataSubject);

      return {
        summary,
        purposes,
        history,
        recommendations
      };

    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new PrivacyError(`Failed to generate consent dashboard: ${message}`, 'DASHBOARD_ERROR');
    }
  }

  // Private helper methods

  private initializeDefaultPurposes(): void {
    // Essential/Functional purposes
    this.purposes.set('essential', {
      id: 'essential',
      name: 'Essential Services',
      description: 'Necessary for core functionality and security',
      category: 'FUNCTIONAL',
      required: true,
      dataTypes: ['session', 'authentication', 'security'],
      recipients: ['internal'],
      retentionPeriod: 30 * 24 * 60 * 60 * 1000, // 30 days
      crossBorderTransfer: false,
      thirdParties: []
    });

    // Analytics purpose
    this.purposes.set('analytics', {
      id: 'analytics',
      name: 'Analytics and Insights',
      description: 'Understanding usage patterns to improve services',
      category: 'ANALYTICS',
      required: false,
      dataTypes: ['behavioral', 'performance', 'demographic'],
      recipients: ['internal', 'analytics-partners'],
      retentionPeriod: 24 * 30 * 24 * 60 * 60 * 1000, // 2 years
      crossBorderTransfer: true,
      thirdParties: [
        {
          name: 'Analytics Provider',
          purpose: 'Usage analytics and insights',
          privacyPolicy: 'https://analytics.example.com/privacy',
          adequacyDecision: true
        }
      ]
    });

    // Marketing purpose
    this.purposes.set('marketing', {
      id: 'marketing',
      name: 'Marketing Communications',
      description: 'Personalized marketing and promotional content',
      category: 'MARKETING',
      required: false,
      dataTypes: ['contact', 'preferences', 'behavioral'],
      recipients: ['internal', 'marketing-partners'],
      retentionPeriod: 36 * 30 * 24 * 60 * 60 * 1000, // 3 years
      crossBorderTransfer: true,
      thirdParties: [
        {
          name: 'Email Service Provider',
          purpose: 'Email marketing campaigns',
          privacyPolicy: 'https://esp.example.com/privacy',
          adequacyDecision: false,
          safeguards: ['Standard Contractual Clauses', 'Data Processing Agreement']
        }
      ]
    });
  }

  private startExpirationChecking(): void {
    // Check for expiring consents every day
    this.expirationCheckInterval = setInterval(() => {
      this.checkExpiringConsents();
    }, 24 * 60 * 60 * 1000);
  }

  private async checkExpiringConsents(): Promise<void> {
    try {
      const now = new Date();
      const warningThreshold = 30 * 24 * 60 * 60 * 1000; // 30 days

      for (const [dataSubjectId, dataSubject] of this.dataSubjects) {
        for (const consent of dataSubject.consents) {
          if (consent.expiresAt) {
            const expirationDate = new Date(consent.expiresAt);
            const timeUntilExpiration = expirationDate.getTime() - now.getTime();

            if (timeUntilExpiration <= warningThreshold && timeUntilExpiration > 0) {
              console.log(`Consent expiring soon for subject ${dataSubjectId}, purpose ${consent.purpose}`);
              // In production: send notification to data subject
            } else if (timeUntilExpiration <= 0) {
              console.log(`Consent expired for subject ${dataSubjectId}, purpose ${consent.purpose}`);
              // Mark as expired
              consent.granted = false;
            }
          }
        }
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`Error checking expiring consents: ${message}`);
    }
  }

  private generateRequestId(): string {
    return `consent_${Date.now()}_${randomBytes(8).toString('hex')}`;
  }

  private generateConsentNotice(
    purposes: ConsentPurpose[],
    locale: string,
    dataController: string
  ): string {
    // Simplified consent notice generation
    const purposeDescriptions = purposes.map(p =>
      `- ${p.name}: ${p.description}${p.required ? ' (Required)' : ' (Optional)'}`
    ).join('\n');

    return `
Data Controller: ${dataController}

We would like to use your data for the following purposes:

${purposeDescriptions}

By providing consent, you agree to the processing of your personal data for the specified purposes. You can withdraw your consent at any time.

For more information, please see our Privacy Policy.
    `.trim();
  }

  private validateConsentDecisions(
    decisions: ConsentDecision[],
    request: ConsentRequest
  ): void {
    // Check all required consents are addressed
    for (const requiredConsent of request.requiredConsents) {
      const decision = decisions.find(d => d.purposeId === requiredConsent);
      if (!decision || !decision.granted) {
        throw new PrivacyError(`Required consent not granted: ${requiredConsent}`, 'REQUIRED_CONSENT_MISSING');
      }
    }

    // Validate decision structure
    for (const decision of decisions) {
      if (!request.purposes.find(p => p.id === decision.purposeId)) {
        throw new PrivacyError(`Invalid purpose in decision: ${decision.purposeId}`, 'INVALID_PURPOSE');
      }
    }
  }

  private generateConsentProof(
    method: ConsentProof['method'],
    evidence: string,
    timestamp: Date
  ): ConsentProof {
    const evidenceHash = createHash('sha256').update(evidence + timestamp.toISOString()).digest('hex');

    return {
      method,
      timestamp,
      evidence: evidenceHash,
      auditTrail: [{
        timestamp,
        action: 'GRANTED',
        actor: 'data_subject',
        context: { method, evidenceLength: evidence.length }
      }]
    };
  }

  private async updateDataSubjectConsents(
    dataSubjectId: string,
    decisions: ConsentDecision[],
    timestamp: Date
  ): Promise<void> {
    let dataSubject = this.dataSubjects.get(dataSubjectId);

    if (!dataSubject) {
      dataSubject = {
        id: dataSubjectId,
        pseudonym: `subject_${dataSubjectId.substring(0, 8)}`,
        consents: [],
        preferences: {
          shareData: false,
          allowProfiling: false,
          marketingConsent: false,
          dataRetention: 365,
          anonymization: true
        }
      };
    }

    // Update or create consent records
    for (const decision of decisions) {
      const existingIndex = dataSubject.consents.findIndex(c => c.purpose === decision.purposeId);

      const consentRecord: ConsentRecord = {
        userId: dataSubjectId,
        purpose: decision.purposeId,
        granted: decision.granted,
        timestamp,
        expiresAt: decision.expiresAt,
        metadata: {
          granularity: decision.granularity,
          conditions: decision.conditions || []
        }
      };

      if (existingIndex >= 0) {
        dataSubject.consents[existingIndex] = consentRecord;
      } else {
        dataSubject.consents.push(consentRecord);
      }
    }

    this.dataSubjects.set(dataSubjectId, dataSubject);
  }

  private getConsentRecord(userId: string, purpose: string): ConsentRecord | null {
    const dataSubject = this.dataSubjects.get(userId);
    return dataSubject?.consents.find(c => c.purpose === purpose) || null;
  }

  private calculateRenewalDate(consent: ConsentRecord): Date | undefined {
    if (!consent.expiresAt) return undefined;

    const expirationDate = new Date(consent.expiresAt);
    const renewalDate = new Date(expirationDate);
    renewalDate.setDate(renewalDate.getDate() - 30); // 30 days before expiration

    return renewalDate;
  }

  private generateConsentRecommendations(dataSubject: DataSubject): string[] {
    const recommendations: string[] = [];
    const now = new Date();

    // Check for expired consents
    const expiredConsents = dataSubject.consents.filter(c =>
      c.expiresAt && new Date(c.expiresAt) <= now
    );

    if (expiredConsents.length > 0) {
      recommendations.push(`You have ${expiredConsents.length} expired consent(s). Consider renewing them.`);
    }

    // Check for overly broad consents
    const marketingConsents = dataSubject.consents.filter(c =>
      c.purpose.includes('marketing') && c.granted
    );

    if (marketingConsents.length > 2) {
      recommendations.push('You have granted consent for multiple marketing purposes. Review if all are still needed.');
    }

    // Check for no analytics consent
    const hasAnalyticsConsent = dataSubject.consents.some(c =>
      c.purpose === 'analytics' && c.granted
    );

    if (!hasAnalyticsConsent) {
      recommendations.push('Consider enabling analytics to help improve our services while maintaining your privacy.');
    }

    // Check for data retention preferences
    if (dataSubject.preferences?.dataRetention && dataSubject.preferences.dataRetention > 365) {
      recommendations.push('Consider reducing your data retention period for better privacy protection.');
    }

    return recommendations;
  }

  private formatAuditEventForHistory(event: ConsentAuditEvent): string {
    switch (event.action) {
      case 'REQUESTED':
        return 'Consent requested';
      case 'GRANTED':
        return `Consent granted for ${event.context?.purposeId || 'purpose'}`;
      case 'WITHDRAWN':
        return `Consent withdrawn for ${event.context?.purposeId || 'purpose'}`;
      case 'RENEWED':
        return `Consent renewed for ${event.context?.purposeId || 'purpose'}`;
      case 'EXPIRED':
        return `Consent expired for ${event.context?.purposeId || 'purpose'}`;
      default:
        return `${event.action} action performed`;
    }
  }

  private logAuditEvent(event: ConsentAuditEvent): void {
    this.auditLog.push(event);

    // Keep only last 1000 events to prevent memory issues
    if (this.auditLog.length > 1000) {
      this.auditLog = this.auditLog.slice(-1000);
    }
  }

  /**
   * Cleanup resources
   */
  destroy(): void {
    if (this.expirationCheckInterval) {
      clearInterval(this.expirationCheckInterval);
    }
  }
}
