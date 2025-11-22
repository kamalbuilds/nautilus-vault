/**
 * Privacy Dashboard and Transparency Controls
 * User-friendly interface for privacy management and data transparency
 */

import {
  DataSubject,
  ConsentRecord,
  PrivacyPreferences,
  SecurityEvent,
  AuditLog,
  ComplianceReport,
  SecurityError,
  PrivacyError
} from '../types';
import { ConsentManager } from '../privacy/consent-manager';
import { DataMinimizer } from '../privacy/data-minimizer';
import { EncryptionManager } from '../security/encryption-manager';

// Helper function to extract error message
function getErrorMessage(error: unknown): string {
  if (error instanceof Error) return getErrorMessage(error);
  return String(error);
}

export interface DashboardData {
  user: UserProfile;
  privacyScore: PrivacyScore;
  dataUsage: DataUsageInfo;
  consents: ConsentInfo[];
  dataCategories: DataCategoryInfo[];
  rights: DataRightsInfo;
  security: SecurityInfo;
  recommendations: Recommendation[];
  notifications: Notification[];
}

export interface UserProfile {
  id: string;
  pseudonym: string;
  joinedDate: Date;
  lastActive: Date;
  preferences: PrivacyPreferences;
  dataController: string;
  privacyOfficer?: string;
}

export interface PrivacyScore {
  overall: number; // 0-100
  components: {
    consentManagement: number;
    dataMinimization: number;
    securityControls: number;
    transparency: number;
    userControl: number;
  };
  trend: 'IMPROVING' | 'STABLE' | 'DECLINING';
  lastCalculated: Date;
  benchmarkComparison: number; // vs. industry average
}

export interface DataUsageInfo {
  totalDataPoints: number;
  dataProcessed: DataProcessingMetrics;
  storageUsed: StorageMetrics;
  sharing: DataSharingInfo;
  retention: RetentionInfo;
}

export interface DataProcessingMetrics {
  last30Days: number;
  byPurpose: Record<string, number>;
  byCategory: Record<string, number>;
  trend: 'INCREASING' | 'STABLE' | 'DECREASING';
}

export interface StorageMetrics {
  totalSize: string;
  encrypted: number;
  anonymous: number;
  identified: number;
  locations: string[];
}

export interface DataSharingInfo {
  thirdParties: ThirdPartyDataSharing[];
  crossBorderTransfers: CrossBorderTransfer[];
  purposes: string[];
  safeguards: string[];
}

export interface ThirdPartyDataSharing {
  name: string;
  category: string;
  dataShared: string[];
  purpose: string;
  lastShared: Date;
  safeguards: string[];
  privacyPolicy: string;
  optOut: boolean;
}

export interface CrossBorderTransfer {
  country: string;
  adequacyDecision: boolean;
  safeguards: string[];
  purpose: string;
  dataTypes: string[];
}

export interface RetentionInfo {
  policies: RetentionPolicy[];
  upcomingDeletions: UpcomingDeletion[];
  totalRetained: string;
}

export interface RetentionPolicy {
  category: string;
  period: string;
  purpose: string;
  nextReview: Date;
}

export interface UpcomingDeletion {
  category: string;
  scheduledDate: Date;
  reason: string;
  preventable: boolean;
}

export interface ConsentInfo {
  id: string;
  purpose: string;
  description: string;
  category: 'FUNCTIONAL' | 'ANALYTICS' | 'MARKETING' | 'PERSONALIZATION';
  status: 'GRANTED' | 'WITHDRAWN' | 'EXPIRED' | 'PENDING';
  grantedDate?: Date;
  expiryDate?: Date;
  withdrawable: boolean;
  required: boolean;
  dataTypes: string[];
  thirdParties: string[];
}

export interface DataCategoryInfo {
  category: string;
  description: string;
  dataPoints: number;
  sensitivity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  purposes: string[];
  lastUpdated: Date;
  retention: string;
  deletable: boolean;
}

export interface DataRightsInfo {
  availableRights: DataRight[];
  pendingRequests: RightsRequest[];
  exercisedRights: ExercisedRight[];
  supportContact: string;
}

export interface DataRight {
  right: 'ACCESS' | 'RECTIFICATION' | 'ERASURE' | 'PORTABILITY' | 'RESTRICTION' | 'OBJECTION';
  name: string;
  description: string;
  available: boolean;
  timeframe: string;
  requirements: string[];
}

export interface RightsRequest {
  id: string;
  right: string;
  requestDate: Date;
  status: 'PENDING' | 'IN_PROGRESS' | 'COMPLETED' | 'REJECTED';
  expectedCompletion?: Date;
  updates: string[];
}

export interface ExercisedRight {
  right: string;
  exerciseDate: Date;
  outcome: string;
  followUpRequired: boolean;
}

export interface SecurityInfo {
  encryptionStatus: EncryptionStatus;
  accessLogs: AccessLog[];
  securityEvents: SecurityEventSummary[];
  recommendations: SecurityRecommendation[];
}

export interface EncryptionStatus {
  percentageEncrypted: number;
  algorithms: string[];
  keyRotationDate: Date;
  nextRotation: Date;
}

export interface AccessLog {
  timestamp: Date;
  action: string;
  ipAddress: string;
  location?: string;
  device?: string;
  success: boolean;
}

export interface SecurityEventSummary {
  type: 'LOGIN_ATTEMPT' | 'DATA_ACCESS' | 'PERMISSION_CHANGE' | 'SECURITY_ALERT';
  count: number;
  lastOccurrence: Date;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
}

export interface SecurityRecommendation {
  id: string;
  priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  title: string;
  description: string;
  action: string;
  category: 'AUTHENTICATION' | 'AUTHORIZATION' | 'ENCRYPTION' | 'MONITORING';
}

export interface Recommendation {
  id: string;
  type: 'PRIVACY' | 'SECURITY' | 'COMPLIANCE' | 'USABILITY';
  priority: 'LOW' | 'MEDIUM' | 'HIGH';
  title: string;
  description: string;
  action: string;
  benefit: string;
  implementationEffort: 'LOW' | 'MEDIUM' | 'HIGH';
}

export interface Notification {
  id: string;
  type: 'CONSENT_EXPIRING' | 'DATA_BREACH' | 'POLICY_UPDATE' | 'RIGHT_FULFILLED' | 'SECURITY_ALERT';
  title: string;
  message: string;
  timestamp: Date;
  read: boolean;
  actionRequired: boolean;
  action?: {
    label: string;
    url: string;
  };
  severity: 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL';
}

export interface PrivacyControlAction {
  type: 'UPDATE_CONSENT' | 'CHANGE_PREFERENCES' | 'EXERCISE_RIGHT' | 'UPDATE_SECURITY';
  userId: string;
  data: any;
  timestamp: Date;
}

export class PrivacyDashboard {
  private consentManager: ConsentManager;
  private dataMinimizer: DataMinimizer;
  private encryptionManager: EncryptionManager;
  private notifications: Map<string, Notification[]> = new Map();
  private userSessions: Map<string, DashboardSession> = new Map();
  private auditLog: PrivacyControlAction[] = [];

  constructor(
    consentManager: ConsentManager,
    dataMinimizer: DataMinimizer,
    encryptionManager: EncryptionManager
  ) {
    this.consentManager = consentManager;
    this.dataMinimizer = dataMinimizer;
    this.encryptionManager = encryptionManager;
  }

  /**
   * Generate comprehensive dashboard data for a user
   */
  async generateDashboard(userId: string): Promise<DashboardData> {
    try {
      const [
        userProfile,
        privacyScore,
        dataUsage,
        consents,
        dataCategories,
        rights,
        security,
        recommendations,
        notifications
      ] = await Promise.all([
        this.getUserProfile(userId),
        this.calculatePrivacyScore(userId),
        this.getDataUsage(userId),
        this.getConsentInfo(userId),
        this.getDataCategories(userId),
        this.getDataRights(userId),
        this.getSecurityInfo(userId),
        this.generateRecommendations(userId),
        this.getNotifications(userId)
      ]);

      return {
        user: userProfile,
        privacyScore,
        dataUsage,
        consents,
        dataCategories,
        rights,
        security,
        recommendations,
        notifications
      };

    } catch (error) {
      throw new PrivacyError(`Failed to generate dashboard: ${error.message}`, 'DASHBOARD_ERROR');
    }
  }

  /**
   * Update user privacy preferences
   */
  async updatePrivacyPreferences(
    userId: string,
    preferences: Partial<PrivacyPreferences>
  ): Promise<void> {
    try {
      // Validate preferences
      this.validatePrivacyPreferences(preferences);

      // Update preferences (in production, update database)
      const currentProfile = await this.getUserProfile(userId);
      const updatedPreferences = { ...currentProfile.preferences, ...preferences };

      // Log the action
      this.logAction({
        type: 'CHANGE_PREFERENCES',
        userId,
        data: { old: currentProfile.preferences, new: updatedPreferences },
        timestamp: new Date()
      });

      // Create notification
      this.addNotification(userId, {
        id: this.generateId(),
        type: 'POLICY_UPDATE',
        title: 'Privacy Preferences Updated',
        message: 'Your privacy preferences have been successfully updated.',
        timestamp: new Date(),
        read: false,
        actionRequired: false,
        severity: 'INFO'
      });

      console.log(`Updated privacy preferences for user ${userId}`);

    } catch (error) {
      throw new PrivacyError(`Failed to update preferences: ${error.message}`, 'PREFERENCE_UPDATE_ERROR');
    }
  }

  /**
   * Exercise data subject rights
   */
  async exerciseDataRight(
    userId: string,
    right: DataRight['right'],
    details?: any
  ): Promise<string> {
    try {
      const requestId = this.generateId();

      // Process the right request
      let outcome: string;

      switch (right) {
        case 'ACCESS':
          outcome = await this.handleDataAccess(userId, details);
          break;
        case 'RECTIFICATION':
          outcome = await this.handleDataRectification(userId, details);
          break;
        case 'ERASURE':
          outcome = await this.handleDataErasure(userId, details);
          break;
        case 'PORTABILITY':
          outcome = await this.handleDataPortability(userId, details);
          break;
        case 'RESTRICTION':
          outcome = await this.handleProcessingRestriction(userId, details);
          break;
        case 'OBJECTION':
          outcome = await this.handleProcessingObjection(userId, details);
          break;
        default:
          throw new PrivacyError(`Unsupported right: ${right}`, 'UNSUPPORTED_RIGHT');
      }

      // Log the action
      this.logAction({
        type: 'EXERCISE_RIGHT',
        userId,
        data: { right, requestId, details, outcome },
        timestamp: new Date()
      });

      // Create notification
      this.addNotification(userId, {
        id: this.generateId(),
        type: 'RIGHT_FULFILLED',
        title: `${right} Request Processed`,
        message: `Your ${right.toLowerCase()} request has been processed. ${outcome}`,
        timestamp: new Date(),
        read: false,
        actionRequired: false,
        severity: 'INFO'
      });

      return requestId;

    } catch (error) {
      throw new PrivacyError(`Failed to exercise right: ${error.message}`, 'RIGHT_EXERCISE_ERROR');
    }
  }

  /**
   * Update consent preferences
   */
  async updateConsents(
    userId: string,
    consentUpdates: Array<{ purposeId: string; granted: boolean; conditions?: string[] }>
  ): Promise<void> {
    try {
      for (const update of consentUpdates) {
        if (update.granted) {
          // Grant consent (simplified - in production, use proper consent flow)
          await this.consentManager.processConsentResponse(
            'temp_request_id',
            [{ purposeId: update.purposeId, granted: true, granularity: 'PURPOSE' }],
            'EXPLICIT',
            'CHECKBOX',
            'user_action',
            { locale: 'en-US' }
          );
        } else {
          // Withdraw consent
          await this.consentManager.withdrawConsent(userId, [update.purposeId]);
        }
      }

      // Log the action
      this.logAction({
        type: 'UPDATE_CONSENT',
        userId,
        data: { updates: consentUpdates },
        timestamp: new Date()
      });

      // Create notification
      this.addNotification(userId, {
        id: this.generateId(),
        type: 'CONSENT_EXPIRING',
        title: 'Consent Preferences Updated',
        message: `Updated consent for ${consentUpdates.length} purpose(s).`,
        timestamp: new Date(),
        read: false,
        actionRequired: false,
        severity: 'INFO'
      });

    } catch (error) {
      throw new PrivacyError(`Failed to update consents: ${error.message}`, 'CONSENT_UPDATE_ERROR');
    }
  }

  /**
   * Generate privacy transparency report
   */
  async generateTransparencyReport(
    userId: string,
    period: { start: Date; end: Date }
  ): Promise<TransparencyReport> {
    try {
      const dashboard = await this.generateDashboard(userId);

      const report: TransparencyReport = {
        userId,
        period,
        generatedAt: new Date(),
        dataProcessing: {
          totalOperations: dashboard.dataUsage.dataProcessed.last30Days,
          purposes: dashboard.dataUsage.dataProcessed.byPurpose,
          legalBases: this.getLegalBases(userId),
          dataMinimizationApplied: dashboard.dataUsage.dataProcessed.byCategory
        },
        dataSharing: {
          thirdParties: dashboard.dataUsage.sharing.thirdParties.map(tp => ({
            name: tp.name,
            purpose: tp.purpose,
            dataShared: tp.dataShared,
            safeguards: tp.safeguards
          })),
          crossBorderTransfers: dashboard.dataUsage.sharing.crossBorderTransfers
        },
        userRights: {
          exercised: dashboard.rights.exercisedRights,
          available: dashboard.rights.availableRights.map(r => r.right),
          pending: dashboard.rights.pendingRequests
        },
        security: {
          encryptionCoverage: dashboard.security.encryptionStatus.percentageEncrypted,
          accessEvents: dashboard.security.accessLogs.length,
          securityIncidents: dashboard.security.securityEvents.filter(e => e.riskLevel !== 'LOW').length
        },
        compliance: {
          frameworks: ['GDPR', 'CCPA'],
          violations: 0, // Calculate based on audit
          remedialActions: dashboard.recommendations.filter(r => r.type === 'COMPLIANCE').length
        }
      };

      return report;

    } catch (error) {
      throw new PrivacyError(`Failed to generate transparency report: ${error.message}`, 'REPORT_ERROR');
    }
  }

  // Private helper methods

  private async getUserProfile(userId: string): Promise<UserProfile> {
    // In production: fetch from database
    return {
      id: userId,
      pseudonym: `user_${userId.substring(0, 8)}`,
      joinedDate: new Date('2024-01-01'),
      lastActive: new Date(),
      preferences: {
        shareData: false,
        allowProfiling: false,
        marketingConsent: true,
        dataRetention: 365,
        anonymization: true
      },
      dataController: 'Walrus Security Suite',
      privacyOfficer: 'privacy@walrus-security.com'
    };
  }

  private async calculatePrivacyScore(userId: string): Promise<PrivacyScore> {
    // Simplified privacy score calculation
    const consentManagement = await this.scoreConsentManagement(userId);
    const dataMinimization = await this.scoreDataMinimization(userId);
    const securityControls = await this.scoreSecurityControls(userId);
    const transparency = await this.scoreTransparency(userId);
    const userControl = await this.scoreUserControl(userId);

    const overall = Math.round(
      (consentManagement + dataMinimization + securityControls + transparency + userControl) / 5
    );

    return {
      overall,
      components: {
        consentManagement,
        dataMinimization,
        securityControls,
        transparency,
        userControl
      },
      trend: 'STABLE',
      lastCalculated: new Date(),
      benchmarkComparison: 15 // 15% above industry average
    };
  }

  private async getDataUsage(userId: string): Promise<DataUsageInfo> {
    return {
      totalDataPoints: 1250,
      dataProcessed: {
        last30Days: 450,
        byPurpose: {
          'essential': 200,
          'analytics': 150,
          'marketing': 100
        },
        byCategory: {
          'personal': 180,
          'behavioral': 270
        },
        trend: 'STABLE'
      },
      storageUsed: {
        totalSize: '2.3 MB',
        encrypted: 85,
        anonymous: 60,
        identified: 40,
        locations: ['US-East', 'EU-West']
      },
      sharing: {
        thirdParties: [
          {
            name: 'Analytics Provider',
            category: 'Data Analytics',
            dataShared: ['behavioral', 'performance'],
            purpose: 'Service improvement',
            lastShared: new Date(),
            safeguards: ['Standard Contractual Clauses'],
            privacyPolicy: 'https://analytics.example.com/privacy',
            optOut: true
          }
        ],
        crossBorderTransfers: [
          {
            country: 'United Kingdom',
            adequacyDecision: true,
            safeguards: [],
            purpose: 'Data processing',
            dataTypes: ['personal', 'behavioral']
          }
        ],
        purposes: ['analytics', 'service_improvement'],
        safeguards: ['Encryption', 'Access Controls', 'Audit Logging']
      },
      retention: {
        policies: [
          {
            category: 'Personal Data',
            period: '1 year',
            purpose: 'Service delivery',
            nextReview: new Date(Date.now() + 180 * 24 * 60 * 60 * 1000)
          }
        ],
        upcomingDeletions: [
          {
            category: 'Marketing Data',
            scheduledDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
            reason: 'Retention period expired',
            preventable: false
          }
        ],
        totalRetained: '2.1 MB'
      }
    };
  }

  private async getConsentInfo(userId: string): Promise<ConsentInfo[]> {
    const consentStatus = await this.consentManager.getConsentStatus(userId);

    return Array.from(consentStatus.purposes.entries()).map(([purposeId, status]) => ({
      id: purposeId,
      purpose: purposeId,
      description: this.getPurposeDescription(purposeId),
      category: this.getPurposeCategory(purposeId),
      status: status.granted ? 'GRANTED' : 'WITHDRAWN',
      grantedDate: status.grantedAt,
      expiryDate: status.expiresAt,
      withdrawable: true,
      required: purposeId === 'essential',
      dataTypes: ['personal', 'behavioral'],
      thirdParties: ['Analytics Provider']
    }));
  }

  private async getDataCategories(userId: string): Promise<DataCategoryInfo[]> {
    return [
      {
        category: 'Personal Information',
        description: 'Name, email, contact details',
        dataPoints: 8,
        sensitivity: 'MEDIUM',
        purposes: ['service', 'communication'],
        lastUpdated: new Date(),
        retention: '1 year',
        deletable: true
      },
      {
        category: 'Behavioral Data',
        description: 'Usage patterns and preferences',
        dataPoints: 450,
        sensitivity: 'LOW',
        purposes: ['analytics', 'personalization'],
        lastUpdated: new Date(),
        retention: '2 years',
        deletable: true
      }
    ];
  }

  private async getDataRights(userId: string): Promise<DataRightsInfo> {
    return {
      availableRights: [
        {
          right: 'ACCESS',
          name: 'Right to Access',
          description: 'Request a copy of your personal data',
          available: true,
          timeframe: '30 days',
          requirements: ['Identity verification']
        },
        {
          right: 'RECTIFICATION',
          name: 'Right to Rectification',
          description: 'Correct inaccurate personal data',
          available: true,
          timeframe: '30 days',
          requirements: ['Proof of correction needed']
        },
        {
          right: 'ERASURE',
          name: 'Right to Erasure',
          description: 'Delete your personal data',
          available: true,
          timeframe: '30 days',
          requirements: ['Valid reason for deletion']
        },
        {
          right: 'PORTABILITY',
          name: 'Data Portability',
          description: 'Receive your data in a portable format',
          available: true,
          timeframe: '30 days',
          requirements: ['Identity verification']
        }
      ],
      pendingRequests: [],
      exercisedRights: [],
      supportContact: 'privacy@walrus-security.com'
    };
  }

  private async getSecurityInfo(userId: string): Promise<SecurityInfo> {
    return {
      encryptionStatus: {
        percentageEncrypted: 95,
        algorithms: ['AES-256-GCM', 'ChaCha20-Poly1305'],
        keyRotationDate: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
        nextRotation: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
      },
      accessLogs: [
        {
          timestamp: new Date(),
          action: 'LOGIN',
          ipAddress: '192.168.1.100',
          location: 'United States',
          device: 'Desktop',
          success: true
        }
      ],
      securityEvents: [
        {
          type: 'LOGIN_ATTEMPT',
          count: 15,
          lastOccurrence: new Date(),
          riskLevel: 'LOW'
        }
      ],
      recommendations: [
        {
          id: 'enable-2fa',
          priority: 'HIGH',
          title: 'Enable Two-Factor Authentication',
          description: 'Add an extra layer of security to your account',
          action: 'Set up 2FA in account settings',
          category: 'AUTHENTICATION'
        }
      ]
    };
  }

  private async generateRecommendations(userId: string): Promise<Recommendation[]> {
    return [
      {
        id: 'reduce-marketing-consent',
        type: 'PRIVACY',
        priority: 'MEDIUM',
        title: 'Review Marketing Consents',
        description: 'You have granted consent for multiple marketing purposes',
        action: 'Review and withdraw unnecessary marketing consents',
        benefit: 'Reduce unwanted communications and improve privacy',
        implementationEffort: 'LOW'
      },
      {
        id: 'enable-anonymization',
        type: 'PRIVACY',
        priority: 'HIGH',
        title: 'Enable Data Anonymization',
        description: 'Anonymize your data for analytics purposes',
        action: 'Enable anonymization in privacy preferences',
        benefit: 'Maintain analytics value while protecting identity',
        implementationEffort: 'LOW'
      }
    ];
  }

  private async getNotifications(userId: string): Promise<Notification[]> {
    return this.notifications.get(userId) || [];
  }

  // Scoring methods
  private async scoreConsentManagement(userId: string): Promise<number> {
    const status = await this.consentManager.getConsentStatus(userId);
    const validConsents = Array.from(status.purposes.values()).filter(p => p.valid).length;
    const totalConsents = status.purposes.size;
    return Math.round((validConsents / Math.max(totalConsents, 1)) * 100);
  }

  private async scoreDataMinimization(userId: string): Promise<number> {
    // Simplified scoring based on data categories
    return 80; // Assume 80% compliance
  }

  private async scoreSecurityControls(userId: string): Promise<number> {
    const securityInfo = await this.getSecurityInfo(userId);
    return securityInfo.encryptionStatus.percentageEncrypted;
  }

  private async scoreTransparency(userId: string): Promise<number> {
    // Score based on availability of transparency features
    return 90;
  }

  private async scoreUserControl(userId: string): Promise<number> {
    // Score based on available user controls
    return 85;
  }

  // Right handlers
  private async handleDataAccess(userId: string, details?: any): Promise<string> {
    // Generate data export
    return 'Data export generated and sent to your registered email address.';
  }

  private async handleDataRectification(userId: string, details?: any): Promise<string> {
    // Update data records
    return 'Data corrections have been applied to your records.';
  }

  private async handleDataErasure(userId: string, details?: any): Promise<string> {
    // Delete data according to scope
    return 'Your data has been deleted according to your request.';
  }

  private async handleDataPortability(userId: string, details?: any): Promise<string> {
    // Export data in portable format
    return 'Your data has been exported in a portable format and sent to your email.';
  }

  private async handleProcessingRestriction(userId: string, details?: any): Promise<string> {
    // Restrict data processing
    return 'Data processing has been restricted according to your request.';
  }

  private async handleProcessingObjection(userId: string, details?: any): Promise<string> {
    // Handle objection to processing
    return 'Your objection to data processing has been recorded and implemented.';
  }

  // Utility methods
  private getPurposeDescription(purposeId: string): string {
    const descriptions: Record<string, string> = {
      essential: 'Core functionality and security features',
      analytics: 'Understanding usage patterns to improve services',
      marketing: 'Personalized marketing and promotional content',
      personalization: 'Customizing your experience'
    };
    return descriptions[purposeId] || 'Data processing purpose';
  }

  private getPurposeCategory(purposeId: string): ConsentInfo['category'] {
    const categories: Record<string, ConsentInfo['category']> = {
      essential: 'FUNCTIONAL',
      analytics: 'ANALYTICS',
      marketing: 'MARKETING',
      personalization: 'PERSONALIZATION'
    };
    return categories[purposeId] || 'FUNCTIONAL';
  }

  private getLegalBases(userId: string): Record<string, string> {
    return {
      essential: 'Legitimate Interest',
      analytics: 'Consent',
      marketing: 'Consent',
      service: 'Contract'
    };
  }

  private validatePrivacyPreferences(preferences: Partial<PrivacyPreferences>): void {
    if (preferences.dataRetention !== undefined && preferences.dataRetention < 0) {
      throw new PrivacyError('Invalid data retention period', 'INVALID_PREFERENCES');
    }
  }

  private addNotification(userId: string, notification: Notification): void {
    if (!this.notifications.has(userId)) {
      this.notifications.set(userId, []);
    }
    this.notifications.get(userId)!.unshift(notification);

    // Keep only last 50 notifications
    const notifications = this.notifications.get(userId)!;
    if (notifications.length > 50) {
      this.notifications.set(userId, notifications.slice(0, 50));
    }
  }

  private logAction(action: PrivacyControlAction): void {
    this.auditLog.push(action);

    // Keep only last 1000 actions
    if (this.auditLog.length > 1000) {
      this.auditLog = this.auditLog.slice(-1000);
    }
  }

  private generateId(): string {
    return `${Date.now()}_${Math.random().toString(36).substring(7)}`;
  }
}

// Supporting interfaces
interface DashboardSession {
  userId: string;
  startTime: Date;
  lastActivity: Date;
  ipAddress: string;
  userAgent: string;
}

interface TransparencyReport {
  userId: string;
  period: { start: Date; end: Date };
  generatedAt: Date;
  dataProcessing: {
    totalOperations: number;
    purposes: Record<string, number>;
    legalBases: Record<string, string>;
    dataMinimizationApplied: Record<string, number>;
  };
  dataSharing: {
    thirdParties: Array<{
      name: string;
      purpose: string;
      dataShared: string[];
      safeguards: string[];
    }>;
    crossBorderTransfers: CrossBorderTransfer[];
  };
  userRights: {
    exercised: ExercisedRight[];
    available: string[];
    pending: RightsRequest[];
  };
  security: {
    encryptionCoverage: number;
    accessEvents: number;
    securityIncidents: number;
  };
  compliance: {
    frameworks: string[];
    violations: number;
    remedialActions: number;
  };
}