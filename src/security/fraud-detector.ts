/**
 * Advanced Fraud Detection System with Machine Learning
 * Implements multiple detection algorithms for comprehensive security
 */

import { FraudIndicator, MLModel, SecurityError, SecurityEvent } from '../types';
import { MLSecurityAnalyzer } from './ml-security-analyzer';
import { createHash } from 'crypto';

// Helper function to extract error message
function getErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}


export interface FraudPattern {
  id: string;
  name: string;
  type: 'BEHAVIORAL' | 'TRANSACTIONAL' | 'IDENTITY' | 'TEMPORAL' | 'NETWORK';
  threshold: number;
  indicators: string[];
  weight: number;
}

export interface RiskScore {
  overall: number;
  behavioral: number;
  transactional: number;
  temporal: number;
  network: number;
  confidence: number;
}

export interface FraudDetectionResult {
  isFraud: boolean;
  riskScore: RiskScore;
  indicators: FraudIndicator[];
  recommendations: string[];
  timestamp: Date;
}

export class FraudDetector {
  private mlAnalyzer: MLSecurityAnalyzer;
  private patterns: Map<string, FraudPattern> = new Map();
  private riskBaseline: Map<string, number> = new Map();
  private behaviorProfiles: Map<string, any> = new Map();
  private detectionHistory: FraudDetectionResult[] = [];

  constructor(mlAnalyzer: MLSecurityAnalyzer) {
    this.mlAnalyzer = mlAnalyzer;
    this.initializePatterns();
  }

  /**
   * Analyze transaction or event for fraud indicators
   */
  async detectFraud(
    event: SecurityEvent,
    context: any = {}
  ): Promise<FraudDetectionResult> {
    try {
      const indicators: FraudIndicator[] = [];

      // Run parallel detection algorithms
      const [
        behavioralIndicators,
        transactionalIndicators,
        temporalIndicators,
        networkIndicators,
        mlIndicators
      ] = await Promise.all([
        this.detectBehavioralAnomalies(event, context),
        this.detectTransactionalFraud(event, context),
        this.detectTemporalAnomalies(event, context),
        this.detectNetworkAnomalies(event, context),
        this.runMLDetection(event, context)
      ]);

      indicators.push(
        ...behavioralIndicators,
        ...transactionalIndicators,
        ...temporalIndicators,
        ...networkIndicators,
        ...mlIndicators
      );

      // Calculate risk scores
      const riskScore = this.calculateRiskScore(indicators);

      // Determine fraud status
      const isFraud = this.determineFraudStatus(riskScore, indicators);

      // Generate recommendations
      const recommendations = this.generateRecommendations(indicators, riskScore);

      const result: FraudDetectionResult = {
        isFraud,
        riskScore,
        indicators,
        recommendations,
        timestamp: new Date()
      };

      // Store result for learning
      this.detectionHistory.push(result);
      this.updateBehaviorProfile(event.userId || 'anonymous', event, riskScore);

      return result;

    } catch (error) {
      throw new SecurityError(`Fraud detection failed: ${error instanceof Error ? error.message : String(error)}`, 'FRAUD_DETECTION_ERROR', 'HIGH');
    }
  }

  /**
   * Detect behavioral anomalies
   */
  private async detectBehavioralAnomalies(
    event: SecurityEvent,
    context: any
  ): Promise<FraudIndicator[]> {
    const indicators: FraudIndicator[] = [];
    const userId = event.userId || 'anonymous';

    // Get user's behavioral baseline
    const profile = this.behaviorProfiles.get(userId);
    if (!profile) {
      // Create initial profile
      this.createBehaviorProfile(userId, event);
      return indicators;
    }

    // Check for unusual access patterns
    if (this.isUnusualAccessTime(event, profile)) {
      indicators.push({
        type: 'ANOMALY',
        severity: 'MEDIUM',
        confidence: 0.7,
        description: 'Unusual access time detected',
        metadata: {
          currentTime: new Date(event.timestamp).getHours(),
          normalTimes: profile.normalAccessHours
        }
      });
    }

    // Check for unusual location
    if (context.location && this.isUnusualLocation(context.location, profile)) {
      indicators.push({
        type: 'ANOMALY',
        severity: 'HIGH',
        confidence: 0.8,
        description: 'Unusual access location detected',
        metadata: {
          currentLocation: context.location,
          normalLocations: profile.normalLocations
        }
      });
    }

    // Check for unusual device
    if (context.device && this.isUnusualDevice(context.device, profile)) {
      indicators.push({
        type: 'ANOMALY',
        severity: 'MEDIUM',
        confidence: 0.6,
        description: 'Unusual device detected',
        metadata: {
          currentDevice: context.device,
          knownDevices: profile.knownDevices
        }
      });
    }

    // Check for rapid successive actions
    if (this.hasRapidSuccessiveActions(event, profile)) {
      indicators.push({
        type: 'PATTERN',
        severity: 'HIGH',
        confidence: 0.9,
        description: 'Rapid successive actions detected',
        metadata: {
          actionInterval: this.calculateActionInterval(event, profile),
          threshold: profile.normalActionInterval
        }
      });
    }

    return indicators;
  }

  /**
   * Detect transactional fraud patterns
   */
  private async detectTransactionalFraud(
    event: SecurityEvent,
    context: any
  ): Promise<FraudIndicator[]> {
    const indicators: FraudIndicator[] = [];

    if (!context.transaction) {
      return indicators;
    }

    const transaction = context.transaction;

    // Check for unusual transaction amounts
    if (this.isUnusualAmount(transaction.amount, event.userId)) {
      indicators.push({
        type: 'THRESHOLD',
        severity: 'HIGH',
        confidence: 0.8,
        description: 'Unusual transaction amount',
        metadata: {
          amount: transaction.amount,
          baseline: this.riskBaseline.get(`${event.userId}_amount`) || 0
        }
      });
    }

    // Check for velocity limits
    if (await this.exceedsVelocityLimits(transaction, event.userId)) {
      indicators.push({
        type: 'PATTERN',
        severity: 'CRITICAL',
        confidence: 0.95,
        description: 'Transaction velocity limits exceeded',
        metadata: {
          currentVelocity: await this.calculateVelocity(event.userId),
          limit: this.getVelocityLimit(event.userId)
        }
      });
    }

    // Check for suspicious recipients
    if (this.isSuspiciousRecipient(transaction.recipient)) {
      indicators.push({
        type: 'PATTERN',
        severity: 'HIGH',
        confidence: 0.85,
        description: 'Suspicious recipient detected',
        metadata: {
          recipient: transaction.recipient,
          riskLevel: this.getRecipientRisk(transaction.recipient)
        }
      });
    }

    // Check for round number patterns
    if (this.hasRoundNumberPattern(transaction.amount)) {
      indicators.push({
        type: 'PATTERN',
        severity: 'MEDIUM',
        confidence: 0.6,
        description: 'Round number transaction pattern',
        metadata: {
          amount: transaction.amount
        }
      });
    }

    return indicators;
  }

  /**
   * Detect temporal anomalies
   */
  private async detectTemporalAnomalies(
    event: SecurityEvent,
    context: any
  ): Promise<FraudIndicator[]> {
    const indicators: FraudIndicator[] = [];

    // Check for impossible travel time
    if (context.previousLocation && context.location) {
      const travelTime = this.calculateTravelTime(
        context.previousLocation,
        context.location,
        context.previousTimestamp,
        event.timestamp
      );

      if (travelTime.isImpossible) {
        indicators.push({
          type: 'ANOMALY',
          severity: 'CRITICAL',
          confidence: 0.99,
          description: 'Impossible travel time detected',
          metadata: {
            requiredTime: travelTime.required,
            actualTime: travelTime.actual,
            distance: travelTime.distance
          }
        });
      }
    }

    // Check for off-hours activity
    if (this.isOffHoursActivity(event, context)) {
      indicators.push({
        type: 'ANOMALY',
        severity: 'MEDIUM',
        confidence: 0.7,
        description: 'Off-hours activity detected',
        metadata: {
          time: new Date(event.timestamp),
          timezone: context.timezone
        }
      });
    }

    // Check for weekend/holiday activity
    if (this.isHolidayActivity(event, context)) {
      indicators.push({
        type: 'ANOMALY',
        severity: 'MEDIUM',
        confidence: 0.6,
        description: 'Holiday/weekend activity detected',
        metadata: {
          date: new Date(event.timestamp),
          isHoliday: this.isHoliday(new Date(event.timestamp))
        }
      });
    }

    return indicators;
  }

  /**
   * Detect network-based anomalies
   */
  private async detectNetworkAnomalies(
    event: SecurityEvent,
    context: any
  ): Promise<FraudIndicator[]> {
    const indicators: FraudIndicator[] = [];

    if (!context.network) {
      return indicators;
    }

    const network = context.network;

    // Check for VPN/Proxy usage
    if (this.isVPNOrProxy(network.ipAddress)) {
      indicators.push({
        type: 'PATTERN',
        severity: 'MEDIUM',
        confidence: 0.8,
        description: 'VPN/Proxy usage detected',
        metadata: {
          ipAddress: network.ipAddress,
          vpnProvider: this.getVPNProvider(network.ipAddress)
        }
      });
    }

    // Check for suspicious geolocation
    if (this.isSuspiciousGeolocation(network.geolocation)) {
      indicators.push({
        type: 'PATTERN',
        severity: 'HIGH',
        confidence: 0.85,
        description: 'Suspicious geolocation detected',
        metadata: {
          country: network.geolocation.country,
          riskScore: this.getCountryRiskScore(network.geolocation.country)
        }
      });
    }

    // Check for tor network
    if (this.isTorNetwork(network.ipAddress)) {
      indicators.push({
        type: 'PATTERN',
        severity: 'HIGH',
        confidence: 0.9,
        description: 'Tor network usage detected',
        metadata: {
          ipAddress: network.ipAddress
        }
      });
    }

    return indicators;
  }

  /**
   * Run machine learning based fraud detection
   */
  private async runMLDetection(
    event: SecurityEvent,
    context: any
  ): Promise<FraudIndicator[]> {
    try {
      const features = this.extractFeatures(event, context);
      const prediction = await this.mlAnalyzer.predictFraud(features);

      const indicators: FraudIndicator[] = [];

      if (prediction.isFraud) {
        indicators.push({
          type: 'ML_PREDICTION',
          severity: this.mapConfidenceToSeverity(prediction.confidence),
          confidence: prediction.confidence,
          description: 'ML model detected fraudulent activity',
          metadata: {
            model: prediction.modelUsed,
            features: features,
            score: prediction.score
          }
        });
      }

      return indicators;
    } catch (error) {
      console.warn('ML detection failed:', error);
      return [];
    }
  }

  /**
   * Calculate overall risk score
   */
  private calculateRiskScore(indicators: FraudIndicator[]): RiskScore {
    const scores = {
      behavioral: 0,
      transactional: 0,
      temporal: 0,
      network: 0,
      confidence: 0
    };

    if (indicators.length === 0) {
      return { overall: 0, behavioral: 0, transactional: 0, temporal: 0, network: 0, confidence: 0 };
    }

    let totalWeightedScore = 0;
    let maxSingleScore = 0;
    let totalConfidence = 0;
    let criticalCount = 0;
    let highCount = 0;

    indicators.forEach(indicator => {
      const weight = this.getSeverityWeight(indicator.severity);
      const weightedScore = indicator.confidence * (weight / 10); // Normalize weight to 0-1
      const categoryScore = Math.min(weightedScore, 1.0);

      totalWeightedScore += weightedScore;
      maxSingleScore = Math.max(maxSingleScore, weightedScore);
      totalConfidence += indicator.confidence;

      // Count severity levels
      if (indicator.severity === 'CRITICAL') criticalCount++;
      if (indicator.severity === 'HIGH') highCount++;

      // Categorize indicators with enhanced scoring
      if (indicator.description.includes('behavioral') || indicator.description.includes('access') || indicator.description.includes('pattern')) {
        scores.behavioral = Math.max(scores.behavioral, categoryScore);
      } else if (indicator.description.includes('transaction') || indicator.description.includes('amount') || indicator.description.includes('velocity')) {
        scores.transactional = Math.max(scores.transactional, categoryScore);
      } else if (indicator.description.includes('time') || indicator.description.includes('travel') || indicator.description.includes('temporal')) {
        scores.temporal = Math.max(scores.temporal, categoryScore);
      } else if (indicator.description.includes('network') || indicator.description.includes('IP') || indicator.description.includes('location') || indicator.description.includes('proxy') || indicator.description.includes('Tor')) {
        scores.network = Math.max(scores.network, categoryScore);
      }
    });

    // Enhanced overall score calculation
    const averageScore = totalWeightedScore / indicators.length;

    // Apply severity bonuses
    let severityBonus = 0;
    if (criticalCount > 0) severityBonus += 0.3;
    if (highCount > 0) severityBonus += 0.15;
    if (criticalCount >= 2) severityBonus += 0.2; // Multiple critical indicators

    // Combine average, max, and severity bonus
    const combinedScore = Math.min(averageScore + severityBonus, 1.0);

    // Ensure minimum risk for suspicious patterns
    const overall = Math.max(combinedScore, maxSingleScore * 0.8);
    const confidence = totalConfidence / indicators.length;

    return {
      overall: Math.min(overall, 1.0),
      behavioral: Math.min(scores.behavioral, 1.0),
      transactional: Math.min(scores.transactional, 1.0),
      temporal: Math.min(scores.temporal, 1.0),
      network: Math.min(scores.network, 1.0),
      confidence: Math.min(confidence, 1.0)
    };
  }

  // Helper methods implementation continues...

  private initializePatterns(): void {
    // Initialize fraud detection patterns
    this.patterns.set('rapid_succession', {
      id: 'rapid_succession',
      name: 'Rapid Successive Actions',
      type: 'BEHAVIORAL',
      threshold: 0.8,
      indicators: ['high_frequency', 'automated_behavior'],
      weight: 0.9
    });

    this.patterns.set('unusual_amount', {
      id: 'unusual_amount',
      name: 'Unusual Transaction Amount',
      type: 'TRANSACTIONAL',
      threshold: 0.7,
      indicators: ['large_amount', 'deviation_from_normal'],
      weight: 0.8
    });

    this.patterns.set('impossible_travel', {
      id: 'impossible_travel',
      name: 'Impossible Travel Time',
      type: 'TEMPORAL',
      threshold: 0.95,
      indicators: ['location_mismatch', 'time_violation'],
      weight: 1.0
    });
  }

  private determineFraudStatus(riskScore: RiskScore, indicators: FraudIndicator[]): boolean {
    // High confidence critical indicators
    const criticalIndicators = indicators.filter(i =>
      i.severity === 'CRITICAL' && i.confidence > 0.9
    );

    if (criticalIndicators.length > 0) {
      return true;
    }

    // Multiple high severity indicators
    const highSeverityIndicators = indicators.filter(i =>
      i.severity === 'HIGH' && i.confidence > 0.7
    );

    if (highSeverityIndicators.length >= 2) {
      return true;
    }

    // Overall risk score threshold
    return riskScore.overall > 0.8 && riskScore.confidence > 0.7;
  }

  private generateRecommendations(
    indicators: FraudIndicator[],
    riskScore: RiskScore
  ): string[] {
    const recommendations: string[] = [];

    if (riskScore.overall > 0.8) {
      recommendations.push('Immediate manual review required');
      recommendations.push('Consider temporarily blocking the account');
    }

    if (riskScore.behavioral > 0.7) {
      recommendations.push('Implement additional authentication steps');
      recommendations.push('Monitor user behavior closely');
    }

    if (riskScore.transactional > 0.7) {
      recommendations.push('Review transaction patterns');
      recommendations.push('Implement transaction limits');
    }

    if (riskScore.temporal > 0.7) {
      recommendations.push('Verify user location and identity');
      recommendations.push('Check for account compromise');
    }

    if (riskScore.network > 0.7) {
      recommendations.push('Block suspicious IP addresses');
      recommendations.push('Implement geo-location restrictions');
    }

    indicators.forEach(indicator => {
      if (indicator.severity === 'CRITICAL') {
        recommendations.push(`Critical: ${indicator.description} - Immediate action required`);
      }
    });

    return [...new Set(recommendations)]; // Remove duplicates
  }

  // Additional helper methods (simplified for brevity)
  private createBehaviorProfile(userId: string, event: SecurityEvent): void {
    this.behaviorProfiles.set(userId, {
      normalAccessHours: [new Date(event.timestamp).getHours()],
      normalLocations: [],
      knownDevices: [],
      normalActionInterval: 60000, // 1 minute
      lastAction: event.timestamp
    });
  }

  private updateBehaviorProfile(userId: string, event: SecurityEvent, riskScore: RiskScore): void {
    if (riskScore.overall < 0.5) { // Only update with legitimate behavior
      const profile = this.behaviorProfiles.get(userId);
      if (profile) {
        profile.normalAccessHours.push(new Date(event.timestamp).getHours());
        profile.lastAction = event.timestamp;
        this.behaviorProfiles.set(userId, profile);
      }
    }
  }

  private isUnusualAccessTime(event: SecurityEvent, profile: any): boolean {
    const hour = new Date(event.timestamp).getHours();
    return !profile.normalAccessHours.includes(hour);
  }

  private isUnusualLocation(location: any, profile: any): boolean {
    return !profile.normalLocations.some((loc: any) =>
      this.calculateDistance(location, loc) < 100 // 100km radius
    );
  }

  private isUnusualDevice(device: any, profile: any): boolean {
    return !profile.knownDevices.some((known: any) =>
      known.fingerprint === device.fingerprint
    );
  }

  private hasRapidSuccessiveActions(event: SecurityEvent, profile: any): boolean {
    return event.timestamp.getTime() - new Date(profile.lastAction).getTime() < 1000; // Less than 1 second
  }

  private calculateActionInterval(event: SecurityEvent, profile: any): number {
    return event.timestamp.getTime() - new Date(profile.lastAction).getTime();
  }

  private isUnusualAmount(amount: number, userId: string): boolean {
    const baseline = this.riskBaseline.get(`${userId}_amount`) || 1000;
    return amount > baseline * 5; // 5x normal amount
  }

  private async exceedsVelocityLimits(transaction: any, userId: string): Promise<boolean> {
    const velocity = await this.calculateVelocity(userId);
    const limit = this.getVelocityLimit(userId);
    return velocity > limit;
  }

  private async calculateVelocity(userId: string): Promise<number> {
    // Simplified velocity calculation
    return 100; // Mock value
  }

  private getVelocityLimit(userId: string): number {
    return 1000; // Mock limit
  }

  private isSuspiciousRecipient(recipient: string): boolean {
    // Enhanced suspicious recipient detection
    if (!recipient) return false;

    const suspiciousPatterns = [
      // Known suspicious patterns
      /^[0-9a-f]{40,}$/i, // Long hex strings (crypto addresses)
      /temp|test|fake|dummy/i, // Temporary/test accounts
      /^.{1,2}$/, // Very short names
      /[0-9]{10,}/, // Long numeric sequences
    ];

    const highRiskDomains = [
      'tempmail.org', '10minutemail.com', 'guerrillamail.com',
      'mailinator.com', 'temp-mail.org'
    ];

    // Check patterns
    if (suspiciousPatterns.some(pattern => pattern.test(recipient))) {
      return true;
    }

    // Check domains if email
    if (recipient.includes('@')) {
      const domain = recipient.split('@')[1];
      if (highRiskDomains.includes(domain)) {
        return true;
      }
    }

    // Check against internal blacklist (simulate database lookup)
    const blacklistedRecipients = this.getBlacklistedRecipients();
    return blacklistedRecipients.includes(recipient.toLowerCase());
  }

  private getRecipientRisk(recipient: string): string {
    return 'low'; // Mock implementation
  }

  private hasRoundNumberPattern(amount: number): boolean {
    return amount % 100 === 0 || amount % 1000 === 0;
  }

  private calculateTravelTime(from: any, to: any, fromTime: Date, toTime: Date): any {
    // Simplified travel time calculation
    return {
      isImpossible: false,
      required: 3600000, // 1 hour
      actual: toTime.getTime() - fromTime.getTime(),
      distance: 100 // km
    };
  }

  private isOffHoursActivity(event: SecurityEvent, context: any): boolean {
    const hour = new Date(event.timestamp).getHours();
    return hour < 6 || hour > 22; // Before 6 AM or after 10 PM
  }

  private isHolidayActivity(event: SecurityEvent, context: any): boolean {
    const day = new Date(event.timestamp).getDay();
    return day === 0 || day === 6; // Weekend
  }

  private isHoliday(date: Date): boolean {
    // Simplified holiday check
    return false;
  }

  private isVPNOrProxy(ipAddress: string): boolean {
    // Check against VPN/proxy database
    return false; // Mock implementation
  }

  private getVPNProvider(ipAddress: string): string {
    return 'unknown'; // Mock implementation
  }

  private isSuspiciousGeolocation(geolocation: any): boolean {
    return this.getCountryRiskScore(geolocation.country) > 0.7;
  }

  private getCountryRiskScore(country: string): number {
    // Country risk scoring
    const highRiskCountries = ['XX', 'YY']; // Mock high-risk countries
    return highRiskCountries.includes(country) ? 0.8 : 0.2;
  }

  private isTorNetwork(ipAddress: string): boolean {
    if (!ipAddress) return false;

    // Known Tor exit node patterns and ranges
    const torPatterns = [
      /^127\.0\.0\.1$/, // Localhost (often used with Tor)
      /^10\./, // Private network ranges often used with Tor bridges
      /^192\.168\./, // Private ranges
    ];

    // Simulate checking against known Tor exit nodes
    const knownTorNodes = [
      '185.220.100.240', '185.220.100.241', '185.220.100.242',
      '185.220.101.1', '185.220.101.2', '185.220.101.3',
      '199.87.154.255', '199.87.154.254'
    ];

    return knownTorNodes.includes(ipAddress) ||
           torPatterns.some(pattern => pattern.test(ipAddress));
  }

  private extractFeatures(event: SecurityEvent, context: any): number[] {
    const date = new Date(event.timestamp);
    const transaction = context.transaction || {};
    const network = context.network || {};
    const device = context.device || {};
    const location = context.location || {};

    // Enhanced feature engineering for fraud detection
    return [
      // Temporal features
      date.getHours(), // Hour of day (0-23)
      date.getDay(), // Day of week (0-6)
      date.getDate(), // Day of month (1-31)
      this.isWeekend(date) ? 1 : 0, // Weekend indicator
      this.isBusinessHours(date) ? 1 : 0, // Business hours indicator

      // Transaction features
      Math.log(Math.max(transaction.amount || 1, 1)), // Log amount (handles outliers)
      this.getAmountPercentile(transaction.amount, event.userId), // Amount percentile for user
      transaction.currency === 'USD' ? 1 : 0, // Currency type
      this.getTransactionVelocity(event.userId), // Recent transaction velocity

      // Location features
      this.isHighRiskCountry(location.country) ? 1 : 0, // High-risk country
      this.getLocationRisk(location.country, location.ip), // Location risk score
      this.isVpnOrTor(network.ip) ? 1 : 0, // VPN/Tor usage
      Math.abs(location.timezoneOffset || 0) / 12, // Timezone offset normalized

      // Device features
      device.isNewDevice ? 1 : 0, // New device indicator
      device.isMobile ? 1 : 0, // Mobile device
      this.getDeviceRiskScore(device), // Device fingerprint risk

      // Behavioral features
      this.getUserRiskScore(event.userId), // Historical user risk
      event.details?.sessionDuration || 0, // Session duration
      this.getRecentFailedAttempts(event.userId), // Recent failed attempts

      // Network features
      network.riskScore || 0, // Network risk score
      this.isProxyDetected(network.ip) ? 1 : 0, // Proxy detection
      network.connectionSpeed || 0 // Connection speed anomaly
    ];
  }

  private mapConfidenceToSeverity(confidence: number): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    if (confidence > 0.9) return 'CRITICAL';
    if (confidence > 0.7) return 'HIGH';
    if (confidence > 0.5) return 'MEDIUM';
    return 'LOW';
  }

  private getSeverityWeight(severity: string): number {
    switch (severity) {
      case 'CRITICAL': return 10;
      case 'HIGH': return 7;
      case 'MEDIUM': return 4;
      case 'LOW': return 2;
      default: return 1;
    }
  }

  private calculateDistance(loc1: any, loc2: any): number {
    // Simplified distance calculation (Haversine formula should be used)
    return Math.sqrt(
      Math.pow(loc1.lat - loc2.lat, 2) + Math.pow(loc1.lng - loc2.lng, 2)
    ) * 111; // Approximate km per degree
  }

  // Enhanced helper methods for improved fraud detection

  private isWeekend(date: Date): boolean {
    const day = date.getDay();
    return day === 0 || day === 6; // Sunday or Saturday
  }

  private isBusinessHours(date: Date): boolean {
    const hour = date.getHours();
    const day = date.getDay();
    // Monday-Friday 9AM-5PM
    return day >= 1 && day <= 5 && hour >= 9 && hour <= 17;
  }

  private getAmountPercentile(amount: number, userId: string): number {
    // Get user's historical transaction amounts
    const userTransactions = this.getUserTransactionHistory(userId);
    if (userTransactions.length === 0) return 0.5; // Default for new users

    const sorted = userTransactions.sort((a, b) => a - b);
    let rank = 0;
    for (let i = 0; i < sorted.length; i++) {
      if (sorted[i] <= amount) rank = i + 1;
    }
    return rank / sorted.length;
  }

  private getTransactionVelocity(userId: string): number {
    // Calculate transactions per hour in last 24 hours
    const recentTransactions = this.getRecentTransactions(userId, 24);
    return recentTransactions.length / 24;
  }

  private isHighRiskCountry(country: string): boolean {
    const highRiskCountries = [
      'AF', 'BY', 'CF', 'CD', 'CU', 'ER', 'GN', 'GW',
      'HT', 'IR', 'IQ', 'LB', 'LY', 'ML', 'MM', 'NI',
      'KP', 'RU', 'SO', 'SS', 'SD', 'SY', 'UA', 'VE',
      'YE', 'ZW', 'PK', 'BD', 'NG' // High-risk countries
    ];
    return highRiskCountries.includes(country?.toUpperCase());
  }

  private getLocationRisk(country: string, ip: string): number {
    let risk = 0;

    if (this.isHighRiskCountry(country)) risk += 0.4;
    if (this.isTorNetwork(ip)) risk += 0.3;
    if (this.isVpnOrTor(ip)) risk += 0.2;
    if (this.isProxyDetected(ip)) risk += 0.15;

    return Math.min(risk, 1.0);
  }

  private isVpnOrTor(ip: string): boolean {
    if (!ip) return false;

    // Enhanced VPN/Tor detection
    const vpnPatterns = [
      /^10\./, // Private networks often used by VPNs
      /^172\.(1[6-9]|2[0-9]|3[01])\./, // Private range 172.16.0.0-172.31.255.255
      /^192\.168\./, // Private range 192.168.0.0-192.168.255.255
    ];

    const knownVpnRanges = [
      '185.220.', // Common VPN provider range
      '91.219.', // Another VPN range
      '5.253.',
    ];

    return this.isTorNetwork(ip) ||
           vpnPatterns.some(pattern => pattern.test(ip)) ||
           knownVpnRanges.some(range => ip.startsWith(range));
  }

  private getDeviceRiskScore(device: any): number {
    let risk = 0;

    if (device.isJailbroken || device.isRooted) risk += 0.3;
    if (device.hasEmulator) risk += 0.25;
    if (device.isSuspiciousUserAgent) risk += 0.2;
    if (!device.cookiesEnabled) risk += 0.15;
    if (device.hasAdBlocker) risk += 0.1;

    return Math.min(risk, 1.0);
  }

  private getUserRiskScore(userId: string): number {
    // Historical user behavior analysis
    const userProfile = this.behaviorProfiles.get(userId);
    if (!userProfile) return 0.1; // New user, low baseline risk

    let risk = 0;

    if (userProfile.failedLoginAttempts > 3) risk += 0.2;
    if (userProfile.suspiciousActivityCount > 2) risk += 0.3;
    if (userProfile.accountAge < 30) risk += 0.15; // days
    if (userProfile.emailVerified === false) risk += 0.2;
    if (userProfile.phoneVerified === false) risk += 0.15;

    return Math.min(risk, 0.9);
  }

  private getRecentFailedAttempts(userId: string): number {
    const userProfile = this.behaviorProfiles.get(userId);
    return userProfile?.recentFailedAttempts || 0;
  }

  private isProxyDetected(ip: string): boolean {
    if (!ip) return false;

    // Enhanced proxy detection
    const proxyPatterns = [
      /^8\.8\.[0-9]+\.[0-9]+$/, // Google DNS (sometimes used as proxy)
      /^1\.1\.[0-9]+\.[0-9]+$/, // Cloudflare DNS
    ];

    const knownProxyRanges = [
      '104.16.', // Cloudflare proxy range
      '172.67.', // Cloudflare proxy range
      '198.41.', // Known proxy range
    ];

    return proxyPatterns.some(pattern => pattern.test(ip)) ||
           knownProxyRanges.some(range => ip.startsWith(range));
  }

  private getUserTransactionHistory(userId: string): number[] {
    // Simulate getting user's historical transaction amounts
    const profile = this.behaviorProfiles.get(userId);
    return profile?.transactionHistory || [100, 250, 500, 75, 300]; // Default history
  }

  private getRecentTransactions(userId: string, hours: number): any[] {
    // Simulate getting recent transactions
    const profile = this.behaviorProfiles.get(userId);
    return profile?.recentTransactions || [];
  }

  private getBlacklistedRecipients(): string[] {
    // Simulate blacklisted recipients database
    return [
      'scammer@example.com',
      'fraud.wallet.addr',
      'suspicious.recipient@temp.com',
      'known.bad.actor'
    ];
  }
}
