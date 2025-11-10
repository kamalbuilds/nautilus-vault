/**
 * Threat Detector - Real-time threat detection and analysis
 */

import { SecurityError } from '../types';

export interface ThreatSignature {
  id: string;
  name: string;
  type: ThreatType;
  pattern: RegExp | string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  mitigation: string;
}

export enum ThreatType {
  MALWARE = 'MALWARE',
  PHISHING = 'PHISHING',
  SQL_INJECTION = 'SQL_INJECTION',
  XSS = 'XSS',
  BRUTE_FORCE = 'BRUTE_FORCE',
  DDoS = 'DDoS',
  PRIVILEGE_ESCALATION = 'PRIVILEGE_ESCALATION',
  DATA_EXFILTRATION = 'DATA_EXFILTRATION'
}

export interface ThreatDetection {
  id: string;
  signature: ThreatSignature;
  detectedAt: Date;
  source: string;
  target?: string;
  confidence: number;
  evidence: ThreatEvidence[];
  blocked: boolean;
  mitigated: boolean;
}

export interface ThreatEvidence {
  type: 'REQUEST' | 'LOG_ENTRY' | 'NETWORK_TRAFFIC' | 'FILE_HASH' | 'BEHAVIOR_PATTERN';
  data: any;
  timestamp: Date;
}

export interface ThreatIntelligence {
  iocs: IndicatorOfCompromise[];
  lastUpdated: Date;
  source: string;
}

export interface IndicatorOfCompromise {
  type: 'IP' | 'DOMAIN' | 'URL' | 'HASH' | 'EMAIL';
  value: string;
  threat_types: ThreatType[];
  confidence: number;
  first_seen: Date;
  last_seen: Date;
}

export class ThreatDetector {
  private signatures: Map<string, ThreatSignature> = new Map();
  private detections: ThreatDetection[] = [];
  private intelligence: ThreatIntelligence[] = [];
  private monitoring: boolean = false;

  constructor() {
    this.initializeSignatures();
  }

  async initialize(): Promise<void> {
    try {
      await this.loadThreatIntelligence();
      this.startMonitoring();
    } catch (error) {
      throw new SecurityError(`Failed to initialize threat detector: ${(error as Error).message}`, 'INITIALIZATION_ERROR');
    }
  }

  async analyzeRequest(request: any): Promise<ThreatDetection[]> {
    const detections: ThreatDetection[] = [];

    try {
      // Check against known signatures
      for (const signature of this.signatures.values()) {
        if (await this.matchesSignature(request, signature)) {
          const detection = await this.createDetection(signature, request);
          detections.push(detection);

          // Auto-block high severity threats
          if (signature.severity === 'CRITICAL' || signature.severity === 'HIGH') {
            await this.blockThreat(detection);
          }
        }
      }

      // Check against threat intelligence
      const intelDetections = await this.checkThreatIntelligence(request);
      detections.push(...intelDetections);

      // Store detections
      this.detections.push(...detections);

      return detections;
    } catch (error) {
      throw new SecurityError(`Request analysis failed: ${(error as Error).message}`, 'ANALYSIS_ERROR');
    }
  }

  async analyzeBehavior(userId: string, actions: any[]): Promise<ThreatDetection[]> {
    const detections: ThreatDetection[] = [];

    try {
      // Analyze for suspicious patterns
      const bruteForceDetection = await this.detectBruteForce(userId, actions);
      if (bruteForceDetection) detections.push(bruteForceDetection);

      const privilegeEscalation = await this.detectPrivilegeEscalation(userId, actions);
      if (privilegeEscalation) detections.push(privilegeEscalation);

      const dataExfiltration = await this.detectDataExfiltration(userId, actions);
      if (dataExfiltration) detections.push(dataExfiltration);

      return detections;
    } catch (error) {
      throw new SecurityError(`Behavior analysis failed: ${(error as Error).message}`, 'BEHAVIOR_ANALYSIS_ERROR');
    }
  }

  async addSignature(signature: ThreatSignature): Promise<void> {
    this.signatures.set(signature.id, signature);
  }

  async getDetections(limit: number = 100): Promise<ThreatDetection[]> {
    return this.detections
      .sort((a, b) => b.detectedAt.getTime() - a.detectedAt.getTime())
      .slice(0, limit);
  }

  async getMetrics(): Promise<ThreatMetrics> {
    const now = new Date();
    const last24h = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    const recent = this.detections.filter(d => d.detectedAt >= last24h);
    const blocked = recent.filter(d => d.blocked).length;
    const critical = recent.filter(d => d.signature.severity === 'CRITICAL').length;

    return {
      totalDetections: this.detections.length,
      detectionsLast24h: recent.length,
      blockedLast24h: blocked,
      criticalLast24h: critical,
      topThreatTypes: this.getTopThreatTypes(recent),
      averageResponseTime: 0 // Would calculate from actual response times
    };
  }

  private async matchesSignature(request: any, signature: ThreatSignature): Promise<boolean> {
    try {
      switch (signature.type) {
        case ThreatType.SQL_INJECTION:
          return this.detectSqlInjection(request);

        case ThreatType.XSS:
          return this.detectXss(request);

        case ThreatType.MALWARE:
          return this.detectMalware(request);

        default:
          // Generic pattern matching
          if (signature.pattern instanceof RegExp) {
            return signature.pattern.test(JSON.stringify(request));
          }
          return JSON.stringify(request).includes(signature.pattern as string);
      }
    } catch (error) {
      return false;
    }
  }

  private detectSqlInjection(request: any): boolean {
    const sqlPatterns = [
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b.*\b(FROM|INTO|SET|WHERE|TABLE)\b)/i,
      /(\bunion\b.*\bselect\b)/i,
      /(\b(or|and)\b\s+\d+\s*=\s*\d+)/i,
      /(';|\b(exec|execute)\b)/i
    ];

    const requestStr = JSON.stringify(request).toLowerCase();
    return sqlPatterns.some(pattern => pattern.test(requestStr));
  }

  private detectXss(request: any): boolean {
    const xssPatterns = [
      /<script[^>]*>.*<\/script>/i,
      /javascript:/i,
      /on\w+\s*=/i,
      /<iframe[^>]*>/i,
      /eval\s*\(/i
    ];

    const requestStr = JSON.stringify(request);
    return xssPatterns.some(pattern => pattern.test(requestStr));
  }

  private detectMalware(request: any): boolean {
    // Simple malware indicators
    const malwarePatterns = [
      /\.exe\b/i,
      /\.bat\b/i,
      /cmd\.exe/i,
      /powershell/i,
      /base64/i
    ];

    const requestStr = JSON.stringify(request);
    return malwarePatterns.some(pattern => pattern.test(requestStr));
  }

  private async createDetection(signature: ThreatSignature, request: any): Promise<ThreatDetection> {
    return {
      id: `detection_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      signature,
      detectedAt: new Date(),
      source: request.source || 'unknown',
      target: request.target,
      confidence: 0.8, // Would calculate based on signature quality
      evidence: [
        {
          type: 'REQUEST',
          data: request,
          timestamp: new Date()
        }
      ],
      blocked: false,
      mitigated: false
    };
  }

  private async blockThreat(detection: ThreatDetection): Promise<void> {
    // Implementation would block the threat source
    console.log(`Blocking threat: ${detection.signature.name} from ${detection.source}`);
    detection.blocked = true;
  }

  private async checkThreatIntelligence(request: any): Promise<ThreatDetection[]> {
    const detections: ThreatDetection[] = [];

    for (const intel of this.intelligence) {
      for (const ioc of intel.iocs) {
        if (this.requestContainsIoc(request, ioc)) {
          // Create detection based on threat intel
          const signature: ThreatSignature = {
            id: `intel_${ioc.type}_${ioc.value}`,
            name: `Threat Intelligence: ${ioc.type}`,
            type: ioc.threat_types[0] || ThreatType.MALWARE,
            pattern: ioc.value,
            severity: ioc.confidence > 0.8 ? 'HIGH' : 'MEDIUM',
            description: `Known malicious ${ioc.type}`,
            mitigation: 'Block and investigate'
          };

          const detection = await this.createDetection(signature, request);
          detection.confidence = ioc.confidence;
          detections.push(detection);
        }
      }
    }

    return detections;
  }

  private requestContainsIoc(request: any, ioc: IndicatorOfCompromise): boolean {
    const requestStr = JSON.stringify(request);
    return requestStr.includes(ioc.value);
  }

  private async detectBruteForce(userId: string, actions: any[]): Promise<ThreatDetection | null> {
    // Count failed login attempts in the last 5 minutes
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
    const failedLogins = actions.filter(action =>
      action.type === 'login_failed' &&
      new Date(action.timestamp) >= fiveMinutesAgo
    );

    if (failedLogins.length >= 5) {
      const signature: ThreatSignature = {
        id: 'brute_force',
        name: 'Brute Force Attack',
        type: ThreatType.BRUTE_FORCE,
        pattern: 'multiple_failed_logins',
        severity: 'HIGH',
        description: 'Multiple failed login attempts detected',
        mitigation: 'Lock account and require additional authentication'
      };

      return await this.createDetection(signature, { userId, actions: failedLogins });
    }

    return null;
  }

  private async detectPrivilegeEscalation(userId: string, actions: any[]): Promise<ThreatDetection | null> {
    // Look for unauthorized access to privileged resources
    const privilegedActions = actions.filter(action =>
      action.type === 'access_denied' &&
      action.resource?.includes('admin')
    );

    if (privilegedActions.length >= 3) {
      const signature: ThreatSignature = {
        id: 'privilege_escalation',
        name: 'Privilege Escalation Attempt',
        type: ThreatType.PRIVILEGE_ESCALATION,
        pattern: 'unauthorized_privileged_access',
        severity: 'HIGH',
        description: 'Attempted access to privileged resources',
        mitigation: 'Review user permissions and investigate'
      };

      return await this.createDetection(signature, { userId, actions: privilegedActions });
    }

    return null;
  }

  private async detectDataExfiltration(userId: string, actions: any[]): Promise<ThreatDetection | null> {
    // Look for large data downloads or exports
    const dataActions = actions.filter(action =>
      action.type === 'data_export' || action.type === 'bulk_download'
    );

    const totalSize = dataActions.reduce((sum, action) => sum + (action.size || 0), 0);

    if (totalSize > 100 * 1024 * 1024) { // 100MB threshold
      const signature: ThreatSignature = {
        id: 'data_exfiltration',
        name: 'Data Exfiltration',
        type: ThreatType.DATA_EXFILTRATION,
        pattern: 'large_data_export',
        severity: 'CRITICAL',
        description: 'Large volume of data exported',
        mitigation: 'Immediately investigate and potentially block user'
      };

      return await this.createDetection(signature, { userId, actions: dataActions, totalSize });
    }

    return null;
  }

  private async loadThreatIntelligence(): Promise<void> {
    // In real implementation, this would fetch from threat intel feeds
    console.log('Loading threat intelligence feeds...');
  }

  private startMonitoring(): void {
    this.monitoring = true;
    console.log('Threat monitoring started');
  }

  private getTopThreatTypes(detections: ThreatDetection[]): Array<{ type: ThreatType; count: number }> {
    const counts = new Map<ThreatType, number>();

    detections.forEach(d => {
      const current = counts.get(d.signature.type) || 0;
      counts.set(d.signature.type, current + 1);
    });

    return Array.from(counts.entries())
      .map(([type, count]) => ({ type, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }

  private initializeSignatures(): void {
    // Add default signatures
    const sqlInjectionSignature: ThreatSignature = {
      id: 'sql_injection_basic',
      name: 'SQL Injection',
      type: ThreatType.SQL_INJECTION,
      pattern: /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b.*\b(FROM|INTO|SET|WHERE|TABLE)\b)/i,
      severity: 'HIGH',
      description: 'SQL injection attempt detected',
      mitigation: 'Sanitize input and use parameterized queries'
    };

    this.signatures.set(sqlInjectionSignature.id, sqlInjectionSignature);
  }
}

export interface ThreatMetrics {
  totalDetections: number;
  detectionsLast24h: number;
  blockedLast24h: number;
  criticalLast24h: number;
  topThreatTypes: Array<{ type: ThreatType; count: number }>;
  averageResponseTime: number;
}