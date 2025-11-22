/**
 * Data Portability - GDPR Article 20 compliance for data portability rights
 */

import { PrivacyError } from '../types';

export interface DataExportRequest {
  id: string;
  dataSubjectId: string;
  requestedData: string[];
  format: 'JSON' | 'CSV' | 'XML' | 'PDF';
  includeMetadata: boolean;
  dateRange?: {
    from: Date;
    to: Date;
  };
  requestedAt: Date;
  status: 'PENDING' | 'PROCESSING' | 'READY' | 'DELIVERED' | 'EXPIRED';
}

export interface DataExportResult {
  requestId: string;
  data: any;
  format: string;
  size: number;
  checksum: string;
  expiresAt: Date;
  downloadUrl?: string;
}

export class DataPortability {
  private exportRequests: Map<string, DataExportRequest> = new Map();

  async requestDataExport(
    dataSubjectId: string,
    requestedData: string[],
    format: 'JSON' | 'CSV' | 'XML' | 'PDF' = 'JSON',
    options?: {
      includeMetadata?: boolean;
      dateRange?: { from: Date; to: Date };
    }
  ): Promise<string> {
    try {
      const request: DataExportRequest = {
        id: `export_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        dataSubjectId,
        requestedData,
        format,
        includeMetadata: options?.includeMetadata || false,
        dateRange: options?.dateRange,
        requestedAt: new Date(),
        status: 'PENDING'
      };

      this.exportRequests.set(request.id, request);

      // Schedule processing
      this.processExportRequest(request.id);

      return request.id;
    } catch (error) {
      throw new PrivacyError(`Failed to request data export: ${(error as Error).message}`, 'EXPORT_REQUEST_ERROR');
    }
  }

  async getExportStatus(requestId: string): Promise<DataExportRequest> {
    const request = this.exportRequests.get(requestId);
    if (!request) {
      throw new PrivacyError(`Export request not found: ${requestId}`, 'REQUEST_NOT_FOUND');
    }
    return request;
  }

  async downloadExport(requestId: string): Promise<DataExportResult> {
    try {
      const request = this.exportRequests.get(requestId);
      if (!request) {
        throw new PrivacyError(`Export request not found: ${requestId}`, 'REQUEST_NOT_FOUND');
      }

      if (request.status !== 'READY') {
        throw new PrivacyError(`Export not ready. Status: ${request.status}`, 'EXPORT_NOT_READY');
      }

      // Generate export data
      const exportData = await this.generateExportData(request);

      // Update status
      request.status = 'DELIVERED';
      this.exportRequests.set(requestId, request);

      return exportData;
    } catch (error) {
      throw new PrivacyError(`Failed to download export: ${(error as Error).message}`, 'DOWNLOAD_ERROR');
    }
  }

  private async processExportRequest(requestId: string): Promise<void> {
    const request = this.exportRequests.get(requestId);
    if (!request) return;

    try {
      // Update status to processing
      request.status = 'PROCESSING';
      this.exportRequests.set(requestId, request);

      // Simulate processing time
      await new Promise(resolve => setTimeout(resolve, 2000));

      // Mark as ready
      request.status = 'READY';
      this.exportRequests.set(requestId, request);

      // Schedule expiration (30 days)
      setTimeout(() => {
        const req = this.exportRequests.get(requestId);
        if (req && req.status !== 'DELIVERED') {
          req.status = 'EXPIRED';
          this.exportRequests.set(requestId, req);
        }
      }, 30 * 24 * 60 * 60 * 1000);

    } catch (error) {
      request.status = 'PENDING'; // Reset to allow retry
      this.exportRequests.set(requestId, request);
    }
  }

  private async generateExportData(request: DataExportRequest): Promise<DataExportResult> {
    // Mock data generation - in real implementation, this would fetch actual user data
    const mockData = {
      dataSubjectId: request.dataSubjectId,
      exportedAt: new Date().toISOString(),
      requestedData: request.requestedData,
      data: {
        profile: { id: request.dataSubjectId, name: 'Mock User' },
        preferences: { theme: 'dark', notifications: true },
        activity: []
      }
    };

    const serializedData = this.serializeData(mockData, request.format);
    const checksum = require('crypto').createHash('sha256').update(serializedData).digest('hex');

    return {
      requestId: request.id,
      data: serializedData,
      format: request.format,
      size: Buffer.byteLength(serializedData, 'utf8'),
      checksum,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days
    };
  }

  private serializeData(data: any, format: string): string {
    switch (format) {
      case 'JSON':
        return JSON.stringify(data, null, 2);

      case 'CSV':
        return this.convertToCSV(data);

      case 'XML':
        return this.convertToXML(data);

      case 'PDF':
        return 'PDF generation not implemented in mock';

      default:
        return JSON.stringify(data, null, 2);
    }
  }

  private convertToCSV(data: any): string {
    // Simple CSV conversion
    const headers = Object.keys(data);
    const values = headers.map(h => JSON.stringify(data[h]));
    return [headers.join(','), values.join(',')].join('\n');
  }

  private convertToXML(data: any): string {
    // Simple XML conversion
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<export>\n';
    Object.entries(data).forEach(([key, value]) => {
      xml += `  <${key}>${JSON.stringify(value)}</${key}>\n`;
    });
    xml += '</export>';
    return xml;
  }
}