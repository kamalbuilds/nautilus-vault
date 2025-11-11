const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000'

export interface ApiResponse<T = any> {
  success: boolean
  data?: T
  error?: string
  message?: string
}

export interface SystemMetrics {
  requests: number
  dataProcessed: number
  threatsBlocked: number
  privacyScore: number
  uptime: number
}

export interface MetricsResponse {
  metrics: SystemMetrics
  performance: {
    requestsPerSecond: number
    threatDetectionRate: string
    dataProtectionLevel: string
  }
  timestamp: string
}

export interface EncryptionResponse {
  success: boolean
  encrypted: {
    ciphertext: string
    algorithm: string
    keyId: string
    iv: string
    tag: string
    metadata: {
      timestamp: number
      version: string
    }
  }
  message: string
}

export interface FraudCheckResponse {
  success: boolean
  riskScore: number
  isFraud: boolean
  status: string
  message: string
}

export interface SecurityPipelineResponse {
  success: boolean
  pipeline: {
    originalData: any
    steps: Array<{
      step: string
      success: boolean
      result?: string
      privacyLevel?: string
      qualityMetrics?: any
      riskScore?: number
      status?: string
      error?: string
    }>
    encrypted: boolean
    anonymized: any
  }
  message: string
  privacyCompliant: boolean
  securityLevel: string
}

class ApiClient {
  private baseUrl: string

  constructor(baseUrl: string = API_BASE_URL) {
    this.baseUrl = baseUrl
  }

  private async request<T = any>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`

    const config: RequestInit = {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      ...options,
    }

    try {
      const response = await fetch(url, config)

      if (!response.ok) {
        throw new Error(`API request failed: ${response.status} ${response.statusText}`)
      }

      return await response.json()
    } catch (error) {
      console.error('API request failed:', error)
      throw error
    }
  }

  async getHealth(): Promise<any> {
    return this.request('/health')
  }

  async getMetrics(): Promise<MetricsResponse> {
    return this.request('/metrics')
  }

  async encryptData(data: string): Promise<EncryptionResponse> {
    return this.request('/api/encrypt', {
      method: 'POST',
      body: JSON.stringify({ data }),
    })
  }

  async decryptData(encryptedData: any): Promise<any> {
    return this.request('/api/decrypt', {
      method: 'POST',
      body: JSON.stringify({ encryptedData }),
    })
  }

  async checkFraud(transactionData: any): Promise<FraudCheckResponse> {
    return this.request('/api/fraud-check', {
      method: 'POST',
      body: JSON.stringify(transactionData),
    })
  }

  async anonymizeData(data: any[]): Promise<any> {
    return this.request('/api/anonymize', {
      method: 'POST',
      body: JSON.stringify({ data }),
    })
  }

  async runSecurityPipeline(userData: any): Promise<SecurityPipelineResponse> {
    return this.request('/api/demo/security-pipeline', {
      method: 'POST',
      body: JSON.stringify({ userData }),
    })
  }

  async generateDemoData(): Promise<any> {
    return this.request('/api/demo/data')
  }

  async createConsent(dataSubjectId: string, purposes: string[]): Promise<any> {
    return this.request('/api/consent/create', {
      method: 'POST',
      body: JSON.stringify({ dataSubjectId, purposes }),
    })
  }
}

export const api = new ApiClient()
export default api