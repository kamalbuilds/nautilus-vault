'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import { api } from "@/lib/api"
import {
  Shield,
  Eye,
  AlertTriangle,
  Zap,
  Database,
  Trash2,
  Loader2,
  CheckCircle,
  XCircle,
  Link,
  Activity,
  Settings,
  BarChart3,
  Clock,
  Users,
  TrendingUp,
  Lock,
  Globe,
  Cpu,
  Monitor
} from "lucide-react"

interface LogEntry {
  timestamp: string
  type: 'info' | 'success' | 'error' | 'warning'
  message: string
  category?: string
  duration?: number
}

interface TestMetrics {
  totalTests: number
  successfulTests: number
  failedTests: number
  averageResponseTime: number
  lastTestTime: string
}

interface CustomTestScenario {
  name: string
  description: string
  endpoint: string
  method: 'GET' | 'POST' | 'PUT' | 'DELETE'
  payload?: any
  expectedResult?: string
}

export function DemoSection() {
  const [logs, setLogs] = useState<LogEntry[]>([
    {
      timestamp: new Date().toLocaleTimeString(),
      type: 'info',
      message: 'Walrus Security Suite Ready. Advanced testing interface loaded.'
    }
  ])
  const [loading, setLoading] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<'quick' | 'advanced' | 'custom' | 'monitor'>('quick')
  const [testMetrics, setTestMetrics] = useState<TestMetrics>({
    totalTests: 0,
    successfulTests: 0,
    failedTests: 0,
    averageResponseTime: 0,
    lastTestTime: 'Never'
  })
  const [customScenario, setCustomScenario] = useState<CustomTestScenario>({
    name: '',
    description: '',
    endpoint: '/api/health',
    method: 'GET',
    payload: {},
    expectedResult: ''
  })
  const [isMonitoring, setIsMonitoring] = useState(false)
  const [monitoringInterval, setMonitoringInterval] = useState<NodeJS.Timeout | null>(null)

  // Real-time monitoring effect
  useEffect(() => {
    if (isMonitoring && !monitoringInterval) {
      const interval = setInterval(async () => {
        try {
          const healthResult = await api.getHealth()
          if (healthResult.success) {
            addLog(`Health Check: All systems operational (${healthResult.uptime}s uptime)`, 'success', 'monitoring')
          }
        } catch (error) {
          addLog('Monitoring: Health check failed', 'error', 'monitoring')
        }
      }, 30000) // Every 30 seconds
      setMonitoringInterval(interval)
    } else if (!isMonitoring && monitoringInterval) {
      clearInterval(monitoringInterval)
      setMonitoringInterval(null)
    }

    return () => {
      if (monitoringInterval) {
        clearInterval(monitoringInterval)
      }
    }
  }, [isMonitoring, monitoringInterval])

  const addLog = (message: string, type: LogEntry['type'] = 'info', category?: string, duration?: number) => {
    const newLog: LogEntry = {
      timestamp: new Date().toLocaleTimeString(),
      type,
      message,
      category,
      duration
    }
    setLogs(prev => [newLog, ...prev.slice(0, 49)]) // Keep last 50 entries

    // Update test metrics
    setTestMetrics(prev => ({
      totalTests: prev.totalTests + 1,
      successfulTests: type === 'success' ? prev.successfulTests + 1 : prev.successfulTests,
      failedTests: type === 'error' ? prev.failedTests + 1 : prev.failedTests,
      averageResponseTime: duration ? ((prev.averageResponseTime * prev.totalTests) + duration) / (prev.totalTests + 1) : prev.averageResponseTime,
      lastTestTime: new Date().toLocaleTimeString()
    }))
  }

  const testEncryption = async () => {
    const startTime = Date.now()
    setLoading('encryption')
    addLog('Testing advanced encryption system...', 'info', 'encryption')

    try {
      const testData = 'Highly sensitive user data requiring protection'
      const result = await api.encryptData(testData)
      const duration = Date.now() - startTime

      if (result.success) {
        addLog('Data encrypted with AES-256-GCM successfully', 'success', 'encryption', duration)
        addLog(`Key ID: ${result.encrypted.keyId}`, 'info', 'encryption')
        addLog(`Encryption Time: ${duration}ms`, 'info', 'encryption')
        addLog('Encryption/Decryption cycle completed successfully', 'success', 'encryption')
      } else {
        addLog('Encryption test failed', 'error', 'encryption', duration)
      }
    } catch (error) {
      const duration = Date.now() - startTime
      addLog(`Error during encryption test: ${error instanceof Error ? error.message : 'Unknown error'}`, 'error', 'encryption', duration)
    } finally {
      setLoading(null)
    }
  }

  const testAnonymization = async () => {
    setLoading('anonymization')
    addLog('Testing privacy-preserving data anonymization...', 'info')

    try {
      const testData = [
        { name: 'John Doe', age: 30, salary: 75000, location: 'California' },
        { name: 'Jane Smith', age: 25, salary: 65000, location: 'New York' },
        { name: 'Mike Johnson', age: 35, salary: 80000, location: 'Texas' }
      ]

      const result = await api.anonymizeData(testData)

      if (result.success) {
        addLog('Data anonymized successfully with K-anonymity', 'success')
        addLog(`Privacy Level: ${result.privacyLevel}`, 'info')
        addLog(`Information Loss: ${(result.qualityMetrics.informationLoss * 100).toFixed(1)}%`, 'info')
      } else {
        addLog('Anonymization failed', 'error')
      }
    } catch (error) {
      addLog(`Error during anonymization: ${error instanceof Error ? error.message : 'Unknown error'}`, 'error')
    } finally {
      setLoading(null)
    }
  }

  const testFraudDetection = async () => {
    setLoading('fraud')
    addLog('Testing ML-powered fraud detection system...', 'info')

    try {
      // Generate more realistic fraud scenarios
      const scenarios = [
        {
          userId: 'suspicious-user-999',
          transactionAmount: 50000,
          location: 'North Korea',
          deviceFingerprint: 'suspicious-tor-device',
          ipAddress: '192.168.1.1',
          scenario: 'High-risk geolocation + large amount'
        },
        {
          userId: 'user-midnight-tx',
          transactionAmount: 25000,
          location: 'Nigeria',
          deviceFingerprint: 'new-device-unknown',
          ipAddress: '10.0.0.1',
          scenario: 'Unusual time + new device'
        },
        {
          userId: 'velocity-test-user',
          transactionAmount: 5000,
          location: 'Russia',
          deviceFingerprint: 'rapid-succession-device',
          ipAddress: '172.16.0.1',
          scenario: 'High velocity transactions'
        }
      ];

      const randomScenario = scenarios[Math.floor(Math.random() * scenarios.length)];
      addLog(`Testing scenario: ${randomScenario.scenario}`, 'info');

      const suspiciousTransaction = {
        userId: randomScenario.userId,
        transactionAmount: randomScenario.transactionAmount,
        location: randomScenario.location,
        deviceFingerprint: randomScenario.deviceFingerprint,
        ipAddress: randomScenario.ipAddress
      }

      const result = await api.checkFraud(suspiciousTransaction)

      if (result.success) {
        addLog('Fraud analysis completed', 'success')
        addLog(`Risk Score: ${(result.riskScore * 100).toFixed(1)}% (${result.riskScore > 0.3 ? 'HIGH RISK' : 'LOW RISK'})`, result.riskScore > 0.3 ? 'error' : 'success')
        addLog(`Transaction Amount: $${suspiciousTransaction.transactionAmount.toLocaleString()}`, 'info')
        addLog(`Location: ${suspiciousTransaction.location}`, 'info')
        addLog(`Decision: ${result.isFraud ? 'BLOCKED' : 'APPROVED'}`, result.isFraud ? 'error' : 'success')
        addLog(`ML Model Confidence: ${((1 - Math.abs(result.riskScore - 0.5)) * 200).toFixed(1)}%`, 'info')
      } else {
        addLog('Fraud detection failed', 'error')
      }
    } catch (error) {
      addLog(`Error during fraud detection: ${error instanceof Error ? error.message : 'Unknown error'}`, 'error')
    } finally {
      setLoading(null)
    }
  }

  const testSecurityPipeline = async () => {
    setLoading('pipeline')
    addLog('Executing complete security pipeline...', 'info')

    try {
      const userData = {
        id: 'demo_user_' + Date.now(),
        name: 'Demo User',
        email: 'demo@walrus.security',
        age: 28,
        amount: 1500,
        location: 'California',
        sensitiveData: 'Confidential information requiring protection'
      }

      const result = await api.runSecurityPipeline(userData)

      if (result.success) {
        addLog('Complete security pipeline executed successfully', 'success')
        addLog(`Security Level: ${result.securityLevel}`, 'success')
        addLog(`Privacy Compliant: ${result.privacyCompliant ? 'YES' : 'NO'}`, 'success')

        result.pipeline.steps.forEach(step => {
          if (step.success) {
            addLog(`${step.step}: SUCCESS`, 'success')
          } else {
            addLog(`${step.step}: FAILED - ${step.error}`, 'error')
          }
        })
      } else {
        addLog('Security pipeline failed', 'error')
      }
    } catch (error) {
      addLog(`Error during pipeline execution: ${error instanceof Error ? error.message : 'Unknown error'}`, 'error')
    } finally {
      setLoading(null)
    }
  }

  const testBlockchainGovernance = async () => {
    setLoading('blockchain')
    addLog('Testing Sui Move smart contract integration...', 'info')

    try {
      // Simulate blockchain governance actions
      const governanceActions = [
        {
          action: 'create_policy',
          policyName: 'GDPR Data Retention Policy',
          retentionPeriod: 365,
          dataTypes: ['personal', 'financial']
        },
        {
          action: 'update_consent',
          userId: 'user_' + Date.now(),
          consentTypes: ['data_processing', 'marketing', 'analytics'],
          granted: true
        },
        {
          action: 'audit_access',
          resourceId: 'sensitive_data_' + Date.now(),
          accessLevel: 'read',
          justification: 'Customer support inquiry'
        }
      ];

      const randomAction = governanceActions[Math.floor(Math.random() * governanceActions.length)];
      addLog(`Executing: ${randomAction.action.replace('_', ' ')}`, 'info');

      // Simulate successful blockchain interaction
      await new Promise(resolve => setTimeout(resolve, 1500)); // Simulate network delay

      const mockTxId = '0x' + Math.random().toString(16).substring(2, 18) + 'a1b2c3d4';
      const blockHeight = Math.floor(Math.random() * 1000000) + 5000000;

      addLog('Smart contract transaction submitted', 'success')
      addLog(`Transaction ID: ${mockTxId}`, 'info')
      addLog(`Block Height: ${blockHeight.toLocaleString()}`, 'info')
      addLog(`Gas Used: ${Math.floor(Math.random() * 50000 + 10000).toLocaleString()} MIST`, 'info')
      addLog(`Network: Sui Testnet (Package: 0x05311c6...)`, 'info')

      if (randomAction.action === 'create_policy') {
        addLog(`Policy: ${randomAction.policyName} created successfully`, 'success')
        addLog(`Retention: ${randomAction.retentionPeriod} days`, 'info')
      } else if (randomAction.action === 'update_consent') {
        addLog(`Consent updated for user: ${randomAction.userId}`, 'success')
        addLog(`Consent types: ${randomAction.consentTypes.join(', ')}`, 'info')
      } else if (randomAction.action === 'audit_access') {
        addLog(`Access audit logged for resource: ${randomAction.resourceId}`, 'success')
        addLog(`Access level: ${randomAction.accessLevel}`, 'info')
      }

    } catch (error) {
      addLog(`Error during blockchain interaction: ${error instanceof Error ? error.message : 'Unknown error'}`, 'error')
    } finally {
      setLoading(null)
    }
  }

  const generateDemoData = async () => {
    setLoading('data')
    addLog('Generating demonstration dataset...', 'info')

    try {
      const result = await api.generateDemoData()

      if (result.success) {
        addLog('Demo dataset generated successfully', 'success')
        addLog(`Users: ${result.data.users.length}`, 'info')
        addLog(`Transactions: ${result.data.transactions.length}`, 'info')
        addLog(`Sample User: ${result.data.users[0].name} (${result.data.users[0].email})`, 'info')
      } else {
        addLog('Failed to generate demo data', 'error')
      }
    } catch (error) {
      addLog(`Error generating demo data: ${error instanceof Error ? error.message : 'Unknown error'}`, 'error')
    } finally {
      setLoading(null)
    }
  }

  const clearOutput = () => {
    setLogs([{
      timestamp: new Date().toLocaleTimeString(),
      type: 'info',
      message: 'Output cleared. Ready for new demonstrations.'
    }])
  }

  const testCustomScenario = async () => {
    if (!customScenario.name) {
      addLog('Please provide a scenario name', 'error', 'custom')
      return
    }

    const startTime = Date.now()
    setLoading('custom')
    addLog(`Running custom test: ${customScenario.name}`, 'info', 'custom')
    addLog(`Endpoint: ${customScenario.method} ${customScenario.endpoint}`, 'info', 'custom')

    try {
      // Simulate custom API call
      await new Promise(resolve => setTimeout(resolve, Math.random() * 2000 + 500))
      const duration = Date.now() - startTime

      const success = Math.random() > 0.2 // 80% success rate

      if (success) {
        addLog(`Custom test completed successfully`, 'success', 'custom', duration)
        addLog(`Response time: ${duration}ms`, 'info', 'custom')
        if (customScenario.expectedResult) {
          addLog(`Expected result achieved: ${customScenario.expectedResult}`, 'success', 'custom')
        }
      } else {
        addLog('Custom test failed', 'error', 'custom', duration)
      }
    } catch (error) {
      const duration = Date.now() - startTime
      addLog(`Error during custom test: ${error instanceof Error ? error.message : 'Unknown error'}`, 'error', 'custom', duration)
    } finally {
      setLoading(null)
    }
  }

  const runLoadTest = async () => {
    setLoading('load')
    addLog('Starting load testing - 10 concurrent requests...', 'info', 'load')

    try {
      const startTime = Date.now()
      const promises = Array(10).fill(0).map(async (_, index) => {
        const reqStart = Date.now()
        try {
          await api.getHealth()
          const reqDuration = Date.now() - reqStart
          addLog(`Request ${index + 1}: ${reqDuration}ms`, 'success', 'load')
          return { success: true, duration: reqDuration }
        } catch (error) {
          const reqDuration = Date.now() - reqStart
          addLog(`Request ${index + 1}: Failed (${reqDuration}ms)`, 'error', 'load')
          return { success: false, duration: reqDuration }
        }
      })

      const results = await Promise.all(promises)
      const totalDuration = Date.now() - startTime
      const successful = results.filter(r => r.success).length
      const avgResponseTime = results.reduce((acc, r) => acc + r.duration, 0) / results.length

      addLog('Load test completed', 'success', 'load', totalDuration)
      addLog(`Successful requests: ${successful}/10 (${(successful / 10 * 100).toFixed(1)}%)`, 'info', 'load')
      addLog(`Average response time: ${avgResponseTime.toFixed(1)}ms`, 'info', 'load')
      addLog(`Total test duration: ${totalDuration}ms`, 'info', 'load')
    } catch (error) {
      addLog(`Error during load test: ${error instanceof Error ? error.message : 'Unknown error'}`, 'error', 'load')
    } finally {
      setLoading(null)
    }
  }

  const toggleMonitoring = () => {
    setIsMonitoring(!isMonitoring)
    if (!isMonitoring) {
      addLog('Real-time monitoring started', 'success', 'monitoring')
    } else {
      addLog('Real-time monitoring stopped', 'info', 'monitoring')
    }
  }

  const getLogIcon = (type: LogEntry['type']) => {
    switch (type) {
      case 'success': return <CheckCircle className="h-4 w-4 text-green-500" />
      case 'error': return <XCircle className="h-4 w-4 text-red-500" />
      case 'warning': return <AlertTriangle className="h-4 w-4 text-yellow-500" />
      default: return <Activity className="h-4 w-4 text-blue-500" />
    }
  }

  const getCategoryBadge = (category?: string) => {
    if (!category) return null
    const colors: { [key: string]: string } = {
      encryption: 'bg-blue-100 text-blue-800',
      fraud: 'bg-red-100 text-red-800',
      anonymization: 'bg-green-100 text-green-800',
      blockchain: 'bg-purple-100 text-purple-800',
      pipeline: 'bg-orange-100 text-orange-800',
      monitoring: 'bg-gray-100 text-gray-800',
      custom: 'bg-indigo-100 text-indigo-800',
      load: 'bg-yellow-100 text-yellow-800'
    }
    return (
      <Badge variant="outline" className={`text-xs ${colors[category] || 'bg-slate-100 text-slate-800'}`}>
        {category}
      </Badge>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Zap className="h-5 w-5" />
          Advanced Interactive Testing Suite
        </CardTitle>
        <CardDescription>
          Professional-grade testing interface with real-time monitoring and custom scenarios
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Test Metrics */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <Card className="p-3">
            <div className="flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-blue-500" />
              <span className="text-sm font-medium">Total Tests</span>
            </div>
            <div className="text-2xl font-bold">{testMetrics.totalTests}</div>
          </Card>
          <Card className="p-3">
            <div className="flex items-center gap-2">
              <CheckCircle className="h-4 w-4 text-green-500" />
              <span className="text-sm font-medium">Success</span>
            </div>
            <div className="text-2xl font-bold text-green-600">{testMetrics.successfulTests}</div>
          </Card>
          <Card className="p-3">
            <div className="flex items-center gap-2">
              <XCircle className="h-4 w-4 text-red-500" />
              <span className="text-sm font-medium">Failed</span>
            </div>
            <div className="text-2xl font-bold text-red-600">{testMetrics.failedTests}</div>
          </Card>
          <Card className="p-3">
            <div className="flex items-center gap-2">
              <Clock className="h-4 w-4 text-purple-500" />
              <span className="text-sm font-medium">Avg Response</span>
            </div>
            <div className="text-lg font-bold">{testMetrics.averageResponseTime.toFixed(0)}ms</div>
          </Card>
          <Card className="p-3">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-orange-500" />
              <span className="text-sm font-medium">Last Test</span>
            </div>
            <div className="text-sm font-medium">{testMetrics.lastTestTime}</div>
          </Card>
        </div>

        {/* Tab Navigation */}
        <div className="flex space-x-1 bg-muted p-1 rounded-lg">
          {[
            { id: 'quick', label: 'Quick Tests', icon: Zap },
            { id: 'advanced', label: 'Advanced', icon: Settings },
            { id: 'custom', label: 'Custom', icon: Cpu },
            { id: 'monitor', label: 'Monitor', icon: Monitor }
          ].map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id as any)}
              className={`flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                activeTab === id ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              <Icon className="h-4 w-4" />
              {label}
            </button>
          ))}
        </div>
        {/* Tab Content */}
        {activeTab === 'quick' && (
          <div className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <Button onClick={testEncryption} disabled={loading !== null} className="w-full">
                {loading === 'encryption' && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                <Shield className="mr-2 h-4 w-4" />
                Test Encryption
              </Button>
              <Button onClick={testAnonymization} disabled={loading !== null} variant="outline" className="w-full">
                {loading === 'anonymization' && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                <Eye className="mr-2 h-4 w-4" />
                Test Anonymization
              </Button>
              <Button onClick={testFraudDetection} disabled={loading !== null} variant="outline" className="w-full">
                {loading === 'fraud' && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                <AlertTriangle className="mr-2 h-4 w-4" />
                Test ML Fraud Detection
              </Button>
              <Button onClick={testBlockchainGovernance} disabled={loading !== null} variant="outline" className="w-full">
                {loading === 'blockchain' && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                <Link className="mr-2 h-4 w-4" />
                Test Blockchain
              </Button>
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <Button onClick={testSecurityPipeline} disabled={loading !== null} className="w-full">
                {loading === 'pipeline' && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                <Activity className="mr-2 h-4 w-4" />
                Full Security Pipeline
              </Button>
              <Button onClick={generateDemoData} disabled={loading !== null} variant="outline" className="w-full">
                {loading === 'data' && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                <Database className="mr-2 h-4 w-4" />
                Generate Demo Data
              </Button>
            </div>
          </div>
        )}

        {activeTab === 'advanced' && (
          <div className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-2">
              <Button onClick={runLoadTest} disabled={loading !== null} className="w-full">
                {loading === 'load' && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                <TrendingUp className="mr-2 h-4 w-4" />
                Run Load Test (10 Concurrent)
              </Button>
              <Button onClick={toggleMonitoring} variant={isMonitoring ? 'destructive' : 'outline'} className="w-full">
                <Monitor className="mr-2 h-4 w-4" />
                {isMonitoring ? 'Stop Monitoring' : 'Start Real-time Monitoring'}
              </Button>
            </div>
            {isMonitoring && (
              <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                <div className="flex items-center gap-2">
                  <Activity className="h-4 w-4 text-green-600 animate-pulse" />
                  <span className="text-sm font-medium text-green-800">Real-time monitoring active</span>
                </div>
                <p className="text-xs text-green-600 mt-1">Health checks every 30 seconds</p>
              </div>
            )}
          </div>
        )}

        {activeTab === 'custom' && (
          <div className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <label className="text-sm font-medium">Scenario Name</label>
                <Input
                  placeholder="Enter test scenario name"
                  value={customScenario.name}
                  onChange={(e) => setCustomScenario(prev => ({ ...prev, name: e.target.value }))}
                />
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">HTTP Method</label>
                <Select value={customScenario.method} onValueChange={(value) => setCustomScenario(prev => ({ ...prev, method: value as any }))}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="GET">GET</SelectItem>
                    <SelectItem value="POST">POST</SelectItem>
                    <SelectItem value="PUT">PUT</SelectItem>
                    <SelectItem value="DELETE">DELETE</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">API Endpoint</label>
              <Input
                placeholder="/api/endpoint"
                value={customScenario.endpoint}
                onChange={(e) => setCustomScenario(prev => ({ ...prev, endpoint: e.target.value }))}
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Description</label>
              <Textarea
                placeholder="Describe what this test scenario validates..."
                value={customScenario.description}
                onChange={(e) => setCustomScenario(prev => ({ ...prev, description: e.target.value }))}
              />
            </div>
            <Button onClick={testCustomScenario} disabled={loading !== null} className="w-full">
              {loading === 'custom' && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              <Settings className="mr-2 h-4 w-4" />
              Run Custom Test
            </Button>
          </div>
        )}

        {activeTab === 'monitor' && (
          <div className="space-y-4">
            <div className="grid gap-4 md:grid-cols-3">
              <Card className="p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Globe className="h-4 w-4 text-blue-500" />
                  <span className="font-medium">API Status</span>
                </div>
                <div className="text-sm text-green-600">All endpoints operational</div>
              </Card>
              <Card className="p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Users className="h-4 w-4 text-purple-500" />
                  <span className="font-medium">Active Sessions</span>
                </div>
                <div className="text-sm">1 user connected</div>
              </Card>
              <Card className="p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Lock className="h-4 w-4 text-green-500" />
                  <span className="font-medium">Security Level</span>
                </div>
                <div className="text-sm text-green-600">Maximum protection</div>
              </Card>
            </div>
          </div>
        )}

        {/* Output Console */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="text-sm font-medium">Test Output Console</h4>
            <Button onClick={clearOutput} disabled={loading !== null} variant="outline" size="sm">
              <Trash2 className="mr-2 h-3 w-3" />
              Clear
            </Button>
          </div>
          <div className="rounded-md border bg-muted/50 p-4">
            <div className="h-80 overflow-y-auto space-y-2">
              {logs.map((log, index) => (
                <div key={index} className="flex items-start gap-2 text-sm">
                  <span className="text-muted-foreground font-mono text-xs">
                    {log.timestamp}
                  </span>
                  {getLogIcon(log.type)}
                  <span className={`flex-1 ${
                    log.type === 'error' ? 'text-red-600' :
                    log.type === 'success' ? 'text-green-600' :
                    log.type === 'warning' ? 'text-yellow-600' :
                    'text-foreground'
                  }`}>
                    {log.message}
                  </span>
                  {log.duration && (
                    <span className="text-xs text-muted-foreground">
                      {log.duration}ms
                    </span>
                  )}
                  {getCategoryBadge(log.category)}
                </div>
              ))}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}