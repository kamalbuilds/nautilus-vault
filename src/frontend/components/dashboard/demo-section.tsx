'use client'

import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
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
  XCircle
} from "lucide-react"

interface LogEntry {
  timestamp: string
  type: 'info' | 'success' | 'error'
  message: string
}

export function DemoSection() {
  const [logs, setLogs] = useState<LogEntry[]>([
    {
      timestamp: new Date().toLocaleTimeString(),
      type: 'info',
      message: 'Walrus Security Suite Ready. Click any button above to test security features in real-time.'
    }
  ])
  const [loading, setLoading] = useState<string | null>(null)

  const addLog = (message: string, type: LogEntry['type'] = 'info') => {
    const newLog: LogEntry = {
      timestamp: new Date().toLocaleTimeString(),
      type,
      message
    }
    setLogs(prev => [newLog, ...prev.slice(0, 19)]) // Keep last 20 entries
  }

  const testEncryption = async () => {
    setLoading('encryption')
    addLog('Testing advanced encryption system...', 'info')

    try {
      const testData = 'Highly sensitive user data requiring protection'
      const result = await api.encryptData(testData)

      if (result.success) {
        addLog('Data encrypted with AES-256-GCM successfully', 'success')
        addLog(`Key ID: ${result.encrypted.keyId}`, 'info')
        addLog('Encryption/Decryption cycle completed successfully', 'success')
      } else {
        addLog('Encryption test failed', 'error')
      }
    } catch (error) {
      addLog(`Error during encryption test: ${error instanceof Error ? error.message : 'Unknown error'}`, 'error')
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
      const suspiciousTransaction = {
        userId: 'user_123',
        amount: 8500,
        merchant: 'Suspicious Electronics',
        location: 'Unknown',
        timestamp: Date.now()
      }

      const result = await api.checkFraud(suspiciousTransaction)

      if (result.success) {
        addLog('Fraud analysis completed', 'success')
        addLog(`Risk Score: ${(result.riskScore * 100).toFixed(1)}%`, 'info')
        addLog(`Status: ${result.status}`, result.isFraud ? 'error' : 'success')
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

  const getLogIcon = (type: LogEntry['type']) => {
    switch (type) {
      case 'success': return <CheckCircle className="h-4 w-4 text-green-500" />
      case 'error': return <XCircle className="h-4 w-4 text-red-500" />
      default: return <div className="h-4 w-4" />
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Zap className="h-5 w-5" />
          Interactive Security Demonstration
        </CardTitle>
        <CardDescription>
          Test all security features in real-time with production-level functionality
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Demo Controls */}
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <Button
            onClick={testEncryption}
            disabled={loading !== null}
            className="w-full"
          >
            {loading === 'encryption' && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            <Shield className="mr-2 h-4 w-4" />
            Test Encryption
          </Button>

          <Button
            onClick={testAnonymization}
            disabled={loading !== null}
            variant="outline"
            className="w-full"
          >
            {loading === 'anonymization' && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            <Eye className="mr-2 h-4 w-4" />
            Test Data Anonymization
          </Button>

          <Button
            onClick={testFraudDetection}
            disabled={loading !== null}
            variant="outline"
            className="w-full"
          >
            {loading === 'fraud' && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            <AlertTriangle className="mr-2 h-4 w-4" />
            Test Fraud Detection
          </Button>

          <Button
            onClick={testSecurityPipeline}
            disabled={loading !== null}
            className="w-full"
          >
            {loading === 'pipeline' && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            <Zap className="mr-2 h-4 w-4" />
            Full Security Pipeline
          </Button>

          <Button
            onClick={generateDemoData}
            disabled={loading !== null}
            variant="outline"
            className="w-full"
          >
            {loading === 'data' && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            <Database className="mr-2 h-4 w-4" />
            Generate Demo Data
          </Button>

          <Button
            onClick={clearOutput}
            disabled={loading !== null}
            variant="destructive"
            className="w-full"
          >
            <Trash2 className="mr-2 h-4 w-4" />
            Clear Output
          </Button>
        </div>

        {/* Output Console */}
        <div className="rounded-md border bg-muted/50 p-4">
          <div className="h-64 overflow-y-auto space-y-2">
            {logs.map((log, index) => (
              <div key={index} className="flex items-start gap-2 text-sm">
                <span className="text-muted-foreground font-mono">
                  {log.timestamp}
                </span>
                {getLogIcon(log.type)}
                <span className={`flex-1 ${
                  log.type === 'error' ? 'text-red-600' :
                  log.type === 'success' ? 'text-green-600' :
                  'text-foreground'
                }`}>
                  {log.message}
                </span>
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}