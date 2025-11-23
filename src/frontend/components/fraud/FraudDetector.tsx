'use client'

import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { api } from "@/lib/api"
import { useStore } from "@/lib/store"
import { AlertTriangle, Shield, TrendingUp, MapPin, CreditCard, User, Loader2 } from "lucide-react"

export function FraudDetector() {
  const [formData, setFormData] = useState({
    userId: '',
    transactionAmount: '',
    location: '',
    deviceFingerprint: '',
    ipAddress: '',
  })
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)

  const { addFraudAnalysis } = useStore()

  const handleInputChange = (field: string, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }))
  }

  const getRiskColor = (score: number) => {
    if (score < 0.2) return 'text-green-600'
    if (score < 0.4) return 'text-yellow-600'
    if (score < 0.6) return 'text-orange-600'
    return 'text-red-600'
  }

  const getRiskLabel = (score: number) => {
    if (score < 0.2) return 'LOW RISK'
    if (score < 0.4) return 'MODERATE RISK'
    if (score < 0.6) return 'HIGH RISK'
    return 'CRITICAL RISK'
  }

  const handleAnalyze = async () => {
    setLoading(true)
    setResult(null)

    try {
      const payload = {
        userId: formData.userId,
        transactionAmount: parseFloat(formData.transactionAmount),
        location: formData.location,
        deviceFingerprint: formData.deviceFingerprint,
        ipAddress: formData.ipAddress,
      }

      const response = await api.checkFraud(payload)

      setResult(response)

      // Add to store
      addFraudAnalysis({
        id: `fraud-${Date.now()}`,
        riskScore: response.riskScore,
        isFraud: response.isFraud,
        details: response,
        timestamp: new Date()
      })
    } catch (error) {
      console.error('Fraud check failed:', error)
    } finally {
      setLoading(false)
    }
  }

  const loadExample = (type: 'safe' | 'suspicious' | 'dangerous') => {
    const examples = {
      safe: {
        userId: 'verified-user-123',
        transactionAmount: '50',
        location: 'United States',
        deviceFingerprint: 'known-device-abc',
        ipAddress: '192.168.1.100',
      },
      suspicious: {
        userId: 'new-user-456',
        transactionAmount: '5000',
        location: 'Unknown',
        deviceFingerprint: 'new-device-xyz',
        ipAddress: '10.0.0.1',
      },
      dangerous: {
        userId: 'suspicious-user-999',
        transactionAmount: '50000',
        location: 'North Korea',
        deviceFingerprint: 'tor-exit-node',
        ipAddress: '192.168.1.1',
      }
    }
    setFormData(examples[type])
    setResult(null)
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            ML-Powered Fraud Detection
          </CardTitle>
          <CardDescription>
            Analyze transactions in real-time using machine learning models
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Quick Examples */}
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => loadExample('safe')}>
              Safe Example
            </Button>
            <Button variant="outline" size="sm" onClick={() => loadExample('suspicious')}>
              Suspicious Example
            </Button>
            <Button variant="outline" size="sm" onClick={() => loadExample('dangerous')}>
              Dangerous Example
            </Button>
          </div>

          {/* Form Fields */}
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <label className="text-sm font-medium flex items-center gap-2">
                <User className="h-3 w-3" />
                User ID
              </label>
              <Input
                placeholder="user-123"
                value={formData.userId}
                onChange={(e) => handleInputChange('userId', e.target.value)}
              />
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium flex items-center gap-2">
                <CreditCard className="h-3 w-3" />
                Transaction Amount ($)
              </label>
              <Input
                type="number"
                placeholder="1000"
                value={formData.transactionAmount}
                onChange={(e) => handleInputChange('transactionAmount', e.target.value)}
              />
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium flex items-center gap-2">
                <MapPin className="h-3 w-3" />
                Location
              </label>
              <Input
                placeholder="United States"
                value={formData.location}
                onChange={(e) => handleInputChange('location', e.target.value)}
              />
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">Device Fingerprint</label>
              <Input
                placeholder="device-abc-123"
                value={formData.deviceFingerprint}
                onChange={(e) => handleInputChange('deviceFingerprint', e.target.value)}
              />
            </div>

            <div className="space-y-2 md:col-span-2">
              <label className="text-sm font-medium">IP Address</label>
              <Input
                placeholder="192.168.1.1"
                value={formData.ipAddress}
                onChange={(e) => handleInputChange('ipAddress', e.target.value)}
              />
            </div>
          </div>

          <Button onClick={handleAnalyze} disabled={loading} className="w-full">
            {loading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Analyzing Transaction...
              </>
            ) : (
              <>
                <TrendingUp className="mr-2 h-4 w-4" />
                Analyze Transaction
              </>
            )}
          </Button>
        </CardContent>
      </Card>

      {/* Results */}
      {result && (
        <Card className="border-2 border-slate-200">
          <CardHeader>
            <CardTitle>Fraud Analysis Results</CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Risk Score */}
            <div className="text-center space-y-2">
              <div className="text-sm font-medium text-muted-foreground">Risk Score</div>
              <div className={`text-6xl font-bold ${getRiskColor(result.riskScore)}`}>
                {(result.riskScore * 100).toFixed(1)}%
              </div>
              <Badge
                className={`text-lg px-4 py-1 ${
                  result.isFraud ? 'bg-red-600' : 'bg-green-600'
                }`}
              >
                {getRiskLabel(result.riskScore)}
              </Badge>
            </div>

            {/* Decision */}
            <div className={`border-2 rounded-lg p-4 ${
              result.isFraud
                ? 'border-red-200 bg-red-50'
                : 'border-green-200 bg-green-50'
            }`}>
              <div className="flex items-center gap-2">
                {result.isFraud ? (
                  <AlertTriangle className="h-5 w-5 text-red-600" />
                ) : (
                  <Shield className="h-5 w-5 text-green-600" />
                )}
                <div>
                  <div className={`font-bold ${result.isFraud ? 'text-red-800' : 'text-green-800'}`}>
                    Transaction {result.status}
                  </div>
                  <div className={`text-sm ${result.isFraud ? 'text-red-600' : 'text-green-600'}`}>
                    {result.message}
                  </div>
                </div>
              </div>
            </div>

            {/* Details */}
            {result.details && (
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-1">
                  <div className="text-sm font-medium">Fraud Indicators</div>
                  <div className="text-2xl font-bold">{result.details.indicators}</div>
                </div>
                <div className="space-y-1">
                  <div className="text-sm font-medium">Model Confidence</div>
                  <div className="text-2xl font-bold">{(result.details.confidence * 100).toFixed(1)}%</div>
                </div>
              </div>
            )}

            {/* Recommendations */}
            {result.details?.recommendations && result.details.recommendations.length > 0 && (
              <div className="space-y-2">
                <div className="text-sm font-medium">Recommendations</div>
                <div className="space-y-1">
                  {result.details.recommendations.map((rec: string, idx: number) => (
                    <div key={idx} className="text-sm bg-blue-50 border border-blue-200 rounded p-2">
                      {rec}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}
