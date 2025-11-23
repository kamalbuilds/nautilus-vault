'use client'

import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Textarea } from "@/components/ui/textarea"
import { Badge } from "@/components/ui/badge"
import { api } from "@/lib/api"
import { useStore } from "@/lib/store"
import { Eye, Shield, TrendingUp, Loader2, CheckCircle, AlertCircle } from "lucide-react"

export function PrivacyDashboard() {
  const [dataToAnonymize, setDataToAnonymize] = useState('')
  const [anonymizedResult, setAnonymizedResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [kValue, setKValue] = useState(3)

  const { privacyScore, updatePrivacyScore } = useStore()

  const handleAnonymize = async () => {
    if (!dataToAnonymize.trim()) return

    setLoading(true)
    setAnonymizedResult(null)

    try {
      let data
      try {
        data = JSON.parse(dataToAnonymize)
      } catch {
        // If not valid JSON, treat as simple data
        data = [{ value: dataToAnonymize }]
      }

      const result = await api.anonymizeData(Array.isArray(data) ? data : [data])

      if (result.success) {
        setAnonymizedResult(result)

        // Update privacy score
        if (result.privacyLevel) {
          const score = parseFloat(result.privacyLevel.replace('%', ''))
          updatePrivacyScore(score)
        }
      }
    } catch (error) {
      console.error('Anonymization failed:', error)
    } finally {
      setLoading(false)
    }
  }

  const loadExample = () => {
    const example = [
      { name: 'John Doe', age: 30, zipcode: '90210', salary: 75000 },
      { name: 'Jane Smith', age: 25, zipcode: '90211', salary: 65000 },
      { name: 'Mike Johnson', age: 35, zipcode: '90212', salary: 80000 },
      { name: 'Sarah Williams', age: 28, zipcode: '90210', salary: 70000 },
      { name: 'Tom Brown', age: 32, zipcode: '90211', salary: 72000 }
    ]
    setDataToAnonymize(JSON.stringify(example, null, 2))
  }

  const getPrivacyScoreColor = (score: number) => {
    if (score >= 95) return 'text-green-600'
    if (score >= 85) return 'text-blue-600'
    if (score >= 75) return 'text-yellow-600'
    return 'text-red-600'
  }

  const getPrivacyScoreLabel = (score: number) => {
    if (score >= 95) return 'Excellent'
    if (score >= 85) return 'Good'
    if (score >= 75) return 'Fair'
    return 'Poor'
  }

  return (
    <div className="space-y-6">
      {/* Privacy Score Overview */}
      <Card className="border-2 border-blue-200">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Privacy Protection Score
          </CardTitle>
          <CardDescription>
            Your current data privacy protection level
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="text-center space-y-4">
            <div className={`text-7xl font-bold ${getPrivacyScoreColor(privacyScore)}`}>
              {privacyScore.toFixed(1)}%
            </div>
            <Badge className="text-lg px-6 py-2 bg-blue-600">
              {getPrivacyScoreLabel(privacyScore)} Protection
            </Badge>
            <div className="grid grid-cols-2 gap-4 mt-6">
              <div className="text-center">
                <div className="text-2xl font-bold text-green-600">K={kValue}</div>
                <div className="text-sm text-muted-foreground">Anonymity Level</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-blue-600">GDPR</div>
                <div className="text-sm text-muted-foreground">Compliant</div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Data Anonymization */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Eye className="h-5 w-5" />
            K-Anonymity Data Protection
          </CardTitle>
          <CardDescription>
            Apply privacy-preserving transformations to your data
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* K-Value Selector */}
          <div className="space-y-2">
            <label className="text-sm font-medium">K-Anonymity Level (K={kValue})</label>
            <div className="flex items-center gap-4">
              <input
                type="range"
                min="2"
                max="10"
                value={kValue}
                onChange={(e) => setKValue(parseInt(e.target.value))}
                className="flex-1"
              />
              <Badge variant="outline" className="w-16 justify-center">
                K={kValue}
              </Badge>
            </div>
            <p className="text-xs text-muted-foreground">
              Higher K values provide better privacy but may reduce data utility
            </p>
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-sm font-medium">Data to Anonymize (JSON format)</label>
              <Button variant="outline" size="sm" onClick={loadExample}>
                Load Example
              </Button>
            </div>
            <Textarea
              placeholder='[{"name": "John", "age": 30, "zipcode": "90210"}]'
              value={dataToAnonymize}
              onChange={(e) => setDataToAnonymize(e.target.value)}
              rows={8}
              className="font-mono text-sm"
            />
          </div>

          <Button onClick={handleAnonymize} disabled={loading || !dataToAnonymize.trim()} className="w-full">
            {loading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Anonymizing Data...
              </>
            ) : (
              <>
                <Shield className="mr-2 h-4 w-4" />
                Apply K-Anonymity Protection
              </>
            )}
          </Button>
        </CardContent>
      </Card>

      {/* Anonymization Results */}
      {anonymizedResult && (
        <Card className="border-2 border-green-200">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <CheckCircle className="h-5 w-5 text-green-600" />
              Anonymization Results
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Metrics */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="text-center">
                <div className="text-2xl font-bold">{anonymizedResult.originalCount}</div>
                <div className="text-sm text-muted-foreground">Original Records</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold">{anonymizedResult.anonymizedCount}</div>
                <div className="text-sm text-muted-foreground">Anonymized Records</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-green-600">{anonymizedResult.privacyLevel}</div>
                <div className="text-sm text-muted-foreground">Privacy Level</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-blue-600">
                  {(anonymizedResult.qualityMetrics?.informationLoss * 100).toFixed(1)}%
                </div>
                <div className="text-sm text-muted-foreground">Info Loss</div>
              </div>
            </div>

            {/* Quality Metrics */}
            {anonymizedResult.qualityMetrics && (
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 space-y-2">
                <div className="font-medium text-sm text-blue-900">Quality Metrics</div>
                <div className="grid grid-cols-2 gap-2 text-sm">
                  <div>
                    <span className="text-muted-foreground">Information Loss:</span>
                    <span className="ml-2 font-medium">
                      {(anonymizedResult.qualityMetrics.informationLoss * 100).toFixed(2)}%
                    </span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Data Utility:</span>
                    <span className="ml-2 font-medium">
                      {((1 - anonymizedResult.qualityMetrics.informationLoss) * 100).toFixed(2)}%
                    </span>
                  </div>
                </div>
              </div>
            )}

            {/* Comparison */}
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <AlertCircle className="h-4 w-4 text-blue-600" />
                <span className="text-sm font-medium">Privacy vs Utility Trade-off</span>
              </div>
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span>Privacy Protection</span>
                  <span className="font-semibold">{anonymizedResult.privacyLevel}</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div
                    className="bg-green-600 h-2 rounded-full"
                    style={{ width: anonymizedResult.privacyLevel }}
                  ></div>
                </div>

                <div className="flex justify-between text-sm mt-3">
                  <span>Data Utility</span>
                  <span className="font-semibold">
                    {((1 - (anonymizedResult.qualityMetrics?.informationLoss || 0)) * 100).toFixed(1)}%
                  </span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div
                    className="bg-blue-600 h-2 rounded-full"
                    style={{
                      width: `${((1 - (anonymizedResult.qualityMetrics?.informationLoss || 0)) * 100).toFixed(1)}%`
                    }}
                  ></div>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
