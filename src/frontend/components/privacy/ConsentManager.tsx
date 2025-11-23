'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { api } from "@/lib/api"
import { useStore } from "@/lib/store"
import { FileCheck, CheckCircle, XCircle, Download, Loader2, Clock } from "lucide-react"

const CONSENT_PURPOSES = [
  { id: 'marketing', label: 'Marketing Communications', description: 'Send promotional emails and offers' },
  { id: 'analytics', label: 'Analytics & Statistics', description: 'Track usage for improving service' },
  { id: 'research', label: 'Research & Development', description: 'Use data for product research' },
  { id: 'third_party', label: 'Third-Party Sharing', description: 'Share data with trusted partners' },
  { id: 'personalization', label: 'Personalization', description: 'Customize your experience' },
]

export function ConsentManager() {
  const [dataSubjectId, setDataSubjectId] = useState('')
  const [selectedPurposes, setSelectedPurposes] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [grantSuccess, setGrantSuccess] = useState(false)

  const { consents, addConsent, revokeConsent: revokeConsentStore } = useStore()

  const togglePurpose = (purposeId: string) => {
    setSelectedPurposes(prev =>
      prev.includes(purposeId)
        ? prev.filter(p => p !== purposeId)
        : [...prev, purposeId]
    )
  }

  const handleGrantConsent = async () => {
    if (!dataSubjectId || selectedPurposes.length === 0) return

    setLoading(true)
    setGrantSuccess(false)

    try {
      const result = await api.createConsent(dataSubjectId, selectedPurposes)

      if (result.success) {
        addConsent({
          id: result.requestId,
          purposes: selectedPurposes,
          granted: true,
          timestamp: new Date()
        })

        setGrantSuccess(true)
        setTimeout(() => {
          setGrantSuccess(false)
          setSelectedPurposes([])
        }, 2000)
      }
    } catch (error) {
      console.error('Consent grant failed:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleRevokeConsent = async (consentId: string) => {
    setLoading(true)

    try {
      const result = await api.revokeConsent(consentId)

      if (result.success) {
        revokeConsentStore(consentId)
      }
    } catch (error) {
      console.error('Consent revocation failed:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleExportData = async () => {
    if (!dataSubjectId) return

    setLoading(true)

    try {
      const result = await api.requestDataPortability(dataSubjectId)

      if (result.success) {
        // Create download
        const blob = new Blob([JSON.stringify(result.data, null, 2)], { type: 'application/json' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `user-data-${dataSubjectId}-${Date.now()}.json`
        a.click()
        URL.revokeObjectURL(url)
      }
    } catch (error) {
      console.error('Data export failed:', error)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Grant Consent Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileCheck className="h-5 w-5" />
            Grant Consent
          </CardTitle>
          <CardDescription>
            Manage your data processing consents (GDPR/CCPA compliant)
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-2">
            <label className="text-sm font-medium">User / Data Subject ID</label>
            <Input
              placeholder="Enter user ID..."
              value={dataSubjectId}
              onChange={(e) => setDataSubjectId(e.target.value)}
            />
          </div>

          <div className="space-y-3">
            <label className="text-sm font-medium">Select Consent Purposes</label>
            <div className="space-y-2">
              {CONSENT_PURPOSES.map((purpose) => (
                <div
                  key={purpose.id}
                  className={`border rounded-lg p-4 cursor-pointer transition-all ${
                    selectedPurposes.includes(purpose.id)
                      ? 'border-blue-500 bg-blue-50'
                      : 'border-slate-200 hover:border-slate-300'
                  }`}
                  onClick={() => togglePurpose(purpose.id)}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="font-medium text-sm">{purpose.label}</div>
                      <div className="text-xs text-muted-foreground mt-1">{purpose.description}</div>
                    </div>
                    {selectedPurposes.includes(purpose.id) && (
                      <CheckCircle className="h-5 w-5 text-blue-600 flex-shrink-0 ml-2" />
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <Button
            onClick={handleGrantConsent}
            disabled={loading || !dataSubjectId || selectedPurposes.length === 0}
            className="w-full"
          >
            {loading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Granting Consent...
              </>
            ) : grantSuccess ? (
              <>
                <CheckCircle className="mr-2 h-4 w-4" />
                Consent Granted!
              </>
            ) : (
              <>
                <FileCheck className="mr-2 h-4 w-4" />
                Grant Consent ({selectedPurposes.length} purposes)
              </>
            )}
          </Button>
        </CardContent>
      </Card>

      {/* Consent History */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Clock className="h-5 w-5" />
            Consent History ({consents.length})
          </CardTitle>
          <CardDescription>
            Your consent history and active consents
          </CardDescription>
        </CardHeader>
        <CardContent>
          {consents.length === 0 ? (
            <div className="text-center text-muted-foreground py-8">
              <FileCheck className="h-12 w-12 mx-auto mb-2 opacity-50" />
              <p>No consents granted yet</p>
              <p className="text-sm">Grant consent to see it here</p>
            </div>
          ) : (
            <div className="space-y-3">
              {consents.map((consent) => (
                <div
                  key={consent.id}
                  className="border rounded-lg p-4"
                >
                  <div className="flex items-start justify-between mb-3">
                    <div>
                      <div className="font-medium text-sm mb-1">Consent ID: {consent.id}</div>
                      <div className="text-xs text-muted-foreground">
                        {new Date(consent.timestamp).toLocaleString()}
                      </div>
                    </div>
                    <Badge className={consent.granted ? 'bg-green-600' : 'bg-red-600'}>
                      {consent.granted ? 'Active' : 'Revoked'}
                    </Badge>
                  </div>

                  <div className="space-y-2">
                    <div className="text-sm font-medium">Purposes:</div>
                    <div className="flex flex-wrap gap-2">
                      {consent.purposes.map((purpose) => (
                        <Badge key={purpose} variant="outline">
                          {CONSENT_PURPOSES.find(p => p.id === purpose)?.label || purpose}
                        </Badge>
                      ))}
                    </div>
                  </div>

                  {consent.granted && (
                    <Button
                      variant="destructive"
                      size="sm"
                      className="mt-3"
                      onClick={() => handleRevokeConsent(consent.id)}
                      disabled={loading}
                    >
                      <XCircle className="mr-1 h-3 w-3" />
                      Revoke Consent
                    </Button>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Data Portability */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Download className="h-5 w-5" />
            Data Portability (GDPR Right)
          </CardTitle>
          <CardDescription>
            Export your personal data in machine-readable format
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <div className="text-sm text-blue-800">
              <strong>Right to Data Portability:</strong> You have the right to receive your personal data
              in a structured, commonly used, and machine-readable format.
            </div>
          </div>

          <Button
            onClick={handleExportData}
            disabled={loading || !dataSubjectId}
            variant="outline"
            className="w-full"
          >
            {loading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Exporting Data...
              </>
            ) : (
              <>
                <Download className="mr-2 h-4 w-4" />
                Export My Data (JSON)
              </>
            )}
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
