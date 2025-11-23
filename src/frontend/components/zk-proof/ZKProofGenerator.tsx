'use client'

import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Badge } from "@/components/ui/badge"
import { Textarea } from "@/components/ui/textarea"
import { api } from "@/lib/api"
import { useStore } from "@/lib/store"
import { Shield, CheckCircle, XCircle, Loader2, Clock, Zap } from "lucide-react"

interface CircuitInput {
  name: string
  type: string
  description: string
  placeholder?: string
}

const CIRCUITS = {
  membership: {
    name: 'Membership Proof',
    description: 'Prove you are part of a group without revealing your identity',
    inputs: [
      { name: 'secret', type: 'text', description: 'Your secret identity', placeholder: 'Enter your secret' },
      { name: 'pathElements', type: 'array', description: 'Merkle tree path', placeholder: '["elem1", "elem2"]' },
      { name: 'pathIndices', type: 'array', description: 'Path indices', placeholder: '[0, 1]' }
    ]
  },
  range: {
    name: 'Range Proof',
    description: 'Prove a value is within a range without revealing the exact value',
    inputs: [
      { name: 'value', type: 'number', description: 'The value to prove', placeholder: '25' },
      { name: 'minValue', type: 'number', description: 'Minimum value', placeholder: '18' },
      { name: 'maxValue', type: 'number', description: 'Maximum value', placeholder: '100' },
      { name: 'randomness', type: 'text', description: 'Random nonce', placeholder: 'random-string' }
    ]
  },
  identity: {
    name: 'Identity Proof',
    description: 'Prove attributes about your identity without revealing personal details',
    inputs: [
      { name: 'privateKey', type: 'text', description: 'Your private key', placeholder: 'private-key-here' },
      { name: 'age', type: 'number', description: 'Your age', placeholder: '25' },
      { name: 'nationality', type: 'number', description: 'Nationality code', placeholder: '1' },
      { name: 'license', type: 'number', description: 'License status (0/1)', placeholder: '1' },
      { name: 'nonce', type: 'text', description: 'Random nonce', placeholder: 'nonce-value' },
      { name: 'minAge', type: 'number', description: 'Minimum age requirement', placeholder: '18' },
      { name: 'requiredNationality', type: 'number', description: 'Required nationality', placeholder: '1' },
      { name: 'requiresLicense', type: 'number', description: 'Requires license (0/1)', placeholder: '1' }
    ]
  }
}

export function ZKProofGenerator() {
  const [selectedCircuit, setSelectedCircuit] = useState<keyof typeof CIRCUITS>('membership')
  const [inputs, setInputs] = useState<Record<string, any>>({})
  const [generatedProof, setGeneratedProof] = useState<any>(null)
  const [verificationResult, setVerificationResult] = useState<boolean | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [generationTime, setGenerationTime] = useState<number>(0)
  const [verificationTime, setVerificationTime] = useState<number>(0)

  const { addZKProof } = useStore()

  const circuit = CIRCUITS[selectedCircuit]

  const handleInputChange = (name: string, value: string) => {
    let processedValue: any = value

    const input = circuit.inputs.find(i => i.name === name)
    if (input?.type === 'number') {
      processedValue = parseInt(value) || 0
    } else if (input?.type === 'array') {
      try {
        processedValue = JSON.parse(value)
      } catch {
        processedValue = value
      }
    }

    setInputs(prev => ({ ...prev, [name]: processedValue }))
  }

  const handleGenerateProof = async () => {
    setLoading(true)
    setError(null)
    setGeneratedProof(null)
    setVerificationResult(null)

    const startTime = Date.now()

    try {
      const result = await api.generateZKProof(selectedCircuit, inputs)
      const endTime = Date.now()
      setGenerationTime(endTime - startTime)

      if (result.success) {
        setGeneratedProof(result.proof)

        // Add to store
        addZKProof({
          id: `zkp-${Date.now()}`,
          circuitName: selectedCircuit,
          proof: result.proof,
          publicSignals: result.publicSignals,
          verified: false,
          timestamp: new Date()
        })
      } else {
        setError(result.error || 'Failed to generate proof')
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate proof')
    } finally {
      setLoading(false)
    }
  }

  const handleVerifyProof = async () => {
    if (!generatedProof) return

    setLoading(true)
    const startTime = Date.now()

    try {
      const result = await api.verifyZKProof(
        generatedProof.proof,
        generatedProof.publicSignals,
        selectedCircuit
      )
      const endTime = Date.now()
      setVerificationTime(endTime - startTime)

      setVerificationResult(result.verified)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to verify proof')
      setVerificationResult(false)
    } finally {
      setLoading(false)
    }
  }

  const clearForm = () => {
    setInputs({})
    setGeneratedProof(null)
    setVerificationResult(null)
    setError(null)
    setGenerationTime(0)
    setVerificationTime(0)
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Zero-Knowledge Proof Generator
          </CardTitle>
          <CardDescription>
            Generate cryptographic proofs without revealing sensitive information
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Circuit Selection */}
          <div className="space-y-2">
            <label className="text-sm font-medium">Select Circuit Type</label>
            <Select value={selectedCircuit} onValueChange={(value) => {
              setSelectedCircuit(value as keyof typeof CIRCUITS)
              clearForm()
            }}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {Object.entries(CIRCUITS).map(([key, circuit]) => (
                  <SelectItem key={key} value={key}>
                    {circuit.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-sm text-muted-foreground">{circuit.description}</p>
          </div>

          {/* Input Fields */}
          <div className="space-y-4">
            <h3 className="text-sm font-medium">Circuit Inputs</h3>
            <div className="grid gap-4 md:grid-cols-2">
              {circuit.inputs.map((input) => (
                <div key={input.name} className="space-y-2">
                  <label className="text-sm font-medium">{input.description}</label>
                  <Input
                    placeholder={input.placeholder}
                    value={inputs[input.name] || ''}
                    onChange={(e) => handleInputChange(input.name, e.target.value)}
                  />
                  <p className="text-xs text-muted-foreground">Type: {input.type}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Actions */}
          <div className="flex gap-3">
            <Button onClick={handleGenerateProof} disabled={loading} className="flex-1">
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Generating...
                </>
              ) : (
                <>
                  <Zap className="mr-2 h-4 w-4" />
                  Generate Proof
                </>
              )}
            </Button>
            <Button onClick={clearForm} variant="outline">
              Clear
            </Button>
          </div>

          {/* Error Display */}
          {error && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-4">
              <div className="flex items-center gap-2 text-red-800">
                <XCircle className="h-4 w-4" />
                <span className="font-medium">Error</span>
              </div>
              <p className="text-sm text-red-600 mt-1">{error}</p>
            </div>
          )}

          {/* Performance Metrics */}
          {generationTime > 0 && (
            <div className="grid grid-cols-2 gap-4">
              <Card className="p-4">
                <div className="flex items-center gap-2 text-blue-600">
                  <Clock className="h-4 w-4" />
                  <span className="text-sm font-medium">Generation Time</span>
                </div>
                <div className="text-2xl font-bold">{generationTime}ms</div>
              </Card>
              {verificationTime > 0 && (
                <Card className="p-4">
                  <div className="flex items-center gap-2 text-green-600">
                    <Clock className="h-4 w-4" />
                    <span className="text-sm font-medium">Verification Time</span>
                  </div>
                  <div className="text-2xl font-bold">{verificationTime}ms</div>
                </Card>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Generated Proof Display */}
      {generatedProof && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span>Generated Proof</span>
              <Button onClick={handleVerifyProof} disabled={loading} size="sm">
                {loading ? (
                  <Loader2 className="mr-2 h-3 w-3 animate-spin" />
                ) : (
                  <Shield className="mr-2 h-3 w-3" />
                )}
                Verify Proof
              </Button>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Verification Status */}
            {verificationResult !== null && (
              <div className={`border rounded-lg p-4 ${
                verificationResult
                  ? 'bg-green-50 border-green-200'
                  : 'bg-red-50 border-red-200'
              }`}>
                <div className="flex items-center gap-2">
                  {verificationResult ? (
                    <>
                      <CheckCircle className="h-5 w-5 text-green-600" />
                      <span className="font-medium text-green-800">Proof Verified Successfully</span>
                    </>
                  ) : (
                    <>
                      <XCircle className="h-5 w-5 text-red-600" />
                      <span className="font-medium text-red-800">Proof Verification Failed</span>
                    </>
                  )}
                </div>
              </div>
            )}

            {/* Proof Data */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Circuit</span>
                <Badge>{selectedCircuit}</Badge>
              </div>
              <Textarea
                value={JSON.stringify(generatedProof, null, 2)}
                readOnly
                className="font-mono text-xs h-64"
              />
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
