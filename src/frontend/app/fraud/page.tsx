'use client'

import { FraudDetector } from "@/components/fraud/FraudDetector"

export default function FraudPage() {
  return (
    <div className="flex-1 space-y-4 p-8 pt-6">
      <div className="space-y-2">
        <h2 className="text-3xl font-bold tracking-tight">
          Fraud Detection
        </h2>
        <p className="text-muted-foreground">
          Real-time ML-powered fraud analysis for transactions
        </p>
      </div>

      <FraudDetector />
    </div>
  )
}
