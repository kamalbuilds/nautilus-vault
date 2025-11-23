'use client'

import { PrivacyDashboard } from "@/components/privacy/PrivacyDashboard"

export default function PrivacyPage() {
  return (
    <div className="flex-1 space-y-4 p-8 pt-6">
      <div className="space-y-2">
        <h2 className="text-3xl font-bold tracking-tight">
          Privacy Dashboard
        </h2>
        <p className="text-muted-foreground">
          K-anonymity data protection and privacy score monitoring
        </p>
      </div>

      <PrivacyDashboard />
    </div>
  )
}
