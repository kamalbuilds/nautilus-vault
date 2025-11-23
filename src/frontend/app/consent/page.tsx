'use client'

import { ConsentManager } from "@/components/privacy/ConsentManager"

export default function ConsentPage() {
  return (
    <div className="flex-1 space-y-4 p-8 pt-6">
      <div className="space-y-2">
        <h2 className="text-3xl font-bold tracking-tight">
          Consent Management
        </h2>
        <p className="text-muted-foreground">
          GDPR/CCPA compliant consent management and data portability
        </p>
      </div>

      <ConsentManager />
    </div>
  )
}
