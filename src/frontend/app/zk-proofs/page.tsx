'use client'

import { ZKProofGenerator } from "@/components/zk-proof/ZKProofGenerator"

export default function ZKProofsPage() {
  return (
    <div className="flex-1 space-y-4 p-8 pt-6">
      <div className="space-y-2">
        <h2 className="text-3xl font-bold tracking-tight">
          Zero-Knowledge Proofs
        </h2>
        <p className="text-muted-foreground">
          Generate and verify cryptographic proofs without revealing sensitive information
        </p>
      </div>

      <ZKProofGenerator />
    </div>
  )
}
