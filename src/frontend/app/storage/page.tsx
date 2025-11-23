'use client'

import { DataStorage } from "@/components/storage/DataStorage"

export default function StoragePage() {
  return (
    <div className="flex-1 space-y-4 p-8 pt-6">
      <div className="space-y-2">
        <h2 className="text-3xl font-bold tracking-tight">
          Walrus Data Storage
        </h2>
        <p className="text-muted-foreground">
          Store and retrieve data securely on the decentralized Walrus network
        </p>
      </div>

      <DataStorage />
    </div>
  )
}
