'use client'

import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Badge } from "@/components/ui/badge"
import { api } from "@/lib/api"
import { useStore } from "@/lib/store"
import { Database, Upload, Download, Trash2, Lock, Unlock, Loader2, CheckCircle } from "lucide-react"

export function DataStorage() {
  const [dataToStore, setDataToStore] = useState('')
  const [encrypt, setEncrypt] = useState(true)
  const [blobId, setBlobId] = useState('')
  const [retrievedData, setRetrievedData] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [uploadSuccess, setUploadSuccess] = useState(false)

  const { storedData, addStoredData } = useStore()

  const handleStore = async () => {
    if (!dataToStore.trim()) return

    setLoading(true)
    setUploadSuccess(false)

    try {
      const result = await api.storeData(dataToStore, encrypt)

      if (result.success) {
        setBlobId(result.blobId)
        setUploadSuccess(true)

        // Add to store
        addStoredData({
          id: `blob-${Date.now()}`,
          blobId: result.blobId,
          name: `Data-${new Date().toLocaleTimeString()}`,
          size: dataToStore.length,
          encrypted: encrypt,
          timestamp: new Date()
        })

        // Clear form after 2 seconds
        setTimeout(() => {
          setDataToStore('')
          setUploadSuccess(false)
        }, 2000)
      }
    } catch (error) {
      console.error('Storage failed:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleRetrieve = async () => {
    if (!blobId.trim()) return

    setLoading(true)
    setRetrievedData(null)

    try {
      const result = await api.retrieveData(blobId)

      if (result.success) {
        setRetrievedData(result.data)
      }
    } catch (error) {
      console.error('Retrieval failed:', error)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Upload Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Upload className="h-5 w-5" />
            Store Data to Walrus
          </CardTitle>
          <CardDescription>
            Upload and store data on the decentralized Walrus storage network
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <label className="text-sm font-medium">Data to Store</label>
            <Textarea
              placeholder="Enter data to store on Walrus..."
              value={dataToStore}
              onChange={(e) => setDataToStore(e.target.value)}
              rows={6}
            />
            <div className="flex items-center justify-between text-sm text-muted-foreground">
              <span>{dataToStore.length} characters</span>
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setEncrypt(!encrypt)}
                  className={encrypt ? 'border-green-500 text-green-700' : ''}
                >
                  {encrypt ? (
                    <>
                      <Lock className="mr-1 h-3 w-3" />
                      Encrypted
                    </>
                  ) : (
                    <>
                      <Unlock className="mr-1 h-3 w-3" />
                      Plaintext
                    </>
                  )}
                </Button>
              </div>
            </div>
          </div>

          <Button onClick={handleStore} disabled={loading || !dataToStore.trim()} className="w-full">
            {loading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Storing to Walrus...
              </>
            ) : uploadSuccess ? (
              <>
                <CheckCircle className="mr-2 h-4 w-4" />
                Stored Successfully!
              </>
            ) : (
              <>
                <Upload className="mr-2 h-4 w-4" />
                Store to Walrus
              </>
            )}
          </Button>

          {blobId && (
            <div className="bg-green-50 border border-green-200 rounded-lg p-4">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-sm font-medium text-green-800">Storage Successful</div>
                  <div className="text-xs text-green-600 font-mono mt-1">Blob ID: {blobId}</div>
                </div>
                <Badge className="bg-green-600">{encrypt ? 'Encrypted' : 'Plaintext'}</Badge>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Retrieve Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Download className="h-5 w-5" />
            Retrieve Data from Walrus
          </CardTitle>
          <CardDescription>
            Retrieve stored data using its Blob ID
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <label className="text-sm font-medium">Blob ID</label>
            <div className="flex gap-2">
              <Input
                placeholder="Enter Blob ID to retrieve..."
                value={blobId}
                onChange={(e) => setBlobId(e.target.value)}
              />
              <Button onClick={handleRetrieve} disabled={loading || !blobId.trim()}>
                {loading ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Download className="h-4 w-4" />
                )}
              </Button>
            </div>
          </div>

          {retrievedData && (
            <div className="space-y-2">
              <label className="text-sm font-medium">Retrieved Data</label>
              <Textarea
                value={typeof retrievedData === 'string' ? retrievedData : JSON.stringify(retrievedData, null, 2)}
                readOnly
                rows={8}
                className="font-mono text-sm"
              />
            </div>
          )}
        </CardContent>
      </Card>

      {/* Stored Blobs List */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Database className="h-5 w-5" />
            Stored Blobs ({storedData.length})
          </CardTitle>
          <CardDescription>
            Your recently stored data blobs
          </CardDescription>
        </CardHeader>
        <CardContent>
          {storedData.length === 0 ? (
            <div className="text-center text-muted-foreground py-8">
              <Database className="h-12 w-12 mx-auto mb-2 opacity-50" />
              <p>No stored blobs yet</p>
              <p className="text-sm">Upload data to see it here</p>
            </div>
          ) : (
            <div className="space-y-2">
              {storedData.map((blob) => (
                <div
                  key={blob.id}
                  className="flex items-center justify-between p-3 border rounded-lg hover:bg-muted/50 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    {blob.encrypted ? (
                      <Lock className="h-4 w-4 text-green-600" />
                    ) : (
                      <Unlock className="h-4 w-4 text-blue-600" />
                    )}
                    <div>
                      <div className="font-medium text-sm">{blob.name}</div>
                      <div className="text-xs text-muted-foreground font-mono">
                        {blob.blobId}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline">{blob.size} bytes</Badge>
                    <Badge className={blob.encrypted ? 'bg-green-600' : 'bg-blue-600'}>
                      {blob.encrypted ? 'Encrypted' : 'Plain'}
                    </Badge>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setBlobId(blob.blobId)}
                    >
                      <Download className="h-3 w-3" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
