'use client'

import { useEffect, useState } from 'react'
import { api, type MetricsResponse } from '@/lib/api'

export function useMetrics(refreshInterval: number = 3000) {
  const [metrics, setMetrics] = useState<MetricsResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let intervalId: NodeJS.Timeout

    const fetchMetrics = async () => {
      try {
        const data = await api.getMetrics()
        setMetrics(data)
        setError(null)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch metrics')
      } finally {
        setLoading(false)
      }
    }

    // Initial fetch
    fetchMetrics()

    // Set up interval for regular updates
    intervalId = setInterval(fetchMetrics, refreshInterval)

    return () => {
      if (intervalId) {
        clearInterval(intervalId)
      }
    }
  }, [refreshInterval])

  return { metrics, loading, error }
}