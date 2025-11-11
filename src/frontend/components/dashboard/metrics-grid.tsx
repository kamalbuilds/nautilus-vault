'use client'

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { useMetrics } from "@/hooks/use-metrics"
import { Loader2, Shield, Zap, Eye, Clock, Activity } from "lucide-react"

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`
  return `${Math.floor(seconds / 86400)}d`
}

export function MetricsGrid() {
  const { metrics, loading, error } = useMetrics()

  if (loading) {
    return (
      <div className="flex items-center justify-center h-48">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    )
  }

  if (error || !metrics) {
    return (
      <div className="text-center text-muted-foreground">
        <p>Unable to load metrics</p>
        {error && <p className="text-sm text-red-500">{error}</p>}
      </div>
    )
  }

  const { metrics: data, performance } = metrics

  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Requests Processed</CardTitle>
          <Activity className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{data.requests.toLocaleString()}</div>
          <p className="text-xs text-muted-foreground">
            {performance.requestsPerSecond.toFixed(2)} req/sec
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Data Objects Secured</CardTitle>
          <Shield className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{data.dataProcessed.toLocaleString()}</div>
          <p className="text-xs text-muted-foreground">
            {performance.dataProtectionLevel} protection
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Threats Blocked</CardTitle>
          <Zap className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-red-600">{data.threatsBlocked.toLocaleString()}</div>
          <p className="text-xs text-muted-foreground">
            {performance.threatDetectionRate} detection rate
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Privacy Score</CardTitle>
          <Eye className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-green-600">{data.privacyScore}%</div>
          <Badge variant="default" className="mt-1">
            GDPR/CCPA Ready
          </Badge>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">System Uptime</CardTitle>
          <Clock className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{formatUptime(data.uptime)}</div>
          <Badge variant="secondary" className="mt-1">
            Production Active
          </Badge>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Security Level</CardTitle>
          <Shield className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-blue-600">MAXIMUM</div>
          <Badge variant="outline" className="mt-1">
            All Systems Operational
          </Badge>
        </CardContent>
      </Card>
    </div>
  )
}