import React from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { useConfig } from '@/hooks/useConfig'
import { Copy, RefreshCw } from 'lucide-react'

/**
 * Debug component to display current configuration
 * Only shows in development or when explicitly enabled
 */
export function ConfigDebug() {
  const config = useConfig()
  const [isVisible, setIsVisible] = React.useState(false)

  // Only show in development or when explicitly enabled
  const shouldShow = config.environment === 'development' || process.env.VITE_SHOW_CONFIG === 'true'

  if (!shouldShow) {
    return null
  }

  const copyToClipboard = () => {
    const configText = JSON.stringify(config, null, 2)
    navigator.clipboard.writeText(configText)
  }

  const refreshConfig = () => {
    window.location.reload()
  }

  return (
    <Card className="fixed bottom-4 right-4 w-80 z-50 bg-background/95 backdrop-blur-sm border-2">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm">Configuration Debug</CardTitle>
          <div className="flex gap-1">
            <Button size="sm" variant="ghost" onClick={copyToClipboard} className="h-6 w-6 p-0">
              <Copy className="h-3 w-3" />
            </Button>
            <Button size="sm" variant="ghost" onClick={refreshConfig} className="h-6 w-6 p-0">
              <RefreshCw className="h-3 w-3" />
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setIsVisible(!isVisible)}
              className="h-6 w-6 p-0"
            >
              {isVisible ? '−' : '+'}
            </Button>
          </div>
        </div>
      </CardHeader>

      {isVisible && (
        <CardContent className="pt-0">
          <div className="space-y-2 text-xs">
            <div className="flex items-center gap-2">
              <span className="font-medium">Environment:</span>
              <Badge variant={config.environment === 'production' ? 'destructive' : 'secondary'}>
                {config.environment}
              </Badge>
            </div>

            <div className="flex items-center gap-2">
              <span className="font-medium">Platform:</span>
              <Badge variant={config.isRailway ? 'default' : 'outline'}>
                {config.isRailway ? 'Railway' : 'Local'}
              </Badge>
            </div>

            {config.serviceName && (
              <div className="flex items-center gap-2">
                <span className="font-medium">Service:</span>
                <Badge variant="outline">{config.serviceName}</Badge>
              </div>
            )}

            <div className="space-y-1">
              <span className="font-medium">API URL:</span>
              <div className="break-all text-muted-foreground bg-muted p-1 rounded">
                {config.apiUrl}
              </div>
            </div>

            <div className="space-y-1">
              <span className="font-medium">Environment Variables:</span>
              <div className="text-muted-foreground bg-muted p-1 rounded text-xs">
                <div>VITE_API_URL: {process.env.VITE_API_URL || 'not set'}</div>
                <div>RAILWAY_ENVIRONMENT: {process.env.RAILWAY_ENVIRONMENT || 'not set'}</div>
                <div>RAILWAY_SERVICE_NAME: {process.env.RAILWAY_SERVICE_NAME || 'not set'}</div>
                <div>RAILWAY_PRIVATE_DOMAIN: {process.env.RAILWAY_PRIVATE_DOMAIN || 'not set'}</div>
                <div>RAILWAY_INTERNAL_HOST: {process.env.RAILWAY_INTERNAL_HOST || 'not set'}</div>
                <div>RAILWAY_PUBLIC_DOMAIN: {process.env.RAILWAY_PUBLIC_DOMAIN || 'not set'}</div>
                <div>BACKEND_URL: {process.env.BACKEND_URL || 'not set'}</div>
                <div>API_URL: {process.env.API_URL || 'not set'}</div>
                <div>SERVER_URL: {process.env.SERVER_URL || 'not set'}</div>
              </div>
            </div>
          </div>
        </CardContent>
      )}
    </Card>
  )
}
