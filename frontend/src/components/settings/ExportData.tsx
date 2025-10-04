import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card'
import { Button } from '../ui/button'
import { Alert, AlertDescription } from '../ui/alert'
import { Download, Loader2, FileJson } from 'lucide-react'

export interface ExportData {
  version: string
  exported_at: string
  user: {
    email: string
    created_at: string
  }
  notes: Array<{
    id: string
    title: string
    content: string
    created_at: string
    updated_at: string
    tags?: string[]
  }>
  settings?: Record<string, unknown>
}

interface ExportDataProps {
  onExport: () => Promise<ExportData>
}

export function ExportDataComponent({ onExport }: ExportDataProps) {
  const [isExporting, setIsExporting] = useState(false)
  const [error, setError] = useState('')

  const formatDate = (date: Date): string => {
    const year = date.getFullYear()
    const month = String(date.getMonth() + 1).padStart(2, '0')
    const day = String(date.getDate()).padStart(2, '0')
    return `${year}-${month}-${day}`
  }

  const handleExport = async () => {
    setIsExporting(true)
    setError('')

    try {
      const data = await onExport()

      // Create blob and trigger download
      const blob = new Blob([JSON.stringify(data, null, 2)], {
        type: 'application/json',
      })
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `leaflock-export-${formatDate(new Date())}.json`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      URL.revokeObjectURL(url)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to export data')
    } finally {
      setIsExporting(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-3">
          <FileJson className="h-6 w-6 text-muted-foreground" />
          <div>
            <CardTitle>Export Your Data</CardTitle>
            <CardDescription>
              Download all your data in JSON format
            </CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <Alert>
          <AlertDescription>
            <div className="space-y-2">
              <p className="font-semibold text-sm">Your export will include:</p>
              <ul className="list-disc list-inside text-sm space-y-1 ml-2">
                <li>All your notes (decrypted and readable)</li>
                <li>Note metadata (creation dates, tags, etc.)</li>
                <li>Account information (email, registration date)</li>
                <li>User preferences and settings</li>
              </ul>
            </div>
          </AlertDescription>
        </Alert>

        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <div className="space-y-2">
          <Button
            onClick={handleExport}
            disabled={isExporting}
            className="w-full sm:w-auto"
          >
            {isExporting ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Exporting...
              </>
            ) : (
              <>
                <Download className="mr-2 h-4 w-4" />
                Export Data
              </>
            )}
          </Button>

          <p className="text-xs text-muted-foreground">
            The export file will be named{' '}
            <span className="font-mono">
              leaflock-export-{formatDate(new Date())}.json
            </span>
          </p>
        </div>

        <Alert>
          <AlertDescription className="text-xs">
            <p className="font-semibold mb-1">Security Notice:</p>
            <p>
              Your exported data contains unencrypted notes. Store this file securely
              and delete it when no longer needed.
            </p>
          </AlertDescription>
        </Alert>
      </CardContent>
    </Card>
  )
}
