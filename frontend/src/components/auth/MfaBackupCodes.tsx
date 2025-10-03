import { useState } from 'react'
import { saveAs } from 'file-saver'
import { Copy, Download, Check, AlertTriangle } from 'lucide-react'
import { Button } from '../ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card'
import { Alert, AlertDescription } from '../ui/alert'

interface MfaBackupCodesProps {
  codes: string[]
  onAcknowledge?: () => void
}

export function MfaBackupCodes({ codes, onAcknowledge }: MfaBackupCodesProps) {
  const [copied, setCopied] = useState(false)

  const copyAll = async () => {
    try {
      const codesText = codes.join('\n')
      await navigator.clipboard.writeText(codesText)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch (err) {
      console.error('Failed to copy codes:', err)
    }
  }

  const downloadCodes = () => {
    const codesText = `LeafLock MFA Backup Codes\nGenerated: ${new Date().toISOString()}\n\n${codes.join('\n')}\n\nIMPORTANT: Save these codes securely. Each code can only be used once.`
    const blob = new Blob([codesText], { type: 'text/plain;charset=utf-8' })
    saveAs(blob, `leaflock-backup-codes-${Date.now()}.txt`)
  }

  return (
    <div className="space-y-4">
      <Alert variant="destructive">
        <AlertTriangle className="h-4 w-4" />
        <AlertDescription className="text-sm">
          <strong>Important:</strong> Save these backup codes securely. They
          won't be shown again and can be used to access your account if you
          lose your authentication device.
        </AlertDescription>
      </Alert>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Backup Recovery Codes</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 p-4 bg-muted rounded-lg font-mono text-sm">
            {codes.map((code, index) => (
              <div
                key={index}
                className="px-3 py-2 bg-background rounded border flex items-center justify-between"
              >
                <span>{code}</span>
                <span className="text-xs text-muted-foreground ml-2">
                  #{index + 1}
                </span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <div className="flex flex-col sm:flex-row gap-2">
        <Button
          type="button"
          variant="outline"
          className="flex-1"
          onClick={copyAll}
        >
          {copied ? (
            <>
              <Check className="mr-2 h-4 w-4 text-green-500" />
              Copied!
            </>
          ) : (
            <>
              <Copy className="mr-2 h-4 w-4" />
              Copy All Codes
            </>
          )}
        </Button>
        <Button
          type="button"
          variant="outline"
          className="flex-1"
          onClick={downloadCodes}
        >
          <Download className="mr-2 h-4 w-4" />
          Download as Text File
        </Button>
      </div>

      <Alert>
        <AlertDescription className="text-xs space-y-1">
          <p>
            <strong>How to use backup codes:</strong>
          </p>
          <ul className="list-disc list-inside space-y-1 ml-2">
            <li>Each code can only be used once</li>
            <li>Use these codes when you don't have access to your authenticator app</li>
            <li>You have {codes.length} backup codes available</li>
            <li>Generate new codes anytime from your security settings</li>
          </ul>
        </AlertDescription>
      </Alert>

      {onAcknowledge && (
        <div className="flex justify-end">
          <Button onClick={onAcknowledge}>
            I've Saved My Backup Codes
          </Button>
        </div>
      )}
    </div>
  )
}
