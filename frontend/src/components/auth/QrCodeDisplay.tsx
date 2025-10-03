import { useState } from 'react'
import { QRCodeSVG } from 'qrcode.react'
import { Copy, Check } from 'lucide-react'
import { Button } from '../ui/button'
import { Card, CardContent } from '../ui/card'
import { Alert, AlertDescription } from '../ui/alert'

interface QrCodeDisplayProps {
  otpauthUrl: string
  secret: string
  issuer?: string
  account?: string
}

export function QrCodeDisplay({
  otpauthUrl,
  secret,
  issuer = 'LeafLock',
  account,
}: QrCodeDisplayProps) {
  const [copied, setCopied] = useState(false)

  const copySecret = async () => {
    try {
      await navigator.clipboard.writeText(secret)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch (err) {
      console.error('Failed to copy secret:', err)
    }
  }

  return (
    <div className="space-y-4">
      <Card className="border-2">
        <CardContent className="pt-6">
          <div className="flex justify-center p-4">
            <QRCodeSVG
              value={otpauthUrl}
              size={200}
              level="H"
              includeMargin={true}
              className="border-4 border-background rounded"
            />
          </div>
        </CardContent>
      </Card>

      <Alert>
        <AlertDescription>
          <div className="space-y-2">
            <p className="text-sm font-medium">
              Scan this QR code with your authenticator app
            </p>
            <p className="text-xs text-muted-foreground">
              Recommended apps: Google Authenticator, Authy, 1Password, or
              Microsoft Authenticator
            </p>
          </div>
        </AlertDescription>
      </Alert>

      <div className="space-y-2">
        <p className="text-sm font-medium">
          Can't scan the code? Enter this secret manually:
        </p>
        <div className="flex items-center gap-2">
          <code className="flex-1 bg-muted px-3 py-2 rounded text-sm font-mono break-all">
            {secret}
          </code>
          <Button
            type="button"
            variant="outline"
            size="icon"
            onClick={copySecret}
            aria-label="Copy secret"
          >
            {copied ? (
              <Check className="h-4 w-4 text-green-500" />
            ) : (
              <Copy className="h-4 w-4" />
            )}
          </Button>
        </div>
        {issuer && account && (
          <p className="text-xs text-muted-foreground">
            Issuer: {issuer} | Account: {account}
          </p>
        )}
      </div>
    </div>
  )
}
