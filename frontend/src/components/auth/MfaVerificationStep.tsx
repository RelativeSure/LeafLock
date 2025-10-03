import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card'
import { Button } from '../ui/button'
import { Alert, AlertDescription } from '../ui/alert'
import { TotpInput } from './TotpInput'
import { Loader2, Shield } from 'lucide-react'

interface MfaVerificationStepProps {
  sessionToken: string
  onVerify: (code: string, isBackupCode: boolean) => Promise<void>
  onCancel: () => void
}

export function MfaVerificationStep({
  sessionToken,
  onVerify,
  onCancel,
}: MfaVerificationStepProps) {
  const [totpCode, setTotpCode] = useState('')
  const [backupCode, setBackupCode] = useState('')
  const [isVerifying, setIsVerifying] = useState(false)
  const [error, setError] = useState('')
  const [useBackupCode, setUseBackupCode] = useState(false)

  const handleVerifyTotp = async (code: string) => {
    if (code.length !== 6) return

    setIsVerifying(true)
    setError('')

    try {
      await onVerify(code, false)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid code. Please try again.')
      setTotpCode('')
    } finally {
      setIsVerifying(false)
    }
  }

  const handleVerifyBackup = async () => {
    if (!backupCode.trim()) return

    setIsVerifying(true)
    setError('')

    try {
      await onVerify(backupCode.trim(), true)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid backup code. Please try again.')
      setBackupCode('')
    } finally {
      setIsVerifying(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center space-y-2">
          <div className="mx-auto w-12 h-12 bg-primary/10 rounded-full flex items-center justify-center">
            <Shield className="h-6 w-6 text-primary" />
          </div>
          <CardTitle>Two-Factor Authentication</CardTitle>
          <CardDescription>
            {useBackupCode
              ? 'Enter one of your backup recovery codes'
              : 'Enter the 6-digit code from your authenticator app'}
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-4">
          {!useBackupCode ? (
            <>
              <TotpInput
                value={totpCode}
                onChange={setTotpCode}
                onComplete={handleVerifyTotp}
                disabled={isVerifying}
                error={!!error}
              />

              <Button
                className="w-full"
                onClick={() => handleVerifyTotp(totpCode)}
                disabled={totpCode.length !== 6 || isVerifying}
              >
                {isVerifying && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {isVerifying ? 'Verifying...' : 'Verify Code'}
              </Button>

              <div className="relative">
                <div className="absolute inset-0 flex items-center">
                  <span className="w-full border-t" />
                </div>
                <div className="relative flex justify-center text-xs uppercase">
                  <span className="bg-background px-2 text-muted-foreground">Or</span>
                </div>
              </div>

              <Button
                variant="outline"
                className="w-full"
                onClick={() => setUseBackupCode(true)}
                disabled={isVerifying}
              >
                Use Backup Code Instead
              </Button>
            </>
          ) : (
            <>
              <div className="space-y-2">
                <input
                  type="text"
                  value={backupCode}
                  onChange={(e) => setBackupCode(e.target.value)}
                  placeholder="XXXX-XXXX-XXXX-XXXX"
                  className="w-full px-3 py-2 border rounded-md font-mono text-center uppercase"
                  disabled={isVerifying}
                  maxLength={19}
                />
                <p className="text-xs text-muted-foreground text-center">
                  Enter your 16-character backup code
                </p>
              </div>

              <Button
                className="w-full"
                onClick={handleVerifyBackup}
                disabled={!backupCode.trim() || isVerifying}
              >
                {isVerifying && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {isVerifying ? 'Verifying...' : 'Verify Backup Code'}
              </Button>

              <Button
                variant="outline"
                className="w-full"
                onClick={() => {
                  setUseBackupCode(false)
                  setBackupCode('')
                  setError('')
                }}
                disabled={isVerifying}
              >
                Back to Authenticator Code
              </Button>
            </>
          )}

          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          <Button variant="ghost" className="w-full" onClick={onCancel} disabled={isVerifying}>
            Cancel
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
