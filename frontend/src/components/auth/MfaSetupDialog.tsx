import { useState } from 'react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '../ui/dialog'
import { Button } from '../ui/button'
import { Alert, AlertDescription } from '../ui/alert'
import { QrCodeDisplay } from './QrCodeDisplay'
import { TotpInput } from './TotpInput'
import { MfaBackupCodes } from './MfaBackupCodes'
import { Loader2 } from 'lucide-react'

interface MfaSetupData {
  secret: string
  otpauth_url: string
  issuer?: string
  account?: string
}

interface MfaSetupDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  setupData: MfaSetupData | null
  onVerify: (code: string) => Promise<{ backup_codes?: string[] }>
  onComplete: () => void
}

export function MfaSetupDialog({
  open,
  onOpenChange,
  setupData,
  onVerify,
  onComplete,
}: MfaSetupDialogProps) {
  const [step, setStep] = useState<'qr' | 'verify' | 'backup'>('qr')
  const [totpCode, setTotpCode] = useState('')
  const [backupCodes, setBackupCodes] = useState<string[]>([])
  const [isVerifying, setIsVerifying] = useState(false)
  const [error, setError] = useState('')

  const handleVerifyCode = async (code: string) => {
    if (code.length !== 6) return

    setIsVerifying(true)
    setError('')

    try {
      const result = await onVerify(code)
      if (result.backup_codes) {
        setBackupCodes(result.backup_codes)
        setStep('backup')
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid code. Please try again.')
      setTotpCode('')
    } finally {
      setIsVerifying(false)
    }
  }

  const handleClose = () => {
    setStep('qr')
    setTotpCode('')
    setBackupCodes([])
    setError('')
    onOpenChange(false)
  }

  const handleComplete = () => {
    handleClose()
    onComplete()
  }

  if (!setupData) return null

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[600px]">
        <DialogHeader>
          <DialogTitle>
            {step === 'qr' && 'Set Up Two-Factor Authentication'}
            {step === 'verify' && 'Verify Your Code'}
            {step === 'backup' && 'Save Your Backup Codes'}
          </DialogTitle>
          <DialogDescription>
            {step === 'qr' && 'Scan this QR code with your authenticator app'}
            {step === 'verify' && 'Enter the 6-digit code from your authenticator app'}
            {step === 'backup' && 'Save these codes in a secure location'}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          {step === 'qr' && (
            <>
              <QrCodeDisplay
                otpauthUrl={setupData.otpauth_url}
                secret={setupData.secret}
                issuer={setupData.issuer}
                account={setupData.account}
              />
              <div className="flex justify-end">
                <Button onClick={() => setStep('verify')}>Next Step</Button>
              </div>
            </>
          )}

          {step === 'verify' && (
            <div className="space-y-4">
              <Alert>
                <AlertDescription>
                  Enter the 6-digit code from your authenticator app to verify the setup
                </AlertDescription>
              </Alert>

              <div className="space-y-2">
                <TotpInput
                  value={totpCode}
                  onChange={setTotpCode}
                  onComplete={handleVerifyCode}
                  disabled={isVerifying}
                  error={!!error}
                />
                {error && (
                  <p id="totp-error" className="text-sm text-red-500 text-center">
                    {error}
                  </p>
                )}
              </div>

              <div className="flex gap-2 justify-between">
                <Button variant="outline" onClick={() => setStep('qr')} disabled={isVerifying}>
                  Back
                </Button>
                <Button
                  onClick={() => handleVerifyCode(totpCode)}
                  disabled={totpCode.length !== 6 || isVerifying}
                >
                  {isVerifying && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  {isVerifying ? 'Verifying...' : 'Verify & Enable'}
                </Button>
              </div>
            </div>
          )}

          {step === 'backup' && (
            <MfaBackupCodes codes={backupCodes} onAcknowledge={handleComplete} />
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}
