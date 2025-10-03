import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card'
import { Button } from '../ui/button'
import { Alert, AlertDescription } from '../ui/alert'
import { Badge } from '../ui/badge'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '../ui/dialog'
import { Input } from '../ui/input'
import { Label } from '../ui/label'
import { MfaSetupDialog } from '../auth/MfaSetupDialog'
import { TotpInput } from '../auth/TotpInput'
import { MfaBackupCodes } from '../auth/MfaBackupCodes'
import { Shield, ShieldCheck, ShieldAlert, Key, RefreshCw, Loader2 } from 'lucide-react'

interface MfaSettingsProps {
  // API methods - implement these in your ApiClient
  onGetMfaStatus: () => Promise<{ enabled: boolean; has_secret: boolean }>
  onBeginMfaSetup: () => Promise<{
    secret: string
    otpauth_url: string
    issuer?: string
    account?: string
  }>
  onEnableMfa: (code: string) => Promise<{ backup_codes?: string[] }>
  onDisableMfa: (code: string) => Promise<{ enabled: boolean }>
  onGetBackupCodes: () => Promise<{ total: number; remaining: number }>
  onRegenerateBackupCodes: (password: string) => Promise<{ codes: string[] }>
}

export function MfaSettings({
  onGetMfaStatus,
  onBeginMfaSetup,
  onEnableMfa,
  onDisableMfa,
  onGetBackupCodes,
  onRegenerateBackupCodes,
}: MfaSettingsProps) {
  const [mfaEnabled, setMfaEnabled] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')

  // Setup dialog state
  const [setupDialogOpen, setSetupDialogOpen] = useState(false)
  const [setupData, setSetupData] = useState<any>(null)

  // Disable MFA dialog state
  const [disableDialogOpen, setDisableDialogOpen] = useState(false)
  const [disableCode, setDisableCode] = useState('')
  const [isDisabling, setIsDisabling] = useState(false)

  // Backup codes state
  const [backupCodesDialogOpen, setBackupCodesDialogOpen] = useState(false)
  const [backupCodesInfo, setBackupCodesInfo] = useState<{
    total: number
    remaining: number
  } | null>(null)

  // Regenerate backup codes dialog state
  const [regenerateDialogOpen, setRegenerateDialogOpen] = useState(false)
  const [regeneratePassword, setRegeneratePassword] = useState('')
  const [newBackupCodes, setNewBackupCodes] = useState<string[]>([])
  const [isRegenerating, setIsRegenerating] = useState(false)

  // Load MFA status on mount
  useState(() => {
    loadMfaStatus()
  })

  const loadMfaStatus = async () => {
    try {
      const status = await onGetMfaStatus()
      setMfaEnabled(status.enabled)
    } catch (err) {
      console.error('Failed to load MFA status:', err)
    }
  }

  const handleBeginSetup = async () => {
    setIsLoading(true)
    setError('')

    try {
      const data = await onBeginMfaSetup()
      setSetupData(data)
      setSetupDialogOpen(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to begin MFA setup')
    } finally {
      setIsLoading(false)
    }
  }

  const handleSetupComplete = () => {
    setMfaEnabled(true)
    setSetupDialogOpen(false)
    setSetupData(null)
  }

  const handleDisableMfa = async () => {
    if (disableCode.length !== 6) return

    setIsDisabling(true)
    setError('')

    try {
      await onDisableMfa(disableCode)
      setMfaEnabled(false)
      setDisableDialogOpen(false)
      setDisableCode('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to disable MFA')
    } finally {
      setIsDisabling(false)
    }
  }

  const handleViewBackupCodes = async () => {
    setIsLoading(true)
    setError('')

    try {
      const info = await onGetBackupCodes()
      setBackupCodesInfo(info)
      setBackupCodesDialogOpen(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load backup codes')
    } finally {
      setIsLoading(false)
    }
  }

  const handleRegenerateBackupCodes = async () => {
    if (!regeneratePassword.trim()) return

    setIsRegenerating(true)
    setError('')

    try {
      const result = await onRegenerateBackupCodes(regeneratePassword)
      setNewBackupCodes(result.codes)
      setRegeneratePassword('')
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Failed to regenerate backup codes'
      )
    } finally {
      setIsRegenerating(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Main MFA Status Card */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              {mfaEnabled ? (
                <ShieldCheck className="h-6 w-6 text-green-500" />
              ) : (
                <ShieldAlert className="h-6 w-6 text-yellow-500" />
              )}
              <div>
                <CardTitle>Multi-Factor Authentication</CardTitle>
                <CardDescription>
                  Add an extra layer of security to your account
                </CardDescription>
              </div>
            </div>
            <Badge variant={mfaEnabled ? 'default' : 'secondary'}>
              {mfaEnabled ? 'Enabled' : 'Disabled'}
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          {!mfaEnabled ? (
            <>
              <p className="text-sm text-muted-foreground">
                Two-factor authentication (2FA) adds an additional layer of security by
                requiring a code from your authenticator app in addition to your
                password.
              </p>
              <Button onClick={handleBeginSetup} disabled={isLoading}>
                {isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                <Shield className="mr-2 h-4 w-4" />
                Enable MFA
              </Button>
            </>
          ) : (
            <div className="space-y-4">
              <Alert>
                <ShieldCheck className="h-4 w-4" />
                <AlertDescription>
                  Your account is protected with two-factor authentication. You'll need
                  your authenticator app to sign in.
                </AlertDescription>
              </Alert>

              <div className="flex gap-2">
                <Button
                  variant="destructive"
                  onClick={() => setDisableDialogOpen(true)}
                >
                  Disable MFA
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Backup Codes Card (only shown when MFA is enabled) */}
      {mfaEnabled && (
        <Card>
          <CardHeader>
            <div className="flex items-center gap-3">
              <Key className="h-5 w-5 text-muted-foreground" />
              <div>
                <CardTitle className="text-lg">Backup Recovery Codes</CardTitle>
                <CardDescription>
                  Emergency codes for account access without your authenticator device
                </CardDescription>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Backup codes are one-time use codes that allow you to access your account
              if you lose access to your authenticator app.
            </p>

            <div className="flex gap-2">
              <Button
                variant="outline"
                onClick={handleViewBackupCodes}
                disabled={isLoading}
              >
                View Backup Code Status
              </Button>
              <Button
                variant="outline"
                onClick={() => setRegenerateDialogOpen(true)}
              >
                <RefreshCw className="mr-2 h-4 w-4" />
                Regenerate Backup Codes
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* MFA Setup Dialog */}
      <MfaSetupDialog
        open={setupDialogOpen}
        onOpenChange={setSetupDialogOpen}
        setupData={setupData}
        onVerify={onEnableMfa}
        onComplete={handleSetupComplete}
      />

      {/* Disable MFA Dialog */}
      <Dialog open={disableDialogOpen} onOpenChange={setDisableDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Disable Two-Factor Authentication</DialogTitle>
            <DialogDescription>
              Enter your current 6-digit authentication code to disable MFA
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <Alert variant="destructive">
              <AlertDescription>
                Disabling MFA will make your account less secure. You'll only need your
                password to sign in.
              </AlertDescription>
            </Alert>

            <div className="space-y-2">
              <Label>Authentication Code</Label>
              <TotpInput
                value={disableCode}
                onChange={setDisableCode}
                onComplete={handleDisableMfa}
                disabled={isDisabling}
                error={!!error}
              />
              {error && <p className="text-sm text-red-500">{error}</p>}
            </div>

            <div className="flex gap-2 justify-end">
              <Button
                variant="outline"
                onClick={() => {
                  setDisableDialogOpen(false)
                  setDisableCode('')
                  setError('')
                }}
                disabled={isDisabling}
              >
                Cancel
              </Button>
              <Button
                variant="destructive"
                onClick={handleDisableMfa}
                disabled={disableCode.length !== 6 || isDisabling}
              >
                {isDisabling && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Disable MFA
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Backup Codes Info Dialog */}
      <Dialog open={backupCodesDialogOpen} onOpenChange={setBackupCodesDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Backup Code Status</DialogTitle>
            <DialogDescription>
              Information about your backup recovery codes
            </DialogDescription>
          </DialogHeader>

          {backupCodesInfo && (
            <div className="space-y-4 py-4">
              <div className="grid grid-cols-2 gap-4">
                <Card>
                  <CardHeader className="pb-3">
                    <CardDescription>Total Codes</CardDescription>
                    <CardTitle className="text-3xl">
                      {backupCodesInfo.total}
                    </CardTitle>
                  </CardHeader>
                </Card>
                <Card>
                  <CardHeader className="pb-3">
                    <CardDescription>Remaining</CardDescription>
                    <CardTitle className="text-3xl">
                      {backupCodesInfo.remaining}
                    </CardTitle>
                  </CardHeader>
                </Card>
              </div>

              {backupCodesInfo.remaining < 3 && (
                <Alert variant="destructive">
                  <AlertDescription>
                    You're running low on backup codes. Consider regenerating them.
                  </AlertDescription>
                </Alert>
              )}

              <Alert>
                <AlertDescription className="text-xs">
                  Backup codes are stored securely and cannot be viewed in plaintext. If
                  you need new codes, you can regenerate them at any time.
                </AlertDescription>
              </Alert>

              <div className="flex justify-end">
                <Button onClick={() => setBackupCodesDialogOpen(false)}>Close</Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Regenerate Backup Codes Dialog */}
      <Dialog open={regenerateDialogOpen} onOpenChange={setRegenerateDialogOpen}>
        <DialogContent className="sm:max-w-[600px]">
          <DialogHeader>
            <DialogTitle>Regenerate Backup Codes</DialogTitle>
            <DialogDescription>
              {newBackupCodes.length > 0
                ? 'Save these new backup codes securely'
                : 'Generate new backup recovery codes'}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            {newBackupCodes.length === 0 ? (
              <>
                <Alert variant="destructive">
                  <AlertDescription>
                    Regenerating backup codes will invalidate all your existing codes,
                    including any unused ones.
                  </AlertDescription>
                </Alert>

                <div className="space-y-2">
                  <Label htmlFor="password">Confirm Your Password</Label>
                  <Input
                    id="password"
                    type="password"
                    value={regeneratePassword}
                    onChange={(e) => setRegeneratePassword(e.target.value)}
                    placeholder="Enter your password"
                    disabled={isRegenerating}
                  />
                </div>

                {error && <p className="text-sm text-red-500">{error}</p>}

                <div className="flex gap-2 justify-end">
                  <Button
                    variant="outline"
                    onClick={() => {
                      setRegenerateDialogOpen(false)
                      setRegeneratePassword('')
                      setError('')
                    }}
                    disabled={isRegenerating}
                  >
                    Cancel
                  </Button>
                  <Button
                    onClick={handleRegenerateBackupCodes}
                    disabled={!regeneratePassword.trim() || isRegenerating}
                  >
                    {isRegenerating && (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    )}
                    Generate New Codes
                  </Button>
                </div>
              </>
            ) : (
              <MfaBackupCodes
                codes={newBackupCodes}
                onAcknowledge={() => {
                  setRegenerateDialogOpen(false)
                  setNewBackupCodes([])
                  setRegeneratePassword('')
                }}
              />
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}
