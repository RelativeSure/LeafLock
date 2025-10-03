import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card'
import { Button } from '../ui/button'
import { Alert, AlertDescription } from '../ui/alert'
import { Input } from '../ui/input'
import { Label } from '../ui/label'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '../ui/dialog'
import { AlertTriangle, Loader2 } from 'lucide-react'

interface DeleteAccountProps {
  onDelete: (password: string) => Promise<void>
}

export function DeleteAccount({ onDelete }: DeleteAccountProps) {
  const [step, setStep] = useState<1 | 2 | 3>(1)
  const [password, setPassword] = useState('')
  const [confirmText, setConfirmText] = useState('')
  const [isDeleting, setIsDeleting] = useState(false)
  const [error, setError] = useState('')
  const [dialogOpen, setDialogOpen] = useState(false)

  const handleReset = () => {
    setStep(1)
    setPassword('')
    setConfirmText('')
    setError('')
    setDialogOpen(false)
  }

  const handleContinueStep1 = () => {
    setStep(2)
    setError('')
  }

  const handleContinueStep2 = () => {
    if (!password.trim()) {
      setError('Password is required')
      return
    }
    setStep(3)
    setError('')
  }

  const handleContinueStep3 = () => {
    if (confirmText !== 'DELETE') {
      setError('Please type DELETE exactly to confirm')
      return
    }
    setDialogOpen(true)
    setError('')
  }

  const handleFinalDelete = async () => {
    setIsDeleting(true)
    setError('')

    try {
      await onDelete(password)
      handleReset()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete account')
      setDialogOpen(false)
    } finally {
      setIsDeleting(false)
    }
  }

  const handleBack = () => {
    if (step > 1) {
      setStep((step - 1) as 1 | 2 | 3)
      setError('')
    }
  }

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex items-center gap-3">
            <AlertTriangle className="h-6 w-6 text-destructive" />
            <div>
              <CardTitle>Delete Account</CardTitle>
              <CardDescription>
                Permanently delete your account and all associated data
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          {/* Step 1: Warning */}
          {step === 1 && (
            <div className="space-y-4">
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>
                  <div className="space-y-2">
                    <p className="font-semibold">This action cannot be undone.</p>
                    <p className="text-sm">Deleting your account will:</p>
                    <ul className="list-disc list-inside text-sm space-y-1 ml-2">
                      <li>Permanently delete all your notes and data</li>
                      <li>Remove your encryption keys (data cannot be recovered)</li>
                      <li>Invalidate all active sessions</li>
                      <li>Delete your user profile and settings</li>
                    </ul>
                  </div>
                </AlertDescription>
              </Alert>

              <Button
                variant="destructive"
                onClick={handleContinueStep1}
                className="w-full"
              >
                I Understand, Continue
              </Button>
            </div>
          )}

          {/* Step 2: Password Confirmation */}
          {step === 2 && (
            <div className="space-y-4">
              <Alert>
                <AlertDescription>
                  Enter your password to verify your identity before proceeding.
                </AlertDescription>
              </Alert>

              <div className="space-y-2">
                <Label htmlFor="delete-password">Your Password</Label>
                <Input
                  id="delete-password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && password.trim()) {
                      handleContinueStep2()
                    }
                  }}
                />
              </div>

              <div className="flex gap-2">
                <Button variant="outline" onClick={handleBack} className="flex-1">
                  Back
                </Button>
                <Button
                  variant="destructive"
                  onClick={handleContinueStep2}
                  disabled={!password.trim()}
                  className="flex-1"
                >
                  Continue
                </Button>
              </div>
            </div>
          )}

          {/* Step 3: Type DELETE Confirmation */}
          {step === 3 && (
            <div className="space-y-4">
              <Alert variant="destructive">
                <AlertDescription>
                  <p className="font-semibold mb-2">Final confirmation required</p>
                  <p className="text-sm">
                    Type <span className="font-mono font-bold">DELETE</span> below to
                    confirm you want to permanently delete your account.
                  </p>
                </AlertDescription>
              </Alert>

              <div className="space-y-2">
                <Label htmlFor="delete-confirm">Type DELETE to confirm</Label>
                <Input
                  id="delete-confirm"
                  type="text"
                  value={confirmText}
                  onChange={(e) => setConfirmText(e.target.value)}
                  placeholder="DELETE"
                  className="font-mono"
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && confirmText === 'DELETE') {
                      handleContinueStep3()
                    }
                  }}
                />
              </div>

              <div className="flex gap-2">
                <Button variant="outline" onClick={handleBack} className="flex-1">
                  Back
                </Button>
                <Button
                  variant="destructive"
                  onClick={handleContinueStep3}
                  disabled={confirmText !== 'DELETE'}
                  className="flex-1"
                >
                  Delete My Account
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Final Confirmation Dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Are you absolutely sure?</DialogTitle>
            <DialogDescription>
              This is your last chance to cancel. Once confirmed, your account and all
              data will be permanently deleted.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>
                This action is irreversible. All your data will be lost forever.
              </AlertDescription>
            </Alert>

            <div className="flex gap-2 justify-end">
              <Button
                variant="outline"
                onClick={() => setDialogOpen(false)}
                disabled={isDeleting}
              >
                Cancel
              </Button>
              <Button
                variant="destructive"
                onClick={handleFinalDelete}
                disabled={isDeleting}
              >
                {isDeleting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Yes, Delete My Account
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </>
  )
}
