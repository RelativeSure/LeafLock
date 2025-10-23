import { useState, useEffect, type FC } from 'react'
import { PenLine, Eye, EyeOff, CheckCircle } from 'lucide-react'

import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { InputGroup, InputGroupButton, InputGroupInput } from '@/components/ui/input-group'
import { Label } from '@/components/ui/label'
import { ThemeToggle } from '@/components/common/ThemeToggle'
import { cn } from '@/lib/utils'

interface ResetPasswordApi {
  verifyResetToken: (token: string) => Promise<{ valid: boolean }>
  confirmPasswordReset: (token: string, newPassword: string) => Promise<{ message: string }>
}

export interface ResetPasswordViewProps {
  api: ResetPasswordApi
  token: string
  onResetComplete?: () => void
}

export const ResetPasswordView: FC<ResetPasswordViewProps> = ({ api, token, onResetComplete }) => {
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [passwordStrength, setPasswordStrength] = useState(0)
  const [loading, setLoading] = useState(false)
  const [verifying, setVerifying] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)
  const [tokenValid, setTokenValid] = useState(false)

  useEffect(() => {
    const verifyToken = async () => {
      try {
        const result = await api.verifyResetToken(token)
        setTokenValid(result.valid)
      } catch (err) {
        const message =
          err instanceof Error && err.message ? err.message : 'Invalid or expired reset token'
        setError(message)
        setTokenValid(false)
      } finally {
        setVerifying(false)
      }
    }

    void verifyToken()
  }, [api, token])

  const calculatePasswordStrength = (pwd: string): number => {
    let strength = 0
    if (pwd.length >= 12) strength++
    if (pwd.length >= 16) strength++
    if (/[a-z]/.test(pwd) && /[A-Z]/.test(pwd)) strength++
    if (/[0-9]/.test(pwd)) strength++
    if (/[^A-Za-z0-9]/.test(pwd)) strength++
    return strength
  }

  const handlePasswordChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const pwd = e.target.value
    setNewPassword(pwd)
    setPasswordStrength(calculatePasswordStrength(pwd))
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)

    // Validation
    if (newPassword.length < 12) {
      setError('Password must be at least 12 characters long')
      return
    }

    if (newPassword !== confirmPassword) {
      setError('Passwords do not match')
      return
    }

    setLoading(true)

    try {
      await api.confirmPasswordReset(token, newPassword)
      setSuccess(true)
      setNewPassword('')
      setConfirmPassword('')

      // Redirect to login after 3 seconds
      setTimeout(() => {
        onResetComplete?.()
      }, 3000)
    } catch (err) {
      const message =
        err instanceof Error && err.message
          ? err.message
          : 'Failed to reset password. Please try again.'
      setError(message)
    } finally {
      setLoading(false)
    }
  }

  if (verifying) {
    return (
      <div className="min-h-screen flex items-center justify-center px-4 py-12 bg-background">
        {/* Theme Toggle */}
        <div className="absolute top-4 right-4">
          <ThemeToggle />
        </div>

        <div className="w-full max-w-md space-y-8">
          <div className="flex flex-col items-center gap-2">
            <div className="flex items-center gap-2 group">
              <PenLine className="h-8 w-8 text-accent group-hover:text-accent/80 transition-colors" />
              <span className="text-2xl font-semibold text-foreground">LeafLock</span>
            </div>
          </div>
          <div className="bg-card border border-border rounded-2xl p-8 shadow-sm text-center">
            <p className="text-muted-foreground">Verifying reset link...</p>
          </div>
        </div>
      </div>
    )
  }

  if (!tokenValid) {
    return (
      <div className="min-h-screen flex items-center justify-center px-4 py-12 bg-background">
        {/* Theme Toggle */}
        <div className="absolute top-4 right-4">
          <ThemeToggle />
        </div>

        <div className="w-full max-w-md space-y-8">
          <div className="flex flex-col items-center gap-2">
            <div className="flex items-center gap-2 group">
              <PenLine className="h-8 w-8 text-accent group-hover:text-accent/80 transition-colors" />
              <span className="text-2xl font-semibold text-foreground">LeafLock</span>
            </div>
          </div>
          <div className="bg-card border border-border rounded-2xl p-8 shadow-sm">
            <div className="space-y-2 text-center mb-8">
              <h1 className="text-3xl font-bold text-foreground text-balance">
                Invalid Reset Link
              </h1>
            </div>
            <Alert variant="destructive">
              <AlertDescription>
                {error ||
                  'This password reset link is invalid or has expired. Please request a new one.'}
              </AlertDescription>
            </Alert>
            <Button className="w-full mt-4" onClick={onResetComplete}>
              Back to Login
            </Button>
          </div>
        </div>
      </div>
    )
  }

  if (success) {
    return (
      <div className="min-h-screen flex items-center justify-center px-4 py-12 bg-background">
        {/* Theme Toggle */}
        <div className="absolute top-4 right-4">
          <ThemeToggle />
        </div>

        <div className="w-full max-w-md space-y-8">
          <div className="flex flex-col items-center gap-2">
            <div className="flex items-center gap-2 group">
              <PenLine className="h-8 w-8 text-accent group-hover:text-accent/80 transition-colors" />
              <span className="text-2xl font-semibold text-foreground">LeafLock</span>
            </div>
          </div>
          <div className="bg-card border border-border rounded-2xl p-8 shadow-sm">
            <div className="space-y-2 text-center mb-8">
              <h1 className="text-3xl font-bold text-foreground text-balance">
                Password Reset Successful
              </h1>
            </div>
            <Alert className="border border-primary/40 bg-primary/10 dark:bg-primary/15">
              <CheckCircle className="h-4 w-4 text-primary" />
              <AlertDescription className="text-foreground">
                Your password has been reset successfully. Redirecting to login...
              </AlertDescription>
            </Alert>
            <Button className="w-full mt-4" onClick={onResetComplete}>
              Continue to Login
            </Button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-4 py-12 bg-background">
      {/* Theme Toggle */}
      <div className="absolute top-4 right-4">
        <ThemeToggle />
      </div>

      <div className="w-full max-w-md space-y-8">
        {/* Logo */}
        <div className="flex flex-col items-center gap-2">
          <div className="flex items-center gap-2 group">
            <PenLine className="h-8 w-8 text-accent group-hover:text-accent/80 transition-colors" />
            <span className="text-2xl font-semibold text-foreground">LeafLock</span>
          </div>
        </div>

        {/* Form Card */}
        <div className="bg-card border border-border rounded-2xl p-8 shadow-sm">
          <div className="space-y-2 text-center mb-8">
            <h1 className="text-3xl font-bold text-foreground text-balance">
              Create a new password
            </h1>
            <p className="text-muted-foreground leading-relaxed">Enter your new password below</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="space-y-2">
              <Label htmlFor="new-password">New Password</Label>
              <InputGroup>
                <InputGroupInput
                  id="new-password"
                  name="new-password"
                  type={showPassword ? 'text' : 'password'}
                  value={newPassword}
                  onChange={handlePasswordChange}
                  required
                  minLength={12}
                  autoComplete="new-password"
                  placeholder="Enter new password"
                  aria-describedby="password-strength"
                />
                <InputGroupButton
                  type="button"
                  variant="ghost"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  onClick={() => setShowPassword((prev) => !prev)}
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </InputGroupButton>
              </InputGroup>
              <div className="space-y-2" id="password-strength">
                <div
                  className="flex space-x-1"
                  role="progressbar"
                  aria-valuenow={passwordStrength}
                  aria-valuemax={5}
                >
                  {[...Array(5)].map((_, index) => (
                    <div
                      key={index}
                      className={cn(
                        'h-2 flex-1 rounded',
                        index < passwordStrength
                          ? passwordStrength <= 2
                            ? 'bg-destructive'
                            : passwordStrength <= 3
                              ? 'bg-yellow-500'
                              : 'bg-primary'
                          : 'bg-muted'
                      )}
                    />
                  ))}
                </div>
                <p className="text-xs text-muted-foreground">
                  Use 12+ characters with mixed case, numbers & symbols
                </p>
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="confirm-password">Confirm Password</Label>
              <InputGroup>
                <InputGroupInput
                  id="confirm-password"
                  name="confirm-password"
                  type={showConfirmPassword ? 'text' : 'password'}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  required
                  minLength={12}
                  autoComplete="new-password"
                  placeholder="Confirm new password"
                />
                <InputGroupButton
                  type="button"
                  variant="ghost"
                  aria-label={showConfirmPassword ? 'Hide password' : 'Show password'}
                  onClick={() => setShowConfirmPassword((prev) => !prev)}
                >
                  {showConfirmPassword ? (
                    <EyeOff className="h-4 w-4" />
                  ) : (
                    <Eye className="h-4 w-4" />
                  )}
                </InputGroupButton>
              </InputGroup>
            </div>

            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <Button
              type="submit"
              className="w-full bg-primary text-primary-foreground hover:bg-primary/90"
              disabled={loading}
            >
              {loading ? 'Resetting...' : 'Reset Password'}
            </Button>
          </form>
        </div>
      </div>
    </div>
  )
}

export default ResetPasswordView
