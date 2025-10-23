import { useState, type FC } from 'react'
import { PenLine, ArrowLeft, Mail } from 'lucide-react'

import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { ThemeToggle } from '@/components/common/ThemeToggle'

interface ForgotPasswordApi {
  requestPasswordReset: (email: string) => Promise<{ message: string }>
}

export interface ForgotPasswordViewProps {
  api: ForgotPasswordApi
  onBackToLogin?: () => void
}

export const ForgotPasswordView: FC<ForgotPasswordViewProps> = ({ api, onBackToLogin }) => {
  const [email, setEmail] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setSuccess(false)
    setLoading(true)

    try {
      await api.requestPasswordReset(email)
      setSuccess(true)
      setEmail('') // Clear email field after success
    } catch (err) {
      const message =
        err instanceof Error && err.message
          ? err.message
          : 'Failed to request password reset. Please try again.'
      setError(message)
    } finally {
      setLoading(false)
    }
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
            <h1 className="text-3xl font-bold text-foreground text-balance">Reset your password</h1>
            <p className="text-muted-foreground leading-relaxed">
              Enter your email address and we'll send you a password reset link
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  id="email"
                  name="email"
                  type="email"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  required
                  autoComplete="username email"
                  autoCapitalize="none"
                  autoCorrect="off"
                  inputMode="email"
                  placeholder="Enter your email"
                  className="pl-10"
                  disabled={loading || success}
                />
              </div>
            </div>

            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            {success && (
              <Alert className="border border-primary/40 bg-primary/10 dark:bg-primary/15">
                <Mail className="h-4 w-4 text-primary" />
                <AlertDescription className="text-foreground">
                  If an account with that email exists, a password reset link has been sent. Please
                  check your inbox.
                </AlertDescription>
              </Alert>
            )}

            <Button
              type="submit"
              className="w-full bg-primary text-primary-foreground hover:bg-primary/90"
              disabled={loading || success}
            >
              {loading ? 'Sending...' : success ? 'Email Sent' : 'Send Reset Link'}
            </Button>

            <Button type="button" variant="ghost" className="w-full" onClick={onBackToLogin}>
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to Login
            </Button>
          </form>
        </div>
      </div>
    </div>
  )
}

export default ForgotPasswordView
