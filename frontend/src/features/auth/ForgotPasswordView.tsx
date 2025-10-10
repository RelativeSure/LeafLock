import { useState, type FC } from 'react'
import { Lock, ArrowLeft, Mail } from 'lucide-react'

import Footer from '@/components/Footer'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

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
      const message = err instanceof Error && err.message
        ? err.message
        : 'Failed to request password reset. Please try again.'
      setError(message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="h-screen overflow-y-auto bg-background flex flex-col items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="space-y-1">
          <div className="flex items-center justify-center mb-4">
            <div className="flex items-center space-x-2">
              <Lock className="h-8 w-8 text-primary" />
              <CardTitle className="text-2xl">LeafLock</CardTitle>
            </div>
          </div>
          <CardTitle className="text-xl text-center">Reset your password</CardTitle>
          <CardDescription className="text-center">
            Enter your email address and we'll send you a password reset link
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
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
              <Alert className="border-green-500 bg-green-50 dark:bg-green-950/30">
                <Mail className="h-4 w-4 text-green-600 dark:text-green-400" />
                <AlertDescription className="text-green-900 dark:text-green-100">
                  If an account with that email exists, a password reset link has been sent. Please check your inbox.
                </AlertDescription>
              </Alert>
            )}

            <Button type="submit" className="w-full" disabled={loading || success}>
              {loading ? 'Sending...' : success ? 'Email Sent' : 'Send Reset Link'}
            </Button>

            <Button
              type="button"
              variant="ghost"
              className="w-full"
              onClick={onBackToLogin}
            >
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to Login
            </Button>
          </form>
        </CardContent>
      </Card>

      <Footer variant="minimal" />
    </div>
  )
}
