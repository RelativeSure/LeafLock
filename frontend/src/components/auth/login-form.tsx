import { useState, useEffect } from 'react'
import { useAuthStore } from '@/stores'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Shield, Lock, Mail } from 'lucide-react'

export function LoginForm({
  onToggleMode,
  animatedTitle,
}: {
  onToggleMode: () => void
  animatedTitle?: React.ReactNode
}) {
  const { login, verifyMFA, user } = useAuthStore()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [mfaCode, setMfaCode] = useState('')
  const [requiresMFA, setRequiresMFA] = useState(false)
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(false)

  // Redirect to dashboard after successful login
  useEffect(() => {
    if (user) {
      console.log('User logged in, redirecting to dashboard...')
      window.location.href = '/dashboard'
    }
  }, [user])

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setIsLoading(true)

    try {
      const result = await login(email, password)
      if (result.requiresMFA) {
        setRequiresMFA(true)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setIsLoading(false)
    }
  }

  const handleMFAVerify = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setIsLoading(true)

    try {
      const success = await verifyMFA(mfaCode)
      if (!success) {
        setError('Invalid MFA code')
      }
      // If successful, the useEffect will handle the redirect
    } catch (err) {
      setError('MFA verification failed')
    } finally {
      setIsLoading(false)
    }
  }

  if (requiresMFA) {
    return (
      <Card className="w-full max-w-md animate-scale-in hover-lift">
        <CardHeader className="space-y-1">
          <div className="flex items-center justify-center w-12 h-12 rounded-full bg-primary/10 mb-4 mx-auto animate-bounce-in">
            <Shield className="w-6 h-6 text-primary" />
          </div>
          <CardTitle className="text-2xl text-center">Two-Factor Authentication</CardTitle>
          <CardDescription className="text-center">
            Enter the 6-digit code from your authenticator app
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleMFAVerify} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="mfa-code">Authentication Code</Label>
              <Input
                id="mfa-code"
                type="text"
                placeholder="000000"
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                maxLength={6}
                className="text-center text-2xl tracking-widest focus:animate-pulse-glow transition-smooth"
                autoFocus
              />
            </div>

            {error && (
              <div className="text-sm text-danger bg-danger/10 p-3 rounded-md animate-slide-in">
                {error}
              </div>
            )}

            <Button
              type="submit"
              className="w-full transition-bounce hover-lift"
              disabled={isLoading || mfaCode.length !== 6}
            >
              {isLoading ? 'Verifying...' : 'Verify'}
            </Button>

            <Button
              type="button"
              variant="ghost"
              className="w-full transition-smooth"
              onClick={() => setRequiresMFA(false)}
            >
              Back to login
            </Button>
          </form>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="w-full max-w-md animate-scale-in hover-lift">
      <CardHeader className="space-y-4">
        <div className="flex items-center justify-center mx-auto">
          <h1 className="text-4xl font-semibold tracking-tight text-slate-100">
            {animatedTitle ? null : 'LeafLock'}
          </h1>
          {animatedTitle}
        </div>
        <div className="space-y-2">
          <p className="text-center text-base text-slate-300 font-normal">
            End-to-End Encrypted Note Taking
          </p>
          <p className="text-center text-sm text-slate-400 font-light">
            Sign in to access your secure notes
          </p>
        </div>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleLogin} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="email">Email</Label>
            <div className="relative">
              <Mail className="absolute left-3 top-3 h-4 w-4 text-muted transition-smooth" />
              <Input
                id="email"
                type="email"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="pl-10 transition-smooth"
                required
              />
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="password">Password</Label>
            <div className="relative">
              <Lock className="absolute left-3 top-3 h-4 w-4 text-muted transition-smooth" />
              <Input
                id="password"
                type="password"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="pl-10 transition-smooth"
                required
              />
            </div>
          </div>

          {error && (
            <div className="text-sm text-danger bg-danger/10 p-3 rounded-md animate-slide-in">
              {error}
            </div>
          )}

          <Button
            type="submit"
            className="w-full transition-bounce hover-lift"
            disabled={isLoading}
          >
            {isLoading ? 'Signing in...' : 'Sign in'}
          </Button>

          <div className="text-center text-sm text-muted-foreground">
            Don't have an account?{' '}
            <button
              type="button"
              onClick={onToggleMode}
              className="text-primary hover:underline transition-smooth"
            >
              Sign up
            </button>
          </div>
        </form>
      </CardContent>
    </Card>
  )
}
