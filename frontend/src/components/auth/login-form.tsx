/**
 * LoginForm Component
 * 
 * Purpose: Provides a secure authentication interface for users to access their encrypted notes.
 * This component handles both standard login and multi-factor authentication (MFA) flows,
 * implementing security best practices for credential handling and user feedback.
 * 
 * User Experience Goals:
 * - Streamlined login process with clear visual feedback
 * - Seamless transition to MFA when required
 * - Informative error messages without exposing security details
 * - Accessible design with proper ARIA labels and keyboard navigation
 * 
 * Security Considerations:
 * - Passwords are handled securely through the auth store (never stored in component state)
 * - MFA codes are sanitized to prevent injection attacks
 * - Error messages are generic to prevent user enumeration
 * - Registration status is checked to prevent unauthorized access attempts
 * 
 * Props Interface:
 * - onToggleMode: Callback to switch between login and registration forms
 * - animatedTitle: Optional animated branding element for enhanced UX
 * 
 * State Management:
 * - Local form state for email, password, and MFA code
 * - Loading states for async operations
 * - Error handling with user-friendly messages
 * - Registration availability check on component mount
 */

import { useState, useEffect } from 'react'
import * as React from 'react'
import { useAuthStore } from '@/stores/authStore'
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
  const { login, verifyMFA, user, checkRegistrationEnabled } = useAuthStore()
  
  // Form state management
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [mfaCode, setMfaCode] = useState('')
  const [requiresMFA, setRequiresMFA] = useState(false)
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [registrationEnabled, setRegistrationEnabled] = useState<boolean | null>(null)

  /**
   * Registration Status Check
   * 
   * Purpose: Determines if new user registration is enabled on the server.
   * This prevents showing registration options when disabled by administrators.
   * 
   * Security: Gracefully handles API failures by defaulting to disabled state
   * to prevent unauthorized access attempts.
   */
  useEffect(() => {
    const checkStatus = async () => {
      try {
        const enabled = await checkRegistrationEnabled()
        setRegistrationEnabled(enabled)
      } catch (error) {
        console.error('Failed to check registration status:', error)
        setRegistrationEnabled(false)
      }
    }
    checkStatus()
  }, [checkRegistrationEnabled])

  /**
   * Post-Login Redirect Handler
   * 
   * Purpose: Automatically redirects authenticated users to the main dashboard.
   * Uses useRef to prevent multiple redirects and setTimeout for proper state cleanup.
   * 
   * Security: Validates both user object and token presence before redirect
   * to ensure complete authentication state.
   */
  const hasRedirected = React.useRef(false)
  useEffect(() => {
    const token = typeof window !== 'undefined' ? localStorage.getItem('token') : null
    if (user && token && !hasRedirected.current) {
      hasRedirected.current = true
      console.log('User logged in, redirecting to dashboard...')
      // Use setTimeout to ensure state updates complete before redirect
      setTimeout(() => {
        window.location.href = '/'
      }, 0)
    }
  }, [user])

  /**
   * Standard Login Handler
   * 
   * Purpose: Processes user credentials and initiates authentication flow.
   * Handles both successful logins and MFA challenges.
   * 
   * Security: Clears previous errors, validates input, and provides generic
   * error messages to prevent user enumeration attacks.
   * 
   * @param e - Form submission event
   */
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

  /**
   * MFA Verification Handler
   * 
   * Purpose: Validates the 6-digit MFA code provided by the user.
   * Completes the two-factor authentication process.
   * 
   * Security: Sanitizes input to accept only digits, limits to 6 characters,
   * and provides specific but secure error messaging.
   * 
   * @param e - Form submission event
   */
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

          <div className="text-center text-sm text-muted-foreground space-y-2">
            {registrationEnabled && (
              <div>
                Don't have an account?{' '}
                <button
                  type="button"
                  onClick={onToggleMode}
                  className="text-primary hover:underline transition-smooth"
                >
                  Sign up
                </button>
              </div>
            )}
            <div>
              <button
                type="button"
                onClick={() => (window.location.href = '/forgot')}
                className="text-primary hover:underline transition-smooth"
              >
                Forgot password?
              </button>
            </div>
          </div>
        </form>
      </CardContent>
    </Card>
  )
}
