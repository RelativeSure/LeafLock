import { useEffect, useState, type FC } from 'react'
import { Lock, Info, MessageSquare, Book, Eye, EyeOff } from 'lucide-react'

import AnnouncementBanner, { type Announcement } from '@/components/AnnouncementBanner'
import Footer from '@/components/Footer'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { InputGroup, InputGroupButton, InputGroupInput } from '@/components/ui/input-group'
import { Label } from '@/components/ui/label'
import type { AuthResponse } from '@/types/auth'
import { cn } from '@/lib/utils'

interface AuthApi {
  getRegistrationStatus: () => Promise<{ enabled?: boolean }>
  register: (email: string, password: string) => Promise<AuthResponse>
  login: (email: string, password: string, mfaCode?: string) => Promise<AuthResponse>
}

interface CryptoServiceLike {
  initSodium: () => Promise<void>
  generateSalt: () => Promise<Uint8Array>
  deriveKeyFromPassword: (password: string, salt: Uint8Array) => Promise<Uint8Array>
  setMasterKey: (key: Uint8Array) => Promise<void>
}

export interface LoginViewProps {
  api: AuthApi
  cryptoService: CryptoServiceLike
  announcements?: Announcement[]
  onAuthenticated?: () => Promise<void> | void
}

export const LoginView: FC<LoginViewProps> = ({ api, cryptoService, announcements = [], onAuthenticated }) => {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [mfaCode, setMfaCode] = useState('')
  const [mfaRequired, setMfaRequired] = useState(false)
  const [isRegistering, setIsRegistering] = useState(false)
  const [registrationEnabled, setRegistrationEnabled] = useState(true)
  const [passwordStrength, setPasswordStrength] = useState(0)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [showPassword, setShowPassword] = useState(false)

  useEffect(() => {
    let isActive = true

    if (typeof window !== 'undefined' && (window as any).__LEAFLOCK_REGISTRATION__ !== undefined) {
      const enabled = Boolean((window as any).__LEAFLOCK_REGISTRATION__)
      setRegistrationEnabled(enabled)
      if (!enabled) {
        setIsRegistering(false)
      }
      return
    }

    void (async () => {
      try {
        const status = await api.getRegistrationStatus()
        if (!isActive) return
        if (typeof status?.enabled === 'boolean') {
          setRegistrationEnabled(status.enabled)
          if (!status.enabled) {
            setIsRegistering(false)
          }
        }
      } catch (err) {
        console.warn('⚠️ Failed to load registration status', err)
      }
    })()

    return () => {
      isActive = false
    }
  }, [api])

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
    setPassword(pwd)
    setPasswordStrength(calculatePasswordStrength(pwd))
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setLoading(true)

    try {
      await cryptoService.initSodium()

      if (isRegistering) {
        if (!registrationEnabled) {
          setError('Registration is currently disabled')
          return
        }

        if (password.length < 12) {
          setError('Password must be at least 12 characters for registration')
          return
        }

        const response = await api.register(email, password)

        const salt = await cryptoService.generateSalt()
        const saltBase64 = btoa(String.fromCharCode(...salt))
        localStorage.setItem('user_salt', saltBase64)

        const key = await cryptoService.deriveKeyFromPassword(password, salt)
        await cryptoService.setMasterKey(key)

        localStorage.setItem('current_user_id', response.user_id)

        await onAuthenticated?.()
        return
      }

      const loginResponse = await api.login(email, password, mfaCode)

      if (loginResponse.mfa_required) {
        setMfaRequired(true)
        setError('Two-factor authentication is enabled. Please enter your 6-digit code.')
        return
      }

      const storedSalt = localStorage.getItem('user_salt')
      let salt: Uint8Array

      if (storedSalt) {
        salt = new Uint8Array(Array.from(atob(storedSalt), (c) => c.charCodeAt(0)))
      } else {
        salt = await cryptoService.generateSalt()
        const saltBase64 = btoa(String.fromCharCode(...salt))
        localStorage.setItem('user_salt', saltBase64)
      }

      const key = await cryptoService.deriveKeyFromPassword(password, salt)
      await cryptoService.setMasterKey(key)

      localStorage.setItem('current_user_id', loginResponse.user_id)

      await onAuthenticated?.()
    } catch (err) {
      const message = err instanceof Error && err.message
        ? err.message
        : isRegistering
          ? 'Registration failed. Please check your email and password.'
          : 'Login failed. Please check your credentials.'

      if (message.includes('Invalid credentials') && isRegistering) {
        setError('Registration failed. Please try a different email address.')
      } else {
        setError(message)
      }
    } finally {
      setLoading(false)
    }
  }

  const publicAnnouncements = announcements.filter((announcement) => announcement.visibility === 'all')

  return (
    <div className="h-screen overflow-y-auto bg-background flex flex-col items-center justify-center p-4">
      {publicAnnouncements.length > 0 && (
        <div className="w-full max-w-md mb-4">
          <AnnouncementBanner announcements={publicAnnouncements} />
        </div>
      )}

      <Alert className="w-full max-w-md mb-3 border-blue-200 bg-blue-50 dark:border-blue-800 dark:bg-blue-950">
        <Info className="h-4 w-4 text-blue-600 dark:text-blue-400" />
        <AlertDescription className="text-blue-800 dark:text-blue-200 text-sm">
          <a
            href="https://docs.leaflock.app"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 underline hover:text-blue-600 dark:hover:text-blue-300 transition-colors"
          >
            <Book className="h-3 w-3" />
            Documentation
          </a>{' '}
          • Setup guides & security features
        </AlertDescription>
      </Alert>

      <Card className="w-full max-w-md">
        <CardHeader className="space-y-1">
          <div className="flex items-center justify-center mb-4">
            <div className="flex items-center space-x-2">
              <Lock className="h-8 w-8 text-primary" />
              <CardTitle className="text-2xl">LeafLock</CardTitle>
            </div>
          </div>
          <CardDescription className="text-center">
            Your secure note-taking application
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
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
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <InputGroup>
                <InputGroupInput
                  id="password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={handlePasswordChange}
                  required
                  minLength={12}
                  autoComplete={isRegistering ? 'new-password' : 'current-password'}
                  placeholder="Enter your password"
                  aria-describedby={isRegistering ? 'password-strength' : undefined}
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
              {isRegistering && (
                <div className="space-y-2" id="password-strength">
                  <div className="flex space-x-1" role="progressbar" aria-valuenow={passwordStrength} aria-valuemax={5}>
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
                                : 'bg-green-500'
                            : 'bg-muted'
                        )}
                      />
                    ))}
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Use 12+ characters with mixed case, numbers & symbols
                  </p>
                </div>
              )}
            </div>

            {mfaRequired && (
              <div className="space-y-2">
                <Label htmlFor="mfa">2FA Code</Label>
                <Input
                  id="mfa"
                  name="code"
                  type="text"
                  value={mfaCode}
                  onChange={(event) => setMfaCode(event.target.value)}
                  placeholder="000000"
                  maxLength={6}
                  required={mfaRequired}
                  autoComplete="one-time-code"
                  inputMode="numeric"
                  pattern="[0-9]*"
                />
                <p className="text-xs text-muted-foreground">
                  Enter the 6-digit code from your authenticator app
                </p>
              </div>
            )}

            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? 'Processing...' : isRegistering ? 'Create Account' : 'Login'}
            </Button>

            {registrationEnabled ? (
              <Button
                type="button"
                variant="ghost"
                className="w-full"
                onClick={() => {
                  setIsRegistering(!isRegistering)
                  setError(null)
                  setMfaRequired(false)
                }}
              >
                {isRegistering ? 'Already have an account? Login' : 'Need an account? Register'}
              </Button>
            ) : (
              <p className="text-sm text-muted-foreground text-center">
                Registration is currently disabled
              </p>
            )}
          </form>
        </CardContent>
      </Card>

      <div className="mt-4 text-center text-sm text-muted-foreground">
        <a
          href="https://github.com/RelativeSure/notes/discussions"
          target="_blank"
          rel="noreferrer"
          className="inline-flex items-center gap-1 hover:underline"
        >
          <MessageSquare className="w-4 h-4" /> Join GitHub Discussions
        </a>
      </div>

      <Footer variant="minimal" />
    </div>
  )
}
