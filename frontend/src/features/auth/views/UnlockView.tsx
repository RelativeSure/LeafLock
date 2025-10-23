import { useState, type FC } from 'react'
import { Lock } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { ThemeToggle } from '@/components/common/ThemeToggle'
import { cn } from '@/lib/utils'

export interface UnlockViewProps {
  onUnlock: (password: string) => Promise<void>
  onLogout: () => void
}

export const UnlockView: FC<UnlockViewProps> = ({ onUnlock, onLogout }) => {
  const [password, setPassword] = useState('')
  const [unlocking, setUnlocking] = useState(false)
  const [unlockError, setUnlockError] = useState<string | null>(null)

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!password.trim()) return

    setUnlocking(true)
    setUnlockError(null)

    try {
      await onUnlock(password)
      setPassword('')
    } catch (error) {
      setUnlockError(error instanceof Error ? error.message : 'Invalid password')
    } finally {
      setUnlocking(false)
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
            <Lock className="h-8 w-8 text-accent group-hover:text-accent/80 transition-colors" />
            <span className="text-2xl font-semibold text-foreground">LeafLock</span>
          </div>
        </div>

        {/* Form Card */}
        <div className="bg-card border border-border rounded-2xl p-8 shadow-sm">
          <div className="space-y-2 text-center mb-8">
            <h1 className="text-3xl font-bold text-foreground text-balance">Unlock Notes</h1>
            <p className="text-muted-foreground leading-relaxed">
              Your session is valid but your notes are locked. Enter your password to decrypt your
              notes.
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="space-y-2">
              <Label htmlFor="unlock-password" className="text-foreground">Password</Label>
              <Input
                id="unlock-password"
                name="password"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="Enter your password"
                required
                autoComplete="current-password"
                autoFocus
                className="h-11"
              />
            </div>

            {unlockError && (
              <Alert variant="destructive">
                <AlertDescription>{unlockError}</AlertDescription>
              </Alert>
            )}

            <div className="flex space-x-4">
              <Button
                type="submit"
                className={cn(
                  'flex-1 h-11 bg-primary text-primary-foreground hover:bg-primary/90',
                  unlocking && 'cursor-not-allowed opacity-80'
                )}
                disabled={unlocking || !password.trim()}
              >
                {unlocking ? 'Unlocking...' : 'Unlock Notes'}
              </Button>

              <Button
                type="button"
                variant="ghost"
                onClick={onLogout}
                className="h-11 text-muted-foreground hover:text-foreground"
              >
                Logout
              </Button>
            </div>
          </form>
        </div>
      </div>
    </div>
  )
}

export default UnlockView
