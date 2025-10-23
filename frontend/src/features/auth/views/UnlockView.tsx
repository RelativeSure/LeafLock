import { useState, type FC } from 'react'

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

            <div className="flex gap-3">
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
                variant="outline"
                onClick={onLogout}
                className="h-11 px-6"
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
