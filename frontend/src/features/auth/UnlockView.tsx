import { useState, type FC } from 'react'

import Footer from '@/components/Footer'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
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
    <div className="min-h-screen bg-gray-900 flex flex-col">
      <div className="flex-1 flex items-center justify-center px-4">
        <div className="max-w-md w-full space-y-8">
          <div className="text-center space-y-3">
            <svg className="mx-auto h-12 w-12 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
              />
            </svg>
            <h2 className="mt-6 text-3xl font-bold text-white">Locked</h2>
            <p className="text-sm text-gray-400">
              Your session is valid but your notes are locked. Enter your password to decrypt your notes.
            </p>
          </div>

          <form className="space-y-6" onSubmit={handleSubmit}>
            <div className="space-y-2">
              <label htmlFor="unlock-password" className="block text-sm font-medium text-gray-300">
                Password
              </label>
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
                className="bg-gray-700 border border-gray-600 text-white"
              />
            </div>

            {unlockError && (
              <div className="bg-red-900/50 border border-red-600 rounded-lg p-3" role="alert">
                <p className="text-red-200 text-sm">{unlockError}</p>
              </div>
            )}

            <div className="flex space-x-4">
              <Button
                type="submit"
                className={cn(
                  'flex-1 bg-blue-600 hover:bg-blue-700 text-white',
                  unlocking && 'cursor-not-allowed opacity-80'
                )}
                disabled={unlocking || !password.trim()}
              >
                {unlocking ? 'Unlocking...' : 'Unlock Notes'}
              </Button>

              <Button type="button" variant="ghost" onClick={onLogout} className="text-gray-400 hover:text-white">
                Logout
              </Button>
            </div>
          </form>
        </div>
      </div>
      <Footer />
    </div>
  )
}
