"use client"

import { useState } from "react"
import { useEncryption } from "@/lib/encryption-context"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog"
import { Lock, Key, AlertCircle } from "lucide-react"
import { Alert, AlertDescription } from "@/components/ui/alert"

interface EncryptionUnlockDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onUnlock: () => void
}

export function EncryptionUnlockDialog({ open, onOpenChange, onUnlock }: EncryptionUnlockDialogProps) {
  const { setEncryptionKey } = useEncryption()
  const [password, setPassword] = useState("")
  const [error, setError] = useState("")

  const handleUnlock = () => {
    if (!password.trim()) {
      setError("Please enter your encryption password")
      return
    }

    if (password.length < 8) {
      setError("Password must be at least 8 characters")
      return
    }

    setEncryptionKey(password)
    setPassword("")
    setError("")
    onUnlock()
    onOpenChange(false)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <div className="flex items-center justify-center w-12 h-12 rounded-full bg-primary/10 mb-4 mx-auto">
            <Lock className="w-6 h-6 text-primary" />
          </div>
          <DialogTitle className="text-center">Unlock Encrypted Note</DialogTitle>
          <DialogDescription className="text-center">
            This note is encrypted. Enter your encryption password to view and edit it.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <Alert>
            <Key className="h-4 w-4" />
            <AlertDescription className="text-xs">
              Your encryption password is never stored. It's used only to encrypt and decrypt your notes in your
              browser.
            </AlertDescription>
          </Alert>

          <div className="space-y-2">
            <Label htmlFor="encryption-password">Encryption Password</Label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted" />
              <Input
                id="encryption-password"
                type="password"
                placeholder="Enter your password"
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value)
                  setError("")
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    handleUnlock()
                  }
                }}
                className="pl-10"
                autoFocus
              />
            </div>
          </div>

          {error && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription className="text-sm">{error}</AlertDescription>
            </Alert>
          )}

          <div className="flex gap-2">
            <Button onClick={handleUnlock} className="flex-1">
              Unlock
            </Button>
            <Button variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
