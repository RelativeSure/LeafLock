"use client"

import { useState } from "react"
import { useCollaboration } from "@/lib/collaboration-context"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { Share2, UserPlus, X, Mail, Users } from "lucide-react"
import { Badge } from "@/components/ui/badge"

interface ShareNoteDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  noteId: string
}

export function ShareNoteDialog({ open, onOpenChange, noteId }: ShareNoteDialogProps) {
  const { shareNote, unshareNote, getSharedUsers, getSessionUsers } = useCollaboration()
  const [email, setEmail] = useState("")
  const [error, setError] = useState("")
  const [isLoading, setIsLoading] = useState(false)

  const sharedUsers = getSharedUsers(noteId)
  const activeUsers = getSessionUsers(noteId)

  const handleShare = async () => {
    if (!email.trim()) return

    setError("")
    setIsLoading(true)

    try {
      await shareNote(noteId, email)
      setEmail("")
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to share note")
    } finally {
      setIsLoading(false)
    }
  }

  const handleUnshare = (userId: string) => {
    unshareNote(noteId, userId)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Share2 className="h-5 w-5" />
            Share Note
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4">
          {/* Share with new user */}
          <div className="space-y-2">
            <Label htmlFor="share-email">Share with</Label>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted" />
                <Input
                  id="share-email"
                  type="email"
                  placeholder="user@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      handleShare()
                    }
                  }}
                  className="pl-10"
                />
              </div>
              <Button onClick={handleShare} disabled={isLoading || !email.trim()}>
                <UserPlus className="h-4 w-4" />
              </Button>
            </div>
            {error && <p className="text-sm text-danger">{error}</p>}
          </div>

          {/* Active collaborators */}
          {activeUsers.length > 1 && (
            <div className="space-y-2">
              <Label className="flex items-center gap-2">
                <Users className="h-4 w-4" />
                Active Now ({activeUsers.length})
              </Label>
              <div className="space-y-2">
                {activeUsers.map((user) => (
                  <div key={user.id} className="flex items-center gap-3 p-2 rounded-lg bg-surface">
                    <Avatar className="h-8 w-8" style={{ backgroundColor: user.color }}>
                      <AvatarFallback className="text-white">{user.name.charAt(0).toUpperCase()}</AvatarFallback>
                    </Avatar>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate">{user.name}</p>
                      <Badge variant="secondary" className="text-xs">
                        Editing
                      </Badge>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Shared with */}
          {sharedUsers.length > 0 && (
            <div className="space-y-2">
              <Label>Shared with ({sharedUsers.length})</Label>
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {sharedUsers.map((user) => (
                  <div key={user.id} className="flex items-center gap-3 p-2 rounded-lg bg-surface group">
                    <Avatar className="h-8 w-8">
                      <AvatarFallback>{user.name.charAt(0).toUpperCase()}</AvatarFallback>
                    </Avatar>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate">{user.name}</p>
                      <p className="text-xs text-muted-foreground truncate">{user.email}</p>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleUnshare(user.id)}
                      className="opacity-0 group-hover:opacity-100 transition-opacity"
                    >
                      <X className="h-4 w-4" />
                    </Button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {sharedUsers.length === 0 && activeUsers.length <= 1 && (
            <div className="text-center py-8 text-muted-foreground">
              <Users className="h-12 w-12 mx-auto mb-2 opacity-50" />
              <p className="text-sm">Not shared with anyone yet</p>
              <p className="text-xs mt-1">Enter an email above to start collaborating</p>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}
