import React, { useState, useEffect } from 'react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from './ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from './ui/select'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { Label } from './ui/label'
import { Badge } from './ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Share2, UserPlus, X, Shield, Eye, Edit } from 'lucide-react'
import { useCollaborationStore, Collaborator } from '../stores/collaborationStore'

interface ShareDialogProps {
  noteId: string
  isOwner: boolean
  children?: React.ReactNode
}

export function ShareDialog({ noteId, isOwner, children }: ShareDialogProps) {
  const [isOpen, setIsOpen] = useState(false)
  const [userEmail, setUserEmail] = useState('')
  const [permission, setPermission] = useState<'read' | 'write' | 'admin'>('read')
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')

  const {
    collaborators,
    shareNote,
    removeCollaborator,
    fetchCollaborators,
  } = useCollaborationStore()

  useEffect(() => {
    if (isOpen) {
      fetchCollaborators(noteId)
    }
  }, [isOpen, noteId, fetchCollaborators])

  const handleShare = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!userEmail.trim()) return

    setIsLoading(true)
    setError('')

    try {
      await shareNote(noteId, userEmail.trim(), permission)
      setUserEmail('')
      setPermission('read')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to share note')
    } finally {
      setIsLoading(false)
    }
  }

  const handleRemoveCollaborator = async (collaborator: Collaborator) => {
    if (!isOwner) return

    try {
      await removeCollaborator(noteId, collaborator.user_id)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to remove collaborator')
    }
  }

  const getPermissionIcon = (permission: string) => {
    switch (permission) {
      case 'admin':
        return <Shield className="h-3 w-3" />
      case 'write':
        return <Edit className="h-3 w-3" />
      case 'read':
        return <Eye className="h-3 w-3" />
      default:
        return <Eye className="h-3 w-3" />
    }
  }

  const getPermissionColor = (permission: string) => {
    switch (permission) {
      case 'admin':
        return 'bg-red-100 text-red-800 border-red-200'
      case 'write':
        return 'bg-blue-100 text-blue-800 border-blue-200'
      case 'read':
        return 'bg-green-100 text-green-800 border-green-200'
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200'
    }
  }

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogTrigger asChild>
        {children || (
          <Button variant="outline" size="sm">
            <Share2 className="h-4 w-4 mr-2" />
            Share
          </Button>
        )}
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Share2 className="h-5 w-5" />
            Share Note
          </DialogTitle>
          <DialogDescription>
            Invite others to collaborate on this note. You can control their access level.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-6">
          {/* Add New Collaborator */}
          {isOwner && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <UserPlus className="h-4 w-4" />
                  Add Collaborator
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <form onSubmit={handleShare} className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="email">Email Address</Label>
                    <Input
                      id="email"
                      type="email"
                      placeholder="Enter email address"
                      value={userEmail}
                      onChange={(e) => setUserEmail(e.target.value)}
                      required
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="permission">Permission Level</Label>
                    <Select value={permission} onValueChange={(value: 'read' | 'write' | 'admin') => setPermission(value)}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="read">
                          <div className="flex items-center gap-2">
                            <Eye className="h-4 w-4" />
                            <div>
                              <div className="font-medium">Read Only</div>
                              <div className="text-sm text-muted-foreground">Can view the note</div>
                            </div>
                          </div>
                        </SelectItem>
                        <SelectItem value="write">
                          <div className="flex items-center gap-2">
                            <Edit className="h-4 w-4" />
                            <div>
                              <div className="font-medium">Read & Write</div>
                              <div className="text-sm text-muted-foreground">Can view and edit the note</div>
                            </div>
                          </div>
                        </SelectItem>
                        <SelectItem value="admin">
                          <div className="flex items-center gap-2">
                            <Shield className="h-4 w-4" />
                            <div>
                              <div className="font-medium">Admin</div>
                              <div className="text-sm text-muted-foreground">Can manage collaborators</div>
                            </div>
                          </div>
                        </SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  {error && (
                    <div className="text-sm text-red-600 bg-red-50 p-2 rounded">
                      {error}
                    </div>
                  )}

                  <Button type="submit" disabled={isLoading || !userEmail.trim()} className="w-full">
                    {isLoading ? 'Sharing...' : 'Share Note'}
                  </Button>
                </form>
              </CardContent>
            </Card>
          )}

          {/* Current Collaborators */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium">
                Current Collaborators ({collaborators.length})
              </CardTitle>
            </CardHeader>
            <CardContent>
              {collaborators.length === 0 ? (
                <div className="text-sm text-muted-foreground text-center py-4">
                  No collaborators yet. Share this note to start collaborating!
                </div>
              ) : (
                <div className="space-y-2">
                  {collaborators.map((collaborator) => (
                    <div
                      key={collaborator.id}
                      className="flex items-center justify-between p-2 rounded-lg border"
                    >
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-full bg-gradient-to-r from-blue-500 to-purple-600 flex items-center justify-center text-white text-sm font-medium">
                          {collaborator.user_email.charAt(0).toUpperCase()}
                        </div>
                        <div>
                          <div className="text-sm font-medium">{collaborator.user_email}</div>
                          <div className="text-xs text-muted-foreground">
                            Added {new Date(collaborator.created_at).toLocaleDateString()}
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-2">
                        <Badge
                          variant="outline"
                          className={`${getPermissionColor(collaborator.permission)} flex items-center gap-1`}
                        >
                          {getPermissionIcon(collaborator.permission)}
                          {collaborator.permission}
                        </Badge>

                        {isOwner && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleRemoveCollaborator(collaborator)}
                            className="text-red-600 hover:text-red-700 hover:bg-red-50"
                          >
                            <X className="h-4 w-4" />
                          </Button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Link Sharing */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium">Share Link</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-2">
                <Input
                  value={`${window.location.origin}/notes/${noteId}`}
                  readOnly
                  className="text-sm"
                />
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    navigator.clipboard.writeText(`${window.location.origin}/notes/${noteId}`)
                  }}
                >
                  Copy
                </Button>
              </div>
              <p className="text-xs text-muted-foreground mt-2">
                Anyone with this link and appropriate permissions can access the note.
              </p>
            </CardContent>
          </Card>
        </div>
      </DialogContent>
    </Dialog>
  )
}