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
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { Label } from './ui/label'
import { Badge } from './ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Share2, UserPlus, X, Shield, Eye, Edit, Link as LinkIcon, Copy, Trash2, Clock, Users } from 'lucide-react'
import { useCollaborationStore, Collaborator } from '../stores/collaborationStore'
import { useShareLinksStore, CreateShareLinkRequest } from '../stores/shareLinksStore'
import { toast } from 'sonner'

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

  // Share link state
  const [linkPermission, setLinkPermission] = useState<'read' | 'write'>('read')
  const [expiresIn, setExpiresIn] = useState<string | null>(null)
  const [maxUses, setMaxUses] = useState<number | undefined>(undefined)
  const [linkPassword, setLinkPassword] = useState('')
  const [isCreatingLink, setIsCreatingLink] = useState(false)

  const {
    collaborators,
    shareNote,
    removeCollaborator,
    fetchCollaborators,
  } = useCollaborationStore()

  const {
    currentNoteLinks,
    createShareLink,
    fetchNoteShareLinks,
    revokeShareLink,
    copyLinkToClipboard,
  } = useShareLinksStore()

  useEffect(() => {
    if (isOpen) {
      fetchCollaborators(noteId)
      fetchNoteShareLinks(noteId)
    }
  }, [isOpen, noteId, fetchCollaborators, fetchNoteShareLinks])

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

  const handleCreateShareLink = async () => {
    if (!isOwner) return

    setIsCreatingLink(true)
    setError('')

    try {
      const config: CreateShareLinkRequest = {
        permission: linkPermission,
      }

      if (expiresIn) {
        config.expires_in = expiresIn
      }

      if (maxUses && maxUses > 0) {
        config.max_uses = maxUses
      }

      if (linkPassword) {
        config.password = linkPassword
      }

      const newLink = await createShareLink(noteId, config)
      toast.success('Share link created successfully!')

      // Reset form
      setLinkPermission('read')
      setExpiresIn(null)
      setMaxUses(undefined)
      setLinkPassword('')

      // Copy to clipboard automatically
      await copyLinkToClipboard(newLink.share_url)
      toast.success('Link copied to clipboard!')
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to create share link'
      setError(message)
      toast.error(message)
    } finally {
      setIsCreatingLink(false)
    }
  }

  const handleCopyLink = async (url: string) => {
    try {
      await copyLinkToClipboard(url)
      toast.success('Link copied to clipboard!')
    } catch (err) {
      toast.error('Failed to copy link')
    }
  }

  const handleRevokeLink = async (token: string) => {
    try {
      await revokeShareLink(token)
      toast.success('Share link revoked')
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to revoke link'
      toast.error(message)
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
      <DialogContent className="sm:max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Share2 className="h-5 w-5" />
            Share Note
          </DialogTitle>
          <DialogDescription>
            Collaborate with others or create shareable links with custom permissions.
          </DialogDescription>
        </DialogHeader>

        <Tabs defaultValue="collaborators" className="w-full">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="collaborators" className="gap-2">
              <Users className="h-4 w-4" />
              Collaborators
            </TabsTrigger>
            <TabsTrigger value="links" className="gap-2">
              <LinkIcon className="h-4 w-4" />
              Share Links
            </TabsTrigger>
          </TabsList>

          {/* Collaborators Tab */}
          <TabsContent value="collaborators" className="space-y-6 mt-4">
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

          </TabsContent>

          {/* Share Links Tab */}
          <TabsContent value="links" className="space-y-6 mt-4">
            {/* Create New Link */}
            {isOwner && (
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium flex items-center gap-2">
                    <LinkIcon className="h-4 w-4" />
                    Create Share Link
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>Permission Level</Label>
                      <Select value={linkPermission} onValueChange={(value: 'read' | 'write') => setLinkPermission(value)}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="read">
                            <div className="flex items-center gap-2">
                              <Eye className="h-4 w-4" />
                              Read Only
                            </div>
                          </SelectItem>
                          <SelectItem value="write">
                            <div className="flex items-center gap-2">
                              <Edit className="h-4 w-4" />
                              Read & Write
                            </div>
                          </SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    <div className="space-y-2">
                      <Label>Expires In</Label>
                      <Select value={expiresIn || 'never'} onValueChange={(value) => setExpiresIn(value === 'never' ? null : value)}>
                        <SelectTrigger>
                          <SelectValue placeholder="Never" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="never">Never</SelectItem>
                          <SelectItem value="1h">1 Hour</SelectItem>
                          <SelectItem value="24h">24 Hours</SelectItem>
                          <SelectItem value="7d">7 Days</SelectItem>
                          <SelectItem value="30d">30 Days</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>Max Uses (Optional)</Label>
                      <Input
                        type="number"
                        placeholder="Unlimited"
                        value={maxUses || ''}
                        onChange={(e) => setMaxUses(e.target.value ? parseInt(e.target.value) : undefined)}
                        min="1"
                      />
                    </div>

                    <div className="space-y-2">
                      <Label>Password (Optional)</Label>
                      <Input
                        type="password"
                        placeholder="Leave empty for no password"
                        value={linkPassword}
                        onChange={(e) => setLinkPassword(e.target.value)}
                      />
                    </div>
                  </div>

                  {error && (
                    <div className="text-sm text-red-600 bg-red-50 p-2 rounded">
                      {error}
                    </div>
                  )}

                  <Button
                    onClick={handleCreateShareLink}
                    disabled={isCreatingLink}
                    className="w-full"
                  >
                    {isCreatingLink ? 'Creating...' : 'Create Share Link'}
                  </Button>
                </CardContent>
              </Card>
            )}

            {/* Active Share Links */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">
                  Active Share Links ({currentNoteLinks.filter(l => l.is_active).length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                {currentNoteLinks.filter(l => l.is_active).length === 0 ? (
                  <div className="text-sm text-muted-foreground text-center py-4">
                    No active share links. Create one to start sharing!
                  </div>
                ) : (
                  <div className="space-y-3">
                    {currentNoteLinks.filter(l => l.is_active).map((link) => (
                      <div
                        key={link.id}
                        className="p-3 rounded-lg border space-y-2"
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className={
                              link.permission === 'write'
                                ? 'bg-blue-100 text-blue-800 border-blue-200'
                                : 'bg-green-100 text-green-800 border-green-200'
                            }>
                              {link.permission === 'write' ? <Edit className="h-3 w-3 mr-1" /> : <Eye className="h-3 w-3 mr-1" />}
                              {link.permission}
                            </Badge>
                            {link.has_password && (
                              <Badge variant="outline" className="bg-yellow-100 text-yellow-800 border-yellow-200">
                                <Shield className="h-3 w-3 mr-1" />
                                Protected
                              </Badge>
                            )}
                          </div>
                          <div className="flex items-center gap-1">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleCopyLink(link.share_url)}
                              title="Copy link"
                            >
                              <Copy className="h-4 w-4" />
                            </Button>
                            {isOwner && (
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => handleRevokeLink(link.token)}
                                className="text-red-600 hover:text-red-700 hover:bg-red-50"
                                title="Revoke link"
                              >
                                <Trash2 className="h-4 w-4" />
                              </Button>
                            )}
                          </div>
                        </div>

                        <div className="text-xs text-muted-foreground space-y-1">
                          <div className="flex items-center gap-2">
                            <Clock className="h-3 w-3" />
                            {link.expires_at
                              ? `Expires ${new Date(link.expires_at).toLocaleDateString()}`
                              : 'Never expires'}
                          </div>
                          <div>
                            Uses: {link.use_count}{link.max_uses ? ` / ${link.max_uses}` : ' (unlimited)'}
                          </div>
                          {link.last_accessed_at && (
                            <div>
                              Last accessed: {new Date(link.last_accessed_at).toLocaleString()}
                            </div>
                          )}
                        </div>

                        <div className="flex items-center gap-2">
                          <Input
                            value={link.share_url}
                            readOnly
                            className="text-xs"
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  )
}