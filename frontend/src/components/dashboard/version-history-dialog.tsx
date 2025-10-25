'use client'

import { useState, useEffect } from 'react'
import { useNotesStore } from '../../stores/notesStore'
import { useToast } from '../../hooks/use-toast'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import {
  History,
  RotateCcw,
  Trash2,
  Clock,
  User,
  FileText,
  Calendar,
} from 'lucide-react'
import { formatDistanceToNow, format } from 'date-fns'
import type { NoteVersion } from '@/types'

interface VersionHistoryDialogProps {
  noteId: string
  noteTitle: string
  children: React.ReactNode
}

export function VersionHistoryDialog({ noteId, noteTitle, children }: VersionHistoryDialogProps) {
  const [open, setOpen] = useState(false)
  const [versions, setVersions] = useState<NoteVersion[]>([])
  const [loading, setLoading] = useState(false)
  const [showCreateDialog, setShowCreateDialog] = useState(false)
  const [changeDescription, setChangeDescription] = useState('')
  const [showRestoreDialog, setShowRestoreDialog] = useState(false)
  const [versionToRestore, setVersionToRestore] = useState<NoteVersion | null>(null)
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const [versionToDelete, setVersionToDelete] = useState<NoteVersion | null>(null)

  const { createNoteVersion, getNoteVersions, restoreNoteVersion, deleteNoteVersion } = useNotesStore()
  const { toast } = useToast()

  const loadVersions = async () => {
    setLoading(true)
    try {
      const versionList = await getNoteVersions(noteId)
      setVersions(versionList.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()))
    } catch (error) {
      toast.error('Failed to load version history.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (open) {
      loadVersions()
    }
  }, [open, noteId])

  const handleCreateVersion = async () => {
    if (!changeDescription.trim()) {
      toast.error('Please enter a description for this version.')
      return
    }

    try {
      await createNoteVersion(noteId, changeDescription)
      toast.success('A new version has been saved successfully.')
      setChangeDescription('')
      setShowCreateDialog(false)
      loadVersions()
    } catch (error) {
      toast.error('Failed to create version.')
    }
  }

  const handleRestoreVersion = async () => {
    if (!versionToRestore) return

    try {
      await restoreNoteVersion(versionToRestore.id)
      toast.success(`Restored to version from ${format(new Date(versionToRestore.createdAt), 'MMM d, yyyy')}.`)
      setShowRestoreDialog(false)
      setVersionToRestore(null)
      setOpen(false)
    } catch (error) {
      toast.error('Failed to restore version.')
    }
  }

  const handleDeleteVersion = async () => {
    if (!versionToDelete) return

    try {
      await deleteNoteVersion(versionToDelete.id)
      toast.success('Version has been permanently deleted.')
      setShowDeleteDialog(false)
      setVersionToDelete(null)
      loadVersions()
    } catch (error) {
      toast.error('Failed to delete version.')
    }
  }

  const openRestoreDialog = (version: NoteVersion) => {
    setVersionToRestore(version)
    setShowRestoreDialog(true)
  }

  const openDeleteDialog = (version: NoteVersion) => {
    setVersionToDelete(version)
    setShowDeleteDialog(true)
  }

  return (
    <>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogTrigger asChild>
          {children}
        </DialogTrigger>
        <DialogContent className="max-w-4xl max-h-[80vh]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <History className="h-5 w-5" />
              Version History
            </DialogTitle>
            <DialogDescription>
              View and manage versions for "{noteTitle}"
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            {/* Create Version Button */}
            <div className="flex justify-between items-center">
              <div className="text-sm text-muted-foreground">
                {versions.length} version{versions.length !== 1 ? 's' : ''} available
              </div>
              <Button onClick={() => setShowCreateDialog(true)} size="sm">
                <FileText className="h-4 w-4 mr-2" />
                Create Version
              </Button>
            </div>

            {/* Versions List */}
            <ScrollArea className="h-[400px]">
              {loading ? (
                <div className="flex items-center justify-center py-8">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
                </div>
              ) : versions.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <History className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No versions available</p>
                  <p className="text-sm">Create your first version to start tracking changes</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {versions.map((version, index) => (
                    <Card key={version.id} className="transition-smooth hover:shadow-md">
                      <CardHeader className="pb-3">
                        <div className="flex items-start justify-between">
                          <div className="space-y-1">
                            <div className="flex items-center gap-2">
                              <Badge variant="outline" className="text-xs">
                                v{version.versionNumber}
                              </Badge>
                              {index === 0 && (
                                <Badge variant="default" className="text-xs">
                                  Current
                                </Badge>
                              )}
                            </div>
                            <CardTitle className="text-sm">
                              {version.changeDescription || 'No description'}
                            </CardTitle>
                            <CardDescription className="text-xs">
                              <div className="flex items-center gap-4">
                                <span className="flex items-center gap-1">
                                  <Calendar className="h-3 w-3" />
                                  {format(new Date(version.createdAt), 'MMM d, yyyy')}
                                </span>
                                <span className="flex items-center gap-1">
                                  <Clock className="h-3 w-3" />
                                  {formatDistanceToNow(new Date(version.createdAt), { addSuffix: true })}
                                </span>
                                <span className="flex items-center gap-1">
                                  <User className="h-3 w-3" />
                                  {version.createdBy}
                                </span>
                              </div>
                            </CardDescription>
                          </div>
                          <div className="flex items-center gap-1">
                            {index > 0 && (
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => openRestoreDialog(version)}
                                className="h-8 w-8 p-0"
                              >
                                <RotateCcw className="h-4 w-4" />
                              </Button>
                            )}
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => openDeleteDialog(version)}
                              className="h-8 w-8 p-0 text-destructive hover:text-destructive"
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </div>
                        </div>
                      </CardHeader>
                      <CardContent className="pt-0">
                        <div className="text-xs text-muted-foreground">
                          <div className="font-medium mb-1">Title:</div>
                          <div className="mb-2">{version.title || 'Untitled'}</div>
                          <div className="font-medium mb-1">Content Preview:</div>
                          <div className="line-clamp-2">
                            {version.content.replace(/<[^>]*>/g, '').substring(0, 100)}
                            {version.content.length > 100 && '...'}
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              )}
            </ScrollArea>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Create Version Dialog */}
      <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create New Version</DialogTitle>
            <DialogDescription>
              Save the current state of this note as a new version.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="changeDescription">Change Description</Label>
              <Input
                id="changeDescription"
                value={changeDescription}
                onChange={(e) => setChangeDescription(e.target.value)}
                placeholder="Describe what changed in this version..."
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreateDialog(false)}>
              Cancel
            </Button>
            <Button onClick={handleCreateVersion}>
              Create Version
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Restore Version Dialog */}
      <AlertDialog open={showRestoreDialog} onOpenChange={setShowRestoreDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Restore Version</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to restore this version? This will replace the current content of the note.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleRestoreVersion}>
              Restore Version
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Delete Version Dialog */}
      <AlertDialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Version</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to permanently delete this version? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleDeleteVersion} className="bg-destructive text-destructive-foreground hover:bg-destructive/90">
              Delete Version
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
