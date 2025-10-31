'use client'

import { useState } from 'react'
import { useNotesStore } from '../../stores/notesStore'
import { useToast } from '../../hooks/use-toast'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent } from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Checkbox } from '@/components/ui/checkbox'
import { Move, Tag, Trash2, X, Folder, FileText } from 'lucide-react'
import type { Note as _Note, Folder as _FolderType } from '@/types'

interface BulkOperationsBarProps {
  selectedNotes: string[]
  onClose: () => void
}

export function BulkOperationsBar({ selectedNotes, onClose }: BulkOperationsBarProps) {
  const [showMoveDialog, setShowMoveDialog] = useState(false)
  const [showTagDialog, setShowTagDialog] = useState(false)
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const [selectedFolder, setSelectedFolder] = useState<string>('')
  const [selectedTags, setSelectedTags] = useState<string[]>([])
  const [newTagName, setNewTagName] = useState('')
  const [isCreatingTag, setIsCreatingTag] = useState(false)

  const handleMoveDialogChange = (open: boolean) => {
    setShowMoveDialog(open)
  }

  const handleTagDialogChange = (open: boolean) => {
    setShowTagDialog(open)
  }

  const handleDeleteDialogChange = (open: boolean) => {
    setShowDeleteDialog(open)
  }

  const {
    notes,
    folders,
    tags,
    moveNotesToFolder,
    addTagsToNotes,
    removeTagsFromNotes,
    createTag,
  } = useNotesStore()
  const { toast } = useToast()

  const selectedNotesData = notes.filter((note) => selectedNotes.includes(note.id))
  const selectedCount = selectedNotes.length

  const handleMoveToFolder = async () => {
    if (!selectedFolder) return

    try {
      await moveNotesToFolder(selectedNotes, selectedFolder)
      toast.success(`${selectedCount} note${selectedCount !== 1 ? 's' : ''} moved to folder.`)
      setShowMoveDialog(false)
      onClose()
    } catch (error) {
      toast.error('Failed to move notes.')
    }
  }

  const handleAddTags = async () => {
    if (selectedTags.length === 0) return

    try {
      await addTagsToNotes(selectedNotes, selectedTags)
      toast.success(`Tags added to ${selectedCount} note${selectedCount !== 1 ? 's' : ''}.`)
      setShowTagDialog(false)
      setSelectedTags([])
      onClose()
    } catch (error) {
      toast.error('Failed to add tags.')
    }
  }

  const handleRemoveTags = async () => {
    if (selectedTags.length === 0) return

    try {
      await removeTagsFromNotes(selectedNotes, selectedTags)
      toast.success(`Tags removed from ${selectedCount} note${selectedCount !== 1 ? 's' : ''}.`)
      setShowTagDialog(false)
      setSelectedTags([])
      onClose()
    } catch (error) {
      toast.error('Failed to remove tags.')
    }
  }

  const handleDeleteNotes = async () => {
    try {
      // Use new bulk delete API
      const result = await useNotesStore.getState().bulkDeleteNotes(selectedNotes)

      if (result.successful > 0) {
        toast.success('Notes updated', {
          description: `${result.successful} note${result.successful !== 1 ? 's' : ''} moved to trash.${result.failed > 0 ? ` ${result.failed} failed.` : ''}`,
        })
      }

      if (result.errors.length > 0) {
        console.error('Bulk delete errors:', result.errors)
      }

      setShowDeleteDialog(false)
      onClose()
    } catch (error) {
      toast.error('Failed to delete notes.')
    }
  }

  const handleCreateAndAddTag = async () => {
    if (!newTagName.trim()) return

    setIsCreatingTag(true)
    try {
      const tag = await createTag({ name: newTagName.trim() })
      setSelectedTags((prev) => [...prev, tag.name])
      setNewTagName('')
    } catch (error) {
      toast.error('Failed to create tag.')
    } finally {
      setIsCreatingTag(false)
    }
  }

  const toggleTagSelection = (tagName: string) => {
    setSelectedTags((prev) =>
      prev.includes(tagName) ? prev.filter((t) => t !== tagName) : [...prev, tagName]
    )
  }

  if (selectedCount === 0) return null

  return (
    <>
      {/* Bulk Operations Bar */}
      <Card className="fixed bottom-4 left-1/2 transform -translate-x-1/2 z-50 shadow-lg border-2 border-primary/20">
        <CardContent className="p-4">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <Badge variant="secondary" className="text-sm">
                {selectedCount} selected
              </Badge>
              <Button variant="ghost" size="sm" onClick={onClose} className="h-6 w-6 p-0">
                <X className="h-4 w-4" />
              </Button>
            </div>

            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowMoveDialog(true)}
                className="gap-2"
              >
                <Move className="h-4 w-4" />
                Move
              </Button>

              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowTagDialog(true)}
                className="gap-2"
              >
                <Tag className="h-4 w-4" />
                Tags
              </Button>

              <Button
                variant="destructive"
                size="sm"
                onClick={() => setShowDeleteDialog(true)}
                className="gap-2"
              >
                <Trash2 className="h-4 w-4" />
                Delete
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Move to Folder Dialog */}
      <Dialog open={showMoveDialog} onOpenChange={handleMoveDialogChange}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Move Notes to Folder</DialogTitle>
            <DialogDescription>
              Select a folder to move {selectedCount} note{selectedCount !== 1 ? 's' : ''} to.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Select Folder</label>
              <Select value={selectedFolder} onValueChange={setSelectedFolder}>
                <SelectTrigger>
                  <SelectValue placeholder="Choose a folder..." />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="">No Folder</SelectItem>
                  {folders.map((folder) => (
                    <SelectItem key={folder.id} value={folder.id}>
                      <div className="flex items-center gap-2">
                        <Folder className="h-4 w-4" style={{ color: folder.color }} />
                        {folder.name}
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">Notes to Move</label>
              <div className="max-h-32 overflow-y-auto space-y-1">
                {selectedNotesData.map((note) => (
                  <div
                    key={note.id}
                    className="flex items-center gap-2 text-sm text-muted-foreground"
                  >
                    <FileText className="h-3 w-3" />
                    {note.title || 'Untitled'}
                  </div>
                ))}
              </div>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setShowMoveDialog(false)}>
              Cancel
            </Button>
            <Button onClick={handleMoveToFolder} disabled={!selectedFolder}>
              Move Notes
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Tag Management Dialog */}
      <Dialog open={showTagDialog} onOpenChange={handleTagDialogChange}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Manage Tags</DialogTitle>
            <DialogDescription>
              Add or remove tags from {selectedCount} note{selectedCount !== 1 ? 's' : ''}.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            {/* Create New Tag */}
            <div className="space-y-2">
              <label className="text-sm font-medium">Create New Tag</label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={newTagName}
                  onChange={(e) => setNewTagName(e.target.value)}
                  placeholder="Enter tag name..."
                  className="flex-1 px-3 py-2 border border-input rounded-md text-sm"
                  onKeyDown={(e) => e.key === 'Enter' && handleCreateAndAddTag()}
                />
                <Button
                  onClick={handleCreateAndAddTag}
                  disabled={!newTagName.trim() || isCreatingTag}
                  size="sm"
                >
                  {isCreatingTag ? 'Creating...' : 'Create'}
                </Button>
              </div>
            </div>

            {/* Select Tags */}
            <div className="space-y-2">
              <label className="text-sm font-medium">Select Tags</label>
              <div className="max-h-32 overflow-y-auto space-y-2">
                {tags.map((tag) => (
                  <div key={tag.id} className="flex items-center gap-2">
                    <Checkbox
                      checked={selectedTags.includes(tag.name)}
                      onCheckedChange={() => toggleTagSelection(tag.name)}
                    />
                    <span className="text-sm">{tag.name}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Selected Notes Preview */}
            <div className="space-y-2">
              <label className="text-sm font-medium">Notes to Update</label>
              <div className="max-h-24 overflow-y-auto space-y-1">
                {selectedNotesData.map((note) => (
                  <div
                    key={note.id}
                    className="flex items-center gap-2 text-sm text-muted-foreground"
                  >
                    <FileText className="h-3 w-3" />
                    {note.title || 'Untitled'}
                  </div>
                ))}
              </div>
            </div>
          </div>

          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setShowTagDialog(false)}>
              Cancel
            </Button>
            <Button
              variant="outline"
              onClick={handleRemoveTags}
              disabled={selectedTags.length === 0}
            >
              Remove Tags
            </Button>
            <Button onClick={handleAddTags} disabled={selectedTags.length === 0}>
              Add Tags
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog open={showDeleteDialog} onOpenChange={handleDeleteDialogChange}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Notes</DialogTitle>
            <DialogDescription>
              Are you sure you want to move {selectedCount} note{selectedCount !== 1 ? 's' : ''} to
              trash? This action can be undone from the trash.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-2">
            <label className="text-sm font-medium">Notes to Delete</label>
            <div className="max-h-32 overflow-y-auto space-y-1">
              {selectedNotesData.map((note) => (
                <div
                  key={note.id}
                  className="flex items-center gap-2 text-sm text-muted-foreground"
                >
                  <FileText className="h-3 w-3" />
                  {note.title || 'Untitled'}
                </div>
              ))}
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setShowDeleteDialog(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleDeleteNotes}>
              Move to Trash
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
