'use client'

import { useState } from 'react'
import { useNotesStore } from '../../stores/notesStore'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
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
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  FolderPlus,
  Plus,
  Folder,
  Tag,
  Edit2,
  Trash2,
  MoreHorizontal,
  FolderOpen,
  Hash,
} from 'lucide-react'
import { useToast } from '@/hooks/use-toast'

export function FoldersTagsPage() {
  const { folders, tags, notes, createFolder, deleteFolder, createTag, deleteTag } = useNotesStore()
  const { toast } = useToast()

  // Folder states
  const [isCreateFolderOpen, setIsCreateFolderOpen] = useState(false)
  const [newFolderName, setNewFolderName] = useState('')
  const [newFolderColor, setNewFolderColor] = useState('#3b82f6')

  // Tag states
  const [isCreateTagOpen, setIsCreateTagOpen] = useState(false)
  const [newTagName, setNewTagName] = useState('')
  const [newTagColor, setNewTagColor] = useState('#3b82f6')

  const activeNotes = (notes || []).filter((note) => !note.isTrashed)

  const handleCreateFolder = async () => {
    if (!newFolderName.trim()) return

    try {
      await createFolder({ name: newFolderName, color: newFolderColor })
      setNewFolderName('')
      setNewFolderColor('#3b82f6')
      setIsCreateFolderOpen(false)
      toast.success(`"${newFolderName}" has been created successfully.`)
    } catch (error) {
      toast.error('Failed to create folder.')
    }
  }

  const handleDeleteFolder = async (folderId: string, folderName: string) => {
    try {
      await deleteFolder(folderId)
      toast.success(`"${folderName}" has been deleted.`)
    } catch (error) {
      toast.error('Failed to delete folder.')
    }
  }

  const handleCreateTag = async () => {
    if (!newTagName.trim()) return

    try {
      await createTag({ name: newTagName, color: newTagColor })
      setNewTagName('')
      setNewTagColor('#3b82f6')
      setIsCreateTagOpen(false)
      toast.success(`"${newTagName}" has been created successfully.`)
    } catch (error) {
      toast.error('Failed to create tag.')
    }
  }

  const handleDeleteTag = async (tagId: string, tagName: string) => {
    try {
      await deleteTag(tagId)
      toast.success(`"${tagName}" has been deleted.`)
    } catch (error) {
      toast.error('Failed to delete tag.')
    }
  }

  const colorOptions = [
    '#3b82f6',
    '#8b5cf6',
    '#10b981',
    '#f59e0b',
    '#ef4444',
    '#6366f1',
    '#ec4899',
    '#06b6d4',
    '#84cc16',
    '#f97316',
    '#8b5cf6',
    '#64748b',
  ]

  return (
    <div className="container mx-auto p-6 max-w-6xl">
      <div className="mb-8">
        <h1 className="text-3xl font-bold">Folders & Tags</h1>
        <p className="text-muted-foreground mt-2">Organize your notes with folders and tags.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Folders Section */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="flex items-center gap-2">
                  <Folder className="h-5 w-5" />
                  Folders
                </CardTitle>
                <CardDescription>Organize your notes into folders</CardDescription>
              </div>
              <Dialog open={isCreateFolderOpen} onOpenChange={setIsCreateFolderOpen}>
                <DialogTrigger asChild>
                  <Button size="sm" className="gap-2">
                    <FolderPlus className="h-4 w-4" />
                    New Folder
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Create Folder</DialogTitle>
                    <DialogDescription>
                      Create a new folder to organize your notes.
                    </DialogDescription>
                  </DialogHeader>
                  <div className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="folder-name">Folder Name</Label>
                      <Input
                        id="folder-name"
                        value={newFolderName}
                        onChange={(e) => setNewFolderName(e.target.value)}
                        placeholder="My Folder"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Color</Label>
                      <div className="flex gap-2 flex-wrap">
                        {colorOptions.map((color, index) => (
                          <Button
                            key={`${color}-${index}`}
                            variant="ghost"
                            size="sm"
                            className={`w-8 h-8 rounded-full p-0 border-2 transition-all ${
                              newFolderColor === color
                                ? 'border-foreground scale-110'
                                : 'border-transparent hover:scale-105'
                            }`}
                            style={{ backgroundColor: color }}
                            onClick={() => setNewFolderColor(color)}
                          />
                        ))}
                      </div>
                    </div>
                  </div>
                  <DialogFooter>
                    <Button variant="outline" onClick={() => setIsCreateFolderOpen(false)}>
                      Cancel
                    </Button>
                    <Button onClick={handleCreateFolder} disabled={!newFolderName.trim()}>
                      Create Folder
                    </Button>
                  </DialogFooter>
                </DialogContent>
              </Dialog>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {(folders || []).map((folder) => {
                const folderNotes = activeNotes.filter((note) => note.folderId === folder.id)

                return (
                  <div
                    key={folder.id}
                    className="flex items-center justify-between p-3 rounded-lg border hover:bg-accent/50 transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      <FolderOpen className="h-5 w-5" style={{ color: folder.color }} />
                      <div>
                        <div className="font-medium">{folder.name}</div>
                        <div className="text-sm text-muted-foreground">
                          {folderNotes.length} note{folderNotes.length !== 1 ? 's' : ''}
                        </div>
                      </div>
                    </div>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="sm">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem>
                          <Edit2 className="h-4 w-4 mr-2" />
                          Edit
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onClick={() => handleDeleteFolder(folder.id, folder.name)}
                          className="text-destructive"
                        >
                          <Trash2 className="h-4 w-4 mr-2" />
                          Delete
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                )
              })}

              {(folders || []).length === 0 && (
                <div className="text-center py-8 text-muted-foreground">
                  <Folder className="h-12 w-12 mx-auto mb-2 opacity-50" />
                  <p>No folders yet</p>
                  <p className="text-sm">Create your first folder to get started</p>
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Tags Section */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="flex items-center gap-2">
                  <Tag className="h-5 w-5" />
                  Tags
                </CardTitle>
                <CardDescription>Label your notes with tags</CardDescription>
              </div>
              <Dialog open={isCreateTagOpen} onOpenChange={setIsCreateTagOpen}>
                <DialogTrigger asChild>
                  <Button size="sm" className="gap-2">
                    <Plus className="h-4 w-4" />
                    New Tag
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Create Tag</DialogTitle>
                    <DialogDescription>Create a new tag to label your notes.</DialogDescription>
                  </DialogHeader>
                  <div className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="tag-name">Tag Name</Label>
                      <Input
                        id="tag-name"
                        value={newTagName}
                        onChange={(e) => setNewTagName(e.target.value)}
                        placeholder="My Tag"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Color</Label>
                      <div className="flex gap-2 flex-wrap">
                        {colorOptions.map((color, index) => (
                          <Button
                            key={`${color}-${index}`}
                            variant="ghost"
                            size="sm"
                            className={`w-8 h-8 rounded-full p-0 border-2 transition-all ${
                              newTagColor === color
                                ? 'border-foreground scale-110'
                                : 'border-transparent hover:scale-105'
                            }`}
                            style={{ backgroundColor: color }}
                          />
                        ))}
                      </div>
                    </div>
                  </div>
                  <DialogFooter>
                    <Button variant="outline" onClick={() => setIsCreateTagOpen(false)}>
                      Cancel
                    </Button>
                    <Button onClick={handleCreateTag} disabled={!newTagName.trim()}>
                      Create Tag
                    </Button>
                  </DialogFooter>
                </DialogContent>
              </Dialog>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {(tags || []).map((tag) => {
                const tagNotes = activeNotes.filter((note) => (note.tags || []).includes(tag.name))

                return (
                  <div
                    key={tag.id}
                    className="flex items-center justify-between p-3 rounded-lg border hover:bg-accent/50 transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      <Hash className="h-5 w-5" style={{ color: tag.color }} />
                      <div>
                        <div className="font-medium">{tag.name}</div>
                        <div className="text-sm text-muted-foreground">
                          {tagNotes.length} note{tagNotes.length !== 1 ? 's' : ''}
                        </div>
                      </div>
                    </div>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="sm">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem>
                          <Edit2 className="h-4 w-4 mr-2" />
                          Edit
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onClick={() => handleDeleteTag(tag.id, tag.name)}
                          className="text-destructive"
                        >
                          <Trash2 className="h-4 w-4 mr-2" />
                          Delete
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                )
              })}

              {(tags || []).length === 0 && (
                <div className="text-center py-8 text-muted-foreground">
                  <Tag className="h-12 w-12 mx-auto mb-2 opacity-50" />
                  <p>No tags yet</p>
                  <p className="text-sm">Create your first tag to get started</p>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
