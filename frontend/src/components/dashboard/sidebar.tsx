import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from '@tanstack/react-router'
import { useNotesStore } from '../../stores/notesStore'
// Encryption unlock dialog integration removed due to runtime error; rely on existing flows
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { ScrollArea } from '@/components/ui/scroll-area'
import { FolderPlus, Plus, Menu, Library, Tag, TagIcon, Search, FolderTree } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { Sheet, SheetContent, SheetTrigger } from '@/components/ui/sheet'
import { Label } from '@/components/ui/label'
import { TemplatesDialog } from './templates-dialog'
import { NoteList } from './note-list'
import { TrashDialog } from './trash-dialog'

export function Sidebar() {
  const navigate = useNavigate()
  const {
    selectedNote,
    createNote,
    selectNote,
    createFolder,
    isLoading,
    folders,
    tags,
    selectedFolder,
    selectFolder,
    selectTag,
  } = useNotesStore()

  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false)
  const [isMobile, setIsMobile] = useState(false)
  const [newFolderName, setNewFolderName] = useState('')
  const [newFolderColor, setNewFolderColor] = useState('#3b82f6')
  const [isCreateFolderOpen, setIsCreateFolderOpen] = useState(false)
  const [isTemplatesOpen, setIsTemplatesOpen] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [debouncedSearchQuery, setDebouncedSearchQuery] = useState('')

  // Mobile detection and responsive behavior
  useEffect(() => {
    const checkMobile = () => {
      // Mobile breakpoint: < 768px (md breakpoint)
      setIsMobile(window.innerWidth < 768)
    }

    checkMobile()
    window.addEventListener('resize', checkMobile)

    return () => window.removeEventListener('resize', checkMobile)
  }, [])

  // Close mobile menu when note is selected
  useEffect(() => {
    // Use setTimeout to avoid synchronous setState in effect
    const timeoutId = setTimeout(() => {
      if (isMobile && selectedNote) {
        setIsMobileMenuOpen(false)
      }
    }, 0)

    return () => clearTimeout(timeoutId)
  }, [selectedNote, isMobile])

  // Debounce search query to avoid excessive re-renders and performance issues
  useEffect(() => {
    const timeoutId = setTimeout(() => {
      setDebouncedSearchQuery(searchQuery)
    }, 300) // 300ms debounce delay

    return () => clearTimeout(timeoutId)
  }, [searchQuery])

  const handleCreateFolder = () => {
    if (newFolderName.trim()) {
      createFolder({ name: newFolderName, color: newFolderColor })
      setNewFolderName('')
      setNewFolderColor('#3b82f6')
      setIsCreateFolderOpen(false)
    }
  }

  const handleCreateNote = async () => {
    try {
      const note = await createNote({})
      if (note?.id) {
        selectNote(note.id)
      }
    } catch (error) {
      console.error('Failed to create note:', error)
    }
  }

  const sidebarContent = (
    <div className="w-full border-r border-border bg-card flex flex-col h-full overflow-hidden">
      {/* Top Actions - Clean and minimal */}
      <div className="p-3 space-y-2 flex-shrink-0">
        {/* New Note button */}
        <Button
          onClick={handleCreateNote}
          className="w-full"
          size="default"
          disabled={isLoading}
          data-testid="new-note-button"
        >
          <Plus className="h-4 w-4 mr-2" />
          New Note
        </Button>

        {/* Search bar */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search notes..."
            value={searchQuery}
            onChange={(event) => setSearchQuery(event.target.value)}
            className="pl-9"
          />
        </div>
      </div>

      {/* Notes List - takes remaining space */}
      <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center h-32">
            <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary" />
          </div>
        ) : (
          <NoteList searchQuery={debouncedSearchQuery} />
        )}
      </div>

      {/* Bottom Actions */}
      <div className="p-3 border-t border-border flex-shrink-0">
        <div className="grid grid-cols-3 gap-2">
          <TrashDialog />
          <Button
            variant="outline"
            size="sm"
            onClick={() => navigate({ to: '/manage' })}
            className="gap-1 bg-transparent"
            disabled={isLoading}
            data-testid="manage-button"
          >
            <FolderTree className="h-4 w-4" />
            Manage
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setIsTemplatesOpen(true)}
            className="gap-1 bg-transparent"
            disabled={isLoading}
            data-testid="templates-button"
          >
            <Library className="h-4 w-4" />
            Templates
          </Button>
        </div>
      </div>

      {/* Dialogs */}
      <TemplatesDialog open={isTemplatesOpen} onOpenChange={setIsTemplatesOpen} />
      <Dialog open={isCreateFolderOpen} onOpenChange={setIsCreateFolderOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Create Folder</DialogTitle>
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
              <Label htmlFor="folder-color">Color</Label>
              <div className="flex gap-2">
                {['#3b82f6', '#8b5cf6', '#10b981', '#f59e0b', '#ef4444', '#6366f1'].map(
                  (color) => (
                    <button
                      key={color}
                      type="button"
                      onClick={() => setNewFolderColor(color)}
                      className={`w-8 h-8 rounded-full border-2 transition-bounce hover:scale-110 ${
                        newFolderColor === color
                          ? 'border-foreground scale-110'
                          : 'border-transparent'
                      }`}
                      style={{ backgroundColor: color }}
                    />
                  )
                )}
              </div>
            </div>
            <Button
              onClick={handleCreateFolder}
              className="w-full"
            >
              Create Folder
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )

  if (isMobile) {
    return (
      <Sheet open={isMobileMenuOpen} onOpenChange={setIsMobileMenuOpen}>
        <SheetTrigger asChild>
          <Button variant="ghost" size="sm" className="fixed top-4 left-4 z-50 md:hidden">
            <Menu className="h-5 w-5" />
          </Button>
        </SheetTrigger>
        <SheetContent side="left" className="p-0 w-80 max-w-[85vw]">
          {sidebarContent}
        </SheetContent>
      </Sheet>
    )
  }

  return sidebarContent
}
