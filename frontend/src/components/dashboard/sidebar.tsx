import { useState, useEffect } from 'react'
import { useNotesStore } from '../../stores/notesStore'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { ScrollArea } from '@/components/ui/scroll-area'
import {
  FolderPlus,
  Plus,
  Menu,
  X,
  Library,
} from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { TemplatesDialog } from './templates-dialog'
import { AdvancedSearchBar } from './advanced-search-bar'
import { NoteList } from './note-list'
import { TrashDialog } from './trash-dialog'

export function Sidebar() {
  const {
    selectedNote,
    createNote,
    selectNote,
    createFolder,
  } = useNotesStore()

  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false)
  const [isMobile, setIsMobile] = useState(false)
  const [newFolderName, setNewFolderName] = useState('')
  const [newFolderColor, setNewFolderColor] = useState('#3b82f6')
  const [isCreateFolderOpen, setIsCreateFolderOpen] = useState(false)
  const [isTemplatesOpen, setIsTemplatesOpen] = useState(false)

  // Mobile detection and responsive behavior
  useEffect(() => {
    const checkMobile = () => {
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
      selectNote(note.id)
    } catch (error) {
      console.error('Failed to create note:', error)
    }
  }

  return (
    <>
      {/* Mobile Menu Button */}
      {isMobile && (
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setIsMobileMenuOpen(true)}
          className="fixed top-4 left-4 z-50 md:hidden"
        >
          <Menu className="h-5 w-5" />
        </Button>
      )}

      {/* Mobile Overlay */}
      {isMobile && isMobileMenuOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-40 md:hidden"
          onClick={() => setIsMobileMenuOpen(false)}
        />
      )}

      {/* Sidebar */}
      <div className={`
        w-64 border-r border-border bg-card flex flex-col h-full
        ${isMobile ? 'fixed left-0 top-0 z-50 transform transition-transform duration-300' : ''}
        ${isMobile && !isMobileMenuOpen ? '-translate-x-full' : ''}
        ${isMobile ? 'w-80' : ''}
      `}>
        {/* Mobile Close Button */}
        {isMobile && (
          <div className="flex justify-end p-4 border-b border-border">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setIsMobileMenuOpen(false)}
            >
              <X className="h-5 w-5" />
            </Button>
          </div>
        )}
      {/* Search */}
      <div className="p-4 border-b border-border space-y-3">
        <AdvancedSearchBar />

        <div className="flex gap-2">
          <Button
            onClick={handleCreateNote}
            className="flex-1 transition-bounce hover-lift"
            size="sm"
          >
            <Plus className="h-4 w-4 mr-1" />
            New Note
          </Button>

          <Dialog open={isCreateFolderOpen} onOpenChange={setIsCreateFolderOpen}>
            <DialogTrigger asChild>
              <Button
                variant="outline"
                size="sm"
                className="transition-smooth hover-lift bg-transparent"
              >
                <FolderPlus className="h-4 w-4" />
              </Button>
            </DialogTrigger>
            <DialogContent className="animate-scale-in">
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
                    className="transition-smooth"
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
                  className="w-full transition-bounce hover-lift"
                >
                  Create Folder
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Notes List */}
      <div className="flex-1 flex flex-col border-b border-border">
        <div className="p-4 border-b border-border">
          <h2 className="font-semibold text-sm">Notes</h2>
        </div>
        <ScrollArea className="flex-1">
          <div className="p-2">
            <NoteList />
          </div>
        </ScrollArea>
      </div>

      {/* Management Link */}
      <div className="p-4 border-t border-border">
        <Button
          variant="outline"
          size="sm"
          onClick={() => window.location.href = '/manage'}
          className="w-full gap-2 bg-transparent"
        >
          <FolderPlus className="h-4 w-4" />
          Manage Folders & Tags
        </Button>
      </div>

      <div className="p-4 border-t border-border space-y-2">
        <div className="flex gap-2">
          <TrashDialog />
          <Button
            variant="outline"
            size="sm"
            onClick={() => setIsTemplatesOpen(true)}
            className="flex-1 gap-2 bg-transparent"
          >
            <Library className="h-4 w-4" />
            Templates
          </Button>
        </div>
      </div>

      {/* Templates Dialog */}
      <TemplatesDialog open={isTemplatesOpen} onOpenChange={setIsTemplatesOpen} />
      </div>
    </>
  )
}
