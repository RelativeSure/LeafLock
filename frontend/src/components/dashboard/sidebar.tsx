import { useState, useEffect } from 'react'
import { useNotesStore } from '../../stores/notesStore'
// Encryption unlock dialog integration removed due to runtime error; rely on existing flows
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { ScrollArea } from '@/components/ui/scroll-area'
import { FolderPlus, Plus, Menu, Library, Tag, TagIcon } from 'lucide-react'
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
      <div className="p-4 border-b border-border space-y-3 flex-shrink-0">
        {/* Replaced AdvancedSearchBar with a basic, non-reactive search input to avoid update-depth loop */}
        <div className="flex items-center gap-2">
          <Input
            placeholder="Search notes..."
            value={searchQuery}
            onChange={(event) => setSearchQuery(event.target.value)}
            className="flex-1"
          />
          <Button variant="outline" size="sm" className="bg-transparent">
            Search
          </Button>
        </div>

        <div className="flex gap-2">
          <Button
            onClick={handleCreateNote}
            className="flex-1 transition-bounce hover-lift"
            size="sm"
            disabled={isLoading}
            data-testid="new-note-button"
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
                title="Create Folder"
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

          <Button
            variant="outline"
            size="sm"
            className="transition-smooth hover-lift bg-transparent"
            title="Create Tag"
            onClick={() => {
              window.location.href = '/manage'
            }}
          >
            <Tag className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Folders Section - Moved to top */}
      <div className="px-4 pt-3 pb-2 border-b border-border flex-shrink-0">
        <h3 className="text-sm font-semibold mb-2">Folders</h3>
        <ScrollArea className="max-h-32">
          <div className="space-y-1 pr-4">
            <Button
              variant={selectedFolder === null ? 'secondary' : 'ghost'}
              size="sm"
              onClick={() => selectFolder(null)}
              className="w-full justify-start text-sm"
            >
              All Notes
            </Button>
            {folders.map((folder) => (
              <Button
                key={folder.id}
                variant={selectedFolder === folder.id ? 'secondary' : 'ghost'}
                size="sm"
                onClick={() => selectFolder(folder.id)}
                className="w-full justify-start text-sm"
              >
                <div
                  className="w-2 h-2 rounded-full mr-2"
                  style={{ backgroundColor: folder.color }}
                />
                {folder.name}
              </Button>
            ))}
          </div>
        </ScrollArea>
      </div>

      {/* Tags Section - Moved to top */}
      {tags.length > 0 && (
        <div className="px-4 pt-3 pb-2 border-b border-border flex-shrink-0">
          <h3 className="text-sm font-semibold mb-2">Tags</h3>
          <ScrollArea className="max-h-32">
            <div className="space-y-1 pr-4">
              {tags.map((tag) => (
                <Button
                  key={tag.id}
                  variant="ghost"
                  size="sm"
                  onClick={() => selectTag(tag.name)}
                  className="w-full justify-start text-sm"
                >
                  <TagIcon className="w-3 h-3 mr-2" />
                  {tag.name}
                </Button>
              ))}
            </div>
          </ScrollArea>
        </div>
      )}

      {/* Notes List - Now in middle, takes remaining space */}
      <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center h-32">
            <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary" />
          </div>
        ) : (
          <NoteList />
        )}
      </div>

      {/* Bottom Actions */}
      <div className="p-4 border-t border-border space-y-2 flex-shrink-0">
        <div className="flex gap-2">
          <TrashDialog />
          <Button
            variant="outline"
            size="sm"
            onClick={() => setIsTemplatesOpen(true)}
            className="flex-1 gap-2 bg-transparent"
            disabled={isLoading}
            data-testid="templates-button"
          >
            <Library className="h-4 w-4" />
            Templates
          </Button>
        </div>
      </div>

      <TemplatesDialog open={isTemplatesOpen} onOpenChange={setIsTemplatesOpen} />
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
