import { useState, useEffect } from 'react'
import { useNotesStore } from '../../stores/notesStore'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { ScrollArea } from '@/components/ui/scroll-area'
import {
  FolderPlus,
  Plus,
  Folder,
  Tag,
  FileText,
  ChevronRight,
  Menu,
  X,
  MoreHorizontal,
  Trash2,
  Edit2,
  Library,
} from 'lucide-react'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible'
import { Label } from '@/components/ui/label'
import { TemplatesDialog } from './templates-dialog'
import { AdvancedSearchBar } from './advanced-search-bar'
// import { ExportImportDialog } from './export-import-dialog'
import { TrashDialog } from './trash-dialog'

export function Sidebar() {
  const {
    folders,
    tags,
    notes,
    selectedFolder,
    selectFolder,
    createFolder,
    deleteFolder,
    createNote,
    selectNote,
  } = useNotesStore()

  // Ensure all store values are arrays
  const safeFolders = Array.isArray(folders) ? folders : []
  const safeTags = Array.isArray(tags) ? tags : []
  const safeNotes = Array.isArray(notes) ? notes : []

  const [expandedFolders, setExpandedFolders] = useState<Set<string>>(new Set())
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

  const toggleFolder = (folderId: string) => {
    setExpandedFolders((prev) => {
      const next = new Set(prev)
      if (next.has(folderId)) {
        next.delete(folderId)
      } else {
        next.add(folderId)
      }
      return next
    })
  }

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

  const activeNotes = safeNotes.filter((note) => !note.isTrashed)

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

      {/* Folders & Tags */}
      <ScrollArea className="flex-1">
        <div className="p-2">

          {/* Folders */}
          <div className="mt-4">
            <div className="px-3 py-2 text-xs font-semibold text-muted-foreground uppercase tracking-wider">
              Folders
            </div>
            {safeFolders.map((folder, index) => {
              const folderNotes = activeNotes.filter((note) => note.folderId === folder.id)
              const isExpanded = expandedFolders.has(folder.id)
              const isSelected = selectedFolder === folder.id

              return (
                <Collapsible
                  key={folder.id}
                  open={isExpanded}
                  onOpenChange={() => toggleFolder(folder.id)}
                  className="stagger-item"
                  style={{ animationDelay: `${index * 0.05}s` }}
                >
                  <div
                    className={`flex items-center gap-2 px-3 py-2 rounded-md text-sm transition-smooth group ${
                      isSelected ? 'bg-primary/10 text-primary' : 'hover:bg-accent'
                    }`}
                  >
                    <CollapsibleTrigger asChild>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 w-6 p-0 hover:bg-accent rounded transition-smooth"
                      >
                        {isExpanded ? (
                          <ChevronDown className="h-3 w-3" />
                        ) : (
                          <ChevronRight className="h-3 w-3" />
                        )}
                      </Button>
                    </CollapsibleTrigger>
                    <button
                      onClick={() => selectFolder(folder.id)}
                      className="flex items-center gap-2 flex-1"
                    >
                      <Folder
                        className="h-4 w-4 transition-smooth"
                        style={{ color: folder.color }}
                      />
                      <span className="truncate">{folder.name}</span>
                      <span className="ml-auto text-xs text-muted-foreground">
                        {folderNotes.length}
                      </span>
                    </button>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-6 w-6 p-0 opacity-0 group-hover:opacity-100 transition-smooth"
                        >
                          <MoreHorizontal className="h-3 w-3" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end" className="animate-scale-in">
                        <DropdownMenuItem className="transition-smooth">
                          <Edit2 className="h-4 w-4 mr-2" />
                          Rename
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onClick={() => deleteFolder(folder.id)}
                          className="text-destructive transition-smooth"
                        >
                          <Trash2 className="h-4 w-4 mr-2" />
                          Delete
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                  <CollapsibleContent className="ml-6 space-y-1">
                    {folderNotes.map((note) => (
                      <button
                        key={note.id}
                        onClick={() => selectNote(note.id)}
                        className="w-full text-left px-3 py-1.5 rounded text-xs hover:bg-accent transition-smooth flex items-center gap-2"
                      >
                        <FileText className="h-3 w-3" />
                        <span className="truncate">{note.title || 'Untitled'}</span>
                      </button>
                    ))}
                    {folderNotes.length === 0 && (
                      <div className="px-3 py-1.5 text-xs text-muted-foreground">
                        No notes in this folder
                      </div>
                    )}
                  </CollapsibleContent>
                </Collapsible>
              )
            })}
          </div>

          {/* Tags */}
          <div className="mt-4">
            <div className="px-3 py-2 text-xs font-semibold text-muted-foreground uppercase tracking-wider">
              Tags
            </div>
            {safeTags.map((tag, index) => {
              const tagNotes = activeNotes.filter((note) => (note.tags || []).includes(tag.name))

              return (
                <button
                  key={tag.id}
                  className="w-full flex items-center gap-2 px-3 py-2 rounded-md text-sm hover:bg-accent transition-smooth stagger-item"
                  style={{ animationDelay: `${index * 0.05}s` }}
                >
                  <Tag className="h-4 w-4" style={{ color: tag.color }} />
                  <span className="truncate">{tag.name}</span>
                  <span className="ml-auto text-xs text-muted-foreground">{tagNotes.length}</span>
                </button>
              )
            })}
          </div>
        </div>
      </ScrollArea>

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
