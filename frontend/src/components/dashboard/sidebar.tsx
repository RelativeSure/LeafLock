import { useState } from 'react'
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
  ChevronDown,
  MoreHorizontal,
  Trash2,
  Edit2,
  Library,
  ExternalLink,
  HelpCircle,
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
import { Label } from '@/components/ui/label'
import { TemplatesDialog } from './templates-dialog'
import { SearchBar } from './search-bar'
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
  const [newFolderName, setNewFolderName] = useState('')
  const [newFolderColor, setNewFolderColor] = useState('#3b82f6')
  const [isCreateFolderOpen, setIsCreateFolderOpen] = useState(false)
  const [isTemplatesOpen, setIsTemplatesOpen] = useState(false)

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
    <div className="w-64 border-r border-border bg-card flex flex-col h-full">
      {/* Search */}
      <div className="p-4 border-b border-border space-y-3">
        <SearchBar />

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
          {/* All Notes */}
          <button
            onClick={() => selectFolder(null)}
            className={`w-full flex items-center gap-2 px-3 py-2 rounded-md text-sm transition-smooth ${
              selectedFolder === null ? 'bg-primary/10 text-primary' : 'hover:bg-accent'
            }`}
          >
            <FileText className="h-4 w-4" />
            <span>All Notes</span>
            <span className="ml-auto text-xs text-muted-foreground">{activeNotes.length}</span>
          </button>

          {/* Templates */}
          <button
            onClick={() => setIsTemplatesOpen(true)}
            className="w-full flex items-center gap-2 px-3 py-2 rounded-md text-sm transition-smooth hover:bg-accent"
          >
            <Library className="h-4 w-4" />
            <span>Templates</span>
          </button>

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
                <div
                  key={folder.id}
                  className="stagger-item"
                  style={{ animationDelay: `${index * 0.05}s` }}
                >
                  <div
                    className={`flex items-center gap-2 px-3 py-2 rounded-md text-sm transition-smooth group ${
                      isSelected ? 'bg-primary/10 text-primary' : 'hover:bg-accent'
                    }`}
                  >
                    <button
                      onClick={() => toggleFolder(folder.id)}
                      className="p-0.5 hover:bg-accent rounded transition-smooth"
                    >
                      {isExpanded ? (
                        <ChevronDown className="h-3 w-3" />
                      ) : (
                        <ChevronRight className="h-3 w-3" />
                      )}
                    </button>
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
                </div>
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
        </div>

        <Button variant="ghost" className="w-full justify-start gap-2 text-sm" asChild>
          <a href="https://docs.leaflock.app" target="_blank" rel="noopener noreferrer">
            <HelpCircle className="h-4 w-4" />
            Documentation
            <ExternalLink className="h-3 w-3 ml-auto" />
          </a>
        </Button>
      </div>

      {/* Templates Dialog */}
      <TemplatesDialog open={isTemplatesOpen} onOpenChange={setIsTemplatesOpen} />
    </div>
  )
}
