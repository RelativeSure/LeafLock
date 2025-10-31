import { useState, useEffect, useMemo } from 'react'
import { BulkOperationsBar } from './bulk-operations-bar'
import { useNotesStore } from '../../stores/notesStore'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { FileText, Lock, TagIcon, Pin, ArrowUpDown, Trash2, Copy } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from '@/components/ui/context-menu'
import { useDecryptedNotes } from '@/hooks/use-decrypted-notes'

type SortOption = 'updated' | 'created' | 'title' | 'pinned'

export function NoteList() {
  const { notes, selectedNote, selectedFolder, selectNote, updateNote, moveToTrash } =
    useNotesStore()
  const [sortBy, setSortBy] = useState<SortOption>('updated')
  const [selectedNotes, setSelectedNotes] = useState<string[]>([])
  const [isBulkMode, setIsBulkMode] = useState(false)

  const activeNotes = useMemo(() => (notes || []).filter((note) => !note.isTrashed), [notes])
  const { decryptedNotes, isUnlocked, isDecrypting } = useDecryptedNotes(activeNotes)

  const handleTogglePin = async (noteId: string, currentlyPinned: boolean) => {
    try {
      await updateNote(noteId, { pinned: !currentlyPinned })
    } catch (error) {
      console.error('Failed to toggle pin:', error)
    }
  }

  const handleDuplicate = (noteId: string) => {
    const noteToDuplicate = notes.find((n) => n.id === noteId)
    if (noteToDuplicate) {
      // Handle duplication - for now just select the note
      selectNote(noteId)
    }
  }

  const handleDelete = async (noteId: string) => {
    try {
      await moveToTrash(noteId)
      if (selectedNote?.id === noteId) {
        selectNote(null)
      }
    } catch (error) {
      console.error('Failed to delete note:', error)
    }
  }

  const filteredNotes = selectedFolder
    ? activeNotes.filter((note) => note.folderId === selectedFolder)
    : activeNotes

  const sortedNotes = [...filteredNotes].sort((a, b) => {
    // Always show pinned notes first
    if (a.pinned && !b.pinned) return -1
    if (!a.pinned && b.pinned) return 1

    switch (sortBy) {
      case 'updated': {
        const aUpdatedTime = a.updatedAt ? new Date(a.updatedAt).getTime() : 0
        const bUpdatedTime = b.updatedAt ? new Date(b.updatedAt).getTime() : 0
        return isNaN(bUpdatedTime)
          ? isNaN(aUpdatedTime)
            ? 0
            : -1
          : isNaN(aUpdatedTime)
            ? 1
            : bUpdatedTime - aUpdatedTime
      }
      case 'created': {
        const aCreatedTime = a.createdAt ? new Date(a.createdAt).getTime() : 0
        const bCreatedTime = b.createdAt ? new Date(b.createdAt).getTime() : 0
        return isNaN(bCreatedTime)
          ? isNaN(aCreatedTime)
            ? 0
            : -1
          : isNaN(aCreatedTime)
            ? 1
            : bCreatedTime - aCreatedTime
      }
      case 'title':
        return (a.title || '').localeCompare(b.title || '')
      default:
        return 0
    }
  })

  const toggleBulkMode = () => {
    setIsBulkMode(!isBulkMode)
    setSelectedNotes([])
  }

  useEffect(() => {
    const handleToggleBulkMode = () => {
      toggleBulkMode()
    }

    window.addEventListener('toggle-bulk-mode', handleToggleBulkMode)
    return () => window.removeEventListener('toggle-bulk-mode', handleToggleBulkMode)
  }, [isBulkMode])

  const toggleNoteSelection = (noteId: string) => {
    setSelectedNotes((prev) =>
      prev.includes(noteId) ? prev.filter((id) => id !== noteId) : [...prev, noteId]
    )
  }

  const selectAllNotes = () => {
    setSelectedNotes(sortedNotes.map((note) => note.id))
  }

  const clearSelection = () => {
    setSelectedNotes([])
  }

  const handleBulkClose = () => {
    setSelectedNotes([])
    setIsBulkMode(false)
  }

  if (filteredNotes.length === 0) {
    return (
      <div className="flex-1 flex items-center justify-center text-muted-foreground">
        <div className="text-center space-y-2 animate-fade-in">
          <FileText className="h-12 w-12 mx-auto opacity-50 animate-float" />
          <p>No notes yet</p>
          <p className="text-sm">Create your first note to get started</p>
        </div>
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="px-4 py-2 border-b border-border flex-shrink-0">
        <div className="flex items-center justify-between">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm" className="gap-2">
                <ArrowUpDown className="h-4 w-4" />
                Sort by:{' '}
                {sortBy === 'updated'
                  ? 'Last Updated'
                  : sortBy === 'created'
                    ? 'Date Created'
                    : 'Title'}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start">
              <DropdownMenuItem onClick={() => setSortBy('updated')}>Last Updated</DropdownMenuItem>
              <DropdownMenuItem onClick={() => setSortBy('created')}>Date Created</DropdownMenuItem>
              <DropdownMenuItem onClick={() => setSortBy('title')}>Title</DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>

          <div className="flex items-center gap-2">
            {isBulkMode && (
              <>
                <Button variant="outline" size="sm" onClick={selectAllNotes}>
                  Select All
                </Button>
                <Button variant="outline" size="sm" onClick={clearSelection}>
                  Clear
                </Button>
              </>
            )}
            <Button variant={isBulkMode ? 'default' : 'outline'} size="sm" onClick={toggleBulkMode}>
              {isBulkMode ? 'Exit Bulk' : 'Bulk Select'}
            </Button>
          </div>
        </div>
      </div>

      <ScrollArea className="flex-1 min-h-0">
        <div className="p-2 space-y-1">
          {sortedNotes.map((note, index) => {
            const isSelected = selectedNote?.id === note.id
            const isBulkSelected = selectedNotes.includes(note.id)
            const decrypted = decryptedNotes[note.id]

            return (
              <ContextMenu key={note.id}>
                <ContextMenuTrigger
                  className={`w-full p-3 rounded-lg transition-smooth hover-lift stagger-item cursor-pointer ${
                    isSelected
                      ? 'bg-primary/10 border border-primary/20'
                      : 'hover:bg-surface-hover border border-transparent'
                  } ${isBulkSelected ? 'bg-primary/5 border-primary/10' : ''}`}
                  style={{ animationDelay: `${index * 0.05}s` }}
                  onClick={(e) => {
                    // Only select if not in bulk mode and click wasn't on checkbox
                    if (
                      !isBulkMode &&
                      !(e.target as HTMLElement).closest('input[type="checkbox"]')
                    ) {
                      selectNote(note.id)
                    }
                  }}
                >
                  <div className="flex items-start gap-3">
                    {isBulkMode && (
                      <div className="flex items-center mt-1">
                        <input
                          type="checkbox"
                          checked={isBulkSelected}
                          onChange={() => toggleNoteSelection(note.id)}
                          onClick={(e) => e.stopPropagation()}
                          className="h-4 w-4 text-primary focus:ring-primary border-gray-300 rounded"
                        />
                      </div>
                    )}

                    <div className="flex-1 text-left">
                      <div className="flex items-start justify-between gap-2 mb-1">
                        <div className="flex items-center gap-2 flex-1 min-w-0">
                          {note.pinned && (
                            <Pin className="h-3 w-3 text-primary flex-shrink-0 mt-0.5" />
                          )}
                          {isUnlocked ? (
                            decrypted ? (
                              <h3 className="font-medium text-sm line-clamp-1">
                                {decrypted.title || 'Untitled'}
                              </h3>
                            ) : isDecrypting ? (
                              <Skeleton className="h-4 w-32" />
                            ) : (
                              <h3 className="font-medium text-sm line-clamp-1">Untitled</h3>
                            )
                          ) : (
                            <h3 className="font-medium text-sm line-clamp-1">Locked</h3>
                          )}
                        </div>
                        {note.encrypted && (
                          <Lock className="h-3 w-3 text-muted flex-shrink-0 mt-0.5 animate-pulse" />
                        )}
                      </div>

                      {isUnlocked ? (
                        decrypted ? (
                          <p className="text-xs text-muted-foreground line-clamp-2 mb-2">
                            {(decrypted.content || '')
                              .replace(/<[^>]*>/g, ' ')
                              .replace(/\s+/g, ' ')
                              .trim() || 'No content'}
                          </p>
                        ) : isDecrypting ? (
                          <div className="space-y-1 mb-2">
                            <Skeleton className="h-3 w-full" />
                            <Skeleton className="h-3 w-3/4" />
                          </div>
                        ) : (
                          <p className="text-xs text-muted-foreground line-clamp-2 mb-2">
                            No content
                          </p>
                        )
                      ) : (
                        <p className="text-xs text-muted-foreground line-clamp-2 mb-2">
                          Unlock to preview content
                        </p>
                      )}

                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-1 flex-wrap">
                          {(note.tags || []).slice(0, 2).map((tag) => (
                            <span
                              key={tag}
                              className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-accent/50 text-xs transition-smooth hover:bg-accent"
                            >
                              <TagIcon className="h-2.5 w-2.5" />
                              {tag}
                            </span>
                          ))}
                          {(note.tags || []).length > 2 && (
                            <span className="text-xs text-muted">
                              +{(note.tags || []).length - 2}
                            </span>
                          )}
                        </div>

                        <span className="text-xs text-muted-foreground flex-shrink-0">
                          {note.updatedAt
                            ? (() => {
                                try {
                                  const date = new Date(note.updatedAt)
                                  return isNaN(date.getTime())
                                    ? 'Unknown'
                                    : formatDistanceToNow(date, { addSuffix: true })
                                } catch {
                                  return 'Unknown'
                                }
                              })()
                            : 'Unknown'}
                        </span>
                      </div>
                    </div>
                  </div>
                </ContextMenuTrigger>
                <ContextMenuContent>
                  <ContextMenuItem onClick={() => selectNote(note.id)}>Open</ContextMenuItem>
                  <ContextMenuSeparator />
                  <ContextMenuItem onClick={() => handleTogglePin(note.id, Boolean(note.pinned))}>
                    <Pin className="h-4 w-4 mr-2" />
                    {note.pinned ? 'Unpin' : 'Pin'}
                  </ContextMenuItem>
                  <ContextMenuItem onClick={() => handleDuplicate(note.id)}>
                    <Copy className="h-4 w-4 mr-2" />
                    Duplicate
                  </ContextMenuItem>
                  <ContextMenuSeparator />
                  <ContextMenuItem
                    className="text-destructive"
                    onClick={() => handleDelete(note.id)}
                  >
                    <Trash2 className="h-4 w-4 mr-2" />
                    Delete
                  </ContextMenuItem>
                </ContextMenuContent>
              </ContextMenu>
            )
          })}
        </div>
      </ScrollArea>

      {/* Bulk Operations Bar */}
      <BulkOperationsBar selectedNotes={selectedNotes} onClose={handleBulkClose} />
    </div>
  )
}
