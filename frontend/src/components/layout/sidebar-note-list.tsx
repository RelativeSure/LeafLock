import { useState, useMemo } from 'react'
import { useNotesStore } from '@/stores/notesStore'
import { useDecryptedNotes } from '@/hooks/use-decrypted-notes'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import {
  SidebarMenu,
  SidebarMenuItem,
  SidebarMenuButton,
  SidebarInput,
} from '@/components/ui/sidebar'
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
import { FileText, Lock, Pin, ArrowUpDown, Trash2, Search, X } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'

type SortOption = 'updated' | 'created' | 'title'

export function SidebarNoteList() {
  const { notes, selectedNote, selectedFolder, selectNote, updateNote, moveToTrash } =
    useNotesStore()

  const [sortBy, setSortBy] = useState<SortOption>('updated')
  const [searchQuery, setSearchQuery] = useState('')

  const activeNotes = useMemo(() => (notes || []).filter((note) => !note.isTrashed), [notes])
  const { decryptedNotes, isUnlocked, isDecrypting } = useDecryptedNotes(activeNotes)

  const handleTogglePin = async (noteId: string, currentlyPinned: boolean) => {
    try {
      await updateNote(noteId, { pinned: !currentlyPinned })
    } catch (error) {
      console.error('Failed to toggle pin:', error)
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

  const filteredNotes = useMemo(() => {
    let filtered = activeNotes

    if (selectedFolder) {
      filtered = filtered.filter((note) => note.folderId === selectedFolder)
    }

    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase()
      filtered = filtered.filter((note) => {
        const decrypted = decryptedNotes[note.id]
        const title = decrypted?.title || ''
        const content = decrypted?.content || ''
        const cleanContent = content
          .replace(/<[^>]*>/g, ' ')
          .replace(/\s+/g, ' ')
          .toLowerCase()
        return (
          title.toLowerCase().includes(query) ||
          cleanContent.includes(query) ||
          (note.tags && note.tags.some((t) => t.toLowerCase().includes(query)))
        )
      })
    }

    return filtered
  }, [activeNotes, selectedFolder, searchQuery, decryptedNotes])

  const sortedNotes = useMemo(() => {
    return [...filteredNotes].sort((a, b) => {
      if (a.pinned && !b.pinned) return -1
      if (!a.pinned && b.pinned) return 1

      switch (sortBy) {
        case 'updated': {
          const aTime = a.updatedAt ? new Date(a.updatedAt).getTime() : 0
          const bTime = b.updatedAt ? new Date(b.updatedAt).getTime() : 0
          return bTime - aTime
        }
        case 'created': {
          const aTime = a.createdAt ? new Date(a.createdAt).getTime() : 0
          const bTime = b.createdAt ? new Date(b.createdAt).getTime() : 0
          return bTime - aTime
        }
        case 'title': {
          const aTitle = decryptedNotes[a.id]?.title || a.title || ''
          const bTitle = decryptedNotes[b.id]?.title || b.title || ''
          return aTitle.localeCompare(bTitle)
        }
        default:
          return 0
      }
    })
  }, [filteredNotes, sortBy, decryptedNotes])

  return (
    <div className="flex flex-col gap-2">
      <div className="relative px-2 group-data-[collapsible=icon]:hidden">
        <Search className="absolute left-4 top-2 h-4 w-4 text-muted-foreground" />
        <SidebarInput
          placeholder="Search notes..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="pl-8 pr-8"
        />
        {searchQuery && (
          <Button
            variant="ghost"
            size="icon"
            className="absolute right-2 top-0 h-8 w-8"
            onClick={() => setSearchQuery('')}
          >
            <X className="h-3 w-3" />
          </Button>
        )}
      </div>

      <div className="px-2 group-data-[collapsible=icon]:hidden">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="sm"
              className="w-full justify-start gap-2 h-7 px-2 text-xs text-muted-foreground hover:text-foreground"
            >
              <ArrowUpDown className="h-3 w-3" />
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
      </div>

      <ScrollArea className="flex-1 max-h-[40vh]">
        {/* Compact note count for collapsed state */}
        <div className="group-data-[collapsible=icon]:flex group-data-[collapsible=icon]:items-center group-data-[collapsible=icon]:justify-center group-data-[collapsible=icon]:py-2 group-data-[collapsible=icon]:text-xs group-data-[collapsible=icon]:text-muted-foreground hidden">
          <FileText className="h-3 w-3 mr-1" />
          {sortedNotes.length}
        </div>
        <SidebarMenu>
          {sortedNotes.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 text-center text-muted-foreground px-2">
              <FileText className="h-6 w-6 opacity-50 mb-2" />
              <p className="text-xs">No notes found</p>
            </div>
          ) : (
            sortedNotes.map((note) => {
              const isSelected = selectedNote?.id === note.id
              const decrypted = decryptedNotes[note.id]
              const title = isUnlocked
                ? decrypted
                  ? decrypted.title || 'Untitled'
                  : isDecrypting
                    ? null
                    : 'Untitled'
                : 'Locked Note'

              const timeAgo = note.updatedAt
                ? (() => {
                    try {
                      const date = new Date(note.updatedAt)
                      return isNaN(date.getTime())
                        ? ''
                        : formatDistanceToNow(date, { addSuffix: true })
                    } catch {
                      return ''
                    }
                  })()
                : ''

              return (
                <SidebarMenuItem key={note.id}>
                  <ContextMenu>
                    <ContextMenuTrigger asChild>
                      <SidebarMenuButton
                        isActive={isSelected}
                        onClick={() => selectNote(note.id)}
                        className="flex flex-col items-start gap-0.5 h-auto py-2"
                      >
                        <div className="flex items-center gap-1.5 w-full">
                          {note.pinned && (
                            <Pin className="h-3 w-3 fill-current text-primary shrink-0" />
                          )}
                          <span className="truncate text-sm font-medium flex-1">
                            {title === null ? (
                              <Skeleton className="h-4 w-20 inline-block" />
                            ) : (
                              title
                            )}
                          </span>
                          {note.encrypted && (
                            <Lock className="h-3 w-3 text-muted-foreground shrink-0" />
                          )}
                        </div>
                        {timeAgo && (
                          <span className="text-[10px] text-muted-foreground">{timeAgo}</span>
                        )}
                      </SidebarMenuButton>
                    </ContextMenuTrigger>
                    <ContextMenuContent>
                      <ContextMenuItem onClick={() => selectNote(note.id)}>Open</ContextMenuItem>
                      <ContextMenuSeparator />
                      <ContextMenuItem
                        onClick={() => handleTogglePin(note.id, Boolean(note.pinned))}
                      >
                        <Pin className="h-4 w-4 mr-2" />
                        {note.pinned ? 'Unpin' : 'Pin'}
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
                </SidebarMenuItem>
              )
            })
          )}
        </SidebarMenu>
      </ScrollArea>
    </div>
  )
}
