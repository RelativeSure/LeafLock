import { useState } from 'react'
import { useNotesStore } from '@/stores'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Button } from '@/components/ui/button'
import { FileText, Lock, TagIcon, Pin, ArrowUpDown } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'

type SortOption = 'updated' | 'created' | 'title' | 'pinned'

export function NoteList() {
  const { notes, selectedNote, selectedFolder, selectNote } = useNotesStore()
  const [sortBy, setSortBy] = useState<SortOption>('updated')

  const activeNotes = (notes || []).filter((note) => !note.isTrashed)
  const filteredNotes = selectedFolder
    ? activeNotes.filter((note) => note.folderId === selectedFolder)
    : activeNotes

  const sortedNotes = [...filteredNotes].sort((a, b) => {
    // Always show pinned notes first
    if (a.pinned && !b.pinned) return -1
    if (!a.pinned && b.pinned) return 1

    switch (sortBy) {
      case 'updated':
        return new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime()
      case 'created':
        return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
      case 'title':
        return a.title.localeCompare(b.title)
      default:
        return 0
    }
  })

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
    <>
      <div className="px-4 py-2 border-b border-border">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="sm" className="w-full justify-start gap-2">
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
      </div>

      <ScrollArea className="flex-1">
        <div className="p-2 space-y-1">
          {sortedNotes.map((note, index) => {
            const isSelected = selectedNote?.id === note.id

            return (
              <button
                key={note.id}
                onClick={() => selectNote(note.id)}
                className={`w-full text-left p-3 rounded-lg transition-smooth hover-lift stagger-item ${
                  isSelected
                    ? 'bg-primary/10 border border-primary/20'
                    : 'hover:bg-surface-hover border border-transparent'
                }`}
                style={{ animationDelay: `${index * 0.05}s` }}
              >
                <div className="flex items-start justify-between gap-2 mb-1">
                  <div className="flex items-center gap-2 flex-1 min-w-0">
                    {note.pinned && <Pin className="h-3 w-3 text-primary flex-shrink-0 mt-0.5" />}
                    <h3 className="font-medium text-sm line-clamp-1">{note.title}</h3>
                  </div>
                  {note.encrypted && (
                    <Lock className="h-3 w-3 text-muted flex-shrink-0 mt-0.5 animate-pulse" />
                  )}
                </div>

                <p className="text-xs text-muted-foreground line-clamp-2 mb-2">
                  {(note.content || '')
                    .replace(/<[^>]*>/g, ' ')
                    .replace(/\s+/g, ' ')
                    .trim() || 'No content'}
                </p>

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
                      <span className="text-xs text-muted">+{(note.tags || []).length - 2}</span>
                    )}
                  </div>

                  <span className="text-xs text-muted-foreground flex-shrink-0">
                    {note.updatedAt ? formatDistanceToNow(new Date(note.updatedAt), { addSuffix: true }) : 'Unknown'}
                  </span>
                </div>
              </button>
            )
          })}
        </div>
      </ScrollArea>
    </>
  )
}
