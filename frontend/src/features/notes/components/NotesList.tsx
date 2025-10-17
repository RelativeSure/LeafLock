import React, { useState, Suspense, lazy } from 'react'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
import { Plus, FileText } from 'lucide-react'
import ComponentLoader from '@/components/loaders/ComponentLoader'
import { NoteListSkeleton } from './NoteSkeletons'
import { ErrorNotice } from '@/features/common/ErrorNotice'
import type { Note, ViewType } from '@/features/app/types'
import type { SearchResult } from '@/services/searchService'
import { cn } from '@/lib/utils'
import { padding } from '@/lib/padding'

const SearchBar = lazy(() => import('@/components/SearchBar'))
const SearchResults = lazy(() => import('@/components/SearchResults'))

interface NotesListProps {
  notes: Note[]
  trashedNotes: Note[]
  viewingTrash: boolean
  selectedNote: Note | null
  loading: boolean
  notesError: string | null
  onRetryLoad: () => Promise<void> | void
  onDismissError: () => void
  onSelectNote: (note: Note) => void
  onClearSelection: () => void
  onChangeView: (view: ViewType) => void
  onRestoreNote: (noteId: string) => Promise<void>
  onPermanentDelete: (noteId: string) => Promise<void>
  onMoveToTrash: (noteId: string) => Promise<boolean>
  onStartNewNote: () => void
  onOpenTemplateSelector: () => void
}

export const NotesList: React.FC<NotesListProps> = ({
  notes,
  trashedNotes,
  viewingTrash,
  selectedNote,
  loading,
  notesError,
  onRetryLoad,
  onDismissError,
  onSelectNote,
  onClearSelection,
  onChangeView,
  onRestoreNote,
  onPermanentDelete,
  onMoveToTrash,
  onStartNewNote,
  onOpenTemplateSelector,
}) => {
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState<SearchResult[]>([])
  const [isSearchMode, setIsSearchMode] = useState(false)

  const currentNotes = viewingTrash ? trashedNotes : notes
  const filteredNotes = currentNotes.filter(
    (note) =>
      note.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      note.content.toLowerCase().includes(searchQuery.toLowerCase())
  )

  const handleSearchResults = (results: SearchResult[], query: string) => {
    setSearchResults(results)
    setIsSearchMode(!!query.trim())
  }

  const handleSearchClear = () => {
    setSearchResults([])
    setIsSearchMode(false)
    setSearchQuery('')
  }

  const handleSelectSearchResult = (noteId: string) => {
    const note = notes.find((n) => n.id === noteId)
    if (note) {
      onSelectNote(note)
      if (window.innerWidth < 768) {
        onChangeView('editor')
      }
    }
  }

  return (
    <nav
      className="w-full bg-card md:border-r border-border flex flex-col h-full shadow-sm animate-slide-in transition-shadow duration-300"
      role="navigation"
      aria-label={viewingTrash ? 'Trash list' : 'Notes list'}
    >
      {/* Header Section */}
      <div
        className={cn(
          'flex-shrink-0 border-b border-border bg-card backdrop-blur-sm transition-colors duration-200',
          padding.editor.titleBar,
          'space-y-3'
        )}
      >
        <div className="flex items-center justify-between">
          {!viewingTrash && <h2 className="text-sm font-semibold text-foreground">Notes</h2>}
          {viewingTrash && (
            <>
              <h2 className="text-sm font-semibold text-foreground">Trash</h2>
              <Badge variant="secondary" className="text-xs">
                {trashedNotes.length}
              </Badge>
            </>
          )}
        </div>

        {!viewingTrash ? (
          <Suspense fallback={<ComponentLoader />}>
            <SearchBar
              onSearchResults={handleSearchResults}
              onClear={handleSearchClear}
              placeholder="Search notes..."
              className="w-full mt-2 rounded-lg border border-border shadow-sm transition-all duration-200 focus-within:ring-1 focus-within:ring-primary/40"
            />
          </Suspense>
        ) : (
          <div className="relative mt-2 rounded-lg border border-border shadow-sm transition-all duration-200 focus-within:ring-1 focus-within:ring-primary/40">
            <label htmlFor="search-trash" className="sr-only">
              Search trash
            </label>
            <svg
              className="absolute left-3 top-2.5 w-5 h-5 text-muted-foreground"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
              aria-hidden="true"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
              />
            </svg>
            <Input
              id="search-trash"
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search trash..."
              className="w-full pl-10"
              aria-describedby="search-help"
            />
            <p id="search-help" className="sr-only">
              Search through your trashed notes
            </p>
          </div>
        )}
      </div>

      {/* Scrollable Content Area */}
      <ScrollArea className="flex-1 px-2 py-2" role="list" aria-label="Notes">
        {notesError ? (
          <div className={cn(padding.sm, 'animate-fade-in')}>
            <ErrorNotice error={notesError} onRetry={onRetryLoad} onDismiss={onDismissError} />
          </div>
        ) : loading ? (
          <NoteListSkeleton />
        ) : !viewingTrash && isSearchMode ? (
          <div className={cn(padding.sm, 'animate-fade-in')}>
            <Suspense fallback={<ComponentLoader />}>
              <SearchResults
                results={searchResults}
                query={searchResults.length > 0 ? 'search' : ''}
                onSelectNote={handleSelectSearchResult}
              />
            </Suspense>
          </div>
        ) : filteredNotes.length > 0 ? (
          filteredNotes.map((note) => {
            const isSelected = selectedNote?.id === note.id

            return (
              <div
                key={note.id}
                className={cn(
                  'group relative border-b border-border transition-colors duration-200 ease-out animate-fade-in',
                  isSelected ? 'bg-accent/60 shadow-inner' : 'bg-transparent'
                )}
              >
                <div className="flex items-stretch">
                  <button
                    data-note-button
                    onClick={() => {
                      if (viewingTrash) return
                      onSelectNote(note)
                      if (window.innerWidth < 768) {
                        onChangeView('editor')
                      }
                    }}
                    className={cn(
                      'flex-1 text-left transition-all duration-200 ease-out focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background rounded-none',
                      padding.component.listItemLg,
                      !viewingTrash &&
                        'cursor-pointer hover:bg-accent/40 active:bg-accent/60 focus-visible:bg-accent/50',
                      viewingTrash && 'cursor-default opacity-90',
                      isSelected && 'bg-accent/40'
                    )}
                    role="listitem"
                    aria-pressed={isSelected}
                    aria-describedby={`note-${note.id}-date`}
                    disabled={viewingTrash}
                  >
                    <h3 className="font-semibold text-foreground line-clamp-1">
                      {note.title || 'Untitled'}
                    </h3>
                    <p className="text-sm text-muted-foreground line-clamp-2 mt-1 mb-1">
                      {note.content || 'No content'}
                    </p>
                    <p id={`note-${note.id}-date`} className="text-xs text-muted-foreground">
                      {viewingTrash ? 'Deleted' : 'Modified'}{' '}
                      {new Date(note.updated_at).toLocaleDateString()}
                    </p>
                  </button>

                  <div className="flex flex-col justify-center gap-2 px-2 py-2 border-l border-border bg-card transition-all duration-200 group-hover:bg-accent/10">
                    {viewingTrash ? (
                      <>
                        <button
                          onClick={() => onRestoreNote(note.id)}
                          className="flex items-center justify-center rounded-md border border-emerald-400/40 bg-emerald-500/10 p-1 text-emerald-400 transition hover:bg-emerald-500/20 hover:text-emerald-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500/50"
                          title="Restore note"
                          aria-label="Restore note"
                        >
                          <svg
                            className="w-4 h-4"
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                            aria-hidden="true"
                          >
                            <path
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth={2}
                              d="M3 10h10a8 8 0 018 8v2M3 10l6 6m-6-6l6-6"
                            />
                          </svg>
                        </button>

                        <button
                          onClick={async () => {
                            if (!confirm('Permanently delete this note? This cannot be undone.'))
                              return
                            await onPermanentDelete(note.id)
                          }}
                          className="flex items-center justify-center rounded-md border border-red-500/40 bg-red-500/10 p-1 text-red-400 transition hover:bg-red-500/20 hover:text-red-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-500/50"
                          title="Delete permanently"
                          aria-label="Delete permanently"
                        >
                          <svg
                            className="w-4 h-4"
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                            aria-hidden="true"
                          >
                            <path
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth={2}
                              d="M6 18L18 6M6 6l12 12"
                            />
                          </svg>
                        </button>
                      </>
                    ) : (
                      <button
                        onClick={async () => {
                          if (!confirm('Move this note to trash?')) return
                          const success = await onMoveToTrash(note.id)
                          if (success && selectedNote?.id === note.id) {
                            onClearSelection()
                          }
                        }}
                        className="flex items-center justify-center rounded-md border border-red-500/40 bg-red-500/10 p-1 text-red-400 transition hover:bg-red-500/20 hover:text-red-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-500/50"
                        title="Move to trash"
                        aria-label="Move to trash"
                      >
                        <svg
                          className="w-4 h-4"
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                          aria-hidden="true"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={2}
                            d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1-1H7a1 1 0 00-1 1v3M4 7h16"
                          />
                        </svg>
                      </button>
                    )}
                  </div>
                </div>
              </div>
            )
          })
        ) : (
          <div className="p-0 text-center text-gray-500" role="status" aria-live="polite">
            {viewingTrash
              ? searchQuery
                ? 'No items found in trash'
                : 'Trash is empty'
              : searchQuery
                ? 'No notes found'
                : 'No notes yet'}
          </div>
        )}
      </ScrollArea>

      {!viewingTrash && (
        <>
          <Separator />
          <div
            className={cn(
              'flex-shrink-0 space-y-2 bg-card',
              padding.editor.titleBar,
              'transition-colors duration-200'
            )}
          >
            <Button
              onClick={() => {
                onStartNewNote()
                onChangeView('editor')
              }}
              className="w-full"
              aria-describedby="new-note-help"
            >
              <Plus className="h-4 w-4 mr-2" />
              New Note
            </Button>
            <Button
              onClick={onOpenTemplateSelector}
              variant="outline"
              className="w-full"
              aria-describedby="template-note-help"
            >
              <FileText className="h-4 w-4 mr-2" />
              New from Template
            </Button>
            <p id="new-note-help" className="sr-only">
              Create a new note
            </p>
            <p id="template-note-help" className="sr-only">
              Create a new note from a template
            </p>
          </div>
        </>
      )}
    </nav>
  )
}

export default NotesList
