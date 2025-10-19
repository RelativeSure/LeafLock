import React, { useState } from 'react'
import { Menu, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { ResizablePanelGroup, ResizablePanel, ResizableHandle } from '@/components/ui/resizable'
import { NotesList } from '@/features/notes/components/NotesList'
import { NotesEditor } from '@/features/notes/components/NotesEditor'
import { EmptyState } from './EmptyState'
import { type Note } from '@/types/auth'
import { type SecureAPI } from '@/services/api/secureApi'
import { type CryptoService } from '@/services/crypto/cryptoService'

interface NotesWorkspaceProps {
  notes: Note[]
  trashedNotes: Note[]
  selectedNote: Note | null
  viewingTrash: boolean
  loading: boolean
  notesError: string | null
  onSelectNote: (note: Note | null) => void
  onNotesChange: React.Dispatch<React.SetStateAction<Note[]>>
  onChangeView: (path: string) => void
  onRestoreNote: (noteId: string) => Promise<void>
  onPermanentDelete: (noteId: string) => Promise<void>
  onMoveToTrash: (noteId: string) => Promise<boolean>
  onStartNewNote: () => void
  onOpenTemplateSelector: () => void
  onRetryLoad: () => Promise<void>
  onDismissError: () => void
  api: SecureAPI
  cryptoService: CryptoService
}

export const NotesWorkspace: React.FC<NotesWorkspaceProps> = ({
  notes,
  trashedNotes,
  selectedNote,
  viewingTrash,
  loading,
  notesError,
  onSelectNote,
  onNotesChange,
  onChangeView,
  onRestoreNote,
  onPermanentDelete,
  onMoveToTrash,
  onStartNewNote,
  onOpenTemplateSelector,
  onRetryLoad,
  onDismissError,
  api,
  cryptoService,
}) => {
  // Local state for mobile view toggle
  const [showMobileEditor, setShowMobileEditor] = useState(false)

  // Update mobile editor state when note selection changes
  React.useEffect(() => {
    if (selectedNote) {
      setShowMobileEditor(true)
    }
  }, [selectedNote])
  return (
    <>
      {/* Mobile: Toggle between notes list and editor */}
      <div className="md:hidden flex flex-col h-full">
        {/* Mobile toggle header */}
        <div className="flex items-center justify-between bg-card border-b border-border px-4 py-3 flex-shrink-0">
          <h1 className="text-base font-semibold text-foreground">
            {!showMobileEditor ? 'Notes' : selectedNote?.title || 'Editor'}
          </h1>
          <Button
            onClick={() => setShowMobileEditor(!showMobileEditor)}
            variant="ghost"
            size="icon"
            aria-label={!showMobileEditor ? 'Show editor' : 'Show notes list'}
          >
            {!showMobileEditor ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </Button>
        </div>

        {/* Mobile content area */}
        <div className="flex-1 overflow-hidden">
          {!showMobileEditor || !selectedNote ? (
            <NotesList
              notes={notes}
              trashedNotes={trashedNotes}
              viewingTrash={viewingTrash}
              selectedNote={selectedNote}
              loading={loading}
              notesError={notesError}
              onRetryLoad={onRetryLoad}
              onDismissError={onDismissError}
              onSelectNote={(note) => {
                onSelectNote(note)
                if (note) setShowMobileEditor(true)
              }}
              onClearSelection={() => onSelectNote(null)}
              onChangeView={onChangeView}
              onRestoreNote={onRestoreNote}
              onPermanentDelete={onPermanentDelete}
              onMoveToTrash={onMoveToTrash}
              onStartNewNote={onStartNewNote}
              onOpenTemplateSelector={onOpenTemplateSelector}
            />
          ) : (
            <>
              {selectedNote ? (
                <NotesEditor
                  selectedNote={selectedNote}
                  onSelectNote={onSelectNote}
                  onNotesChange={onNotesChange}
                  api={api}
                  cryptoService={cryptoService}
                />
              ) : (
                <EmptyState />
              )}
            </>
          )}
        </div>
      </div>

      {/* Desktop: Resizable panels */}
      <div className="hidden md:block h-full">
        <ResizablePanelGroup direction="horizontal">
          {/* Sidebar Panel */}
          <ResizablePanel defaultSize={20} minSize={15} maxSize={30}>
            <NotesList
              notes={notes}
              trashedNotes={trashedNotes}
              viewingTrash={viewingTrash}
              selectedNote={selectedNote}
              loading={loading}
              notesError={notesError}
              onRetryLoad={onRetryLoad}
              onDismissError={onDismissError}
              onSelectNote={onSelectNote}
              onClearSelection={() => onSelectNote(null)}
              onChangeView={onChangeView}
              onRestoreNote={onRestoreNote}
              onPermanentDelete={onPermanentDelete}
              onMoveToTrash={onMoveToTrash}
              onStartNewNote={onStartNewNote}
              onOpenTemplateSelector={onOpenTemplateSelector}
            />
          </ResizablePanel>

          {/* Resizable Handle */}
          <ResizableHandle withHandle />

          {/* Editor Panel */}
          <ResizablePanel defaultSize={80}>
            <div className="h-full flex flex-col">
              {selectedNote ? (
                <NotesEditor
                  selectedNote={selectedNote}
                  onSelectNote={onSelectNote}
                  onNotesChange={onNotesChange}
                  api={api}
                  cryptoService={cryptoService}
                />
              ) : (
                <EmptyState />
              )}
            </div>
          </ResizablePanel>
        </ResizablePanelGroup>
      </div>
    </>
  )
}
