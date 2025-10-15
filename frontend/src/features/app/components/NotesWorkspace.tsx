import React from 'react'
import { Menu, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { ResizablePanelGroup, ResizablePanel, ResizableHandle } from '@/components/ui/resizable'
import { NotesList } from '@/features/notes/components/NotesList'
import { NotesEditor } from '@/features/notes/components/NotesEditor'
import { EmptyState } from './EmptyState'
import { type Note, type ViewType } from '../types'
import { type SecureAPI } from '@/services/secureApi'
import { type CryptoService } from '@/services/cryptoService'

interface NotesWorkspaceProps {
  notes: Note[]
  trashedNotes: Note[]
  selectedNote: Note | null
  viewingTrash: boolean
  loading: boolean
  notesError: string | null
  currentView: ViewType
  onSelectNote: (note: Note | null) => void
  onNotesChange: React.Dispatch<React.SetStateAction<Note[]>>
  onChangeView: (view: ViewType) => void
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
  currentView,
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
  return (
    <>
      {/* Mobile: Toggle between notes list and editor */}
      <div className="md:hidden flex flex-col h-full">
        {/* Mobile toggle header */}
        <div className="flex items-center justify-between bg-card border-b border-border px-4 py-3 flex-shrink-0">
          <h1 className="text-base font-semibold text-foreground">
            {currentView === 'notes' ? 'Notes' : selectedNote?.title || 'Editor'}
          </h1>
          <Button
            onClick={() => onChangeView(currentView === 'notes' ? 'editor' : 'notes')}
            variant="ghost"
            size="icon"
            aria-label={currentView === 'notes' ? 'Show editor' : 'Show notes list'}
          >
            {currentView === 'notes' ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </Button>
        </div>

        {/* Mobile content area */}
        <div className="flex-1 overflow-hidden">
          {currentView === 'notes' || !selectedNote ? (
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
                if (note) onChangeView('editor')
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
