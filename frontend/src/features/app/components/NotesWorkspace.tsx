import React from 'react'
import { Button } from '@/components/ui/button'
import { NotesList } from '@/features/notes/components/NotesList'
import { NotesEditor } from '@/features/notes/components/NotesEditor'
import { MainHeader } from './MainHeader'
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
  isAdmin: boolean
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
  onLoadNotes: () => Promise<void>
  onLoadTrash: () => Promise<void>
  onSetViewingTrash: (viewing: boolean) => void
  onSetNotesError: (error: string | null) => void
  onLogout: () => void
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
  isAdmin,
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
  onLoadNotes,
  onLoadTrash,
  onSetViewingTrash,
  onSetNotesError,
  onLogout,
  api,
  cryptoService,
}) => {
  return (
    <>
      {/* Mobile header */}
      <div className="md:hidden flex items-center justify-between bg-card border-b border-border px-4 py-3">
        <h1 className="text-lg font-semibold text-foreground">LeafLock</h1>
        <Button
          onClick={() => onChangeView(currentView === 'notes' ? 'editor' : 'notes')}
          variant="ghost"
          size="sm"
          className="p-1"
          aria-label={currentView === 'notes' ? 'Show editor' : 'Show notes list'}
        >
          {currentView === 'notes' ? (
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
          ) : (
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          )}
        </Button>
      </div>

      {/* Notes list sidebar */}
      <div
        className={`${currentView === 'notes' || selectedNote || currentView === 'editor' ? 'hidden md:block' : 'block'} w-full md:w-80`}
      >
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
      </div>

      {/* Editor area */}
      <div className={`${currentView === 'notes' && !selectedNote ? 'hidden md:flex' : 'flex'} flex-1 flex-col`}>
        <MainHeader
          selectedNote={selectedNote}
          notes={notes}
          setNotes={onNotesChange}
          viewingTrash={viewingTrash}
          isAdmin={isAdmin}
          onLoadNotes={onLoadNotes}
          onLoadTrash={onLoadTrash}
          onChangeView={onChangeView}
          onLogout={onLogout}
          onSetViewingTrash={onSetViewingTrash}
          onSetNotesError={onSetNotesError}
        />

        {selectedNote || currentView === 'editor' ? (
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
    </>
  )
}
