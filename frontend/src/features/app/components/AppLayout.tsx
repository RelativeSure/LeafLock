import React from 'react'
import Footer from '@/components/Footer'
import AnnouncementBanner, { type Announcement } from '@/components/AnnouncementBanner'
import { NotesWorkspace } from './NotesWorkspace'
import { type Note, type ViewType } from '../types'
import { type SecureAPI } from '@/services/secureApi'
import { type CryptoService } from '@/services/cryptoService'

interface AppLayoutProps {
  announcements: Announcement[]
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
  onLoadNotes: () => Promise<void>
  onLoadTrash: () => Promise<void>
  onSetViewingTrash: (viewing: boolean) => void
  onSetNotesError: (error: string | null) => void
  onLogout: () => void
  api: SecureAPI
  cryptoService: CryptoService
}

export const AppLayout: React.FC<AppLayoutProps> = ({
  announcements,
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
  onLoadNotes,
  onLoadTrash,
  onSetViewingTrash,
  onSetNotesError,
  onLogout,
  api,
  cryptoService,
}) => {
  const loggedInAnnouncements = announcements.filter(
    (announcement) => announcement.visibility === 'all' || announcement.visibility === 'logged_in'
  )

  return (
    <div className="h-screen flex flex-col bg-background">
      {loggedInAnnouncements.length > 0 && (
        <div className="border-b border-border bg-card/50 px-4 py-2">
          <AnnouncementBanner announcements={loggedInAnnouncements} />
        </div>
      )}

      <div className="flex-1 flex flex-col md:flex-row overflow-hidden">
        <NotesWorkspace
          notes={notes}
          trashedNotes={trashedNotes}
          selectedNote={selectedNote}
          viewingTrash={viewingTrash}
          loading={loading}
          notesError={notesError}
          currentView={currentView}
          isAdmin={isAdmin}
          onSelectNote={onSelectNote}
          onNotesChange={onNotesChange}
          onChangeView={onChangeView}
          onRestoreNote={onRestoreNote}
          onPermanentDelete={onPermanentDelete}
          onMoveToTrash={onMoveToTrash}
          onStartNewNote={onStartNewNote}
          onOpenTemplateSelector={onOpenTemplateSelector}
          onRetryLoad={onLoadNotes}
          onDismissError={() => onSetNotesError(null)}
          onLoadNotes={onLoadNotes}
          onLoadTrash={onLoadTrash}
          onSetViewingTrash={onSetViewingTrash}
          onSetNotesError={onSetNotesError}
          onLogout={onLogout}
          api={api}
          cryptoService={cryptoService}
        />
      </div>

      <Footer />
    </div>
  )
}
