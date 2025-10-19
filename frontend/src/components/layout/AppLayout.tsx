import React, { Suspense } from 'react'
import { Leaf, Shield, Settings, Hash, Folder, FileText, LogOut, Trash2 } from 'lucide-react'
import { AnnouncementBanner, type Announcement } from '@/features/announcements'
import { ThemeToggle } from '@/components/common'
import { ComponentLoader } from '@/components/loaders'
import { Separator } from '@/components/ui/separator'
import { Button } from '@/components/ui/button'
import { NotesWorkspace } from '@/features/workspace/components/NotesWorkspace'
import { type Note } from '@/types/auth'
import { type SecureAPI } from '@/services/api/secureApi'
import { type CryptoService } from '@/services/crypto/cryptoService'
import { ImportExportDialog } from '@/features/templates/components/ImportExportDialog'

interface AppLayoutProps {
  announcements: Announcement[]
  notes: Note[]
  trashedNotes: Note[]
  selectedNote: Note | null
  viewingTrash: boolean
  loading: boolean
  notesError: string | null

  isAdmin: boolean
  onSelectNote: (note: Note | null) => void
  onNotesChange: React.Dispatch<React.SetStateAction<Note[]>>
  onChangeView: (path: string) => void
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
      {/* Announcement Banner */}
      {loggedInAnnouncements.length > 0 && (
        <div className="border-b border-border bg-card/50 px-4 py-2 flex-shrink-0">
          <AnnouncementBanner announcements={loggedInAnnouncements} />
        </div>
      )}

      {/* App Header - Global Navigation */}
      <header className="h-14 border-b border-border bg-card flex items-center justify-between px-4 flex-shrink-0">
        {/* Left: Branding */}
        <div className="flex items-center gap-3">
          <Leaf className="w-5 h-5 text-primary" aria-hidden="true" />
          <h1 className="text-base font-semibold tracking-tight">LeafLock</h1>
          {selectedNote && (
            <span className="hidden lg:inline text-sm text-muted-foreground">
              / {selectedNote.title || 'Untitled'}
            </span>
          )}
        </div>

        {/* Right: Global Actions */}
        <div className="flex items-center gap-2">
          <Suspense fallback={<ComponentLoader />}>
            <ImportExportDialog
              noteId={selectedNote?.id}
              notes={notes}
              setNotes={onNotesChange}
              onImportSuccess={() => onLoadNotes()}
            />
          </Suspense>

          <ThemeToggle />

          <Separator orientation="vertical" className="h-6 hidden md:block" />

          <Button
            variant="ghost"
            size="icon"
            onClick={() => onChangeView('/app/settings')}
            aria-label="Security settings"
            title="Security settings"
            className="hidden md:inline-flex"
          >
            <Settings className="w-5 h-5" />
          </Button>

          <Button
            variant="ghost"
            size="icon"
            onClick={() => onChangeView('/app/tags')}
            aria-label="Manage tags"
            title="Manage tags"
            className="hidden md:inline-flex"
          >
            <Hash className="w-5 h-5" />
          </Button>

          <Button
            variant="ghost"
            size="icon"
            onClick={() => onChangeView('/app/folders')}
            aria-label="Manage folders"
            title="Manage folders"
            className="hidden md:inline-flex"
          >
            <Folder className="w-5 h-5" />
          </Button>

          <Button
            variant="ghost"
            size="icon"
            onClick={() => onChangeView('/app/templates')}
            aria-label="Manage templates"
            title="Manage templates"
            className="hidden md:inline-flex"
          >
            <FileText className="w-5 h-5" />
          </Button>

          <Button
            variant={viewingTrash ? 'destructive' : 'ghost'}
            size="sm"
            onClick={async () => {
              try {
                const newViewingTrash = !viewingTrash
                onSetViewingTrash(newViewingTrash)
                onSetNotesError(null)
                if (newViewingTrash) {
                  await onLoadTrash()
                }
              } catch (err) {
                console.error('Failed to toggle trash view:', err)
                onSetNotesError('Failed to toggle trash view')
                onSetViewingTrash(false)
              }
            }}
            aria-label={viewingTrash ? 'Exit trash view' : 'View trash'}
            title={viewingTrash ? 'Exit trash view' : 'View trash'}
            className="hidden md:inline-flex"
          >
            <Trash2 className="w-4 h-4 mr-1" />
            {viewingTrash ? 'Exit Trash' : 'Trash'}
          </Button>

          {isAdmin && (
            <Button
              variant="ghost"
              size="icon"
              onClick={() => onChangeView('/app/admin')}
              aria-label="Admin panel"
              title="Admin panel"
              className="hidden md:inline-flex"
            >
              <Shield className="w-5 h-5" />
            </Button>
          )}

          <Separator orientation="vertical" className="h-6 hidden md:block" />

          <Button
            variant="ghost"
            size="icon"
            onClick={onLogout}
            aria-label="Sign out"
            title="Sign out"
          >
            <LogOut className="w-5 h-5" />
          </Button>
        </div>
      </header>

      {/* Main Workspace with Resizable Panels */}
      <div className="flex-1 overflow-hidden">
        <NotesWorkspace
          notes={notes}
          trashedNotes={trashedNotes}
          selectedNote={selectedNote}
          viewingTrash={viewingTrash}
          loading={loading}
          notesError={notesError}
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
          api={api}
          cryptoService={cryptoService}
        />
      </div>
    </div>
  )
}
