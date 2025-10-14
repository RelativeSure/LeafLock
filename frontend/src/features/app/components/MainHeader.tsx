import React, { Suspense, lazy } from 'react'
import { Shield, Settings, Hash, Folder, FileText } from 'lucide-react'
import { ThemeToggle } from '@/components/ThemeToggle'
import ComponentLoader from '@/components/loaders/ComponentLoader'
import { type Note, type ViewType } from '../types'

const ImportExportDialog = lazy(() =>
  import('@/components/ImportExportDialog').then((module) => ({ default: module.ImportExportDialog }))
)

interface MainHeaderProps {
  selectedNote: Note | null
  notes: Note[]
  setNotes: React.Dispatch<React.SetStateAction<Note[]>>
  viewingTrash: boolean
  isAdmin: boolean
  onLoadNotes: () => Promise<void>
  onLoadTrash: () => Promise<void>
  onChangeView: (view: ViewType) => void
  onLogout: () => void
  onSetViewingTrash: (viewing: boolean) => void
  onSetNotesError: (error: string | null) => void
}

export const MainHeader: React.FC<MainHeaderProps> = ({
  selectedNote,
  notes,
  setNotes,
  viewingTrash,
  isAdmin,
  onLoadNotes,
  onLoadTrash,
  onChangeView,
  onLogout,
  onSetViewingTrash,
  onSetNotesError,
}) => {
  return (
    <header className="hidden md:flex bg-card border-b border-border px-6 py-3 items-center justify-between">
      <div className="flex items-center space-x-4">
        <h1 className="text-lg font-semibold text-foreground">LeafLock</h1>
      </div>

      <div className="flex items-center space-x-4">
        <Suspense fallback={<ComponentLoader />}>
          <ImportExportDialog
            noteId={selectedNote?.id}
            notes={notes}
            setNotes={setNotes}
            onImportSuccess={() => onLoadNotes()}
          />
        </Suspense>

        <ThemeToggle />

        <button
          onClick={() => onChangeView('settings')}
          className="text-gray-400 hover:text-white transition focus:outline-none focus:ring-2 focus:ring-blue-500/50 rounded p-1"
          aria-label="Security settings"
          title="Security settings"
        >
          <Settings className="w-5 h-5" />
        </button>

        <button
          onClick={() => onChangeView('tags')}
          className="text-gray-400 hover:text-white transition focus:outline-none focus:ring-2 focus:ring-blue-500/50 rounded p-1"
          aria-label="Manage tags"
          title="Manage tags"
        >
          <Hash className="w-5 h-5" />
        </button>

        <button
          onClick={() => onChangeView('folders')}
          className="text-gray-400 hover:text-white transition focus:outline-none focus:ring-2 focus:ring-blue-500/50 rounded p-1"
          aria-label="Manage folders"
          title="Manage folders"
        >
          <Folder className="w-5 h-5" />
        </button>

        <button
          onClick={() => onChangeView('templates')}
          className="text-gray-400 hover:text-white transition focus:outline-none focus:ring-2 focus:ring-blue-500/50 rounded p-1"
          aria-label="Manage templates"
          title="Manage templates"
        >
          <FileText className="w-5 h-5" />
        </button>

        <button
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
          className={`flex items-center px-3 py-1 text-sm rounded transition focus:outline-none focus:ring-2 focus:ring-blue-500/50 ${
            viewingTrash ? 'bg-red-600 text-white' : 'text-gray-400 hover:text-white'
          }`}
          aria-label={viewingTrash ? 'Exit trash view' : 'View trash'}
          title={viewingTrash ? 'Exit trash view' : 'View trash'}
        >
          <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1-1H7a1 1 0 00-1 1v3M4 7h16"
            />
          </svg>
          {viewingTrash ? 'Exit Trash' : 'Trash'}
        </button>

        {isAdmin && (
          <button
            onClick={() => onChangeView('admin')}
            className="text-gray-400 hover:text-white transition focus:outline-none focus:ring-2 focus:ring-blue-500/50 rounded p-1"
            aria-label="Admin panel"
            title="Admin panel"
          >
            <Shield className="w-5 h-5" />
          </button>
        )}

        <button
          onClick={onLogout}
          className="text-gray-400 hover:text-white transition focus:outline-none focus:ring-2 focus:ring-blue-500/50 rounded p-1"
          aria-label="Sign out"
          title="Sign out"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"
            />
          </svg>
        </button>
      </div>
    </header>
  )
}
