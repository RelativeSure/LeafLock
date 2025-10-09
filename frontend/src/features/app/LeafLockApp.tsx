import React, { useState, useEffect, useCallback, Suspense, lazy } from 'react'
import { Shield, Settings, Hash, Folder, FileText } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { OnboardingOverlay } from '@/features/onboarding/OnboardingOverlay'
import { LoginView } from '@/features/auth/LoginView'
import { UnlockView } from '@/features/auth/UnlockView'
import Footer from '@/components/Footer'
import AnnouncementBanner, { Announcement } from '@/components/AnnouncementBanner'
import { getStoredAuthToken } from '@/utils/auth'
import { secureApi as api } from '@/services/secureApi'
import { cryptoService } from '@/services/cryptoService'
import { NotesEditor } from '@/features/notes/components/NotesEditor'
import { NotesList } from '@/features/notes/components/NotesList'
import ComponentLoader from '@/components/loaders/ComponentLoader'
import { ThemeToggle } from '@/components/ThemeToggle'
import { type Note, type ViewType, type EncryptionStatus } from './types'
import { Template } from '@/services/templatesService'

const AdminPage = lazy(() => import('@/AdminPage'))
const SettingsPage = lazy(() =>
  import('@/components/settings/SettingsPage').then((module) => ({ default: module.SettingsPage }))
)
const ImportExportDialog = lazy(() =>
  import('@/components/ImportExportDialog').then((module) => ({ default: module.ImportExportDialog }))
)
const TagsManager = lazy(() => import('@/components/TagsManager'))
const FoldersManager = lazy(() => import('@/components/FoldersManager'))
const TemplatesManager = lazy(() => import('@/components/TemplatesManager'))

export const LeafLockApp: React.FC = () => {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [currentView, setCurrentView] = useState<ViewType>('login')
  const [notes, setNotes] = useState<Note[]>([])
  const [trashedNotes, setTrashedNotes] = useState<Note[]>([])
  const [selectedNote, setSelectedNote] = useState<Note | null>(null)
  const [encryptionStatus, setEncryptionStatus] = useState<EncryptionStatus>('locked')
  const [viewingTrash, setViewingTrash] = useState(false)
  const [loading, setLoading] = useState(false)
  const [initializing, setInitializing] = useState(true)
  const [, setError] = useState<string | null>(null)
  const [notesError, setNotesError] = useState<string | null>(null)
  const [showOnboarding, setShowOnboarding] = useState(false)
  const [onboardingStep, setOnboardingStep] = useState(0)
  const [isAdmin, setIsAdmin] = useState(false)
  const [announcements, setAnnouncements] = useState<Announcement[]>([])
  const [_announcementsLoading, setAnnouncementsLoading] = useState(false)
  const [showTemplateSelector, setShowTemplateSelector] = useState(false)

  console.log(
    '🔄 LeafLockApp render - initializing:',
    initializing,
    'isAuthenticated:',
    isAuthenticated,
    'currentView:',
    currentView
  )

  const handleLogout = useCallback(() => {
    console.log('🚪 Performing complete logout...')

    api.clearToken()
    cryptoService.masterKey = null
    localStorage.removeItem('user_salt')

    setIsAuthenticated(false)
    setCurrentView('login')
    setEncryptionStatus('locked')
    setNotes([])
    setTrashedNotes([])
    setSelectedNote(null)
    setError(null)
    setNotesError(null)
    setIsAdmin(false)

    console.log('✅ Complete logout finished')
  }, [])

  const loadNotes = useCallback(async () => {
    try {
      setLoading(true)
      setNotesError(null)
      console.log('📝 Loading notes...')
      const fetchedNotes = await api.getNotes()
      setNotes(fetchedNotes)
      console.log(`✅ Loaded ${fetchedNotes.length} notes`)
    } catch (err) {
      console.error('💥 Failed to load notes:', err)
      const message = (err as Error).message || 'Failed to load notes'

      if (message.includes('401') || message.includes('Unauthorized')) {
        console.log('🚨 Authentication error while loading notes - logging out')
        handleLogout()
        return
      }

      setNotesError(message)
    } finally {
      setLoading(false)
    }
  }, [handleLogout])

  const loadTrash = useCallback(async () => {
    try {
      setLoading(true)
      setNotesError(null)
      console.log('🗑️ Loading trash...')
      const fetchedTrash = await api.getTrash()
      setTrashedNotes(fetchedTrash)
      console.log(`✅ Loaded ${fetchedTrash.length} trashed notes`)
    } catch (err) {
      console.error('💥 Failed to load trash:', err)
      const message = (err as Error).message || 'Failed to load trash'

      if (message.includes('401') || message.includes('Unauthorized')) {
        console.log('🚨 Authentication error while loading trash - logging out')
        handleLogout()
        return
      }

      setNotesError(message)
    } finally {
      setLoading(false)
    }
  }, [handleLogout])

  const handleUnlockWithPassword = useCallback(
    async (password: string) => {
      const trimmed = password.trim()
      if (!trimmed) {
        throw new Error('Password is required')
      }

      const storedSalt = localStorage.getItem('user_salt')
      if (!storedSalt) {
        throw new Error('No stored salt found - please log in again')
      }

      try {
        await cryptoService.initSodium()
        const salt = new Uint8Array(Array.from(atob(storedSalt), (c) => c.charCodeAt(0)))
        const key = await cryptoService.deriveKeyFromPassword(trimmed, salt)
        await cryptoService.setMasterKey(key)

        setCurrentView('notes')
        setEncryptionStatus('unlocked')
        await loadNotes()
      } catch (error) {
        console.error('💥 Failed to unlock with provided password:', error)
        throw (error instanceof Error ? error : new Error('Failed to unlock notes'))
      }
    },
    [loadNotes]
  )

  const handleRestoreNote = useCallback(
    async (noteId: string) => {
      try {
        console.log('♻️ Restoring note:', noteId)
        await api.restoreNote(noteId)
        console.log('✅ Note restored successfully')

        await Promise.all([loadNotes(), loadTrash()])

        if (selectedNote && selectedNote.id === noteId) {
          setSelectedNote(null)
        }
      } catch (err) {
        console.error('💥 Failed to restore note:', err)
        setNotesError((err as Error).message || 'Failed to restore note')
      }
    },
    [loadNotes, loadTrash, selectedNote]
  )

  const handlePermanentDelete = useCallback(
    async (noteId: string) => {
      try {
        console.log('🗑️ Permanently deleting note:', noteId)
        await api.permanentlyDeleteNote(noteId)
        console.log('✅ Note permanently deleted')

        await loadTrash()

        if (selectedNote && selectedNote.id === noteId) {
          setSelectedNote(null)
        }
      } catch (err) {
        console.error('💥 Failed to permanently delete note:', err)
        setNotesError((err as Error).message || 'Failed to permanently delete note')
      }
    },
    [loadTrash, selectedNote]
  )

  const handleMoveNoteToTrash = useCallback(
    async (noteId: string): Promise<boolean> => {
      try {
        await api.deleteNote(noteId)
        setNotes((prevNotes) => prevNotes.filter((note) => note.id !== noteId))

        if (selectedNote?.id === noteId) {
          setSelectedNote(null)
        }

        return true
      } catch (err) {
        console.error('Failed to delete note:', err)
        setNotesError((err as Error).message || 'Failed to delete note')
        return false
      }
    },
    [selectedNote]
  )

  const handleStartNewNote = useCallback(() => {
    const now = new Date().toISOString()
    setSelectedNote({
      id: '',
      title: '',
      content: '',
      created_at: now,
      updated_at: now,
    })
  }, [])

  const handleTemplateSelect = useCallback(
    async (template: Template) => {
      try {
        const response = await api.request(`/templates/${template.id}/use`, {
          method: 'POST',
          body: JSON.stringify({
            title: `${template.name} - ${new Date().toLocaleDateString()}`,
          }),
        })

        console.log('✅ Note created from template:', response)

        setShowTemplateSelector(false)
        await loadNotes()

        const newNote = notes.find((note) => note.id === response.id)
        if (newNote) {
          setSelectedNote(newNote)
          setCurrentView('editor')
        }
      } catch (err) {
        console.error('Failed to create note from template:', err)
        setError(err instanceof Error ? err.message : 'Failed to create note from template')
      }
    },
    [loadNotes, notes]
  )

  const handleOnboardingNext = () => {
    setOnboardingStep((prev) => prev + 1)
  }

  const handleOnboardingPrev = () => {
    setOnboardingStep((prev) => Math.max(0, prev - 1))
  }

  const handleOnboardingSkip = () => {
    localStorage.setItem('hasSeenOnboarding', 'true')
    setShowOnboarding(false)
    setOnboardingStep(0)
  }

  const handleOnboardingComplete = () => {
    localStorage.setItem('hasSeenOnboarding', 'true')
    setShowOnboarding(false)
    setOnboardingStep(0)
  }

  useEffect(() => {
    const initializeApp = async () => {
      try {
        console.log('🚀 Starting app initialization...')
        const token = getStoredAuthToken()
        if (token && !localStorage.getItem('current_user_id')) {
          try {
            const payload = JSON.parse(atob(token.split('.')[1] || ''))
            if (payload && typeof payload.user_id === 'string') {
              localStorage.setItem('current_user_id', payload.user_id)
            }
          } catch {
            // ignore payload parsing failures; setup continues without cached id
          }
        }

        if (token) {
          console.log('🔐 Found stored token, validating...')
          let isValid = false
          try {
            console.log('🔍 Validating token with 3-second timeout...')
            const timeoutPromise = new Promise<boolean>((_, reject) =>
              setTimeout(() => reject(new Error('Validation timeout')), 3000)
            )
            isValid = await Promise.race([api.validateToken(), timeoutPromise])
          } catch (err) {
            console.warn('⚠️ Token validation failed:', err)
            isValid = false
          }

          if (isValid) {
            console.log('✅ Token valid, checking encryption key...')
            try {
              const adminOk = await api.adminHealth()
              setIsAdmin(!!adminOk)
            } catch {
              setIsAdmin(false)
            }

            if (!cryptoService.masterKey) {
              console.log('🔐 No master key - user needs to re-enter password')
              setIsAuthenticated(true)
              setCurrentView('unlock')
              setEncryptionStatus('locked')
            } else {
              console.log('🔑 Master key found, initializing app...')
              setIsAuthenticated(true)
              setCurrentView('notes')
              setEncryptionStatus('unlocked')
              loadNotes().catch((err) => {
                console.error('Failed to load notes during init:', err)
              })
              const hasSeenOnboarding = localStorage.getItem('hasSeenOnboarding')
              if (!hasSeenOnboarding) {
                setShowOnboarding(true)
              }
            }
          } else {
            console.log('❌ Token invalid, clearing and redirecting to login')
            api.clearToken()
            localStorage.removeItem('user_salt')
            cryptoService.masterKey = null
            setIsAuthenticated(false)
            setCurrentView('login')
            setEncryptionStatus('locked')
          }
        } else {
          console.log('ℹ️ No stored token found - showing login')
          setIsAuthenticated(false)
          setCurrentView('login')
          setEncryptionStatus('locked')
        }
      } catch (err) {
        console.error('💥 Failed to initialize app:', err)
        setError('Failed to initialize application')
        setIsAuthenticated(false)
        setCurrentView('login')
        setEncryptionStatus('locked')
      } finally {
        console.log('🏁 App initialization complete, setting initializing = false')
        setInitializing(false)
        console.log('✅ setInitializing(false) called')
      }
    }

    void initializeApp()
  }, [loadNotes])

  const loadAnnouncements = useCallback(async () => {
    try {
      setAnnouncementsLoading(true)
      const response = await api.getAnnouncements()
      setAnnouncements(response.announcements || [])
    } catch (error) {
      console.warn('Failed to load announcements:', error)
    } finally {
      setAnnouncementsLoading(false)
    }
  }, [])

  useEffect(() => {
    if (!initializing) {
      void loadAnnouncements()
    }
  }, [initializing, loadAnnouncements])

  useEffect(() => {
    if (!initializing && encryptionStatus === 'locked' && isAuthenticated && currentView !== 'unlock') {
      console.log('🚨 Security check: Locked while authenticated outside unlock view - forcing logout')
      setIsAuthenticated(false)
      setCurrentView('login')
    }
  }, [encryptionStatus, isAuthenticated, initializing, currentView])

  // Removed loading overlay - app initializes in background

  const AppLayout: React.FC = () => {
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

        <div className="flex-1 flex flex-col md:flex-row">
          <div className="md:hidden flex items-center justify-between bg-card border-b border-border px-4 py-3">
            <h1 className="text-lg font-semibold text-foreground">LeafLock</h1>
            <Button
              onClick={() => setCurrentView(currentView === 'notes' ? 'editor' : 'notes')}
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
              onRetryLoad={loadNotes}
              onDismissError={() => setNotesError(null)}
              onSelectNote={setSelectedNote}
              onClearSelection={() => setSelectedNote(null)}
              onChangeView={setCurrentView}
              onRestoreNote={handleRestoreNote}
              onPermanentDelete={handlePermanentDelete}
              onMoveToTrash={handleMoveNoteToTrash}
              onStartNewNote={handleStartNewNote}
              onOpenTemplateSelector={() => setShowTemplateSelector(true)}
            />
          </div>

          <div
            className={`${currentView === 'notes' && !selectedNote ? 'hidden md:flex' : 'flex'} flex-1 flex-col`}
          >
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
                    onImportSuccess={() => loadNotes()}
                  />
                </Suspense>

                <ThemeToggle />

                <button
                  onClick={() => setCurrentView('settings')}
                  className="text-gray-400 hover:text-white transition focus:outline-none focus:ring-2 focus:ring-blue-500/50 rounded p-1"
                  aria-label="Security settings"
                  title="Security settings"
                >
                  <Settings className="w-5 h-5" />
                </button>

                <button
                  onClick={() => setCurrentView('tags')}
                  className="text-gray-400 hover:text-white transition focus:outline-none focus:ring-2 focus:ring-blue-500/50 rounded p-1"
                  aria-label="Manage tags"
                  title="Manage tags"
                >
                  <Hash className="w-5 h-5" />
                </button>

                <button
                  onClick={() => setCurrentView('folders')}
                  className="text-gray-400 hover:text-white transition focus:outline-none focus:ring-2 focus:ring-blue-500/50 rounded p-1"
                  aria-label="Manage folders"
                  title="Manage folders"
                >
                  <Folder className="w-5 h-5" />
                </button>

                <button
                  onClick={() => setCurrentView('templates')}
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
                      setViewingTrash(newViewingTrash)
                      setNotesError(null) // Clear any existing errors
                      if (newViewingTrash) {
                        await loadTrash()
                      }
                    } catch (err) {
                      console.error('Failed to toggle trash view:', err)
                      setNotesError('Failed to toggle trash view')
                      setViewingTrash(false) // Reset to safe state
                    }
                  }}
                  className={`flex items-center px-3 py-1 text-sm rounded transition focus:outline-none focus:ring-2 focus:ring-blue-500/50 ${
                    viewingTrash ? 'bg-red-600 text-white' : 'text-gray-400 hover:text-white'
                  }`}
                  aria-label={viewingTrash ? 'Exit trash view' : 'View trash'}
                  title={viewingTrash ? 'Exit trash view' : 'View trash'}
                >
                  <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1-1H7a1 1 0 00-1 1v3M4 7h16" />
                  </svg>
                  {viewingTrash ? 'Exit Trash' : 'Trash'}
                </button>

                {isAdmin && (
                  <button
                    onClick={() => setCurrentView('admin')}
                    className="text-gray-400 hover:text-white transition focus:outline-none focus:ring-2 focus:ring-blue-500/50 rounded p-1"
                    aria-label="Admin panel"
                    title="Admin panel"
                  >
                    <Shield className="w-5 h-5" />
                  </button>
                )}

                <button
                  onClick={handleLogout}
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

            {selectedNote || currentView === 'editor' ? (
              <NotesEditor
                selectedNote={selectedNote}
                onSelectNote={setSelectedNote}
                onNotesChange={setNotes}
                api={api}
                cryptoService={cryptoService}
              />
            ) : (
              <main className="flex-1 flex items-center justify-center" role="main">
                <div className="text-center">
                  <svg className="w-16 h-16 mx-auto text-gray-600 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  <p className="text-gray-500">Select a note or create a new one</p>
                  <p className="text-gray-600 text-sm mt-2">Your notes are end-to-end encrypted for maximum privacy</p>
                </div>
              </main>
            )}
          </div>
        </div>
        <Footer />
      </div>
    )
  }

  if (isAuthenticated && encryptionStatus === 'unlocked' && currentView === 'settings') {
    return (
      <Suspense fallback={<ComponentLoader />}>
        <SettingsPage api={api} onBack={() => setCurrentView('notes')} onLogout={handleLogout} />
      </Suspense>
    )
  }

  if (isAuthenticated && encryptionStatus === 'unlocked' && currentView === 'tags') {
    return (
      <div className="h-screen flex items-center justify-center bg-background">
        <Suspense fallback={<ComponentLoader />}>
          <TagsManager onClose={() => setCurrentView('notes')} />
        </Suspense>
      </div>
    )
  }

  if (isAuthenticated && encryptionStatus === 'unlocked' && currentView === 'folders') {
    return (
      <div className="h-screen flex items-center justify-center bg-background">
        <Suspense fallback={<ComponentLoader />}>
          <FoldersManager onClose={() => setCurrentView('notes')} />
        </Suspense>
      </div>
    )
  }

  if (isAuthenticated && encryptionStatus === 'unlocked' && currentView === 'templates') {
    return (
      <div className="h-screen flex items-center justify-center bg-background">
        <Suspense fallback={<ComponentLoader />}>
          <TemplatesManager onClose={() => setCurrentView('notes')} mode="manage" />
        </Suspense>
      </div>
    )
  }

  if (isAuthenticated && encryptionStatus === 'unlocked' && isAdmin && currentView === 'admin') {
    return (
      <Suspense fallback={<ComponentLoader />}>
        <AdminPage api={api} onBack={() => setCurrentView('notes')} />
      </Suspense>
    )
  }

  if (isAuthenticated && encryptionStatus === 'unlocked') {
    return (
      <>
        <AppLayout />
        {showOnboarding && (
          <OnboardingOverlay
            step={onboardingStep}
            onNext={handleOnboardingNext}
            onPrev={handleOnboardingPrev}
            onSkip={handleOnboardingSkip}
            onComplete={handleOnboardingComplete}
          />
        )}
        {showTemplateSelector && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
            <div className="bg-background rounded-lg max-w-6xl w-full max-h-[90vh] overflow-hidden">
              <Suspense fallback={<ComponentLoader />}>
                <TemplatesManager
                  onClose={() => setShowTemplateSelector(false)}
                  onTemplateSelect={handleTemplateSelect}
                  mode="select"
                />
              </Suspense>
            </div>
          </div>
        )}
      </>
    )
  }

  if (isAuthenticated && currentView === 'unlock') {
    return <UnlockView onUnlock={handleUnlockWithPassword} onLogout={handleLogout} />
  }

  return (
    <>
      <LoginView
        api={api}
        cryptoService={cryptoService}
        announcements={announcements}
        onAuthenticated={async () => {
          setIsAuthenticated(true)
          setCurrentView('notes')
          setEncryptionStatus('unlocked')
          try {
            const adminOk = await api.adminHealth()
            setIsAdmin(!!adminOk)
          } catch {
            setIsAdmin(false)
          }
          try {
            await loadNotes()
          } catch (e) {
            console.error('Failed to load notes after auth:', e)
          }
          const hasSeenOnboarding = localStorage.getItem('hasSeenOnboarding')
          if (!hasSeenOnboarding) setShowOnboarding(true)
        }}
      />
      {showTemplateSelector && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-background rounded-lg max-w-6xl w-full max-h-[90vh] overflow-hidden">
            <Suspense fallback={<ComponentLoader />}>
              <TemplatesManager
                onClose={() => setShowTemplateSelector(false)}
                onTemplateSelect={handleTemplateSelect}
                mode="select"
              />
            </Suspense>
          </div>
        </div>
      )}
    </>
  )
}

export default LeafLockApp
