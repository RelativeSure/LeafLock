import React, { useState, useEffect, useCallback, Suspense, lazy, useMemo, useRef } from 'react'
import { useNavigate, useRouterState } from '@tanstack/react-router'
import { OnboardingOverlay } from '@/features/onboarding/OnboardingOverlay'
import { LoginView } from '@/features/auth/LoginView'
import { UnlockView } from '@/features/auth/UnlockView'
import { ForgotPasswordView } from '@/features/auth/ForgotPasswordView'
import { ResetPasswordView } from '@/features/auth/ResetPasswordView'
import { getStoredAuthToken } from '@/utils/auth'
import { secureApi as api } from '@/services/secureApi'
import { cryptoService } from '@/services/cryptoService'
import ComponentLoader from '@/components/loaders/ComponentLoader'
import { type ViewType, type EncryptionStatus } from './types'
import { Template } from '@/services/templatesService'
import { AppLayout, TemplateSelectorModal } from './components'
import { useNotes } from './hooks/useNotes'
import { useAnnouncements } from './hooks/useAnnouncements'

const AdminPage = lazy(() => import('@/AdminPage'))
const SettingsPage = lazy(() =>
  import('@/components/settings/SettingsPage').then((module) => ({ default: module.SettingsPage }))
)
const TagsManager = lazy(() => import('@/components/TagsManager'))
const FoldersManager = lazy(() => import('@/components/FoldersManager'))
const TemplatesManager = lazy(() => import('@/components/TemplatesManager'))

const APP_VIEWS = new Set<ViewType>([
  'notes',
  'editor',
  'settings',
  'tags',
  'folders',
  'templates',
  'admin',
])
const POST_LOGIN_REDIRECT_VIEWS = new Set<ViewType>(['login', 'forgot'])

const normalizePath = (path: string): string => {
  if (!path) return '/'
  if (path === '/') return '/'
  return path.endsWith('/') ? path.slice(0, -1) : path
}

const viewToPathMap: Record<ViewType, string> = {
  login: '/auth/login',
  unlock: '/auth/unlock',
  forgot: '/auth/forgot',
  reset: '/auth/reset',
  notes: '/app/notes',
  editor: '/app/editor',
  settings: '/app/settings',
  tags: '/app/tags',
  folders: '/app/folders',
  templates: '/app/templates',
  admin: '/app/admin',
}

const viewToPath = (view: ViewType): string => viewToPathMap[view] ?? '/auth/login'

const pathToView = (path: string): { view: ViewType; known: boolean } => {
  switch (path) {
    case '/':
    case '/auth':
    case '/auth/login':
      return { view: 'login', known: true }
    case '/auth/unlock':
      return { view: 'unlock', known: true }
    case '/auth/forgot':
      return { view: 'forgot', known: true }
    case '/auth/reset':
      return { view: 'reset', known: true }
    case '/app':
    case '/app/notes':
      return { view: 'notes', known: true }
    case '/app/editor':
      return { view: 'editor', known: true }
    case '/app/settings':
      return { view: 'settings', known: true }
    case '/app/tags':
      return { view: 'tags', known: true }
    case '/app/folders':
      return { view: 'folders', known: true }
    case '/app/templates':
      return { view: 'templates', known: true }
    case '/app/admin':
      return { view: 'admin', known: true }
    default:
      return { view: 'login', known: false }
  }
}

export const LeafLockApp: React.FC = () => {
  const navigate = useNavigate({ from: '/' })
  const location = useRouterState({ select: (state) => state.location })
  const normalizedPath = useMemo(() => normalizePath(location.pathname), [location.pathname])
  const { view: derivedView, known: isKnownPath } = useMemo(
    () => pathToView(normalizedPath),
    [normalizedPath]
  )

  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [encryptionStatus, setEncryptionStatus] = useState<EncryptionStatus>('locked')
  const [isMobile, setIsMobile] = useState<boolean>(() =>
    typeof window === 'undefined' ? true : window.innerWidth < 768
  )
  const [viewingTrash, setViewingTrash] = useState(false)
  const [initializing, setInitializing] = useState(true)
  const [, setError] = useState<string | null>(null)
  const [showOnboarding, setShowOnboarding] = useState(false)
  const [onboardingStep, setOnboardingStep] = useState(0)
  const [isAdmin, setIsAdmin] = useState(false)
  const [showTemplateSelector, setShowTemplateSelector] = useState(false)
  const [resetToken, setResetToken] = useState<string | null>(null)

  // Track if initialization has completed to prevent re-running on navigation
  const hasInitialized = useRef(false)

  // Use custom hooks for notes and announcements
  const {
    notes,
    setNotes,
    trashedNotes,
    selectedNote,
    setSelectedNote,
    loading,
    notesError,
    setNotesError,
    loadNotes,
    loadTrash,
    handleRestoreNote,
    handlePermanentDelete,
    handleMoveNoteToTrash,
    handleStartNewNote,
  } = useNotes(api, () => handleLogout())

  const { announcements } = useAnnouncements(api, initializing)

  const goToView = useCallback(
    (view: ViewType) => {
      const target = viewToPath(view)
      const targetNormalized = normalizePath(target)
      if (targetNormalized === normalizedPath) {
        return
      }
      void navigate({ to: target as any })
    },
    [navigate, normalizedPath]
  )

  useEffect(() => {
    if (typeof window === 'undefined') return

    const handleResize = () => {
      setIsMobile(window.innerWidth < 768)
    }

    handleResize()
    window.addEventListener('resize', handleResize)

    return () => {
      window.removeEventListener('resize', handleResize)
    }
  }, [])

  const fallbackView: ViewType = useMemo(() => {
    if (!isAuthenticated) return 'login'
    return encryptionStatus === 'unlocked' ? 'notes' : 'unlock'
  }, [isAuthenticated, encryptionStatus])

  const currentView: ViewType = useMemo(
    () => (isKnownPath ? derivedView : fallbackView),
    [isKnownPath, derivedView, fallbackView]
  )

  useEffect(() => {
    if (!isKnownPath) {
      goToView(fallbackView)
      return
    }

    if (!isAuthenticated) {
      if (APP_VIEWS.has(currentView) || currentView === 'unlock') {
        goToView('login')
        return
      }
    } else {
      if (encryptionStatus === 'locked' && APP_VIEWS.has(currentView)) {
        goToView('unlock')
        return
      }

      if (encryptionStatus === 'unlocked') {
        if (currentView === 'unlock' || POST_LOGIN_REDIRECT_VIEWS.has(currentView)) {
          goToView('notes')
          return
        }
      }
    }

    if (normalizedPath === '/' || normalizedPath === '/auth') {
      goToView(fallbackView)
    } else if (normalizedPath === '/app') {
      goToView('notes')
    }
  }, [
    isKnownPath,
    fallbackView,
    goToView,
    normalizedPath,
    isAuthenticated,
    encryptionStatus,
    currentView,
  ])

  useEffect(() => {
    if (
      isAuthenticated &&
      encryptionStatus === 'unlocked' &&
      currentView === 'editor' &&
      !isMobile
    ) {
      goToView('notes')
    }
  }, [isAuthenticated, encryptionStatus, currentView, isMobile, goToView])

  console.log(
    '🔄 LeafLockApp render - initializing:',
    initializing,
    'isAuthenticated:',
    isAuthenticated,
    'currentView:',
    currentView,
    'path:',
    normalizedPath
  )

  const handleLogout = useCallback(() => {
    console.log('🚪 Performing complete logout...')

    api.clearToken()
    cryptoService.masterKey = null
    localStorage.removeItem('user_salt')

    setIsAuthenticated(false)
    goToView('login')
    setEncryptionStatus('locked')
    setSelectedNote(null)
    setError(null)
    setNotesError(null)
    setIsAdmin(false)

    console.log('✅ Complete logout finished')
  }, [goToView, setSelectedNote, setNotesError])

  const handleUnlockWithPassword = useCallback(
    async (password: string) => {
      const trimmed = password.trim()
      if (!trimmed) {
        throw new Error('Password is required')
      }

      const storedSalt = localStorage.getItem('user_salt')
      if (!storedSalt) {
        console.log('🚨 No stored salt found - redirecting to login')
        // Clear session and redirect to login
        handleLogout()
        throw new Error('Session expired. Please log in again.')
      }

      try {
        await cryptoService.initSodium()
        const salt = new Uint8Array(Array.from(atob(storedSalt), (c) => c.charCodeAt(0)))
        const key = await cryptoService.deriveKeyFromPassword(trimmed, salt)
        await cryptoService.setMasterKey(key)

        goToView('notes')
        setEncryptionStatus('unlocked')
        await loadNotes()
      } catch (error) {
        console.error('💥 Failed to unlock with provided password:', error)
        throw error instanceof Error ? error : new Error('Failed to unlock notes')
      }
    },
    [loadNotes, handleLogout, goToView]
  )

  const handleTemplateSelect = useCallback(
    async (template: Template) => {
      try {
        const response = await api.useTemplate(template.id, {
          title: `${template.name} - ${new Date().toLocaleDateString()}`,
        })

        console.log('✅ Note created from template:', response)

        setShowTemplateSelector(false)
        await loadNotes()

        const newNote = notes.find((note) => note.id === response.id)
        if (newNote) {
          setSelectedNote(newNote)
          goToView('editor')
        }
      } catch (err) {
        console.error('Failed to create note from template:', err)
        setError(err instanceof Error ? err.message : 'Failed to create note from template')
      }
    },
    [loadNotes, notes, goToView]
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
    // Check for password reset token in URL
    const urlParams = new URLSearchParams(window.location.search)
    const token = urlParams.get('token')
    if (token) {
      console.log('🔑 Password reset token found in URL')
      setResetToken(token)
      // Clear the token from URL for security
      window.history.replaceState({}, document.title, window.location.pathname)
    }
  }, [])

  useEffect(() => {
    // Only run initialization once on mount
    if (hasInitialized.current) {
      return
    }

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
              void navigate({ to: '/auth/unlock' as any })
              setEncryptionStatus('locked')
            } else {
              console.log('🔑 Master key found, initializing app...')
              setIsAuthenticated(true)
              void navigate({ to: '/app/notes' as any })
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
            void navigate({ to: '/auth/login' as any })
            setEncryptionStatus('locked')
          }
        } else {
          console.log('ℹ️ No stored token found - showing login')
          setIsAuthenticated(false)
          void navigate({ to: '/auth/login' as any })
          setEncryptionStatus('locked')
        }
      } catch (err) {
        console.error('💥 Failed to initialize app:', err)
        setError('Failed to initialize application')
        setIsAuthenticated(false)
        void navigate({ to: '/auth/login' as any })
        setEncryptionStatus('locked')
      } finally {
        console.log('🏁 App initialization complete, setting initializing = false')
        setInitializing(false)
        console.log('✅ setInitializing(false) called')
        hasInitialized.current = true
      }
    }

    void initializeApp()
  }, []) // Run only once on mount - intentionally ignoring loadNotes and navigate dependencies

  useEffect(() => {
    if (
      !initializing &&
      encryptionStatus === 'locked' &&
      isAuthenticated &&
      currentView !== 'unlock'
    ) {
      console.log(
        '🚨 Security check: Locked while authenticated outside unlock view - forcing logout'
      )
      setIsAuthenticated(false)
      goToView('login')
    }
  }, [encryptionStatus, isAuthenticated, initializing, currentView, goToView])

  // Removed loading overlay - app initializes in background

  if (isAuthenticated && encryptionStatus === 'unlocked' && currentView === 'settings') {
    return (
      <Suspense fallback={<ComponentLoader />}>
        <SettingsPage api={api} onBack={() => goToView('notes')} onLogout={handleLogout} />
      </Suspense>
    )
  }

  if (isAuthenticated && encryptionStatus === 'unlocked' && currentView === 'tags') {
    return (
      <div className="h-screen flex items-center justify-center bg-background">
        <Suspense fallback={<ComponentLoader />}>
          <TagsManager onClose={() => goToView('notes')} />
        </Suspense>
      </div>
    )
  }

  if (isAuthenticated && encryptionStatus === 'unlocked' && currentView === 'folders') {
    return (
      <div className="h-screen flex items-center justify-center bg-background">
        <Suspense fallback={<ComponentLoader />}>
          <FoldersManager onClose={() => goToView('notes')} />
        </Suspense>
      </div>
    )
  }

  if (isAuthenticated && encryptionStatus === 'unlocked' && currentView === 'templates') {
    return (
      <div className="h-screen flex items-center justify-center bg-background">
        <Suspense fallback={<ComponentLoader />}>
          <TemplatesManager onClose={() => goToView('notes')} mode="manage" />
        </Suspense>
      </div>
    )
  }

  if (isAuthenticated && encryptionStatus === 'unlocked' && isAdmin && currentView === 'admin') {
    return (
      <Suspense fallback={<ComponentLoader />}>
        <AdminPage api={api} onBack={() => goToView('notes')} />
      </Suspense>
    )
  }

  if (isAuthenticated && encryptionStatus === 'unlocked') {
    return (
      <>
        <AppLayout
          announcements={announcements}
          notes={notes}
          trashedNotes={trashedNotes}
          selectedNote={selectedNote}
          viewingTrash={viewingTrash}
          loading={loading}
          notesError={notesError}
          currentView={currentView}
          isAdmin={isAdmin}
          onSelectNote={setSelectedNote}
          onNotesChange={setNotes}
          onChangeView={goToView}
          onRestoreNote={handleRestoreNote}
          onPermanentDelete={handlePermanentDelete}
          onMoveToTrash={handleMoveNoteToTrash}
          onStartNewNote={handleStartNewNote}
          onOpenTemplateSelector={() => setShowTemplateSelector(true)}
          onLoadNotes={loadNotes}
          onLoadTrash={loadTrash}
          onSetViewingTrash={setViewingTrash}
          onSetNotesError={setNotesError}
          onLogout={handleLogout}
          api={api}
          cryptoService={cryptoService}
        />
        {showOnboarding && (
          <OnboardingOverlay
            step={onboardingStep}
            onNext={handleOnboardingNext}
            onPrev={handleOnboardingPrev}
            onSkip={handleOnboardingSkip}
            onComplete={handleOnboardingComplete}
          />
        )}
        <TemplateSelectorModal
          open={showTemplateSelector}
          onOpenChange={setShowTemplateSelector}
          onTemplateSelect={handleTemplateSelect}
        />
      </>
    )
  }

  if (isAuthenticated && currentView === 'unlock') {
    return <UnlockView onUnlock={handleUnlockWithPassword} onLogout={handleLogout} />
  }

  // Password reset flow
  if (currentView === 'reset' && resetToken) {
    return (
      <ResetPasswordView
        api={api}
        token={resetToken}
        onResetComplete={() => {
          setResetToken(null)
          goToView('login')
        }}
      />
    )
  }

  if (currentView === 'forgot') {
    return <ForgotPasswordView api={api} onBackToLogin={() => goToView('login')} />
  }

  return (
    <>
      <LoginView
        api={api}
        cryptoService={cryptoService}
        announcements={announcements}
        onForgotPassword={() => goToView('forgot')}
        onAuthenticated={async () => {
          setIsAuthenticated(true)
          goToView('notes')
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
      <TemplateSelectorModal
        open={showTemplateSelector}
        onOpenChange={setShowTemplateSelector}
        onTemplateSelect={handleTemplateSelect}
      />
    </>
  )
}

export default LeafLockApp
