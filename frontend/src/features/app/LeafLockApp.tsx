import React, { useState, useEffect, useCallback, Suspense, lazy } from 'react'
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

export const LeafLockApp: React.FC = () => {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [currentView, setCurrentView] = useState<ViewType>('login')
  const [encryptionStatus, setEncryptionStatus] = useState<EncryptionStatus>('locked')
  const [viewingTrash, setViewingTrash] = useState(false)
  const [initializing, setInitializing] = useState(true)
  const [, setError] = useState<string | null>(null)
  const [showOnboarding, setShowOnboarding] = useState(false)
  const [onboardingStep, setOnboardingStep] = useState(0)
  const [isAdmin, setIsAdmin] = useState(false)
  const [showTemplateSelector, setShowTemplateSelector] = useState(false)
  const [showForgotPassword, setShowForgotPassword] = useState(false)
  const [resetToken, setResetToken] = useState<string | null>(null)

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
    setSelectedNote(null)
    setError(null)
    setNotesError(null)
    setIsAdmin(false)

    console.log('✅ Complete logout finished')
  }, [setSelectedNote, setNotesError])

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

        setCurrentView('notes')
        setEncryptionStatus('unlocked')
        await loadNotes()
      } catch (error) {
        console.error('💥 Failed to unlock with provided password:', error)
        throw error instanceof Error ? error : new Error('Failed to unlock notes')
      }
    },
    [loadNotes, handleLogout]
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
      setCurrentView('login')
    }
  }, [encryptionStatus, isAuthenticated, initializing, currentView])

  // Removed loading overlay - app initializes in background

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
          onChangeView={setCurrentView}
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
  if (resetToken) {
    return (
      <ResetPasswordView
        api={api}
        token={resetToken}
        onResetComplete={() => {
          setResetToken(null)
          setShowForgotPassword(false)
        }}
      />
    )
  }

  if (showForgotPassword) {
    return <ForgotPasswordView api={api} onBackToLogin={() => setShowForgotPassword(false)} />
  }

  return (
    <>
      <LoginView
        api={api}
        cryptoService={cryptoService}
        announcements={announcements}
        onForgotPassword={() => setShowForgotPassword(true)}
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
      <TemplateSelectorModal
        open={showTemplateSelector}
        onOpenChange={setShowTemplateSelector}
        onTemplateSelect={handleTemplateSelect}
      />
    </>
  )
}

export default LeafLockApp
