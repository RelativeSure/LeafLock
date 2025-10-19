import React, { useEffect, useState } from 'react'
import { OnboardingOverlay } from '@/features/onboarding/components/OnboardingOverlay'
import { LoginView } from '@/features/auth/views/LoginView'
import { ForgotPasswordView } from '@/features/auth/views/ForgotPasswordView'
import { ResetPasswordView } from '@/features/auth/views/ResetPasswordView'
import { UnlockView } from '@/features/auth/views/UnlockView'
import { SettingsView } from '@/features/settings/views/SettingsView'
import { TagsView } from '@/features/tags/views/TagsView'
import { FoldersView } from '@/features/folders/views/FoldersView'
import { TemplatesView } from '@/features/templates/views/TemplatesView'
import { AdminView } from '@/features/admin/views/AdminView'
import { AppLayout } from '@/components/layout/AppLayout'
import { TemplateSelectorModal } from '@/features/templates/components/TemplateSelectorModal'
import { secureApi as api } from '@/services/api/secureApi'
import { cryptoService } from '@/services/crypto/cryptoService'
import { useNotes } from '@/features/notes/hooks/useNotes'
import { useAnnouncements } from '@/features/announcements/hooks/useAnnouncements'
import { useAuthentication } from '@/features/auth/hooks/useAuthentication'
import { useOnboarding } from '@/features/onboarding/hooks/useOnboarding'
import { useTemplates } from '@/features/templates/hooks/useTemplates'
import { useRouting } from '@/features/workspace/hooks/useRouting'
import { ROUTES } from '@/config/constants'

export const AppRouter: React.FC = () => {
  const [, setError] = useState<string | null>(null)
  const [viewingTrash, setViewingTrash] = useState(false)

  // Authentication hook - declared first with minimal dependencies
  const {
    isAuthenticated,
    encryptionStatus,
    isAdmin,
    initializing,
    resetToken,
    handleLogout,
    handleUnlockWithPassword,
    handleAuthenticated,
    initializeApp,
    setResetToken,
    navigateToPath,
  } = useAuthentication()

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
  } = useNotes(api, handleLogout)

  const { announcements } = useAnnouncements(api, initializing)

  // Onboarding hook
  const {
    showOnboarding,
    onboardingStep,
    handleOnboardingNext,
    handleOnboardingPrev,
    handleOnboardingSkip,
    handleOnboardingComplete,
    checkAndShowOnboarding,
  } = useOnboarding()

  // Templates hook
  const {
    showTemplateSelector,
    handleTemplateSelect,
    openTemplateSelector,
    closeTemplateSelector,
  } = useTemplates({
    notes,
    onNotesLoad: loadNotes,
    onSelectedNoteChange: setSelectedNote,
    onNavigate: navigateToPath,
    onError: setError,
  })

  // Routing hook
  const { currentView } = useRouting({
    isAuthenticated,
    encryptionStatus,
    navigateToPath,
  })

  // Check for password reset token in URL
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search)
    const token = urlParams.get('token')
    if (token) {
      console.log('🔑 Password reset token found in URL')
      setResetToken(token)
      // Clear the token from URL for security
      window.history.replaceState({}, document.title, window.location.pathname)
    }
  }, [setResetToken])

  // Initialize app on mount
  useEffect(() => {
    void initializeApp()
  }, [initializeApp])

  // Show onboarding after successful authentication and notes load
  useEffect(() => {
    if (isAuthenticated && encryptionStatus === 'unlocked' && !initializing) {
      checkAndShowOnboarding()
    }
  }, [isAuthenticated, encryptionStatus, initializing, checkAndShowOnboarding])

  console.log(
    '🔄 AppRouter render - initializing:',
    initializing,
    'isAuthenticated:',
    isAuthenticated,
    'currentView:',
    currentView
  )

  // Render different views based on authentication and current view
  if (isAuthenticated && encryptionStatus === 'unlocked') {
    // Settings view
    if (currentView === 'settings') {
      return (
        <SettingsView
          onBack={() => navigateToPath(ROUTES.notes)}
          onLogout={handleLogout}
        />
      )
    }

    // Tags view
    if (currentView === 'tags') {
      return <TagsView onClose={() => navigateToPath(ROUTES.notes)} />
    }

    // Folders view
    if (currentView === 'folders') {
      return <FoldersView onClose={() => navigateToPath(ROUTES.notes)} />
    }

    // Templates view
    if (currentView === 'templates') {
      return (
        <TemplatesView onClose={() => navigateToPath(ROUTES.notes)} />
      )
    }

    // Admin view
    if (isAdmin && currentView === 'admin') {
      return <AdminView onBack={() => navigateToPath(ROUTES.notes)} />
    }

    // Main app view (notes/editor)
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
          isAdmin={isAdmin}
          onSelectNote={setSelectedNote}
          onNotesChange={setNotes}
          onChangeView={navigateToPath}
          onRestoreNote={handleRestoreNote}
          onPermanentDelete={handlePermanentDelete}
          onMoveToTrash={handleMoveNoteToTrash}
          onStartNewNote={handleStartNewNote}
          onOpenTemplateSelector={openTemplateSelector}
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
          onOpenChange={closeTemplateSelector}
          onTemplateSelect={handleTemplateSelect}
        />
      </>
    )
  }

  // Unlock view
  if (isAuthenticated && currentView === 'unlock') {
    return (
      <UnlockView
        onUnlock={handleUnlockWithPassword}
        onLogout={handleLogout}
      />
    )
  }

  // Password reset flow
  if (currentView === 'reset' && resetToken) {
    return (
      <ResetPasswordView
        api={api}
        token={resetToken}
        onResetComplete={() => {
          setResetToken(null)
          navigateToPath(ROUTES.login)
        }}
      />
    )
  }

  // Forgot password view
  if (currentView === 'forgot') {
    return (
      <ForgotPasswordView
        api={api}
        onBackToLogin={() => navigateToPath(ROUTES.login)}
      />
    )
  }

  // Login view (default)
  return (
    <>
      <LoginView
        api={api}
        cryptoService={cryptoService}
        announcements={announcements}
        onForgotPassword={() => navigateToPath(ROUTES.forgot)}
        onAuthenticated={handleAuthenticated}
      />
      <TemplateSelectorModal
        open={showTemplateSelector}
        onOpenChange={closeTemplateSelector}
        onTemplateSelect={handleTemplateSelect}
      />
    </>
  )
}

export default AppRouter
