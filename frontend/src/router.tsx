import React from 'react'
import { Outlet, createRoute, createRouter, createRootRoute } from '@tanstack/react-router'

import { ThemeProvider } from './context/ThemeContext'
import { EncryptionProvider } from './lib/encryption-context'
// import { Toaster } from './components/ui/sonner'
// Temporarily remove AppErrorBoundary to isolate React 185
import { useAuthStore } from './stores/authStore'

// Lazy load stores and components to prevent circular dependencies
const LoginForm = React.lazy(() =>
  import('./components/auth/login-form').then((m) => ({ default: m.LoginForm }))
)
const RegisterForm = React.lazy(() =>
  import('./components/auth/register-form').then((m) => ({ default: m.RegisterForm }))
)
const ForgotPasswordForm = React.lazy(() =>
  import('./components/auth/forgot-password-form').then((m) => ({ default: m.ForgotPasswordForm }))
)
// Direct imports to avoid ref/timing issues during auth transitions
import { Sidebar } from './components/dashboard/sidebar'
<<<<<<< HEAD
const NoteEditor = React.lazy(() =>
  import('./components/dashboard/note-editor').then((m) => ({ default: m.NoteEditor }))
)
=======
// import { NoteEditor } from './components/dashboard/note-editor'
>>>>>>> 92a5971798cd3aa571a071ab07873cbaceace8a4
// import { NoteEditor } from './components/dashboard/note-editor'
// Removed global KeyboardShortcutsDialog lazy import to avoid duplicate mounts

// ThemeToggle temporarily disabled to isolate post-login ref error
import { Button } from './components/ui/button'
import { Leaf } from 'lucide-react'
// Dropdown menu temporarily removed to avoid ref issues during post-login render
import { UserAvatar } from './components/ui/user-avatar'
import { SettingsPage } from './components/settings/settings-page'
import { FoldersTagsPage } from './components/management/folders-tags-page'
import { AdminPage } from './components/admin/admin-page'
import { ProtectedRoute } from './components/common/ProtectedRoute'
import { InteractiveGridPattern } from './components/ui/interactive-grid-pattern'
import { isOnAuthRoute, safeRedirectToLogin } from './lib/navigation'

const RootLayout: React.FC = () => (
  <ThemeProvider>
    <EncryptionProvider>
      <div className="min-h-screen transition-all duration-300 ease-in-out">
        <Outlet />
      </div>
    </EncryptionProvider>
  </ThemeProvider>
)

const rootRoute = createRootRoute({
  component: RootLayout,
})

// Dashboard route at root - will handle auth check internally
// Index route removed - dashboard at root for authenticated users

// Auth routes - clean URLs without /auth/ prefix
const AuthComponent: React.FC<{ mode?: 'login' | 'register' | 'forgot' }> = ({
  mode: initialMode = 'login',
}) => {
  const [mode, setMode] = React.useState<'login' | 'register' | 'forgot'>(initialMode)

  React.useEffect(() => {
    setMode(initialMode)
  }, [initialMode])

  // Ensure auth store reflects storage state when landing on auth pages
  React.useEffect(() => {
    // Sync in-memory user with localStorage; clears stale user if token missing
    try {
      useAuthStore.getState().initialize()
    } catch (_) {
      // no-op
    }
  }, [])

  return (
    <div className="min-h-screen flex items-center justify-center p-4 animate-in fade-in-50 duration-700 relative overflow-hidden bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      <InteractiveGridPattern width={50} height={50} className="absolute inset-0 opacity-50" />
      <div className="w-full max-w-md relative z-10">
        <React.Suspense
          fallback={
            <div className="flex items-center justify-center p-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
            </div>
          }
        >
          {mode === 'login' ? (
            <LoginForm onToggleMode={() => setMode('register')} />
          ) : mode === 'register' ? (
            <RegisterForm onToggleMode={() => setMode('login')} />
          ) : (
            <ForgotPasswordForm onToggleMode={() => setMode('login')} />
          )}
        </React.Suspense>
      </div>
    </div>
  )
}

// Auth routes - using clean URLs at root level
const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'login',
  component: () => <AuthComponent mode="login" />,
})

const registerRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'register',
  component: () => <AuthComponent mode="register" />,
})

const forgotRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'forgot',
  component: () => <AuthComponent mode="forgot" />,
})

// Dashboard route
const DashboardComponent: React.FC = () => {
  // Initialize auth store on mount (guarded to run once)
  const initializedRef = React.useRef(false)
  React.useEffect(() => {
    if (initializedRef.current) return
    initializedRef.current = true
    try {
      useAuthStore.getState().initialize()
    } catch (err) {
      console.warn('Auth initialize failed:', err)
    }
  }, [])

  // Subscribe to specific store slices (stable hooks each render)
  const user = useAuthStore((state) => state.user)
  const isLoading = useAuthStore((state) => state.isLoading)

<<<<<<< HEAD
  const [editorReady, setEditorReady] = React.useState(false)

=======
>>>>>>> 92a5971798cd3aa571a071ab07873cbaceace8a4
  React.useEffect(() => {
    if (!isLoading && !user) {
      if (typeof window === 'undefined' || !isOnAuthRoute()) {
        safeRedirectToLogin()
      }
    }
  }, [user, isLoading])

  // Notes loading guarded to run once after auth is ready
  const notesLoadedRef = React.useRef(false)
  React.useEffect(() => {
    if (!isLoading && user && !notesLoadedRef.current) {
      notesLoadedRef.current = true
      import('./stores/notesStore').then(({ useNotesStore }) => {
        const store = useNotesStore.getState()
        store
          .loadData()
<<<<<<< HEAD
          .then(() => store.initializeDefaultNote())
          .then(() => setEditorReady(true))
          .catch((err) => {
            console.warn('Notes bootstrap failed:', err)
            setEditorReady(true)
          })
=======
          .then(() => {
            return store.initializeDefaultNote()
          })
          .catch((err) => console.warn('Notes bootstrap failed:', err))
>>>>>>> 92a5971798cd3aa571a071ab07873cbaceace8a4
      })
    }
  }, [isLoading, user])

  if (isLoading || !user) {
    return (
      <div className="min-h-screen flex items-center justify-center animate-in fade-in-50 duration-500">
        <div className="flex flex-col items-center gap-4">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
          <p className="text-sm text-muted-foreground animate-pulse">Loading LeafLock...</p>
        </div>
      </div>
    )
  }

  const handleLogout = async () => {
    const { useAuthStore } = await import('./stores/authStore')
    useAuthStore.getState().logout()
    window.location.href = '/login'
  }

  return (
    <div className="h-screen flex flex-col animate-in fade-in-50 duration-700">
      {/* Header - Mobile optimized */}
      <header className="border-b border-border bg-card px-3 md:px-6 py-2 md:py-3 flex items-center justify-between animate-slide-in">
        <div className="flex items-center gap-2 md:gap-3">
          <div className="w-7 h-7 md:w-8 md:h-8 rounded-lg bg-primary flex items-center justify-center hover-glow transition-smooth">
            <Leaf className="w-4 h-4 md:w-5 md:h-5 text-primary-foreground" />
          </div>
          <div>
            <h1 className="text-lg md:text-xl font-bold">LeafLock</h1>
            <p className="text-xs md:text-sm text-muted-foreground hidden sm:block">Dashboard</p>
          </div>
        </div>

        <div className="flex items-center gap-2 md:gap-3">
          <Button variant="ghost" size="sm" className="gap-2 transition-smooth hover-lift" onClick={handleLogout}>
            <UserAvatar user={user} size={28} />
            <span className="hidden md:inline text-sm">Logout</span>
          </Button>
        </div>
      </header>

<<<<<<< HEAD
      {/* Main Content - Sidebar + conditional editor */}
=======
      {/* Main Content - Sidebar + placeholder (editor temporarily disabled) */}
>>>>>>> 92a5971798cd3aa571a071ab07873cbaceace8a4
      <div className="flex-1 flex overflow-hidden">
        <div className="w-0 md:w-48 xl:w-64 md:flex-shrink-0">
          <Sidebar />
        </div>
<<<<<<< HEAD
        <div className="flex-1 flex flex-col min-w-0">
          {editorReady ? (
            <React.Suspense
              fallback={
                <div className="flex-1 flex items-center justify-center">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
                </div>
              }
            >
              <NoteEditor />
            </React.Suspense>
          ) : (
            <div className="flex-1 flex items-center justify-center">
              <div className="text-center space-y-2">
                <h2 className="text-xl font-semibold">Welcome</h2>
                <p className="text-sm text-muted-foreground">Preparing editor…</p>
              </div>
            </div>
          )}
=======
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center space-y-2">
            <h2 className="text-xl font-semibold">Welcome</h2>
            <p className="text-sm text-muted-foreground">Editor temporarily disabled while we isolate an update loop.</p>
          </div>
>>>>>>> 92a5971798cd3aa571a071ab07873cbaceace8a4
        </div>
      </div>

      {/* Keyboard Shortcuts Dialog rendered within NoteEditor to avoid duplication */}
    </div>
  )
}

// Dashboard route at root - handles authentication check internally
const dashboardRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  component: DashboardComponent,
})

const settingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'settings',
  component: SettingsPage,
})

const manageRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'manage',
  component: FoldersTagsPage,
})

const AdminPageComponent = () => {
  const [authStore, setAuthStore] = React.useState<any>(null)
  const [isLoading, setIsLoading] = React.useState(true)

  React.useEffect(() => {
    // Dynamically import auth store to prevent circular dependency
    import('./stores/authStore').then(({ useAuthStore }) => {
      const store = useAuthStore.getState()
      setAuthStore(store)
      store.initialize().then(() => {
        setIsLoading(false)
      })
    })
  }, [])

  return (
    <ProtectedRoute requiredRole="admin" isLoading={isLoading} user={authStore?.user}>
      <AdminPage />
    </ProtectedRoute>
  )
}

const adminRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'admin',
  component: AdminPageComponent,
})

// Create the router - dashboard at root, auth routes use clean URLs
export const router = createRouter({
  routeTree: rootRoute.addChildren([
    dashboardRoute, // Dashboard at root for authenticated users
    loginRoute,
    registerRoute,
    forgotRoute,
    settingsRoute,
    manageRoute,
    adminRoute,
  ]),
})

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}
