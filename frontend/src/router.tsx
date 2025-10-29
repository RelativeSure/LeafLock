import React from 'react'
import { Outlet, createRoute, createRouter, createRootRoute } from '@tanstack/react-router'

import { ThemeProvider } from './context/ThemeContext'
import { EncryptionProvider } from './lib/encryption-context'
import { Toaster } from './components/ui/sonner'
import { AppErrorBoundary } from './components/common/AppErrorBoundary'

// Lazy load stores and components to prevent circular dependencies
// Wrap lazy components in forwardRef-compatible wrappers for React 19
const lazyWithRef = <T extends React.ComponentType<any>>(
  importFn: () => Promise<{ default: T }>
): React.LazyExoticComponent<T> => {
  return React.lazy(importFn)
}

const LoginForm = lazyWithRef(() =>
  import('./components/auth/login-form').then((m) => ({ default: m.LoginForm }))
)
const RegisterForm = lazyWithRef(() =>
  import('./components/auth/register-form').then((m) => ({ default: m.RegisterForm }))
)
const ForgotPasswordForm = lazyWithRef(() =>
  import('./components/auth/forgot-password-form').then((m) => ({ default: m.ForgotPasswordForm }))
)
const Sidebar = lazyWithRef(() =>
  import('./components/dashboard/sidebar').then((m) => ({ default: m.Sidebar }))
)
const NoteEditor = lazyWithRef(() =>
  import('./components/dashboard/note-editor').then((m) => ({ default: m.NoteEditor }))
)
const KeyboardShortcutsDialog = lazyWithRef(() =>
  import('./components/dashboard/keyboard-shortcuts-dialog').then((m) => ({
    default: m.KeyboardShortcutsDialog,
  }))
)

import { ThemeToggle } from './components/theme-toggle'
import { Button } from './components/ui/button'
import {
  Leaf,
  Settings,
  LogOut,
  ShieldCheck,
  Keyboard,
  HelpCircle,
  ExternalLink,
  FolderOpen,
} from 'lucide-react'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from './components/ui/dropdown-menu'
import { UserAvatar } from './components/ui/user-avatar'
import { SettingsPage } from './components/settings/settings-page'
import { FoldersTagsPage } from './components/management/folders-tags-page'
import { AdminPage } from './components/admin/admin-page'
import { ProtectedRoute } from './components/common/ProtectedRoute'
import { InteractiveGridPattern } from './components/ui/interactive-grid-pattern'

const RootLayout: React.FC = () => (
  <AppErrorBoundary>
    <ThemeProvider>
      <EncryptionProvider>
        <div className="min-h-screen transition-all duration-300 ease-in-out">
          <Outlet />
        </div>
        <Toaster />
      </EncryptionProvider>
    </ThemeProvider>
  </AppErrorBoundary>
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

  React.useEffect(() => {
    if (!isLoading && authStore && !authStore.user) {
      window.location.href = '/login'
    }
  }, [authStore, isLoading])

  // Load notes data when dashboard loads
  React.useEffect(() => {
    if (!isLoading && authStore && authStore.user) {
      // Dynamically import notes store to prevent circular dependency
      import('./stores/notesStore').then(({ useNotesStore }) => {
        const store = useNotesStore.getState()
        store.loadData().then(() => {
          // Initialize default note after data is loaded
          store.initializeDefaultNote()
        })
      })
    }
  }, [isLoading, authStore])

  if (isLoading || !authStore || !authStore.user) {
    return (
      <div className="min-h-screen flex items-center justify-center animate-in fade-in-50 duration-500">
        <div className="flex flex-col items-center gap-4">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
          <p className="text-sm text-muted-foreground animate-pulse">Loading LeafLock...</p>
        </div>
      </div>
    )
  }

  const { user, logout } = authStore

  const handleLogout = () => {
    logout()
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
          <ThemeToggle />

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm" className="gap-2 transition-smooth hover-lift">
                <UserAvatar user={user} size={28} />
                <span className="hidden md:inline text-sm">{user?.name}</span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="animate-scale-in">
              <DropdownMenuItem
                onClick={() => (window.location.href = '/settings')}
                className="transition-smooth"
              >
                <Settings className="h-4 w-4 mr-2" />
                Settings
              </DropdownMenuItem>
              <DropdownMenuItem
                onClick={() => (window.location.href = '/admin')}
                className="transition-smooth"
              >
                <ShieldCheck className="h-4 w-4 mr-2" />
                Admin Dashboard
              </DropdownMenuItem>
              <DropdownMenuItem
                onClick={() => (window.location.href = '/manage')}
                className="transition-smooth"
              >
                <FolderOpen className="h-4 w-4 mr-2" />
                Folders & Tags
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onClick={() => {
                  // Open keyboard shortcuts dialog
                  const event = new CustomEvent('open-keyboard-shortcuts')
                  window.dispatchEvent(event)
                }}
                className="transition-smooth"
              >
                <Keyboard className="h-4 w-4 mr-2" />
                Keyboard Shortcuts
              </DropdownMenuItem>
              <DropdownMenuItem
                onClick={() => window.open('https://docs.leaflock.app', '_blank')}
                className="transition-smooth"
              >
                <HelpCircle className="h-4 w-4 mr-2" />
                Documentation
                <ExternalLink className="h-3 w-3 ml-auto" />
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={handleLogout} className="transition-smooth">
                <LogOut className="h-4 w-4 mr-2" />
                Logout
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </header>

      {/* Main Content - Responsive Layout */}
      <div className="flex-1 flex overflow-hidden">
        {/* Sidebar - Hidden width on mobile, visible on desktop */}
        <React.Suspense
          fallback={
            <div className="hidden md:flex w-48 xl:w-64 border-r border-border items-center justify-center">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
            </div>
          }
        >
          <div className="w-0 md:w-48 xl:w-64 md:flex-shrink-0">
            <Sidebar />
          </div>
        </React.Suspense>

        {/* Note Editor - Full width on mobile, flex-1 on desktop */}
        <div className="flex-1 flex flex-col min-w-0">
          <React.Suspense
            fallback={
              <div className="flex-1 flex items-center justify-center">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
              </div>
            }
          >
            <NoteEditor />
          </React.Suspense>
        </div>
      </div>

      {/* Keyboard Shortcuts Dialog */}
      <React.Suspense fallback={null}>
        <KeyboardShortcutsDialog />
      </React.Suspense>
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
