import React from 'react'
import { Outlet, createRoute, createRouter, createRootRoute } from '@tanstack/react-router'

import { ThemeProvider } from './context/ThemeContext'
import { EncryptionProvider } from './lib/encryption-context'
import { Toaster } from './components/ui/sonner'
import { AppErrorBoundary } from './components/common/AppErrorBoundary'

// Lazy load stores and components to prevent circular dependencies
const LoginForm = React.lazy(() => import('./components/auth/login-form').then(m => ({ default: m.LoginForm })))
const RegisterForm = React.lazy(() => import('./components/auth/register-form').then(m => ({ default: m.RegisterForm })))
const Sidebar = React.lazy(() => import('./components/dashboard/sidebar').then(m => ({ default: m.Sidebar })))
const NoteList = React.lazy(() => import('./components/dashboard/note-list').then(m => ({ default: m.NoteList })))
const NoteEditor = React.lazy(() => import('./components/dashboard/note-editor').then(m => ({ default: m.NoteEditor })))

import { ThemeToggle } from './components/theme-toggle'
import { Button } from './components/ui/button'
import { Leaf, Settings, LogOut, ShieldCheck } from 'lucide-react'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from './components/ui/dropdown-menu'
import { Avatar, AvatarFallback } from './components/ui/avatar'
import { SettingsPage } from './components/settings/settings-page-minimal'
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

// Index route
const IndexComponent: React.FC = () => {
  React.useEffect(() => {
    window.location.href = '/auth'
  }, [])
  return null
}

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  component: IndexComponent,
})

// Auth routes
const AuthComponent: React.FC = () => {
  const [mode, setMode] = React.useState<'login' | 'register'>('login')

  return (
    <div className="min-h-screen flex items-center justify-center p-4 animate-in fade-in-50 duration-700 relative overflow-hidden bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      <InteractiveGridPattern width={50} height={50} className="absolute inset-0 opacity-50" />
      <div className="w-full max-w-md relative z-10">
        <React.Suspense fallback={
          <div className="flex items-center justify-center p-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          </div>
        }>
          {mode === 'login' ? (
            <LoginForm onToggleMode={() => setMode('register')} />
          ) : (
            <RegisterForm onToggleMode={() => setMode('login')} />
          )}
        </React.Suspense>
      </div>
    </div>
  )
}

const authRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'auth',
  component: AuthComponent,
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
      window.location.href = '/auth'
    }
  }, [authStore, isLoading])

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
    window.location.href = '/auth'
  }

  return (
    <div className="h-screen flex flex-col animate-in fade-in-50 duration-700">
      {/* Header */}
      <header className="border-b border-border bg-card px-6 py-3 flex items-center justify-between animate-slide-in">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-primary flex items-center justify-center hover-glow transition-smooth">
            <Leaf className="w-5 h-5 text-primary-foreground" />
          </div>
          <h1 className="text-xl font-bold">LeafLock</h1>
        </div>

        <div className="flex items-center gap-3">
          <ThemeToggle />

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" className="gap-2 transition-smooth hover-lift">
                <Avatar className="h-8 w-8">
                  <AvatarFallback>{user?.name.charAt(0).toUpperCase()}</AvatarFallback>
                </Avatar>
                <span className="hidden md:inline">{user?.name}</span>
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
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={handleLogout} className="transition-smooth">
                <LogOut className="h-4 w-4 mr-2" />
                Logout
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex-1 flex overflow-hidden">
        <React.Suspense fallback={
          <div className="w-64 border-r border-border flex items-center justify-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          </div>
        }>
          <Sidebar />
        </React.Suspense>
        <div className="flex-1 flex border-r border-border">
          <div className="w-80 border-r border-border flex flex-col animate-slide-in-left">
            <div className="p-4 border-b border-border">
              <h2 className="font-semibold">Notes</h2>
            </div>
            <React.Suspense fallback={
              <div className="flex-1 flex items-center justify-center">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
              </div>
            }>
              <NoteList />
            </React.Suspense>
          </div>
          <React.Suspense fallback={
            <div className="flex-1 flex items-center justify-center">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
            </div>
          }>
            <NoteEditor />
          </React.Suspense>
        </div>
      </div>
    </div>
  )
}

const dashboardRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'dashboard',
  component: DashboardComponent,
})

const settingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'settings',
  component: SettingsPage,
})

const adminRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'admin',
  component: () => (
    <ProtectedRoute requiredRole="admin">
      <AdminPage />
    </ProtectedRoute>
  ),
})

// Create the router
export const router = createRouter({
  routeTree: rootRoute.addChildren([
    indexRoute,
    authRoute,
    dashboardRoute,
    settingsRoute,
    adminRoute,
  ]),
})

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}
