import React from 'react'
import { Outlet, createRoute, createRouter, createRootRoute } from '@tanstack/react-router'

import { ThemeProvider } from './context/ThemeContext'
import { EncryptionProvider } from './lib/encryption-context'
import { Toaster } from './components/ui/sonner'
import { AppErrorBoundary } from './components/common/AppErrorBoundary'
import { useAuthStore, useNotesStore } from './stores'
import { LoginForm } from './components/auth/login-form'
import { RegisterForm } from './components/auth/register-form'
// import { Sidebar } from './components/dashboard/sidebar'
// import { NoteList } from './components/dashboard/note-list'
// import { NoteEditor } from './components/dashboard/note-editor'
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
import { SettingsPage } from './components/settings/settings-page'
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

// Landing page route
const IndexComponent: React.FC = () => {
  const { user, isLoading, initialize } = useAuthStore()

  React.useEffect(() => {
    initialize()
  }, [initialize])

  React.useEffect(() => {
    if (!isLoading) {
      if (user) {
        window.location.href = '/dashboard'
      } else {
        window.location.href = '/auth'
      }
    }
  }, [user, isLoading])

  return (
    <div className="min-h-screen flex items-center justify-center animate-in fade-in-50 duration-500">
      <div className="text-center space-y-4">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto"></div>
        <p className="text-muted-foreground">Loading...</p>
      </div>
    </div>
  )
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
        {mode === 'login' ? (
          <LoginForm onToggleMode={() => setMode('register')} />
        ) : (
          <RegisterForm onToggleMode={() => setMode('login')} />
        )}
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
  const { user, isLoading, logout, initialize } = useAuthStore()
  const notesStore = useNotesStore()
  const { loadData, isLoading: notesLoading } = notesStore

  // Initialize auth store if not already done
  React.useEffect(() => {
    initialize()
  }, [initialize])

  React.useEffect(() => {
    if (!isLoading && !user) {
      window.location.href = '/auth'
    }
  }, [user, isLoading])

  // Load data when user is available
  React.useEffect(() => {
    if (user && !isLoading) {
      loadData()
    }
  }, [user, isLoading, loadData])

  if (isLoading || !user || notesLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center animate-in fade-in-50 duration-500">
        <div className="flex flex-col items-center gap-4">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
          <p className="text-sm text-muted-foreground animate-pulse">Loading LeafLock...</p>
        </div>
      </div>
    )
  }

  // Ensure store has proper data before rendering components
  if (!notesStore.notes || !notesStore.folders || !notesStore.tags) {
    return (
      <div className="min-h-screen flex items-center justify-center animate-in fade-in-50 duration-500">
        <div className="flex flex-col items-center gap-4">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
          <p className="text-sm text-muted-foreground animate-pulse">Loading data...</p>
        </div>
      </div>
    )
  }

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
        {/* Temporarily disable components to isolate the error */}
        <div className="w-64 border-r border-border bg-card flex flex-col h-full p-4">
          <h2 className="font-semibold mb-4">Sidebar (Disabled)</h2>
          <p className="text-sm text-muted-foreground">Sidebar component temporarily disabled for debugging</p>
        </div>
        <div className="flex-1 flex border-r border-border">
          <div className="w-80 border-r border-border flex flex-col p-4">
            <h2 className="font-semibold mb-4">Note List (Disabled)</h2>
            <p className="text-sm text-muted-foreground">Note List component temporarily disabled for debugging</p>
          </div>
          <div className="flex-1 p-4">
            <h2 className="font-semibold mb-4">Note Editor (Disabled)</h2>
            <p className="text-sm text-muted-foreground">Note Editor component temporarily disabled for debugging</p>
          </div>
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

// Settings route
const SettingsComponent: React.FC = () => {
  const { user, isLoading } = useAuthStore()

  return (
    <ProtectedRoute
      user={user}
      isLoading={isLoading}
      requiredRole="user"
      fallbackRoute="/auth/login"
    >
      <div className="min-h-screen bg-background animate-in fade-in-50 duration-700">
        <SettingsPage />
      </div>
    </ProtectedRoute>
  )
}

const settingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'settings',
  component: SettingsComponent,
})

// Admin route
const AdminComponent: React.FC = () => {
  const { user, isLoading } = useAuthStore()

  return (
    <ProtectedRoute
      user={user}
      isLoading={isLoading}
      requiredRole="admin"
      fallbackRoute="/dashboard"
    >
      <div className="min-h-screen bg-background animate-in fade-in-50 duration-700">
        <AdminPage />
      </div>
    </ProtectedRoute>
  )
}

const adminRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'admin',
  component: AdminComponent,
})

// 404 route
const NotFoundComponent: React.FC = () => (
  <div className="min-h-screen flex items-center justify-center animate-in fade-in-50 duration-700">
    <div className="text-center space-y-6">
      <h1 className="text-2xl font-bold animate-slide-in">404 - Page Not Found</h1>
      <p className="text-muted-foreground animate-fade-in">
        The page you're looking for doesn't exist.
      </p>
      <button
        onClick={() => (window.location.href = '/')}
        className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-all duration-200 hover:scale-105 active:scale-95 animate-scale-in"
      >
        Go Home
      </button>
    </div>
  </div>
)

const notFoundRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '*',
  component: NotFoundComponent,
})

const routeTree = rootRoute.addChildren([
  indexRoute,
  authRoute,
  dashboardRoute,
  settingsRoute,
  adminRoute,
  notFoundRoute,
])

export const router = createRouter({
  routeTree,
})

export type AppRouterInstance = typeof router
