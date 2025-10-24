import React from 'react'
import { Outlet, createRoute, createRouter, createRootRoute } from '@tanstack/react-router'

import { ThemeProvider } from './context/ThemeContext'
import { Toaster } from './components/ui/sonner'
import { AppErrorBoundary } from './components/common/AppErrorBoundary'
import { useAuthStore } from './stores'
import { LoginForm } from './components/auth/login-form'
import { RegisterForm } from './components/auth/register-form'
import { Sidebar } from './components/dashboard/sidebar'
import { NoteList } from './components/dashboard/note-list'
import { NoteEditor } from './components/dashboard/note-editor'
import { ThemeToggle } from './components/theme-toggle'
import { Button } from './components/ui/button'
import { Leaf, Settings, LogOut, ShieldCheck } from 'lucide-react'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from './components/ui/dropdown-menu'
import { Avatar, AvatarFallback } from './components/ui/avatar'

const RootLayout: React.FC = () => (
  <AppErrorBoundary>
    <ThemeProvider>
      <Outlet />
      <Toaster />
    </ThemeProvider>
  </AppErrorBoundary>
)

const rootRoute = createRootRoute({
  component: RootLayout,
})

// Landing page route
const IndexComponent: React.FC = () => {
  const { user, isLoading } = useAuthStore()
  
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
    <div className="min-h-screen flex items-center justify-center">
      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
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
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-surface via-background to-surface p-4">
      <div className="w-full max-w-md space-y-8">
        <div className="text-center space-y-2 animate-fade-in">
          <h1 className="text-4xl font-bold text-balance bg-gradient-to-r from-primary to-primary/60 bg-clip-text text-transparent">
            LeafLock
          </h1>
        </div>

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
  const { user, isLoading, logout } = useAuthStore()
  
  React.useEffect(() => {
    if (!isLoading && !user) {
      window.location.href = '/auth'
    }
  }, [user, isLoading])

  if (isLoading || !user) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
          <p className="text-sm text-muted-foreground animate-pulse">Loading LeafLock...</p>
        </div>
      </div>
    )
  }

  const handleLogout = () => {
    logout()
    window.location.href = '/auth'
  }

  return (
    <div className="h-screen flex flex-col">
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
              <DropdownMenuItem onClick={() => window.location.href = '/settings'} className="transition-smooth">
                <Settings className="h-4 w-4 mr-2" />
                Settings
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => window.location.href = '/admin'} className="transition-smooth">
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
        <Sidebar />
        <div className="flex-1 flex border-r border-border">
          <div className="w-80 border-r border-border flex flex-col animate-slide-in-left">
            <div className="p-4 border-b border-border">
              <h2 className="font-semibold">Notes</h2>
            </div>
            <NoteList />
          </div>
          <NoteEditor />
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
  
  React.useEffect(() => {
    if (!isLoading && !user) {
      window.location.href = '/auth'
    }
  }, [user, isLoading])

  if (isLoading || !user) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="text-center">
        <h1 className="text-2xl font-bold mb-4">Settings</h1>
        <p className="text-muted-foreground">Settings page coming soon...</p>
      </div>
    </div>
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
  
  React.useEffect(() => {
    if (!isLoading && !user) {
      window.location.href = '/auth'
    }
  }, [user, isLoading])

  if (isLoading || !user) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="text-center">
        <h1 className="text-2xl font-bold mb-4">Admin Dashboard</h1>
        <p className="text-muted-foreground">Admin panel coming soon...</p>
      </div>
    </div>
  )
}

const adminRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'admin',
  component: AdminComponent,
})

// 404 route
const NotFoundComponent: React.FC = () => (
  <div className="min-h-screen flex items-center justify-center">
    <div className="text-center">
      <h1 className="text-2xl font-bold mb-4">404 - Page Not Found</h1>
      <p className="text-muted-foreground mb-4">The page you're looking for doesn't exist.</p>
      <button 
        onClick={() => window.location.href = '/'}
        className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
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
