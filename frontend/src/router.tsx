import React from 'react'
import { Outlet, createRoute, createRouter, createRootRoute } from '@tanstack/react-router'

import { ThemeProvider } from './context/ThemeContext'
import { EncryptionProvider } from './lib/encryption-context'
import { useAuthStore } from './stores/authStore'

// Lazy load stores and components
const LoginForm = React.lazy(() =>
  import('./components/auth/login-form').then((m) => ({ default: m.LoginForm }))
)
const RegisterForm = React.lazy(() =>
  import('./components/auth/register-form').then((m) => ({ default: m.RegisterForm }))
)
const ForgotPasswordForm = React.lazy(() =>
  import('./components/auth/forgot-password-form').then((m) => ({ default: m.ForgotPasswordForm }))
)

// New Layouts & Views
import { ProtectedLayout } from './components/layout/protected-layout'
import { DashboardView } from './components/dashboard/dashboard-view'
import { SettingsPage } from './components/settings/settings-page'
import { FoldersTagsPage } from './components/management/folders-tags-page'
import { AdminPage } from './components/admin/admin-page'
import { ProtectedRoute } from './components/common/ProtectedRoute'
import { InteractiveGridPattern } from './components/ui/interactive-grid-pattern'

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

// Auth routes
const AuthComponent: React.FC<{ mode?: 'login' | 'register' | 'forgot' }> = ({
  mode: initialMode = 'login',
}) => {
  const [mode, setMode] = React.useState<'login' | 'register' | 'forgot'>(initialMode)

  React.useEffect(() => {
    setMode(initialMode)
  }, [initialMode])

  React.useEffect(() => {
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

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'login',
  component: () => <AuthComponent mode="login" />,
})

const registerRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'register',
  component: () => <AuthComponent mode="register" />,
  beforeLoad: async () => {
    const { checkRegistrationEnabled } = useAuthStore.getState()
    const enabled = await checkRegistrationEnabled()
    if (!enabled) {
      window.location.href = '/login'
      throw new Error('Registration is disabled')
    }
  },
})

const forgotRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'forgot',
  component: () => <AuthComponent mode="forgot" />,
})

// Protected routes structure
const protectedLayoutRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: '_auth',
  component: ProtectedLayout,
})

const dashboardRoute = createRoute({
  getParentRoute: () => protectedLayoutRoute,
  path: '/',
  component: DashboardView,
})

const settingsRoute = createRoute({
  getParentRoute: () => protectedLayoutRoute,
  path: 'settings',
  component: SettingsPage,
})

const manageRoute = createRoute({
  getParentRoute: () => protectedLayoutRoute,
  path: 'manage',
  component: FoldersTagsPage,
})

const AdminPageComponent = () => {
  const [authStore, setAuthStore] = React.useState<any>(null)
  const [isLoading, setIsLoading] = React.useState(true)

  React.useEffect(() => {
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
  getParentRoute: () => protectedLayoutRoute,
  path: 'admin',
  component: AdminPageComponent,
})

// Create router
export const router = createRouter({
  routeTree: rootRoute.addChildren([
    loginRoute,
    registerRoute,
    forgotRoute,
    protectedLayoutRoute.addChildren([
      dashboardRoute,
      settingsRoute,
      manageRoute,
      adminRoute,
    ]),
  ]),
})

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}
