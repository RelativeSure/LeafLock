/**
 * Application Router Configuration with Clerk Authentication
 * 
 * @description
 * Defines all application routes using TanStack Router with Clerk authentication.
 * Implements authentication flow, protected routes, and role-based access control via Clerk.
 * 
 * @architecture
 * - Root layout provides ClerkProvider, ThemeProvider and EncryptionProvider to all routes
 * - Auth routes use Clerk's pre-built components for login, registration, and password recovery
 * - Protected routes require authentication via Clerk's useAuth hook
 * - Admin route requires admin role from Clerk's user metadata
 * - Lazy loading reduces initial bundle size and improves performance
 * 
 * @route-structure
 * / (root) - Theme, encryption, and Clerk providers
 * ├── /login - Clerk SignIn component
 * ├── /register - Clerk SignUp component with registration check
 * ├── /forgot - Clerk password recovery flow
 * └── / (protected layout) - Requires authentication
 *     ├── / - Dashboard view (default route)
 *     ├── /settings - User settings page
 *     ├── /manage - Folder and tag management
 *     └── /admin - Admin panel (requires admin role)
 * 
 * @performance-features
 * - Component lazy loading with React.Suspense fallback
 * - Route-based code splitting
 * - Dynamic imports for heavy components
 * 
 * @security-features
 * - Protected routes with Clerk authentication
 * - Role-based access control using Clerk user metadata
 * - Automatic redirects for unauthorized access via Clerk
 */
import React from 'react'
import { Outlet, createRoute, createRouter, createRootRoute, redirect } from '@tanstack/react-router'
import { useAuth, useUser, SignIn, SignUp } from '@clerk/clerk-react'

import { ThemeProvider } from './context/ThemeContext'
import { EncryptionProvider } from './lib/encryption-context'
import { useSyncClerkAuth } from './stores/clerkAuthStore'

// Legacy components - no longer used but kept for reference during migration
// const LoginForm = React.lazy(() =>
//   import('./components/auth/login-form').then((m) => ({ default: m.LoginForm }))
// )
// const RegisterForm = React.lazy(() =>
//   import('./components/auth/register-form').then((m) => ({ default: m.RegisterForm }))
// )
// const ForgotPasswordForm = React.lazy(() =>
//   import('./components/auth/forgot-password-form').then((m) => ({ default: m.ForgotPasswordForm }))
// )

// New Layouts & Views
import { ProtectedLayout } from './components/layout/protected-layout'
import { DashboardView } from './components/dashboard/dashboard-view'
import { SettingsPage } from './components/settings/settings-page'
import { FoldersTagsPage } from './components/management/folders-tags-page'
import { AdminPage } from './components/admin/admin-page'
import { ProtectedRoute } from './components/common/ProtectedRoute'
import { InteractiveGridPattern } from './components/ui/interactive-grid-pattern'

const RootLayout: React.FC = () => {
  useSyncClerkAuth() // Sync Clerk auth state with our store
  
  return (
    <ThemeProvider>
      <EncryptionProvider>
        <div className="min-h-screen transition-all duration-300 ease-in-out">
          <Outlet />
        </div>
      </EncryptionProvider>
    </ThemeProvider>
  )
}

const rootRoute = createRootRoute({
  component: RootLayout,
})

// Clerk authentication components
const ClerkAuthLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div className="min-h-screen flex items-center justify-center p-4 animate-in fade-in-50 duration-700 relative overflow-hidden bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
    <InteractiveGridPattern width={50} height={50} className="absolute inset-0 opacity-50" />
    <div className="w-full max-w-md relative z-10">
      {children}
    </div>
  </div>
)

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'login',
  component: () => (
    <ClerkAuthLayout>
      <SignIn
        routing="path"
        path="/login"
        signUpUrl="/register"
        afterSignInUrl="/"
        appearance={{
          elements: {
            rootBox: 'mx-auto',
            card: 'bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60',
            headerTitle: 'text-foreground',
            headerSubtitle: 'text-muted-foreground',
            socialButtonsBlockButton: 'bg-background border-border text-foreground hover:bg-accent',
            formFieldLabel: 'text-foreground',
            formFieldInput: 'bg-background border-border text-foreground',
            footerActionText: 'text-muted-foreground',
            footerActionLink: 'text-primary hover:text-primary/90',
            identityPreviewText: 'text-foreground',
            identityPreviewEditButton: 'text-primary',
            alternativeMethodsBlockButton: 'text-foreground hover:bg-accent',
            dividerLine: 'bg-border',
            dividerText: 'text-muted-foreground',
          },
        }}
      />
    </ClerkAuthLayout>
  ),
})

const registerRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'register',
  component: () => (
    <ClerkAuthLayout>
      <SignUp
        routing="path"
        path="/register"
        signInUrl="/login"
        afterSignUpUrl="/"
        appearance={{
          elements: {
            rootBox: 'mx-auto',
            card: 'bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60',
            headerTitle: 'text-foreground',
            headerSubtitle: 'text-muted-foreground',
            socialButtonsBlockButton: 'bg-background border-border text-foreground hover:bg-accent',
            formFieldLabel: 'text-foreground',
            formFieldInput: 'bg-background border-border text-foreground',
            footerActionText: 'text-muted-foreground',
            footerActionLink: 'text-primary hover:text-primary/90',
            dividerLine: 'bg-border',
            dividerText: 'text-muted-foreground',
          },
        }}
      />
    </ClerkAuthLayout>
  ),
  beforeLoad: async () => {
    // Check if registration is enabled via environment variable
    // In production, you might want to check this via an API call
    const registrationEnabled = import.meta.env.VITE_ENABLE_REGISTRATION !== 'false'
    if (!registrationEnabled) {
      throw redirect({ to: '/login' })
    }
  },
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
  const { user, isLoaded } = useUser()
  const { isSignedIn } = useAuth()

  if (!isLoaded) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    )
  }

  if (!isSignedIn) {
    return null // Will be handled by route protection
  }

  // Check if user has admin role from Clerk metadata
  const isAdmin = user?.publicMetadata?.isAdmin === true || user?.publicMetadata?.role === 'admin'

  const clerkUser = user ? { 
    id: user.id, 
    email: user.primaryEmailAddress?.emailAddress || '', 
    isAdmin 
  } : null

  return (
    <ProtectedRoute requiredRole="admin" isLoading={!isLoaded} user={clerkUser}>
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
    protectedLayoutRoute.addChildren([dashboardRoute, settingsRoute, manageRoute, adminRoute]),
  ]),
  // Note: forgotRoute removed - handled by Clerk's built-in password recovery
})

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}
