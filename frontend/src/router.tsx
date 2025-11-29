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
import {
  Outlet,
  createRoute,
  createRouter,
  createRootRoute,
  redirect,
} from '@tanstack/react-router'
import { useAuth, useUser, SignIn, SignUp } from '@clerk/clerk-react'

import { ThemeProvider } from './context/ThemeContext'
import { EncryptionProvider } from './lib/encryption-context'
import { useSyncClerkAuth } from './stores/clerkAuthStore'
import { ClerkAuthWithErrorBoundary } from './components/auth/clerk-error-boundary'

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

// Clerk authentication components with LeafLock design system and enhanced loading
const ClerkAuthLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div className="min-h-screen flex items-center justify-center p-4 animate-in fade-in-50 duration-700 relative overflow-hidden bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
    <InteractiveGridPattern width={50} height={50} className="absolute inset-0 opacity-50" />
    <div className="w-full max-w-md relative z-10 animate-in slide-in-from-bottom-4 duration-1000 delay-200">
      {children}
    </div>
  </div>
)

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'login',
  component: () => (
    <ClerkAuthLayout>
      <ClerkAuthWithErrorBoundary>
        <SignIn
          routing="path"
          path="/login"
          signUpUrl="/register"
          afterSignInUrl="/"
          appearance={{
            elements: {
              // Layout and container with enhanced animations
              rootBox: 'mx-auto w-full max-w-md',
              card: 'bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60 border border-border/50 shadow-2xl rounded-2xl p-8 space-y-6 animate-in fade-in-0 zoom-in-95 duration-700 hover-lift',

              // Headers and titles with staggered animations
              headerTitle:
                'text-2xl font-bold text-foreground tracking-tight animate-in slide-in-from-top-2 duration-500',
              headerSubtitle:
                'text-muted-foreground text-sm animate-in slide-in-from-top-2 duration-500 delay-100',

              // Social authentication buttons with enhanced interactions
              socialButtonsBlockButton:
                'w-full bg-background border border-border text-foreground hover:bg-accent hover:border-accent-foreground/20 transition-all duration-200 rounded-lg px-4 py-3 font-medium shadow-sm hover:shadow-md active:scale-[0.98] group',
              socialButtonsBlockButtonText:
                'text-foreground font-medium group-hover:text-accent-foreground',
              socialButtonsProviderIcon: 'w-5 h-5 transition-transform group-hover:scale-110',

              // Form fields with enhanced focus states
              formFieldLabel: 'text-foreground font-medium text-sm mb-2',
              formFieldLabel__emailAddress: 'text-foreground font-medium text-sm mb-2',
              formFieldLabel__password: 'text-foreground font-medium text-sm mb-2',
              formFieldInput:
                'w-full bg-background border border-border text-foreground placeholder:text-muted-foreground rounded-lg px-4 py-3 transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-primary focus:border-primary hover:border-border/80 focus:shadow-lg',
              formFieldInput__emailAddress:
                'w-full bg-background border border-border text-foreground placeholder:text-muted-foreground rounded-lg px-4 py-3 transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-primary focus:border-primary hover:border-border/80 focus:shadow-lg',
              formFieldInput__password:
                'w-full bg-background border border-border text-foreground placeholder:text-muted-foreground rounded-lg px-4 py-3 transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-primary focus:border-primary hover:border-border/80 focus:shadow-lg',
              formFieldInputShowPasswordButton:
                'text-muted-foreground hover:text-foreground transition-colors hover:scale-110',
              formFieldSuccessText: 'text-green-600 text-sm mt-1',
              formFieldErrorText: 'text-destructive text-sm mt-1',
              formFieldHintText: 'text-muted-foreground text-xs mt-1',
              formFieldHintText__password: 'text-muted-foreground text-xs mt-1',

              // Primary action buttons with enhanced interactions
              formButtonPrimary:
                'w-full bg-primary text-primary-foreground hover:bg-primary/90 rounded-lg px-4 py-3 font-semibold transition-all duration-200 shadow-sm hover:shadow-md active:scale-[0.98] focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 focus:ring-offset-background',
              formButtonReset:
                'w-full bg-secondary text-secondary-foreground hover:bg-secondary/80 rounded-lg px-4 py-3 font-semibold transition-all duration-200',

              // Footer and links with enhanced hover effects
              footerActionText: 'text-muted-foreground text-sm',
              footerActionLink:
                'text-primary hover:text-primary/90 font-medium underline-offset-4 hover:underline transition-all duration-200 hover:scale-105',

              // Identity preview (for social auth)
              identityPreview: 'bg-accent/50 border border-accent/20 rounded-lg p-4',
              identityPreviewText: 'text-foreground font-medium',
              identityPreviewEditButton:
                'text-primary hover:text-primary/90 font-medium transition-colors hover:scale-105',

              // Alternative methods
              alternativeMethods: 'mt-6 pt-6 border-t border-border/50',
              alternativeMethodsBlockButton:
                'w-full text-foreground hover:bg-accent/50 rounded-lg px-4 py-3 font-medium transition-all duration-200 hover:scale-[1.02]',

              // Dividers with enhanced styling
              dividerLine: 'border-border/50',
              dividerText: 'text-muted-foreground text-xs font-medium bg-background/95 px-2',

              // Loading and spinners
              spinner: 'text-primary',

              // Footer container
              footer: 'mt-8 pt-6 border-t border-border/50',
            },
            variables: {
              colorPrimary: '#3b82f6',
              colorBackground: '#0f172a',
              colorText: '#f8fafc',
              colorInputBackground: '#1e293b',
              colorInputText: '#f8fafc',
              fontFamily:
                'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
              fontSize: '14px',
              borderRadius: '8px',
              spacingUnit: '4px',
            },
            layout: {
              socialButtonsPlacement: 'bottom',
              socialButtonsVariant: 'blockButton',
              helpPageUrl: '/help',
              showOptionalFields: true,
            },
          }}
        />
      </ClerkAuthWithErrorBoundary>
    </ClerkAuthLayout>
  ),
})

const registerRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'register',
  component: () => (
    <ClerkAuthLayout>
      <ClerkAuthWithErrorBoundary>
        <SignUp
          routing="path"
          path="/register"
          signInUrl="/login"
          afterSignUpUrl="/"
          appearance={{
            elements: {
              // Layout and container
              rootBox: 'mx-auto w-full max-w-md',
              card: 'bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60 border border-border/50 shadow-2xl rounded-2xl p-8 space-y-6 animate-in fade-in-0 zoom-in-95 duration-700',

              // Headers and titles
              headerTitle:
                'text-2xl font-bold text-foreground tracking-tight animate-in slide-in-from-top-2 duration-500',
              headerSubtitle:
                'text-muted-foreground text-sm animate-in slide-in-from-top-2 duration-500 delay-100',

              // Social authentication buttons
              socialButtonsBlockButton:
                'w-full bg-background border border-border text-foreground hover:bg-accent hover:border-accent-foreground/20 transition-all duration-200 rounded-lg px-4 py-3 font-medium shadow-sm hover:shadow-md active:scale-[0.98]',
              socialButtonsBlockButtonText: 'text-foreground font-medium',
              socialButtonsProviderIcon: 'w-5 h-5',

              // Form fields with specific field targeting
              formFieldLabel: 'text-foreground font-medium text-sm mb-2',
              formFieldLabel__emailAddress: 'text-foreground font-medium text-sm mb-2',
              formFieldLabel__password: 'text-foreground font-medium text-sm mb-2',
              formFieldLabel__confirmPassword: 'text-foreground font-medium text-sm mb-2',
              formFieldLabel__firstName: 'text-foreground font-medium text-sm mb-2',
              formFieldLabel__lastName: 'text-foreground font-medium text-sm mb-2',
              formFieldInput:
                'w-full bg-background border border-border text-foreground placeholder:text-muted-foreground rounded-lg px-4 py-3 transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-primary focus:border-primary hover:border-border/80',
              formFieldInput__emailAddress:
                'w-full bg-background border border-border text-foreground placeholder:text-muted-foreground rounded-lg px-4 py-3 transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-primary focus:border-primary hover:border-border/80',
              formFieldInput__password:
                'w-full bg-background border border-border text-foreground placeholder:text-muted-foreground rounded-lg px-4 py-3 transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-primary focus:border-primary hover:border-border/80',
              formFieldInput__confirmPassword:
                'w-full bg-background border border-border text-foreground placeholder:text-muted-foreground rounded-lg px-4 py-3 transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-primary focus:border-primary hover:border-border/80',
              formFieldInput__firstName:
                'w-full bg-background border border-border text-foreground placeholder:text-muted-foreground rounded-lg px-4 py-3 transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-primary focus:border-primary hover:border-border/80',
              formFieldInput__lastName:
                'w-full bg-background border border-border text-foreground placeholder:text-muted-foreground rounded-lg px-4 py-3 transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-primary focus:border-primary hover:border-border/80',
              formFieldInputShowPasswordButton:
                'text-muted-foreground hover:text-foreground transition-colors',
              formFieldSuccessText: 'text-green-600 text-sm mt-1',
              formFieldErrorText: 'text-destructive text-sm mt-1',
              formFieldHintText: 'text-muted-foreground text-xs mt-1',
              formFieldHintText__password: 'text-muted-foreground text-xs mt-1',
              formFieldHintText__confirmPassword: 'text-muted-foreground text-xs mt-1',

              // Primary action buttons
              formButtonPrimary:
                'w-full bg-primary text-primary-foreground hover:bg-primary/90 rounded-lg px-4 py-3 font-semibold transition-all duration-200 shadow-sm hover:shadow-md active:scale-[0.98] focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2',
              formButtonReset:
                'w-full bg-secondary text-secondary-foreground hover:bg-secondary/80 rounded-lg px-4 py-3 font-semibold transition-all duration-200',

              // Footer and links
              footerActionText: 'text-muted-foreground text-sm',
              footerActionLink:
                'text-primary hover:text-primary/90 font-medium underline-offset-4 hover:underline transition-all duration-200',

              // Identity preview (for social auth)
              identityPreview: 'bg-accent/50 border border-accent/20 rounded-lg p-4',
              identityPreviewText: 'text-foreground font-medium',
              identityPreviewEditButton:
                'text-primary hover:text-primary/90 font-medium transition-colors',

              // Alternative methods
              alternativeMethods: 'mt-6 pt-6 border-t border-border/50',
              alternativeMethodsBlockButton:
                'w-full text-foreground hover:bg-accent/50 rounded-lg px-4 py-3 font-medium transition-all duration-200',

              // Dividers
              dividerLine: 'border-border/50',
              dividerText: 'text-muted-foreground text-xs font-medium bg-background/95 px-2',

              // Loading and spinners
              spinner: 'text-primary',

              // Footer container
              footer: 'mt-8 pt-6 border-t border-border/50',
            },
            variables: {
              colorPrimary: '#3b82f6',
              colorBackground: '#0f172a',
              colorText: '#f8fafc',
              colorInputBackground: '#1e293b',
              colorInputText: '#f8fafc',
              fontFamily:
                'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
              fontSize: '14px',
              borderRadius: '8px',
              spacingUnit: '4px',
            },
            layout: {
              socialButtonsPlacement: 'bottom',
              socialButtonsVariant: 'blockButton',
              helpPageUrl: '/help',
              showOptionalFields: true,
            },
          }}
        />
      </ClerkAuthWithErrorBoundary>
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

  const clerkUser = user
    ? {
        id: user.id,
        email: user.primaryEmailAddress?.emailAddress || '',
        isAdmin,
      }
    : null

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
