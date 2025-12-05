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
  <div className="clerk-auth-modern">
    <InteractiveGridPattern width={50} height={50} className="absolute inset-0 opacity-30" />
    <div className="clerk-card-enhanced animate-fade-in-zoom">
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
          fallbackRedirectUrl="/"
          appearance={{
            elements: {
              // Root container
              rootBox: 'w-full',
              card: 'w-full bg-transparent border-0 shadow-none p-0 space-y-6',
              
              // Header
              headerTitle: 'clerk-title-enhanced',
              headerSubtitle: 'clerk-subtitle-enhanced',
              
              // Form fields
              formFieldLabel: 'clerk-label-enhanced',
              formFieldInput: 'clerk-input-enhanced',
              formFieldInput__emailAddress: 'clerk-input-enhanced',
              formFieldInput__password: 'clerk-input-enhanced',
              formFieldInputShowPasswordButton: 'text-muted-foreground hover:text-foreground hover:scale-110 transition-all',
              formFieldErrorText: 'clerk-message-error-enhanced',
              formFieldSuccessText: 'clerk-message-success-enhanced',
              formFieldHintText: 'text-muted-foreground text-xs mt-2',
              
              // Buttons
              formButtonPrimary: 'clerk-button-primary-enhanced',
              formButtonReset: 'clerk-button-secondary-enhanced',
              
              // Social auth
              socialButtonsBlockButton: 'clerk-social-button-enhanced',
              socialButtonsBlockButtonText: 'font-medium',
              socialButtonsProviderIcon: 'clerk-social-icon-enhanced',
              
              // Footer
              footerActionText: 'clerk-footer-text-enhanced',
              footerActionLink: 'clerk-footer-link-enhanced',
              footer: 'clerk-footer-enhanced',
              
              // Divider
              dividerLine: 'clerk-divider-enhanced',
              dividerText: 'clerk-divider-text-enhanced',
              
              // Alternative methods
              alternativeMethods: 'mt-8 pt-6 border-t border-border/30',
              alternativeMethodsBlockButton: 'clerk-button-secondary-enhanced',
              
              // Identity preview
              identityPreview: 'clerk-identity-enhanced',
              identityPreviewText: 'clerk-identity-text-enhanced',
              identityPreviewEditButton: 'clerk-identity-edit-enhanced',
              
              // Loading
              spinner: 'clerk-spinner-enhanced',
            },
            variables: {
              colorPrimary: '#3b82f6',
              colorBackground: 'transparent',
              colorText: '#f8fafc',
              colorInputBackground: 'rgba(30, 41, 59, 0.8)',
              colorInputText: '#f8fafc',
              fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
              fontSize: '16px',
              borderRadius: '12px',
              spacingUnit: '6px',
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
          fallbackRedirectUrl="/"
          appearance={{
            elements: {
              // Root container
              rootBox: 'w-full',
              card: 'w-full bg-transparent border-0 shadow-none p-0 space-y-6',
              
              // Header
              headerTitle: 'clerk-title-enhanced',
              headerSubtitle: 'clerk-subtitle-enhanced',
              
              // Form fields
              formFieldLabel: 'clerk-label-enhanced',
              formFieldLabel__emailAddress: 'clerk-label-enhanced',
              formFieldLabel__password: 'clerk-label-enhanced',
              formFieldLabel__confirmPassword: 'clerk-label-enhanced',
              formFieldLabel__firstName: 'clerk-label-enhanced',
              formFieldLabel__lastName: 'clerk-label-enhanced',
              formFieldInput: 'clerk-input-enhanced',
              formFieldInput__emailAddress: 'clerk-input-enhanced',
              formFieldInput__password: 'clerk-input-enhanced',
              formFieldInput__confirmPassword: 'clerk-input-enhanced',
              formFieldInput__firstName: 'clerk-input-enhanced',
              formFieldInput__lastName: 'clerk-input-enhanced',
              formFieldInputShowPasswordButton: 'text-muted-foreground hover:text-foreground hover:scale-110 transition-all',
              formFieldErrorText: 'clerk-message-error-enhanced',
              formFieldSuccessText: 'clerk-message-success-enhanced',
              formFieldHintText: 'text-muted-foreground text-xs mt-2',
              formFieldHintText__password: 'text-muted-foreground text-xs mt-2',
              formFieldHintText__confirmPassword: 'text-muted-foreground text-xs mt-2',
              
              // Buttons
              formButtonPrimary: 'clerk-button-primary-enhanced',
              formButtonReset: 'clerk-button-secondary-enhanced',
              
              // Social auth
              socialButtonsBlockButton: 'clerk-social-button-enhanced',
              socialButtonsBlockButtonText: 'font-medium',
              socialButtonsProviderIcon: 'clerk-social-icon-enhanced',
              
              // Footer
              footerActionText: 'clerk-footer-text-enhanced',
              footerActionLink: 'clerk-footer-link-enhanced',
              footer: 'clerk-footer-enhanced',
              
              // Divider
              dividerLine: 'clerk-divider-enhanced',
              dividerText: 'clerk-divider-text-enhanced',
              
              // Alternative methods
              alternativeMethods: 'mt-8 pt-6 border-t border-border/30',
              alternativeMethodsBlockButton: 'clerk-button-secondary-enhanced',
              
              // Identity preview
              identityPreview: 'clerk-identity-enhanced',
              identityPreviewText: 'clerk-identity-text-enhanced',
              identityPreviewEditButton: 'clerk-identity-edit-enhanced',
              
              // Loading
              spinner: 'clerk-spinner-enhanced',
            },
            variables: {
              colorPrimary: '#3b82f6',
              colorBackground: 'transparent',
              colorText: '#f8fafc',
              colorInputBackground: 'rgba(30, 41, 59, 0.8)',
              colorInputText: '#f8fafc',
              fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
              fontSize: '16px',
              borderRadius: '12px',
              spacingUnit: '6px',
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
    // Registration is controlled by Clerk dashboard settings
    // Clerk handles user registration restrictions automatically
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
