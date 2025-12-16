/**
 * App Component - Root Application Wrapper
 *
 * @description
 * Main application entry point that provides core providers and lazy-loads routing.
 * Handles encryption context, theme management, and application initialization.
 *
 * @architecture
 * - Lazy loads router to prevent circular dependencies during build
 * - Provides ThemeProvider for consistent styling across components
 * - Wraps application with EncryptionProvider for client-side encryption
 * - Displays loading spinner during router initialization
 * - Uses runtime configuration for Clerk key (supports Railway deployment)
 *
 * @performance-considerations
 * - Router lazy loading reduces initial bundle size
 * - Dynamic import prevents circular dependency issues
 * - Minimal loading state prevents layout shift
 *
 * @providers
 * - ThemeProvider: Manages light/dark theme switching
 * - EncryptionProvider: Handles client-side encryption keys and operations
 * - RouterProvider: Manages application routing and navigation
 */
import React from 'react'
import { RouterProvider } from '@tanstack/react-router'
import { ClerkProvider, useSession } from '@clerk/clerk-react'
import { ThemeProvider } from './context/ThemeContext'
import { EncryptionProvider } from './lib/encryption-context'
import { clerkApiClient } from './services/api/clerkApiClient'
import { contentService } from './services/api/contentService'
import { useEnhancedClerk } from './hooks/useEnhancedClerk'
import { getClerkPublishableKey, debugRuntimeConfig } from './lib/runtime-config'
import './styles/clerk-auth.css'

// Temporarily remove wrappers to isolate update loop

// Lazy load router to prevent circular dependency
let routerInstance: any = null

/**
 * AppContent Component - Wrapper for Clerk-dependent hooks
 *
 * @description
 * This component must be rendered inside ClerkProvider to access Clerk hooks.
 * It handles router initialization, session monitoring, and provides the router.
 */
const AppContent: React.FC = () => {
  const [router, setRouter] = React.useState<any>(null)
  const { session, isLoaded } = useSession()

  // Initialize API clients with Clerk session (now inside ClerkProvider)
  React.useEffect(() => {
    if (!isLoaded || !session) return
    clerkApiClient.setSession({ session })
    contentService.setSession({ session })
  }, [isLoaded, session])

  // Use enhanced Clerk functionality (now inside ClerkProvider)
  const { isExpiringSoon, timeUntilExpiry } = useEnhancedClerk()

  // Monitor session expiration
  React.useEffect(() => {
    if (isExpiringSoon && timeUntilExpiry) {
      console.log(`Clerk session expiring in ${Math.floor(timeUntilExpiry / 60000)} minutes`)

      // Could show a notification to the user
      // Could automatically refresh the session
      // Could redirect to login when expired
    }
  }, [isExpiringSoon, timeUntilExpiry])

  React.useEffect(() => {
    // Dynamically import router to break circular dependency
    if (!routerInstance) {
      import('./router').then((module) => {
        routerInstance = module.router
        setRouter(routerInstance)
      })
    } else {
      setRouter(routerInstance)
    }
  }, [])

  if (!router) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
      </div>
    )
  }

  return (
    <ThemeProvider>
      <EncryptionProvider>
        <RouterProvider router={router} />
        {/* Show auth debug panel in development */}
        {import.meta.env.DEV &&
          React.createElement(React.lazy(() => import('./components/debug/ClerkAuthDebug')))}
      </EncryptionProvider>
    </ThemeProvider>
  )
}

const App: React.FC = () => {
  const [clerkKey, setClerkKey] = React.useState<string | undefined>(getClerkPublishableKey())

  React.useEffect(() => {
    // Debug runtime config in development
    if (import.meta.env.DEV) {
      debugRuntimeConfig()
    }

    // Listen for runtime config updates
    const handleConfigReady = () => {
      const key = getClerkPublishableKey()
      if (key && key !== clerkKey) {
        console.log('✅ Clerk key loaded from runtime config')
        setClerkKey(key)
      }
    }

    window.addEventListener('runtime-config-ready', handleConfigReady)
    return () => window.removeEventListener('runtime-config-ready', handleConfigReady)
  }, [clerkKey])

  // Show error if Clerk key is missing
  if (!clerkKey) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 px-4">
        <div className="max-w-md w-full bg-white rounded-lg shadow-lg p-6">
          <div className="text-center">
            <div className="text-4xl mb-4">🔑</div>
            <h1 className="text-2xl font-bold text-gray-900 mb-2">Configuration Error</h1>
            <p className="text-gray-600 mb-4">
              Clerk publishable key is not configured. Please check your environment variables.
            </p>
            <div className="bg-gray-100 rounded p-4 text-left text-sm">
              <p className="font-mono text-gray-800 mb-2">
                Required: <strong>VITE_CLERK_PUBLISHABLE_KEY</strong>
              </p>
              <p className="text-gray-600 text-xs">
                This should be set in your Railway environment variables or .env file.
              </p>
            </div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <ClerkProvider
      publishableKey={clerkKey}
      afterSignOutUrl="/login"
      signInUrl="/login"
      signUpUrl="/register"
    >
      <AppContent />
    </ClerkProvider>
  )
}

export default App
