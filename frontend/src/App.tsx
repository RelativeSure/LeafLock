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
import { ClerkProvider } from '@clerk/clerk-react'
import { ThemeProvider } from './context/ThemeContext'
import { EncryptionProvider } from './lib/encryption-context'
import { useClerkApiClient } from './services/api/clerkApiClient'
// import { ConfigDebug } from './components/debug/ConfigDebug'
// Temporarily remove wrappers to isolate update loop

// Lazy load router to prevent circular dependency
let routerInstance: any = null

const App: React.FC = () => {
  const [router, setRouter] = React.useState<any>(null)
  
  // Initialize Clerk API client with session
  useClerkApiClient()

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
    <ClerkProvider
      publishableKey={import.meta.env.VITE_CLERK_PUBLISHABLE_KEY}
      afterSignOutUrl="/login"
      signInUrl="/login"
      signUpUrl="/register"
    >
      <ThemeProvider>
        <EncryptionProvider>
          <RouterProvider router={router} />
        </EncryptionProvider>
      </ThemeProvider>
    </ClerkProvider>
  )
}

export default App
