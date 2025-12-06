/**
 * Clerk Authentication Store
 *
 * @description
 * Replaces the legacy Zustand auth store with Clerk authentication.
 * Provides compatibility layer for existing components while transitioning to Clerk.
 *
 * @features
 * - Clerk authentication state management
 * - User profile management
 * - Session handling
 * - Role-based access control
 * - Migration helpers from legacy auth
 */

import React from 'react'
import { create } from 'zustand'
import { useAuth, useUser, useSession } from '@clerk/clerk-react'

export interface User {
  id: string
  email: string
  name?: string
  isAdmin: boolean
  createdAt?: Date
  updatedAt?: Date
}

export interface AuthState {
  user: User | null
  isAuthenticated: boolean
  isLoading: boolean
  isAdmin: boolean

  // Actions
  setUser: (user: User | null) => void
  setLoading: (loading: boolean) => void
  logout: () => Promise<void>

  // Migration helpers
  getAuthToken: () => Promise<string | null>
  getEncryptionKey: () => Promise<string | null>
}

export const useClerkAuthStore = create<AuthState>((set) => ({
  user: null,
  isAuthenticated: false,
  isLoading: true,
  isAdmin: false,

  setUser: (user) => set({ user, isAuthenticated: !!user, isAdmin: user?.isAdmin || false }),

  setLoading: (loading) => set({ isLoading: loading }),

  logout: async () => {
    // This will be handled by Clerk's signOut functionality
    set({ user: null, isAuthenticated: false, isAdmin: false })
  },

  getAuthToken: async () => {
    // Get Clerk session token for API calls
    // This hook should be used within a React component
    return null // Will be implemented when used in components
  },

  getEncryptionKey: async () => {
    // For zero-knowledge encryption - this will need to be handled differently with Clerk
    // The encryption key should be derived from the user's password or a separate encryption secret
    return null // Will be implemented based on encryption requirements
  },
}))

// Hook to sync Clerk auth state with our store with enhanced session management
export const useSyncClerkAuth = () => {
  const { isSignedIn, isLoaded } = useAuth()
  const { user: clerkUser } = useUser()
  const { session } = useSession()

  const { setUser, setLoading } = useClerkAuthStore()

  React.useEffect(() => {
    if (!isLoaded) {
      setLoading(true)
      return
    }

    setLoading(false)

    if (isSignedIn && clerkUser) {
      const user: User = {
        id: clerkUser.id,
        email: clerkUser.primaryEmailAddress?.emailAddress || '',
        name: clerkUser.fullName || undefined,
        isAdmin:
          clerkUser.publicMetadata?.isAdmin === true || clerkUser.publicMetadata?.role === 'admin',
        createdAt: clerkUser.createdAt ? new Date(clerkUser.createdAt) : undefined,
        updatedAt: clerkUser.updatedAt ? new Date(clerkUser.updatedAt) : undefined,
      }
      setUser(user)
    } else {
      setUser(null)
    }
  }, [isSignedIn, isLoaded, clerkUser, setUser, setLoading])

  // Enhanced session monitoring
  React.useEffect(() => {
    if (session && isSignedIn) {
      console.log('Clerk session active:', {
        id: session.id,
        status: session.status,
        expiresAt: session.expireAt,
      })

      // Monitor session expiration
      if (session.expireAt) {
        const expirationTime = new Date(session.expireAt).getTime()
        const now = Date.now()
        const timeUntilExpiration = expirationTime - now

        if (timeUntilExpiration < 5 * 60 * 1000) {
          // Less than 5 minutes
          console.warn('Clerk session expiring soon, consider refresh')
        }
      }
    }
  }, [session, isSignedIn])
}

// Export clerk hooks for direct usage
export { useAuth, useUser, useSession } from '@clerk/clerk-react'
