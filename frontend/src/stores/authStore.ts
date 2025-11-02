import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { User } from '../types'
import { apiClient } from '../services/api/secureApi'
import { deriveKey, setStoredKey, setStoredSalt } from '@/lib/encryption-utils'

interface AuthState {
  user: User | null
  isLoading: boolean
  pendingEncryption: { password: string; salt?: string | null } | null
  login: (email: string, password: string) => Promise<{ requiresMFA: boolean }>
  verifyMFA: (code: string) => Promise<boolean>
  logout: () => void
  register: (email: string, password: string, name: string) => Promise<void>
  enableMFA: () => Promise<string>
  disableMFA: () => Promise<void>
  initialize: () => Promise<void>
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      isLoading: true,
      pendingEncryption: null,

      initialize: async () => {
        console.log('Auth store initializing...')
        const storedUser = localStorage.getItem('user')
        const storedToken = localStorage.getItem('token')

        if (storedUser && storedToken) {
          try {
            const userData = JSON.parse(storedUser)
            set({ user: userData })
            console.log('Found stored user:', userData.email)
            // Don't validate health check on initial load - it can cause redirect loops
            // The API client will handle 401 errors on actual API calls
            console.log('Token found in storage')
          } catch (error) {
            console.error('Error parsing stored user or token invalid:', error)
            localStorage.removeItem('user')
            localStorage.removeItem('token')
            set({ user: null })
          }
        } else {
          // Ensure we clear any stale in-memory user if token is missing
          if (storedUser || storedToken) {
            localStorage.removeItem('user')
            localStorage.removeItem('token')
          }
          set({ user: null })
          console.log('No stored user/token found; clearing user state')
        }
        console.log('Auth store initialization complete, setting isLoading to false')
        set({ isLoading: false })
      },

      login: async (email: string, password: string) => {
        try {
          const response = await apiClient.login(email, password)

          if (response.requiresMFA) {
            if (response.encryptionSalt) {
              await setStoredSalt(response.encryptionSalt)
            }
            set({ pendingEncryption: { password, salt: response.encryptionSalt } })
            return { requiresMFA: true }
          }

          set({ user: { ...response.user, isAdmin: response.user.role === 'admin' } })

          if (response.encryptionSalt) {
            console.log('[Auth] Received salt on login (success)', {
              len: response.encryptionSalt.length,
              prefix: response.encryptionSalt.slice(0, 12),
            })
            await setStoredSalt(response.encryptionSalt)
            try {
              const derivedKey = await deriveKey(password, response.encryptionSalt)
              setStoredKey(derivedKey)
            } catch (deriveError) {
              console.error('Failed to derive encryption key:', deriveError)
              setStoredKey(null)
            }
          }

          set({ pendingEncryption: null })

          return { requiresMFA: false }
        } catch (error) {
          throw new Error(error instanceof Error ? error.message : 'Login failed')
        }
      },

      verifyMFA: async (code: string) => {
        try {
          const response = await apiClient.verifyMFA(code)
          set({ user: { ...response.user, isAdmin: response.user.role === 'admin' } })

          const { pendingEncryption } = get()
          const salt = response.encryptionSalt || pendingEncryption?.salt
          if (salt) {
            console.log('[Auth] Received salt on verifyMFA', {
              len: salt.length,
              prefix: salt.slice(0, 12),
            })
            await setStoredSalt(salt)
          }

          if (pendingEncryption?.password && salt) {
            try {
              const derivedKey = await deriveKey(pendingEncryption.password, salt)
              setStoredKey(derivedKey)
            } catch (deriveError) {
              console.error('Failed to derive encryption key after MFA verification:', deriveError)
              setStoredKey(null)
            }
          }

          set({ pendingEncryption: null })
          return true
        } catch (error) {
          console.error('MFA verification failed:', error)
          return false
        }
      },

      register: async (email: string, password: string, name: string) => {
        try {
          const response = await apiClient.register(email, password, name)
          set({ user: { ...response.user, isAdmin: response.user.role === 'admin' } })

          if (response.encryptionSalt) {
            console.log('[Auth] Received salt on register', {
              len: response.encryptionSalt.length,
              prefix: response.encryptionSalt.slice(0, 12),
            })
            await setStoredSalt(response.encryptionSalt)
            try {
              const derivedKey = await deriveKey(password, response.encryptionSalt)
              setStoredKey(derivedKey)
            } catch (deriveError) {
              console.error('Failed to derive encryption key after registration:', deriveError)
              setStoredKey(null)
            }
          }

          set({ pendingEncryption: null })
        } catch (error) {
          throw new Error(error instanceof Error ? error.message : 'Registration failed')
        }
      },

      enableMFA: async () => {
        const { user } = get()
        if (!user) throw new Error('No user logged in')

        try {
          const response = await apiClient.beginMFASetup()
          return response.secret
        } catch (error) {
          throw new Error(error instanceof Error ? error.message : 'Failed to enable MFA')
        }
      },

      disableMFA: async () => {
        const { user } = get()
        if (!user) throw new Error('No user logged in')

        try {
          await apiClient.disableMFA()
        } catch (error) {
          throw new Error(error instanceof Error ? error.message : 'Failed to disable MFA')
        }
      },

      logout: () => {
        apiClient.logout()
        set({ user: null, pendingEncryption: null })
        setStoredKey(null)
      },
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({ user: state.user }),
    }
  )
)
