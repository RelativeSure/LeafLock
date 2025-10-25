import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { User } from '../types'
import { apiClient } from '../services/api/secureApi'

interface AuthState {
  user: User | null
  isLoading: boolean
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

      initialize: async () => {
        console.log('Auth store initializing...')
        const storedUser = localStorage.getItem('user')
        const storedToken = localStorage.getItem('token')

        if (storedUser && storedToken) {
          try {
            const userData = JSON.parse(storedUser)
            set({ user: userData })
            console.log('Found stored user:', userData.email)
            // Verify token is still valid by making a health check
            try {
              await apiClient.healthCheck()
              console.log('Token validation successful')
            } catch (error) {
              console.warn('Health check failed, but continuing with stored token:', error)
            }
          } catch (error) {
            console.error('Error parsing stored user or token invalid:', error)
            localStorage.removeItem('user')
            localStorage.removeItem('token')
            set({ user: null })
          }
        } else {
          console.log('No stored user/token found')
        }
        console.log('Auth store initialization complete, setting isLoading to false')
        set({ isLoading: false })
      },

      login: async (email: string, password: string) => {
        try {
          const response = await apiClient.login(email, password)

          if (response.requiresMFA) {
            return { requiresMFA: true }
          }

          set({ user: { ...response.user, isAdmin: response.user.role === 'admin' } })

          // Set up encryption key after successful login
          // For now, use a simple key derived from email + password
          // In production, this should be more secure
          const encryptionKey = btoa(email + password).substring(0, 32)
          if (typeof window !== 'undefined') {
            localStorage.setItem('encryptionKey', encryptionKey)
          }

          return { requiresMFA: false }
        } catch (error) {
          throw new Error(error instanceof Error ? error.message : 'Login failed')
        }
      },

      verifyMFA: async (code: string) => {
        try {
          const response = await apiClient.verifyMFA(code)
          set({ user: { ...response.user, isAdmin: response.user.role === 'admin' } })
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
        set({ user: null })
      },
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({ user: state.user }),
    }
  )
)
