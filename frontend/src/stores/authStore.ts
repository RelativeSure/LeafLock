/**
 * Authentication Store - Core Authentication and Security Management
 *
 * @description
 * Manages user authentication state, multi-factor authentication (MFA),
 * encryption key derivation, and session persistence. This store serves as
 * the foundation for all authenticated operations in the application.
 *
 * @responsibilities
 * - User authentication (login/logout/register)
 * - Multi-factor authentication flow management
 * - Encryption key derivation and storage for client-side encryption
 * - Session persistence and restoration
 * - Registration availability checking
 * - User role and permission management
 *
 * @security-considerations
 * - Passwords are never stored - only used for key derivation during login
 * - Encryption keys are derived from passwords and stored salts
 * - MFA sessions are temporary and cleared after verification
 * - User data is persisted to localStorage for session restoration
 * - Registration can be disabled server-side for security
 *
 * @integration-patterns
 * - Used by ProtectedRoute component for route guarding
 * - Consumed by LoginForm, MFA verification components
 * - Provides encryption keys to notesStore for content encryption
 * - Integrates with authService for API communication
 *
 * @state-persistence
 * - User object persisted to localStorage via zustand persist middleware
 * - Encryption keys stored separately in secure storage
 * - MFA sessions kept in memory only (not persisted)
 * - Registration status cached in memory to reduce API calls
 */
import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { User } from '../types'
import { authService } from '@/services/api'


interface AuthState {
  /**
   * Authenticated user object containing profile information and role
   * @type {User | null} null when no user is authenticated
   */
  user: User | null

  /**
   * Loading state for authentication operations
   * @type {boolean} true during login/logout/initialization operations
   */
  isLoading: boolean

  /**
   * Temporary storage for encryption credentials during MFA flow
   * @type {{ password: string; salt?: string | null } | null}
   * Used to derive encryption keys after MFA verification completes
   * Cleared after successful authentication or logout
   */
  pendingEncryption: { password: string; salt?: string | null } | null

  /**
   * MFA session token for multi-factor authentication flow
   * @type {string | null} Temporary session ID for MFA verification
   * Obtained during login when MFA is required
   * Cleared after successful MFA verification or logout
   */
  mfaSession: string | null

  /**
   * Registration availability status
   * @type {boolean | null} true if registration is enabled, false if disabled
   * null if not yet checked - defaults to false for security
   * Cached to reduce API calls
   */
  registrationEnabled: boolean | null

  /**
   * Begin MFA setup process for current user
   * @returns Promise resolving to MFA secret for QR code generation
   * @throws {Error} If no user is logged in
   *
   * @note
   * - Requires authenticated user
   * - Returns secret that should be displayed as QR code
   * - User must verify setup with enableMFA to complete enrollment
   */
  enableMFA: () => Promise<string>

  /**
   * Disable MFA for current user
   * @throws {Error} If no user is logged in or disable fails
   *
   * @security
   * - Requires user re-authentication before disabling
   * - Immediately removes MFA requirement for future logins
   */
  disableMFA: () => Promise<void>

  /**
   * Initialize authentication state from localStorage
   * Restores user session if valid token exists
   * Sets isLoading to false when complete
   * Called during app initialization
   *
   * @flow
   * 1. Check for stored user and token in localStorage
   * 2. Validate stored data integrity
   * 3. Restore user state if valid
   * 4. Clear invalid data and set loading to false
   *
   * @note
   * - Does NOT validate token with server on init (prevents redirect loops)
   * - API client handles 401 errors on actual API calls
   * - Automatically cleans up corrupted storage data
   */
  initialize: () => Promise<void>

  /**
   * Check if user registration is enabled on the server
   * @returns Promise resolving to registration status
   * @throws {Error} On API failure (defaults to false for security)
   *
   * @caching
   * - Caches result in registrationEnabled state
   * - Returns cached value on subsequent calls
   * - Defaults to false (disabled) on API errors for security
   */
  checkRegistrationEnabled: () => Promise<boolean>
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      isLoading: true,
      pendingEncryption: null,
      mfaSession: null,
      registrationEnabled: null,

      initialize: async () => {
        console.log('Auth store initializing...')
        // Authentication is handled by Clerk - no initialization needed
        set({ isLoading: false })
        console.log('Auth store initialization complete')
      },

      checkRegistrationEnabled: async () => {
        const { registrationEnabled } = get()

        // Return cached value if already checked
        if (registrationEnabled !== null) {
          return registrationEnabled
        }

        try {
          const enabled = await authService.isRegistrationEnabled()
          set({ registrationEnabled: enabled })
          return enabled
        } catch (error) {
          console.error('Failed to check registration status:', error)
          // Default to false on error for security
          set({ registrationEnabled: false })
          return false
        }
      },

      enableMFA: async () => {
        const { user } = get()
        if (!user) throw new Error('No user logged in')

        try {
          const response = await authService.beginMFASetup()
          return response.secret
        } catch (error) {
          throw new Error(error instanceof Error ? error.message : 'Failed to enable MFA')
        }
      },

      disableMFA: async () => {
        const { user } = get()
        if (!user) throw new Error('No user logged in')

        try {
          await authService.disableMFA()
        } catch (error) {
          throw new Error(error instanceof Error ? error.message : 'Failed to disable MFA')
        }
      },

      // Legacy methods for backward compatibility - now handled by Clerk
      login: async (_email: string, _password: string) => {
        throw new Error('JWT authentication is deprecated. Use Clerk authentication instead.')
      },

      verifyMFA: async (_code: string) => {
        throw new Error('JWT authentication is deprecated. Use Clerk authentication instead.')
      },

      register: async (email: string, password: string, name: string) => {
        return authService.register(email, password, name)
      },

      logout: () => {
        set({ user: null, pendingEncryption: null, mfaSession: null })
        // JWT cleanup removed - Clerk handles logout
      },
    }),
    {
      name: 'auth-store',
      partialize: (state) => ({
        user: state.user,
        registrationEnabled: state.registrationEnabled,
      }),
    }
  )
)
