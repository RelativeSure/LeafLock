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
   * Authenticate user with email and password
   * @param email - User's email address
   * @param password - User's password (used for key derivation, not stored)
   * @returns Promise resolving to MFA requirements
   * @throws {Error} On authentication failure or network errors
   *
   * @flow
   * 1. Submit credentials to authService
   * 2. If MFA required: store encryption credentials and session
   * 3. If direct login: derive and store encryption keys
   * 4. Update user state and persist to storage
   *
   * @encryption
   * - Receives encryption salt from server
   * - Derives encryption key from password + salt
   * - Stores derived key for subsequent operations
   */
  login: (email: string, password: string) => Promise<{ requiresMFA: boolean }>

  /**
   * Verify multi-factor authentication code
   * @param code - 6-digit MFA code from authenticator app
   * @returns Promise resolving to success status
   * @throws {Error} On verification failure
   *
   * @flow
   * 1. Submit MFA code with stored session token
   * 2. On success: derive encryption keys from pending credentials
   * 3. Clear MFA session and pending encryption data
   * 4. Update user state
   *
   * @note
   * - Requires valid mfaSession from previous login attempt
   * - Uses pendingEncryption data to complete key derivation
   * - Automatically clears sensitive temporary data
   */
  verifyMFA: (code: string) => Promise<boolean>

  /**
   * Logout current user and clear all authentication state
   * Clears: user data, encryption keys, MFA sessions, pending encryption
   * Calls authService.logout for server-side session cleanup
   */
  logout: () => void

  /**
   * Register new user account
   * @param email - New user's email
   * @param password - New user's password
   * @param name - New user's display name
   * @returns Promise resolving to success message
   * @throws {Error} On registration failure or if registration is disabled
   *
   * @note
   * - Checks registrationEnabled status before proceeding
   * - Provides user-friendly error messages for disabled registration
   * - Does not automatically log in the new user
   */
  register: (email: string, password: string, name: string) => Promise<string>

  /**
   * Begin MFA setup process for current user
   * @returns Promise resolving to MFA secret for QR code generation
   * @throws {Error} If no user is logged in
   *
   * @note
   * - Requires authenticated user
   * - Returns secret that should be displayed as QR code
   * - User must verify setup with verifyMFA to complete enrollment
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
        // JWT authentication is deprecated - use Clerk instead
        set({ user: null })
        console.log('Auth store initialization complete, setting isLoading to false')
        set({ isLoading: false })
      },

      login: async () => {
        throw new Error('JWT authentication is deprecated. Use Clerk authentication instead.')
      },

      verifyMFA: async () => {
        throw new Error('JWT authentication is deprecated. Use Clerk authentication instead.')
      },

      register: async () => {
        throw new Error('JWT authentication is deprecated. Use Clerk authentication instead.')
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
