/**
 * Clerk Authentication Service (Compatibility Layer)
 *
 * @description
 * Provides compatibility layer for existing auth service interface using Clerk.
 * Maintains the same API surface while using Clerk authentication internally.
 *
 * @features
 * - Clerk-based authentication
 * - MFA support via Clerk
 * - Password reset via Clerk
 * - Compatibility with existing auth service interface
 */

import { useClerkApiClient } from './clerkApiClient'
import { ClerkUser, RegisterResponse, MFAStatusResponse } from './types'
import { useAuth, useUser, useSession } from '@clerk/clerk-react'
import { getRuntimeConfig } from '@/lib/runtime-config'

import React from 'react'

interface ClerkAuthServiceDeps {
  apiClient: ReturnType<typeof useClerkApiClient>
  auth: ReturnType<typeof useAuth>
  user: ReturnType<typeof useUser>
  session: ReturnType<typeof useSession>
}

class ClerkAuthService {
  private apiClient: ReturnType<typeof useClerkApiClient>
  private auth: ReturnType<typeof useAuth>
  private user: ReturnType<typeof useUser>
  private session: ReturnType<typeof useSession>

  constructor(deps: ClerkAuthServiceDeps) {
    this.apiClient = deps.apiClient
    this.auth = deps.auth
    this.user = deps.user
    this.session = deps.session
  }

  // Add missing method that was referenced
  async get<T>(endpoint: string): Promise<T> {
    return this.apiClient.get<T>(endpoint)
  }

  async post<T>(endpoint: string, data?: any): Promise<T> {
    return this.apiClient.post<T>(endpoint, data)
  }

  // Legacy login method - now handled by Clerk
  async login(_email: string, _password: string): Promise<{ user: ClerkUser }> {
    // This method is no longer needed as Clerk handles login
    // Return a mock response for compatibility during transition
    throw new Error('Use Clerk signIn instead of authService.login()')
  }

  // Legacy register method - now handled by Clerk
  async register(_email: string, _password: string, _name: string): Promise<RegisterResponse> {
    // This method is no longer needed as Clerk handles registration
    // Return a mock response for compatibility during transition
    throw new Error('Use Clerk signUp instead of authService.register()')
  }

  // MFA verification - now handled by Clerk
  async verifyMFA(_code: string, _sessionToken?: string): Promise<{ user: ClerkUser }> {
    // MFA is handled by Clerk's built-in MFA flow
    throw new Error('Use Clerk MFA flow instead of authService.verifyMFA()')
  }

  // Logout - use Clerk's signOut
  async logout(): Promise<void> {
    // This will be handled by Clerk's signOut functionality
    // The actual signOut should be called from the Clerk hooks
    throw new Error('Use Clerk signOut instead of authService.logout()')
  }

  // Get MFA status from backend (still needed for backend MFA setup)
  async getMFAStatus(): Promise<MFAStatusResponse> {
    return this.apiClient.get<MFAStatusResponse>('/auth/mfa/status')
  }

  // Begin MFA setup (backend still handles TOTP secret generation)
  async beginMFASetup(): Promise<{ secret: string; qrCode: string }> {
    return this.apiClient.post<{ secret: string; qrCode: string }>('/auth/mfa/begin')
  }

  // Enable MFA (backend still handles TOTP verification)
  async enableMFA(code: string): Promise<void> {
    await this.apiClient.post('/auth/mfa/enable', { code })
  }

  // Disable MFA via backend
  async disableMFA(): Promise<void> {
    await this.apiClient.post('/auth/mfa/disable')
  }

  // Get backup codes (backend still manages backup codes)
  async getBackupCodes(): Promise<string[]> {
    const response = await this.apiClient.get<{ backupCodes: string[] }>('/auth/mfa/backup-codes')
    return response.backupCodes
  }

  // Regenerate backup codes (backend still manages backup codes)
  async regenerateBackupCodes(): Promise<string[]> {
    const response = await this.apiClient.post<{ backupCodes: string[] }>(
      '/auth/mfa/backup-codes/regenerate'
    )
    return response.backupCodes
  }

  // Request password reset - now handled by Clerk
  async requestPasswordReset(_email: string): Promise<void> {
    // This is handled by Clerk's password reset flow
    throw new Error('Use Clerk password reset instead of authService.requestPasswordReset()')
  }

  // Check registration enabled status
  async isRegistrationEnabled(): Promise<boolean> {
    try {
      const response = await this.apiClient.get<{ enabled: boolean }>('/auth/registration')
      return response.enabled
    } catch (error) {
      // If the endpoint doesn't exist or fails, default to true
      // (Clerk handles registration controls)
      return true
    }
  }

  // Get current Clerk user info in legacy format
  getCurrentUser(): ClerkUser | null {
    const { user: clerkUser } = this.user
    const { isSignedIn } = this.auth

    if (!isSignedIn || !clerkUser) {
      return null
    }

    return {
      id: clerkUser.id,
      email: clerkUser.primaryEmailAddress?.emailAddress || '',
      name: clerkUser.fullName || '',
      role:
        clerkUser.publicMetadata?.isAdmin === true || clerkUser.publicMetadata?.role === 'admin'
          ? 'admin'
          : 'user',
      mfaEnabled: clerkUser.twoFactorEnabled === true,
      createdAt: clerkUser.createdAt
        ? new Date(clerkUser.createdAt).toISOString()
        : new Date().toISOString(),
    }
  }

  // Get Clerk session token for API calls
  async getSessionToken(): Promise<string | null> {
    const session = this.session
    const jwtTemplate = getRuntimeConfig().clerkJwtTemplate || undefined
    if (!session || !('session' in session) || !session.session) {
      return null
    }
    try {
      if ('getToken' in session.session) {
        let token: string | null = null
        if (jwtTemplate) {
          token = await session.session.getToken({ template: jwtTemplate })
        }
        if (!token) {
          token = await session.session.getToken()
        }
        return token
      }
      return null
    } catch {
      return null
    }
  }

  // Check if user is authenticated
  isAuthenticated(): boolean {
    return this.auth.isSignedIn === true
  }

  // Check if user has admin role
  isAdmin(): boolean {
    const { user: clerkUser } = this.user
    return (
      clerkUser?.publicMetadata?.isAdmin === true || clerkUser?.publicMetadata?.role === 'admin'
    )
  }
}

// Hook for using the Clerk auth service
export const useClerkAuthService = () => {
  const auth = useAuth()
  const user = useUser()
  const session = useSession()
  const apiClient = useClerkApiClient()

  return React.useMemo(() => {
    return new ClerkAuthService({
      apiClient,
      auth,
      user,
      session,
    })
  }, [apiClient, auth, user, session])
}

// Export a function to get the service instance (for migration compatibility)
export const getClerkAuthService = () => {
  // This will be replaced by the hook-based approach
  throw new Error('Use useClerkAuthService() hook instead of getClerkAuthService()')
}
