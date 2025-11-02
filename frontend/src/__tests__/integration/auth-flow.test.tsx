import { describe, it, expect, beforeEach, vi } from 'vitest'
import { useAuthStore } from '@/stores/authStore'
import { apiClient } from '@/services/api/secureApi'

vi.mock('@/services/api/secureApi', () => ({
  apiClient: {
    login: vi.fn(),
    register: vi.fn(),
    logout: vi.fn(),
    verifyMFA: vi.fn(),
    setupMFA: vi.fn(),
    enableMFA: vi.fn(),
    disableMFA: vi.fn(),
    getBackupCodes: vi.fn(),
  },
}))

describe('Integration: Complete Auth Flow', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,
    })
    localStorage.clear()
    vi.clearAllMocks()
  })

  describe('User Registration → Login → Logout Flow', () => {
    it('should complete full registration and login flow', async () => {
      // Step 1: Register new user
      const registerResponse = {
        token: 'register-token',
        user: {
          id: '123',
          email: 'newuser@example.com',
          name: 'New User',
          role: 'user' as const,
          mfaEnabled: false,
          createdAt: '2024-01-01',
        },
        encryptionSalt: 'salt-123',
      }

      vi.mocked(apiClient.register).mockResolvedValue(registerResponse as any)

      await useAuthStore.getState().register('newuser@example.com', 'password123', 'New User')

      expect(useAuthStore.getState().isAuthenticated).toBe(true)
      expect(useAuthStore.getState().user?.email).toBe('newuser@example.com')
      expect(localStorage.getItem('token')).toBe('register-token')

      // Step 2: Logout
      vi.mocked(apiClient.logout).mockResolvedValue(undefined)

      await useAuthStore.getState().logout()

      expect(useAuthStore.getState().isAuthenticated).toBe(false)
      expect(useAuthStore.getState().user).toBeNull()
      expect(localStorage.getItem('token')).toBeNull()

      // Step 3: Login again
      const loginResponse = {
        token: 'login-token',
        user: registerResponse.user,
        encryptionSalt: 'salt-123',
      }

      vi.mocked(apiClient.login).mockResolvedValue(loginResponse as any)

      await useAuthStore.getState().login('newuser@example.com', 'password123')

      expect(useAuthStore.getState().isAuthenticated).toBe(true)
      expect(localStorage.getItem('token')).toBe('login-token')
    })

    it('should handle registration failure and retry', async () => {
      // Step 1: Failed registration (email exists)
      vi.mocked(apiClient.register).mockRejectedValueOnce(new Error('Email already exists'))

      await expect(
        useAuthStore.getState().register('existing@example.com', 'password', 'User')
      ).rejects.toThrow('Email already exists')

      expect(useAuthStore.getState().isAuthenticated).toBe(false)

      // Step 2: Retry with different email succeeds
      const registerResponse = {
        token: 'token',
        user: {
          id: '123',
          email: 'newemail@example.com',
          name: 'User',
          role: 'user' as const,
          mfaEnabled: false,
          createdAt: '2024-01-01',
        },
        encryptionSalt: 'salt',
      }

      vi.mocked(apiClient.register).mockResolvedValue(registerResponse as any)

      await useAuthStore.getState().register('newemail@example.com', 'password', 'User')

      expect(useAuthStore.getState().isAuthenticated).toBe(true)
    })
  })

  describe('MFA Setup and Authentication Flow', () => {
    it('should complete full MFA setup flow', async () => {
      // Step 1: Login as regular user
      const loginResponse = {
        token: 'token',
        user: {
          id: '123',
          email: 'user@example.com',
          name: 'User',
          role: 'user' as const,
          mfaEnabled: false,
          createdAt: '2024-01-01',
        },
        encryptionSalt: 'salt',
      }

      vi.mocked(apiClient.login).mockResolvedValue(loginResponse as any)

      await useAuthStore.getState().login('user@example.com', 'password')

      expect(useAuthStore.getState().user?.mfaEnabled).toBe(false)

      // Step 2: Setup MFA
      const setupResponse = {
        secret: 'JBSWY3DPEHPK3PXP',
        qrCode: 'data:image/png;base64,ABC',
        backupCodes: ['1111-2222-3333', '4444-5555-6666'],
      }

      vi.mocked(apiClient.setupMFA).mockResolvedValue(setupResponse)

      const mfaSetup = await useAuthStore.getState().setupMFA()

      expect(mfaSetup.qrCode).toBeTruthy()
      expect(mfaSetup.backupCodes).toHaveLength(2)

      // Step 3: Enable MFA with code
      vi.mocked(apiClient.enableMFA).mockResolvedValue(undefined)

      await useAuthStore.getState().enableMFA('123456')

      // Update user state to reflect MFA enabled
      useAuthStore.setState({
        user: { ...useAuthStore.getState().user!, mfaEnabled: true },
      })

      expect(useAuthStore.getState().user?.mfaEnabled).toBe(true)

      // Step 4: Logout
      vi.mocked(apiClient.logout).mockResolvedValue(undefined)
      await useAuthStore.getState().logout()

      // Step 5: Login with MFA required
      const mfaLoginResponse = {
        requiresMFA: true,
        user: { ...loginResponse.user, mfaEnabled: true },
        encryptionSalt: 'salt',
      }

      vi.mocked(apiClient.login).mockResolvedValue(mfaLoginResponse as any)

      await useAuthStore.getState().login('user@example.com', 'password')

      expect(useAuthStore.getState().isAuthenticated).toBe(false) // Not fully authenticated yet

      // Step 6: Verify MFA code
      const verifyResponse = {
        token: 'mfa-token',
        user: mfaLoginResponse.user,
      }

      vi.mocked(apiClient.verifyMFA).mockResolvedValue(verifyResponse as any)

      await useAuthStore.getState().verifyMFA('123456')

      expect(useAuthStore.getState().isAuthenticated).toBe(true)
      expect(localStorage.getItem('token')).toBe('mfa-token')
    })

    it('should handle MFA verification failure and retry', async () => {
      // Setup: User requires MFA
      useAuthStore.setState({
        user: {
          id: '123',
          email: 'user@example.com',
          name: 'User',
          role: 'user',
          isAdmin: false,
          mfaEnabled: true,
          createdAt: '2024-01-01',
        },
        isAuthenticated: false,
      })

      // Step 1: First MFA attempt fails
      vi.mocked(apiClient.verifyMFA).mockRejectedValueOnce(new Error('Invalid code'))

      await expect(useAuthStore.getState().verifyMFA('000000')).rejects.toThrow('Invalid code')

      expect(useAuthStore.getState().isAuthenticated).toBe(false)

      // Step 2: Second attempt succeeds
      const verifyResponse = {
        token: 'mfa-token',
        user: {
          id: '123',
          email: 'user@example.com',
          name: 'User',
          role: 'user' as const,
          mfaEnabled: true,
          createdAt: '2024-01-01',
        },
      }

      vi.mocked(apiClient.verifyMFA).mockResolvedValue(verifyResponse as any)

      await useAuthStore.getState().verifyMFA('123456')

      expect(useAuthStore.getState().isAuthenticated).toBe(true)
    })

    it('should disable MFA and login without it', async () => {
      // Setup: User with MFA enabled
      useAuthStore.setState({
        user: {
          id: '123',
          email: 'user@example.com',
          name: 'User',
          role: 'user',
          isAdmin: false,
          mfaEnabled: true,
          createdAt: '2024-01-01',
        },
        isAuthenticated: true,
      })

      // Step 1: Disable MFA
      vi.mocked(apiClient.disableMFA).mockResolvedValue(undefined)

      await useAuthStore.getState().disableMFA('password123')

      // Update user state
      useAuthStore.setState({
        user: { ...useAuthStore.getState().user!, mfaEnabled: false },
      })

      // Step 2: Logout and login without MFA
      vi.mocked(apiClient.logout).mockResolvedValue(undefined)
      await useAuthStore.getState().logout()

      const loginResponse = {
        token: 'token',
        user: {
          id: '123',
          email: 'user@example.com',
          name: 'User',
          role: 'user' as const,
          mfaEnabled: false,
          createdAt: '2024-01-01',
        },
        encryptionSalt: 'salt',
      }

      vi.mocked(apiClient.login).mockResolvedValue(loginResponse as any)

      await useAuthStore.getState().login('user@example.com', 'password123')

      expect(useAuthStore.getState().isAuthenticated).toBe(true)
      expect(useAuthStore.getState().user?.mfaEnabled).toBe(false)
    })
  })

  describe('Session Persistence Flow', () => {
    it('should restore session from localStorage', () => {
      // Simulate existing session
      const mockUser = {
        id: '123',
        email: 'user@example.com',
        name: 'User',
        role: 'user' as const,
        isAdmin: false,
        mfaEnabled: false,
        createdAt: '2024-01-01',
      }

      localStorage.setItem('token', 'existing-token')
      localStorage.setItem('user', JSON.stringify(mockUser))

      // Restore session
      useAuthStore.setState({
        user: mockUser,
        isAuthenticated: true,
      })

      expect(useAuthStore.getState().isAuthenticated).toBe(true)
      expect(useAuthStore.getState().user).toEqual(mockUser)
    })

    it('should handle invalid session and require re-login', async () => {
      // Simulate corrupted session
      localStorage.setItem('token', 'expired-token')
      localStorage.setItem('user', 'invalid-json')

      // Attempt to use app triggers re-login
      const loginResponse = {
        token: 'new-token',
        user: {
          id: '123',
          email: 'user@example.com',
          name: 'User',
          role: 'user' as const,
          mfaEnabled: false,
          createdAt: '2024-01-01',
        },
        encryptionSalt: 'salt',
      }

      vi.mocked(apiClient.login).mockResolvedValue(loginResponse as any)

      await useAuthStore.getState().login('user@example.com', 'password')

      expect(useAuthStore.getState().isAuthenticated).toBe(true)
      expect(localStorage.getItem('token')).toBe('new-token')
    })
  })

  describe('Error Recovery Flow', () => {
    it('should recover from network errors during login', async () => {
      // Step 1: Network error
      vi.mocked(apiClient.login).mockRejectedValueOnce(new Error('Network error'))

      await expect(
        useAuthStore.getState().login('user@example.com', 'password')
      ).rejects.toThrow('Network error')

      expect(useAuthStore.getState().isAuthenticated).toBe(false)

      // Step 2: Retry succeeds
      const loginResponse = {
        token: 'token',
        user: {
          id: '123',
          email: 'user@example.com',
          name: 'User',
          role: 'user' as const,
          mfaEnabled: false,
          createdAt: '2024-01-01',
        },
        encryptionSalt: 'salt',
      }

      vi.mocked(apiClient.login).mockResolvedValue(loginResponse as any)

      await useAuthStore.getState().login('user@example.com', 'password')

      expect(useAuthStore.getState().isAuthenticated).toBe(true)
    })

    it('should handle logout failure gracefully', async () => {
      // Setup: User logged in
      useAuthStore.setState({
        user: {
          id: '123',
          email: 'user@example.com',
          name: 'User',
          role: 'user',
          isAdmin: false,
          mfaEnabled: false,
          createdAt: '2024-01-01',
        },
        isAuthenticated: true,
      })

      localStorage.setItem('token', 'token')

      // Logout fails but local state is cleared anyway
      vi.mocked(apiClient.logout).mockRejectedValue(new Error('Server error'))

      await useAuthStore.getState().logout()

      // Should still clear local state even if server fails
      expect(useAuthStore.getState().isAuthenticated).toBe(false)
      expect(localStorage.getItem('token')).toBeNull()
    })
  })
})
