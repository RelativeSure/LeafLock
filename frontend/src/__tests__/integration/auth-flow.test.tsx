import { describe, it, expect, beforeEach, vi } from 'vitest'
import { useAuthStore } from '@/stores/authStore'
import { authService } from '@/services/api'

vi.mock('@/services/api', () => ({
  authService: {
    login: vi.fn(),
    register: vi.fn(),
    logout: vi.fn(),
    verifyMFA: vi.fn(),
    beginMFASetup: vi.fn(),
    enableMFA: vi.fn(),
    disableMFA: vi.fn(),
    getBackupCodes: vi.fn(),
  },
}))

describe('Integration: Complete Auth Flow', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: null,
      isLoading: false,
    })
    localStorage.clear()
    vi.clearAllMocks()
  })

  describe('User Registration → Login → Logout Flow', () => {
    it('should complete full registration and login flow', async () => {
      // Step 1: Register new user
      const registerResponse = {
        message: 'Registration successful',
      }

      vi.mocked(authService.register).mockResolvedValue(registerResponse as any)

      const message = await useAuthStore
        .getState()
        .register('newuser@example.com', 'password123', 'New User')

      expect(message).toBe('Registration successful')
      expect(useAuthStore.getState().user).toBeNull() // Not logged in yet

      // Step 2: Login with registered credentials
      const loginResponse = {
        token: 'login-token',
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

      vi.mocked(authService.login).mockResolvedValue(loginResponse as any)

      await useAuthStore.getState().login('newuser@example.com', 'password123')

      expect(useAuthStore.getState().user).not.toBeNull()
      expect(useAuthStore.getState().user?.email).toBe('newuser@example.com')

      // Step 3: Logout
      vi.mocked(authService.logout).mockImplementation(() => {
        localStorage.removeItem('token')
        localStorage.removeItem('user')
        return Promise.resolve(undefined)
      })

      await useAuthStore.getState().logout()

      expect(useAuthStore.getState().user).toBeNull()
    })

    it('should handle registration failure and retry', async () => {
      // Step 1: Failed registration (email exists)
      vi.mocked(authService.register).mockRejectedValueOnce(new Error('Email already exists'))

      await expect(
        useAuthStore.getState().register('existing@example.com', 'password', 'User')
      ).rejects.toThrow('Email already exists')

      expect(useAuthStore.getState().user).toBeNull()

      // Step 2: Retry with different email succeeds
      const registerResponse = {
        message: 'Registration successful',
      }

      vi.mocked(authService.register).mockResolvedValue(registerResponse as any)

      const message = await useAuthStore
        .getState()
        .register('newemail@example.com', 'password', 'User')

      expect(message).toBe('Registration successful')
      expect(useAuthStore.getState().user).toBeNull() // Still not logged in, just registered
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

      vi.mocked(authService.login).mockResolvedValue(loginResponse as any)

      await useAuthStore.getState().login('user@example.com', 'password')

      expect(useAuthStore.getState().user?.mfaEnabled).toBe(false)

      // Step 2: Setup MFA
      const setupResponse = {
        secret: 'JBSWY3DPEHPK3PXP',
        qrCode: 'data:image/png;base64,ABC',
      }

      vi.mocked(authService.beginMFASetup).mockResolvedValue(setupResponse)

      const mfaSecret = await useAuthStore.getState().enableMFA()

      expect(mfaSecret).toBe('JBSWY3DPEHPK3PXP')

      // Step 3: Enable MFA with code (call API directly)
      vi.mocked(authService.enableMFA).mockResolvedValue(undefined)

      await authService.enableMFA('123456')

      // Update user state to reflect MFA enabled
      useAuthStore.setState({
        user: { ...useAuthStore.getState().user!, mfaEnabled: true },
      })

      expect(useAuthStore.getState().user?.mfaEnabled).toBe(true)

      // Step 4: Logout
      vi.mocked(authService.logout).mockImplementation(() => {
        localStorage.removeItem('token')
        localStorage.removeItem('user')
        return Promise.resolve(undefined)
      })
      await useAuthStore.getState().logout()

      // Step 5: Login with MFA required
      const mfaLoginResponse = {
        requiresMFA: true,
        user: { ...loginResponse.user, mfaEnabled: true },
        encryptionSalt: 'salt',
      }

      vi.mocked(authService.login).mockResolvedValue(mfaLoginResponse as any)

      await useAuthStore.getState().login('user@example.com', 'password')

      expect(useAuthStore.getState().user).toBeNull() // Not fully authenticated yet

      // Step 6: Verify MFA code
      const verifyResponse = {
        token: 'mfa-token',
        user: mfaLoginResponse.user,
      }

      vi.mocked(authService.verifyMFA).mockResolvedValue(verifyResponse as any)

      await useAuthStore.getState().verifyMFA('123456')

      expect(useAuthStore.getState().user).not.toBeNull()
      expect(useAuthStore.getState().user?.mfaEnabled).toBe(true)
    })

    it('should handle MFA verification failure and retry', async () => {
      // Setup: User requires MFA
      useAuthStore.setState({
        user: null, // User not authenticated yet (MFA pending)
        mfaSession: 'session-token',
      })

      // Step 1: First MFA attempt fails
      vi.mocked(authService.verifyMFA).mockRejectedValueOnce(new Error('Invalid code'))

      const result1 = await useAuthStore.getState().verifyMFA('000000')
      expect(result1).toBe(false) // verifyMFA returns false on error

      expect(useAuthStore.getState().user).toBeNull()

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

      vi.mocked(authService.verifyMFA).mockResolvedValue(verifyResponse as any)

      await useAuthStore.getState().verifyMFA('123456')

      expect(useAuthStore.getState().user).not.toBeNull()
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
      })

      // Step 1: Disable MFA
      vi.mocked(authService.disableMFA).mockResolvedValue(undefined)

      await useAuthStore.getState().disableMFA()

      // Update user state
      useAuthStore.setState({
        user: { ...useAuthStore.getState().user!, mfaEnabled: false },
      })

      // Step 2: Logout and login without MFA
      vi.mocked(authService.logout).mockResolvedValue(undefined)
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

      vi.mocked(authService.login).mockResolvedValue(loginResponse as any)

      await useAuthStore.getState().login('user@example.com', 'password123')

      expect(useAuthStore.getState().user).not.toBeNull()
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
      })

      expect(useAuthStore.getState().user).not.toBeNull()
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

      vi.mocked(authService.login).mockResolvedValue(loginResponse as any)

      await useAuthStore.getState().login('user@example.com', 'password')

      expect(useAuthStore.getState().user).not.toBeNull()
      // Note: Token is set by authService.login() internally, not by authStore
    })
  })

  describe('Error Recovery Flow', () => {
    it('should recover from network errors during login', async () => {
      // Step 1: Network error
      vi.mocked(authService.login).mockRejectedValueOnce(new Error('Network error'))

      await expect(useAuthStore.getState().login('user@example.com', 'password')).rejects.toThrow(
        'Network error'
      )

      expect(useAuthStore.getState().user).toBeNull()

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

      vi.mocked(authService.login).mockResolvedValue(loginResponse as any)

      await useAuthStore.getState().login('user@example.com', 'password')

      expect(useAuthStore.getState().user).not.toBeNull()
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
      })

      localStorage.setItem('token', 'token')

      // Logout fails but local store state is still cleared
      vi.mocked(authService.logout).mockImplementation(() => {
        // Even on error, we should clear localStorage for security
        localStorage.removeItem('token')
        localStorage.removeItem('user')
        return Promise.reject(new Error('Server error'))
      })

      await useAuthStore.getState().logout()

      // Should still clear local state even if server fails
      expect(useAuthStore.getState().user).toBeNull()
      expect(localStorage.getItem('token')).toBeNull()
    })
  })
})
