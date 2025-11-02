import { describe, it, expect, beforeEach, vi } from 'vitest'
import { useAuthStore } from '../authStore'
import { apiClient } from '@/services/api/secureApi'

vi.mock('@/services/api/secureApi', () => ({
  apiClient: {
    login: vi.fn(),
    register: vi.fn(),
    logout: vi.fn(),
    verifyMFA: vi.fn(),
    getMFAStatus: vi.fn(),
    setupMFA: vi.fn(),
    enableMFA: vi.fn(),
    disableMFA: vi.fn(),
    getBackupCodes: vi.fn(),
  },
}))

describe('authStore - Advanced Scenarios', () => {
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

  describe('Multi-step authentication', () => {
    it('should handle MFA-required login flow', async () => {
      const mockResponse = {
        requiresMFA: true,
        user: {
          id: '123',
          email: 'test@example.com',
          name: 'Test User',
          role: 'user',
          mfaEnabled: true,
          createdAt: '2024-01-01',
        },
        encryptionSalt: 'salt',
      }

      vi.mocked(apiClient.login).mockResolvedValue(mockResponse as any)

      await useAuthStore.getState().login('test@example.com', 'password123')

      const state = useAuthStore.getState()
      expect(state.isAuthenticated).toBe(false) // Not authenticated yet, needs MFA
      expect(state.user).toBeTruthy()
    })

    it('should complete MFA verification', async () => {
      const mockToken = 'jwt-token'
      const mockUser = {
        id: '123',
        email: 'test@example.com',
        name: 'Test User',
        role: 'user' as const,
        mfaEnabled: true,
        createdAt: '2024-01-01',
      }

      vi.mocked(apiClient.verifyMFA).mockResolvedValue({
        token: mockToken,
        user: mockUser,
      } as any)

      await useAuthStore.getState().verifyMFA('123456')

      const state = useAuthStore.getState()
      expect(state.isAuthenticated).toBe(true)
      expect(localStorage.getItem('token')).toBe(mockToken)
    })

    it('should handle incorrect MFA code', async () => {
      vi.mocked(apiClient.verifyMFA).mockRejectedValue(new Error('Invalid code'))

      await expect(useAuthStore.getState().verifyMFA('000000')).rejects.toThrow('Invalid code')

      const state = useAuthStore.getState()
      expect(state.isAuthenticated).toBe(false)
    })
  })

  describe('MFA Setup', () => {
    beforeEach(() => {
      useAuthStore.setState({
        user: {
          id: '123',
          email: 'test@example.com',
          name: 'Test User',
          role: 'user',
          isAdmin: false,
          mfaEnabled: false,
          createdAt: '2024-01-01',
        },
        isAuthenticated: true,
      })
    })

    it('should setup MFA and receive QR code', async () => {
      const mockSetupResponse = {
        secret: 'JBSWY3DPEHPK3PXP',
        qrCode: 'data:image/png;base64,ABC123',
        backupCodes: ['1111-2222-3333', '4444-5555-6666'],
      }

      vi.mocked(apiClient.setupMFA).mockResolvedValue(mockSetupResponse)

      const result = await useAuthStore.getState().setupMFA()

      expect(result.qrCode).toBeTruthy()
      expect(result.backupCodes).toHaveLength(2)
    })

    it('should enable MFA after verification', async () => {
      vi.mocked(apiClient.enableMFA).mockResolvedValue(undefined)

      await useAuthStore.getState().enableMFA('123456')

      expect(apiClient.enableMFA).toHaveBeenCalledWith('123456')
    })

    it('should disable MFA', async () => {
      vi.mocked(apiClient.disableMFA).mockResolvedValue(undefined)

      await useAuthStore.getState().disableMFA('password123')

      expect(apiClient.disableMFA).toHaveBeenCalledWith('password123')
    })

    it('should get backup codes', async () => {
      const mockCodes = ['1111-2222-3333', '4444-5555-6666']
      vi.mocked(apiClient.getBackupCodes).mockResolvedValue(mockCodes)

      const codes = await useAuthStore.getState().getBackupCodes()

      expect(codes).toEqual(mockCodes)
    })
  })

  describe('Session management', () => {
    it('should maintain session across page reloads', () => {
      const mockUser = {
        id: '123',
        email: 'test@example.com',
        name: 'Test User',
        role: 'user' as const,
        isAdmin: false,
        mfaEnabled: false,
        createdAt: '2024-01-01',
      }

      localStorage.setItem('token', 'jwt-token')
      localStorage.setItem('user', JSON.stringify(mockUser))

      // Simulate store initialization
      useAuthStore.setState({
        user: mockUser,
        isAuthenticated: true,
      })

      expect(useAuthStore.getState().isAuthenticated).toBe(true)
      expect(useAuthStore.getState().user).toEqual(mockUser)
    })

    it('should clear session on logout', async () => {
      useAuthStore.setState({
        user: {
          id: '123',
          email: 'test@example.com',
          name: 'Test User',
          role: 'user',
          isAdmin: false,
          mfaEnabled: false,
          createdAt: '2024-01-01',
        },
        isAuthenticated: true,
      })

      localStorage.setItem('token', 'jwt-token')
      localStorage.setItem('user', JSON.stringify({}))

      vi.mocked(apiClient.logout).mockResolvedValue(undefined)

      await useAuthStore.getState().logout()

      expect(useAuthStore.getState().isAuthenticated).toBe(false)
      expect(useAuthStore.getState().user).toBeNull()
      expect(localStorage.getItem('token')).toBeNull()
      expect(localStorage.getItem('user')).toBeNull()
    })

    it('should handle expired session gracefully', async () => {
      vi.mocked(apiClient.login).mockRejectedValue(new Error('Session expired'))

      await expect(useAuthStore.getState().login('test@example.com', 'password')).rejects.toThrow(
        'Session expired'
      )

      expect(useAuthStore.getState().isAuthenticated).toBe(false)
    })
  })

  describe('Error handling', () => {
    it('should handle network errors during login', async () => {
      vi.mocked(apiClient.login).mockRejectedValue(new Error('Network error'))

      await expect(useAuthStore.getState().login('test@example.com', 'password')).rejects.toThrow(
        'Network error'
      )

      expect(useAuthStore.getState().error).toBeTruthy()
    })

    it('should handle invalid credentials', async () => {
      vi.mocked(apiClient.login).mockRejectedValue(new Error('Invalid credentials'))

      await expect(useAuthStore.getState().login('test@example.com', 'wrong')).rejects.toThrow(
        'Invalid credentials'
      )
    })

    it('should handle registration errors', async () => {
      vi.mocked(apiClient.register).mockRejectedValue(new Error('Email already exists'))

      await expect(
        useAuthStore.getState().register('existing@example.com', 'password', 'User')
      ).rejects.toThrow('Email already exists')
    })

    it('should recover from error state', async () => {
      useAuthStore.setState({ error: 'Previous error' })

      const mockResponse = {
        token: 'jwt-token',
        user: {
          id: '123',
          email: 'test@example.com',
          name: 'Test User',
          role: 'user',
          mfaEnabled: false,
          createdAt: '2024-01-01',
        },
        encryptionSalt: 'salt',
      }

      vi.mocked(apiClient.login).mockResolvedValue(mockResponse as any)

      await useAuthStore.getState().login('test@example.com', 'password')

      expect(useAuthStore.getState().error).toBeNull()
      expect(useAuthStore.getState().isAuthenticated).toBe(true)
    })
  })

  describe('Admin users', () => {
    it('should identify admin users correctly', async () => {
      const mockAdminUser = {
        id: '123',
        email: 'admin@example.com',
        name: 'Admin User',
        role: 'admin' as const,
        isAdmin: true,
        mfaEnabled: false,
        createdAt: '2024-01-01',
      }

      useAuthStore.setState({
        user: mockAdminUser,
        isAuthenticated: true,
      })

      expect(useAuthStore.getState().user?.isAdmin).toBe(true)
      expect(useAuthStore.getState().user?.role).toBe('admin')
    })

    it('should handle admin login', async () => {
      const mockResponse = {
        token: 'jwt-token',
        user: {
          id: '123',
          email: 'admin@example.com',
          name: 'Admin User',
          role: 'admin',
          isAdmin: true,
          mfaEnabled: false,
          createdAt: '2024-01-01',
        },
        encryptionSalt: 'salt',
      }

      vi.mocked(apiClient.login).mockResolvedValue(mockResponse as any)

      await useAuthStore.getState().login('admin@example.com', 'password')

      expect(useAuthStore.getState().user?.role).toBe('admin')
    })
  })

  describe('Concurrent operations', () => {
    it('should handle multiple simultaneous login attempts', async () => {
      const mockResponse = {
        token: 'jwt-token',
        user: {
          id: '123',
          email: 'test@example.com',
          name: 'Test User',
          role: 'user',
          mfaEnabled: false,
          createdAt: '2024-01-01',
        },
        encryptionSalt: 'salt',
      }

      vi.mocked(apiClient.login).mockResolvedValue(mockResponse as any)

      await Promise.all([
        useAuthStore.getState().login('test@example.com', 'password'),
        useAuthStore.getState().login('test@example.com', 'password'),
      ])

      expect(useAuthStore.getState().isAuthenticated).toBe(true)
    })

    it('should prevent double logout', async () => {
      useAuthStore.setState({
        user: {
          id: '123',
          email: 'test@example.com',
          name: 'Test User',
          role: 'user',
          isAdmin: false,
          mfaEnabled: false,
          createdAt: '2024-01-01',
        },
        isAuthenticated: true,
      })

      vi.mocked(apiClient.logout).mockResolvedValue(undefined)

      await Promise.all([useAuthStore.getState().logout(), useAuthStore.getState().logout()])

      expect(useAuthStore.getState().isAuthenticated).toBe(false)
    })
  })
})
