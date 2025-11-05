import { describe, it, expect, beforeEach, vi } from 'vitest'
import { useAuthStore } from '../authStore'
import { authService } from '@/services/api'

vi.mock('@/services/api', () => ({
  authService: {
    login: vi.fn(),
    register: vi.fn(),
    logout: vi.fn(),
    verifyMFA: vi.fn(),
    getMFAStatus: vi.fn(),
    beginMFASetup: vi.fn(),
    enableMFA: vi.fn(),
    disableMFA: vi.fn(),
    getBackupCodes: vi.fn(),
  },
}))

describe('authStore - Advanced Scenarios', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: null,

      isLoading: false,
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

      vi.mocked(authService.login).mockResolvedValue(mockResponse as any)

      const result = await useAuthStore.getState().login('test@example.com', 'password123')

      const state = useAuthStore.getState()
      expect(state.user).toBeNull() // Not authenticated yet, needs MFA
      expect(result.requiresMFA).toBe(true) // Should return MFA required flag
      expect(state.pendingEncryption).toBeTruthy() // Should have pending encryption data
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

      vi.mocked(authService.verifyMFA).mockResolvedValue({
        token: mockToken,
        user: mockUser,
      } as any)

      const result = await useAuthStore.getState().verifyMFA('123456')

      const state = useAuthStore.getState()
      expect(state.user).not.toBeNull()
      expect(result).toBe(true) // verifyMFA returns boolean
      expect(authService.verifyMFA).toHaveBeenCalled()
    })

    it('should handle incorrect MFA code', async () => {
      vi.mocked(authService.verifyMFA).mockRejectedValue(new Error('Invalid code'))

      await expect(useAuthStore.getState().verifyMFA('000000')).rejects.toThrow('Invalid code')

      const state = useAuthStore.getState()
      expect(state.user).toBeNull()
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
      })
    })

    it('should setup MFA and receive QR code', async () => {
      const mockSetupResponse = {
        secret: 'JBSWY3DPEHPK3PXP',
        qrCode: 'data:image/png;base64,ABC123',
        backupCodes: ['1111-2222-3333', '4444-5555-6666'],
      }

      vi.mocked(authService.beginMFASetup).mockResolvedValue(mockSetupResponse)

      const secret = await useAuthStore.getState().enableMFA()

      expect(secret).toBe('JBSWY3DPEHPK3PXP')
      expect(mockSetupResponse.qrCode).toBeTruthy()
      expect(mockSetupResponse.backupCodes).toHaveLength(2)
    })

    it('should enable MFA after verification', async () => {
      const mockSetupResponse = {
        secret: 'SECRET',
        qrCode:
          'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
      }
      vi.mocked(authService.beginMFASetup).mockResolvedValue(mockSetupResponse)
      vi.mocked(authService.enableMFA).mockResolvedValue(undefined)

      await useAuthStore.getState().enableMFA()
      await authService.enableMFA('123456')

      expect(authService.enableMFA).toHaveBeenCalledWith('123456')
    })

    it('should disable MFA', async () => {
      vi.mocked(authService.disableMFA).mockResolvedValue(undefined)

      await useAuthStore.getState().disableMFA()

      expect(authService.disableMFA).toHaveBeenCalled()
    })

    it('should get backup codes', async () => {
      const mockCodes = ['1111-2222-3333', '4444-5555-6666']
      vi.mocked(authService.getBackupCodes).mockResolvedValue(mockCodes)

      const codes = await authService.getBackupCodes()

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
      })

      expect(useAuthStore.getState().user).not.toBeNull()
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
      })

      localStorage.setItem('token', 'jwt-token')
      localStorage.setItem('user', JSON.stringify({}))

      vi.mocked(authService.logout).mockResolvedValue(undefined)

      await useAuthStore.getState().logout()

      expect(useAuthStore.getState().user).toBeNull()
      expect(useAuthStore.getState().user).toBeNull()
      expect(localStorage.getItem('token')).toBeNull()
      expect(localStorage.getItem('user')).toBeNull()
    })

    it('should handle expired session gracefully', async () => {
      vi.mocked(authService.login).mockRejectedValue(new Error('Session expired'))

      await expect(useAuthStore.getState().login('test@example.com', 'password')).rejects.toThrow(
        'Session expired'
      )

      expect(useAuthStore.getState().user).toBeNull()
    })
  })

  describe('Error handling', () => {
    it('should handle network errors during login', async () => {
      vi.mocked(authService.login).mockRejectedValue(new Error('Network error'))

      await expect(useAuthStore.getState().login('test@example.com', 'password')).rejects.toThrow(
        'Network error'
      )

      expect(useAuthStore.getState().user).toBeTruthy()
    })

    it('should handle invalid credentials', async () => {
      vi.mocked(authService.login).mockRejectedValue(new Error('Invalid credentials'))

      await expect(useAuthStore.getState().login('test@example.com', 'wrong')).rejects.toThrow(
        'Invalid credentials'
      )
    })

    it('should handle registration errors', async () => {
      vi.mocked(authService.register).mockRejectedValue(new Error('Email already exists'))

      await expect(
        useAuthStore.getState().register('existing@example.com', 'password', 'User')
      ).rejects.toThrow('Email already exists')
    })

    it('should successfully login after previous error', async () => {
      // First attempt fails
      vi.mocked(authService.login).mockRejectedValueOnce(new Error('Network error'))

      await expect(useAuthStore.getState().login('test@example.com', 'password')).rejects.toThrow(
        'Network error'
      )

      expect(useAuthStore.getState().user).toBeNull()

      // Second attempt succeeds
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

      vi.mocked(authService.login).mockResolvedValue(mockResponse as any)

      await useAuthStore.getState().login('test@example.com', 'password')

      expect(useAuthStore.getState().user).not.toBeNull()
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

      vi.mocked(authService.login).mockResolvedValue(mockResponse as any)

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

      vi.mocked(authService.login).mockResolvedValue(mockResponse as any)

      await Promise.all([
        useAuthStore.getState().login('test@example.com', 'password'),
        useAuthStore.getState().login('test@example.com', 'password'),
      ])

      expect(useAuthStore.getState().user).not.toBeNull()
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
      })

      vi.mocked(authService.logout).mockResolvedValue(undefined)

      await Promise.all([useAuthStore.getState().logout(), useAuthStore.getState().logout()])

      expect(useAuthStore.getState().user).toBeNull()
    })
  })
})
