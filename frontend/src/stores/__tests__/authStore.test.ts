import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { useAuthStore } from '../authStore'
import { apiClient } from '@/services/api/secureApi'
import * as encryptionUtils from '@/lib/encryption-utils'

// Mock dependencies
vi.mock('@/services/api/secureApi', () => ({
  apiClient: {
    login: vi.fn(),
    verifyMFA: vi.fn(),
    register: vi.fn(),
    beginMFASetup: vi.fn(),
    disableMFA: vi.fn(),
    logout: vi.fn(),
  },
}))

vi.mock('@/lib/encryption-utils', () => ({
  deriveKey: vi.fn(),
  setStoredKey: vi.fn(),
  setStoredSalt: vi.fn(),
}))

describe('authStore', () => {
  const mockUser = {
    id: '123',
    email: 'test@example.com',
    name: 'Test User',
    role: 'user' as const,
    isAdmin: false,
    mfaEnabled: false,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }

  const mockAdminUser = {
    ...mockUser,
    id: '456',
    email: 'admin@example.com',
    role: 'admin' as const,
    isAdmin: true,
  }

  beforeEach(() => {
    // Clear store state
    useAuthStore.setState({ user: null, isLoading: true, pendingEncryption: null })

    // Clear localStorage
    localStorage.clear()

    // Reset all mocks
    vi.clearAllMocks()

    // Mock console methods to reduce noise
    vi.spyOn(console, 'log').mockImplementation(vi.fn())
    vi.spyOn(console, 'error').mockImplementation(vi.fn())
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('Initial state', () => {
    it('should have correct initial state', () => {
      const state = useAuthStore.getState()
      expect(state.user).toBeNull()
      expect(state.isLoading).toBe(true)
      expect(state.pendingEncryption).toBeNull()
    })

    it('should have all required methods', () => {
      const state = useAuthStore.getState()
      expect(typeof state.initialize).toBe('function')
      expect(typeof state.login).toBe('function')
      expect(typeof state.verifyMFA).toBe('function')
      expect(typeof state.register).toBe('function')
      expect(typeof state.enableMFA).toBe('function')
      expect(typeof state.disableMFA).toBe('function')
      expect(typeof state.logout).toBe('function')
    })
  })

  describe('initialize', () => {
    it('should initialize with no stored user', async () => {
      await useAuthStore.getState().initialize()

      const state = useAuthStore.getState()
      expect(state.user).toBeNull()
      expect(state.isLoading).toBe(false)
    })

    it('should restore user from localStorage', async () => {
      localStorage.setItem('user', JSON.stringify(mockUser))
      localStorage.setItem('token', 'test-token')

      await useAuthStore.getState().initialize()

      const state = useAuthStore.getState()
      expect(state.user).toEqual(mockUser)
      expect(state.isLoading).toBe(false)
    })

    it('should handle invalid stored user data', async () => {
      localStorage.setItem('user', 'invalid-json')
      localStorage.setItem('token', 'test-token')

      await useAuthStore.getState().initialize()

      const state = useAuthStore.getState()
      expect(state.user).toBeNull()
      expect(localStorage.getItem('user')).toBeNull()
      expect(localStorage.getItem('token')).toBeNull()
    })

    it('should clear user if token is missing', async () => {
      localStorage.setItem('user', JSON.stringify(mockUser))

      await useAuthStore.getState().initialize()

      const state = useAuthStore.getState()
      expect(state.user).toBeNull()
      expect(localStorage.getItem('user')).toBeNull()
    })

    it('should clear token if user is missing', async () => {
      localStorage.setItem('token', 'test-token')

      await useAuthStore.getState().initialize()

      const state = useAuthStore.getState()
      expect(state.user).toBeNull()
      expect(localStorage.getItem('token')).toBeNull()
    })
  })

  describe('login', () => {
    it('should login successfully without MFA', async () => {
      const mockResponse = {
        user: mockUser,
        requiresMFA: false,
        token: 'test-token',
        encryptionSalt: 'test-salt-base64',
      }

      vi.mocked(apiClient.login).mockResolvedValue(mockResponse)
      vi.mocked(encryptionUtils.deriveKey).mockResolvedValue('derived-key')

      const result = await useAuthStore.getState().login('test@example.com', 'password123')

      expect(result.requiresMFA).toBe(false)
      expect(useAuthStore.getState().user).toEqual({
        ...mockUser,
        isAdmin: false,
      })
      expect(encryptionUtils.setStoredSalt).toHaveBeenCalledWith('test-salt-base64')
      expect(encryptionUtils.deriveKey).toHaveBeenCalledWith('password123', 'test-salt-base64')
      expect(encryptionUtils.setStoredKey).toHaveBeenCalledWith('derived-key')
      expect(useAuthStore.getState().pendingEncryption).toBeNull()
    })

    it('should login admin user with correct role', async () => {
      const mockResponse = {
        user: mockAdminUser,
        requiresMFA: false,
        token: 'test-token',
        encryptionSalt: 'test-salt-base64',
      }

      vi.mocked(apiClient.login).mockResolvedValue(mockResponse)
      vi.mocked(encryptionUtils.deriveKey).mockResolvedValue('derived-key')

      await useAuthStore.getState().login('admin@example.com', 'password123')

      expect(useAuthStore.getState().user).toEqual({
        ...mockAdminUser,
        isAdmin: true,
      })
    })

    it('should handle MFA required', async () => {
      const mockResponse = {
        user: mockUser,
        requiresMFA: true,
        token: 'test-token',
        encryptionSalt: 'test-salt-base64',
      }

      vi.mocked(apiClient.login).mockResolvedValue(mockResponse)

      const result = await useAuthStore.getState().login('test@example.com', 'password123')

      expect(result.requiresMFA).toBe(true)
      expect(useAuthStore.getState().user).toBeNull()
      expect(useAuthStore.getState().pendingEncryption).toEqual({
        password: 'password123',
        salt: 'test-salt-base64',
      })
      expect(encryptionUtils.setStoredSalt).toHaveBeenCalledWith('test-salt-base64')
      expect(encryptionUtils.deriveKey).not.toHaveBeenCalled()
    })

    it('should handle login without encryption salt', async () => {
      const mockResponse = {
        user: mockUser,
        requiresMFA: false,
        token: 'test-token',
        encryptionSalt: undefined,
      }

      vi.mocked(apiClient.login).mockResolvedValue(mockResponse)

      await useAuthStore.getState().login('test@example.com', 'password123')

      expect(useAuthStore.getState().user).toEqual({
        ...mockUser,
        isAdmin: false,
      })
      expect(encryptionUtils.setStoredSalt).not.toHaveBeenCalled()
      expect(encryptionUtils.deriveKey).not.toHaveBeenCalled()
    })

    it('should handle encryption key derivation failure', async () => {
      const mockResponse = {
        user: mockUser,
        requiresMFA: false,
        token: 'test-token',
        encryptionSalt: 'test-salt-base64',
      }

      vi.mocked(apiClient.login).mockResolvedValue(mockResponse)
      vi.mocked(encryptionUtils.deriveKey).mockRejectedValue(new Error('Derivation failed'))

      await useAuthStore.getState().login('test@example.com', 'password123')

      expect(useAuthStore.getState().user).toEqual({
        ...mockUser,
        isAdmin: false,
      })
      expect(encryptionUtils.setStoredKey).toHaveBeenCalledWith(null)
    })

    it('should handle login API failure', async () => {
      vi.mocked(apiClient.login).mockRejectedValue(new Error('Invalid credentials'))

      await expect(
        useAuthStore.getState().login('test@example.com', 'wrong-password')
      ).rejects.toThrow('Invalid credentials')

      expect(useAuthStore.getState().user).toBeNull()
    })
  })

  describe('verifyMFA', () => {
    beforeEach(() => {
      // Set up pending encryption state
      useAuthStore.setState({
        pendingEncryption: {
          password: 'password123',
          salt: 'test-salt-base64',
        },
      })
    })

    it('should verify MFA successfully', async () => {
      const mockResponse = {
        user: mockUser,
        token: 'test-token',
        encryptionSalt: 'test-salt-base64',
      }

      vi.mocked(apiClient.verifyMFA).mockResolvedValue(mockResponse)
      vi.mocked(encryptionUtils.deriveKey).mockResolvedValue('derived-key')

      const result = await useAuthStore.getState().verifyMFA('123456')

      expect(result).toBe(true)
      expect(useAuthStore.getState().user).toEqual({
        ...mockUser,
        isAdmin: false,
      })
      expect(encryptionUtils.setStoredSalt).toHaveBeenCalledWith('test-salt-base64')
      expect(encryptionUtils.deriveKey).toHaveBeenCalledWith('password123', 'test-salt-base64')
      expect(encryptionUtils.setStoredKey).toHaveBeenCalledWith('derived-key')
      expect(useAuthStore.getState().pendingEncryption).toBeNull()
    })

    it('should use pending salt if response salt is missing', async () => {
      const mockResponse = {
        user: mockUser,
        token: 'test-token',
        encryptionSalt: undefined,
      }

      vi.mocked(apiClient.verifyMFA).mockResolvedValue(mockResponse)
      vi.mocked(encryptionUtils.deriveKey).mockResolvedValue('derived-key')

      await useAuthStore.getState().verifyMFA('123456')

      expect(encryptionUtils.deriveKey).toHaveBeenCalledWith('password123', 'test-salt-base64')
    })

    it('should handle MFA verification failure', async () => {
      vi.mocked(apiClient.verifyMFA).mockRejectedValue(new Error('Invalid MFA code'))

      const result = await useAuthStore.getState().verifyMFA('wrong-code')

      expect(result).toBe(false)
      expect(useAuthStore.getState().user).toBeNull()
    })

    it('should handle encryption key derivation failure', async () => {
      const mockResponse = {
        user: mockUser,
        token: 'test-token',
        encryptionSalt: 'test-salt-base64',
      }

      vi.mocked(apiClient.verifyMFA).mockResolvedValue(mockResponse)
      vi.mocked(encryptionUtils.deriveKey).mockRejectedValue(new Error('Derivation failed'))

      const result = await useAuthStore.getState().verifyMFA('123456')

      expect(result).toBe(true)
      expect(encryptionUtils.setStoredKey).toHaveBeenCalledWith(null)
    })
  })

  describe('register', () => {
    it('should register successfully', async () => {
      const mockResponse = {
        user: mockUser,
        token: 'test-token',
        encryptionSalt: 'test-salt-base64',
      }

      vi.mocked(apiClient.register).mockResolvedValue(mockResponse)
      vi.mocked(encryptionUtils.deriveKey).mockResolvedValue('derived-key')

      await useAuthStore.getState().register('test@example.com', 'password123', 'Test User')

      expect(useAuthStore.getState().user).toEqual({
        ...mockUser,
        isAdmin: false,
      })
      expect(encryptionUtils.setStoredSalt).toHaveBeenCalledWith('test-salt-base64')
      expect(encryptionUtils.deriveKey).toHaveBeenCalledWith('password123', 'test-salt-base64')
      expect(encryptionUtils.setStoredKey).toHaveBeenCalledWith('derived-key')
      expect(useAuthStore.getState().pendingEncryption).toBeNull()
    })

    it('should handle registration without encryption salt', async () => {
      const mockResponse = {
        user: mockUser,
        token: 'test-token',
        encryptionSalt: undefined,
      }

      vi.mocked(apiClient.register).mockResolvedValue(mockResponse)

      await useAuthStore.getState().register('test@example.com', 'password123', 'Test User')

      expect(useAuthStore.getState().user).toEqual({
        ...mockUser,
        isAdmin: false,
      })
      expect(encryptionUtils.setStoredSalt).not.toHaveBeenCalled()
      expect(encryptionUtils.deriveKey).not.toHaveBeenCalled()
    })

    it('should handle encryption key derivation failure', async () => {
      const mockResponse = {
        user: mockUser,
        token: 'test-token',
        encryptionSalt: 'test-salt-base64',
      }

      vi.mocked(apiClient.register).mockResolvedValue(mockResponse)
      vi.mocked(encryptionUtils.deriveKey).mockRejectedValue(new Error('Derivation failed'))

      await useAuthStore.getState().register('test@example.com', 'password123', 'Test User')

      expect(encryptionUtils.setStoredKey).toHaveBeenCalledWith(null)
    })

    it('should handle registration API failure', async () => {
      vi.mocked(apiClient.register).mockRejectedValue(new Error('Email already exists'))

      await expect(
        useAuthStore.getState().register('test@example.com', 'password123', 'Test User')
      ).rejects.toThrow('Email already exists')

      expect(useAuthStore.getState().user).toBeNull()
    })
  })

  describe('enableMFA', () => {
    it('should enable MFA successfully', async () => {
      useAuthStore.setState({ user: mockUser })
      vi.mocked(apiClient.beginMFASetup).mockResolvedValue({
        secret: 'JBSWY3DPEHPK3PXP',
        qrCode:
          'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
      })

      const secret = await useAuthStore.getState().enableMFA()

      expect(secret).toBe('JBSWY3DPEHPK3PXP')
      expect(apiClient.beginMFASetup).toHaveBeenCalled()
    })

    it('should throw error if no user is logged in', async () => {
      useAuthStore.setState({ user: null })

      await expect(useAuthStore.getState().enableMFA()).rejects.toThrow('No user logged in')
    })

    it('should handle API failure', async () => {
      useAuthStore.setState({ user: mockUser })
      vi.mocked(apiClient.beginMFASetup).mockRejectedValue(new Error('MFA setup failed'))

      await expect(useAuthStore.getState().enableMFA()).rejects.toThrow('MFA setup failed')
    })
  })

  describe('disableMFA', () => {
    it('should disable MFA successfully', async () => {
      useAuthStore.setState({ user: { ...mockUser, mfaEnabled: true } })
      vi.mocked(apiClient.disableMFA).mockResolvedValue(undefined)

      await useAuthStore.getState().disableMFA()

      expect(apiClient.disableMFA).toHaveBeenCalled()
    })

    it('should throw error if no user is logged in', async () => {
      useAuthStore.setState({ user: null })

      await expect(useAuthStore.getState().disableMFA()).rejects.toThrow('No user logged in')
    })

    it('should handle API failure', async () => {
      useAuthStore.setState({ user: mockUser })
      vi.mocked(apiClient.disableMFA).mockRejectedValue(new Error('MFA disable failed'))

      await expect(useAuthStore.getState().disableMFA()).rejects.toThrow('MFA disable failed')
    })
  })

  describe('logout', () => {
    it('should logout successfully', () => {
      useAuthStore.setState({
        user: mockUser,
        pendingEncryption: { password: 'test', salt: 'salt' },
      })

      useAuthStore.getState().logout()

      expect(apiClient.logout).toHaveBeenCalled()
      expect(useAuthStore.getState().user).toBeNull()
      expect(useAuthStore.getState().pendingEncryption).toBeNull()
      expect(encryptionUtils.setStoredKey).toHaveBeenCalledWith(null)
    })

    it('should logout when no user is logged in', () => {
      useAuthStore.setState({ user: null })

      useAuthStore.getState().logout()

      expect(apiClient.logout).toHaveBeenCalled()
      expect(useAuthStore.getState().user).toBeNull()
    })
  })
})
