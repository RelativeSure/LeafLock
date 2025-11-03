import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { useAuthStore } from '../authStore'
import { authService } from '@/services/api'
import * as encryptionUtils from '@/lib/encryption-utils'

// Mock dependencies
vi.mock('@/services/api', () => ({
  authService: {
    login: vi.fn(),
    verifyMFA: vi.fn(),
    register: vi.fn(),
    beginMFASetup: vi.fn(),
    disableMFA: vi.fn(),
    logout: vi.fn(),
    isRegistrationEnabled: vi.fn(),
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

      vi.mocked(authService.login).mockResolvedValue(mockResponse)
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

      vi.mocked(authService.login).mockResolvedValue(mockResponse)
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

      vi.mocked(authService.login).mockResolvedValue(mockResponse)

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

      vi.mocked(authService.login).mockResolvedValue(mockResponse)

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

      vi.mocked(authService.login).mockResolvedValue(mockResponse)
      vi.mocked(encryptionUtils.deriveKey).mockRejectedValue(new Error('Derivation failed'))

      await useAuthStore.getState().login('test@example.com', 'password123')

      expect(useAuthStore.getState().user).toEqual({
        ...mockUser,
        isAdmin: false,
      })
      expect(encryptionUtils.setStoredKey).toHaveBeenCalledWith(null)
    })

    it('should handle login API failure', async () => {
      vi.mocked(authService.login).mockRejectedValue(new Error('Invalid credentials'))

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

      vi.mocked(authService.verifyMFA).mockResolvedValue(mockResponse)
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

      vi.mocked(authService.verifyMFA).mockResolvedValue(mockResponse)
      vi.mocked(encryptionUtils.deriveKey).mockResolvedValue('derived-key')

      await useAuthStore.getState().verifyMFA('123456')

      expect(encryptionUtils.deriveKey).toHaveBeenCalledWith('password123', 'test-salt-base64')
    })

    it('should handle MFA verification failure', async () => {
      vi.mocked(authService.verifyMFA).mockRejectedValue(new Error('Invalid MFA code'))

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

      vi.mocked(authService.verifyMFA).mockResolvedValue(mockResponse)
      vi.mocked(encryptionUtils.deriveKey).mockRejectedValue(new Error('Derivation failed'))

      const result = await useAuthStore.getState().verifyMFA('123456')

      expect(result).toBe(true)
      expect(encryptionUtils.setStoredKey).toHaveBeenCalledWith(null)
    })
  })

  describe('register', () => {
    it('should register successfully and return message', async () => {
      vi.mocked(authService.register).mockResolvedValue({ message: 'Registration accepted' })

      const message = await useAuthStore
        .getState()
        .register('test@example.com', 'password123', 'Test User')

      expect(message).toBe('Registration accepted')
      expect(useAuthStore.getState().user).toBeNull()
      expect(encryptionUtils.setStoredSalt).not.toHaveBeenCalled()
      expect(encryptionUtils.deriveKey).not.toHaveBeenCalled()
      expect(encryptionUtils.setStoredKey).not.toHaveBeenCalled()
      expect(useAuthStore.getState().pendingEncryption).toBeNull()
    })

    it('should handle registration API failure', async () => {
      vi.mocked(authService.register).mockRejectedValue(new Error('Email already exists'))

      await expect(
        useAuthStore.getState().register('test@example.com', 'password123', 'Test User')
      ).rejects.toThrow('Email already exists')

      expect(useAuthStore.getState().user).toBeNull()
    })
  })

  describe('enableMFA', () => {
    it('should enable MFA successfully', async () => {
      useAuthStore.setState({ user: mockUser })
      vi.mocked(authService.beginMFASetup).mockResolvedValue({
        secret: 'JBSWY3DPEHPK3PXP',
        qrCode:
          'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
      })

      const secret = await useAuthStore.getState().enableMFA()

      expect(secret).toBe('JBSWY3DPEHPK3PXP')
      expect(authService.beginMFASetup).toHaveBeenCalled()
    })

    it('should throw error if no user is logged in', async () => {
      useAuthStore.setState({ user: null })

      await expect(useAuthStore.getState().enableMFA()).rejects.toThrow('No user logged in')
    })

    it('should handle API failure', async () => {
      useAuthStore.setState({ user: mockUser })
      vi.mocked(authService.beginMFASetup).mockRejectedValue(new Error('MFA setup failed'))

      await expect(useAuthStore.getState().enableMFA()).rejects.toThrow('MFA setup failed')
    })
  })

  describe('disableMFA', () => {
    it('should disable MFA successfully', async () => {
      useAuthStore.setState({ user: { ...mockUser, mfaEnabled: true } })
      vi.mocked(authService.disableMFA).mockResolvedValue(undefined)

      await useAuthStore.getState().disableMFA()

      expect(authService.disableMFA).toHaveBeenCalled()
    })

    it('should throw error if no user is logged in', async () => {
      useAuthStore.setState({ user: null })

      await expect(useAuthStore.getState().disableMFA()).rejects.toThrow('No user logged in')
    })

    it('should handle API failure', async () => {
      useAuthStore.setState({ user: mockUser })
      vi.mocked(authService.disableMFA).mockRejectedValue(new Error('MFA disable failed'))

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

      expect(authService.logout).toHaveBeenCalled()
      expect(useAuthStore.getState().user).toBeNull()
      expect(useAuthStore.getState().pendingEncryption).toBeNull()
      expect(encryptionUtils.setStoredKey).toHaveBeenCalledWith(null)
    })

    it('should logout when no user is logged in', () => {
      useAuthStore.setState({ user: null })

      useAuthStore.getState().logout()

      expect(authService.logout).toHaveBeenCalled()
      expect(useAuthStore.getState().user).toBeNull()
    })
  })

  describe('checkRegistrationEnabled', () => {
    beforeEach(() => {
      // Reset registration status in store
      useAuthStore.setState({ registrationEnabled: null })
    })

    it('should check registration status and return true when enabled', async () => {
      vi.mocked(authService.isRegistrationEnabled).mockResolvedValue(true)

      const result = await useAuthStore.getState().checkRegistrationEnabled()

      expect(result).toBe(true)
      expect(authService.isRegistrationEnabled).toHaveBeenCalledTimes(1)
      expect(useAuthStore.getState().registrationEnabled).toBe(true)
    })

    it('should check registration status and return false when disabled', async () => {
      vi.mocked(authService.isRegistrationEnabled).mockResolvedValue(false)

      const result = await useAuthStore.getState().checkRegistrationEnabled()

      expect(result).toBe(false)
      expect(authService.isRegistrationEnabled).toHaveBeenCalledTimes(1)
      expect(useAuthStore.getState().registrationEnabled).toBe(false)
    })

    it('should return cached value on subsequent calls without calling API', async () => {
      vi.mocked(authService.isRegistrationEnabled).mockResolvedValue(true)

      // First call
      const result1 = await useAuthStore.getState().checkRegistrationEnabled()
      expect(result1).toBe(true)
      expect(authService.isRegistrationEnabled).toHaveBeenCalledTimes(1)

      // Second call - should use cached value
      const result2 = await useAuthStore.getState().checkRegistrationEnabled()
      expect(result2).toBe(true)
      expect(authService.isRegistrationEnabled).toHaveBeenCalledTimes(1) // Still 1, not 2

      // Third call - should still use cached value
      const result3 = await useAuthStore.getState().checkRegistrationEnabled()
      expect(result3).toBe(true)
      expect(authService.isRegistrationEnabled).toHaveBeenCalledTimes(1) // Still 1, not 3
    })

    it('should cache false value and return it on subsequent calls', async () => {
      vi.mocked(authService.isRegistrationEnabled).mockResolvedValue(false)

      // First call
      const result1 = await useAuthStore.getState().checkRegistrationEnabled()
      expect(result1).toBe(false)

      // Second call - should use cached value
      const result2 = await useAuthStore.getState().checkRegistrationEnabled()
      expect(result2).toBe(false)
      expect(authService.isRegistrationEnabled).toHaveBeenCalledTimes(1)
    })

    it('should return false and cache it when API call fails', async () => {
      const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(vi.fn())
      vi.mocked(authService.isRegistrationEnabled).mockRejectedValue(new Error('Network error'))

      const result = await useAuthStore.getState().checkRegistrationEnabled()

      expect(result).toBe(false)
      expect(useAuthStore.getState().registrationEnabled).toBe(false)
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        'Failed to check registration status:',
        expect.any(Error)
      )

      consoleErrorSpy.mockRestore()
    })

    it('should return cached false value after API error without retrying', async () => {
      const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(vi.fn())
      vi.mocked(authService.isRegistrationEnabled).mockRejectedValue(new Error('Network error'))

      // First call - API fails
      const result1 = await useAuthStore.getState().checkRegistrationEnabled()
      expect(result1).toBe(false)
      expect(authService.isRegistrationEnabled).toHaveBeenCalledTimes(1)

      // Second call - should use cached false value
      const result2 = await useAuthStore.getState().checkRegistrationEnabled()
      expect(result2).toBe(false)
      expect(authService.isRegistrationEnabled).toHaveBeenCalledTimes(1) // No retry

      consoleErrorSpy.mockRestore()
    })

    it('should have correct initial state for registrationEnabled', () => {
      const state = useAuthStore.getState()
      expect(state.registrationEnabled).toBeNull()
    })

    it('should update store state when registration status changes', async () => {
      // Initially null
      expect(useAuthStore.getState().registrationEnabled).toBeNull()

      // Set to true
      vi.mocked(authService.isRegistrationEnabled).mockResolvedValue(true)
      await useAuthStore.getState().checkRegistrationEnabled()
      expect(useAuthStore.getState().registrationEnabled).toBe(true)

      // Manually reset cache to simulate app restart
      useAuthStore.setState({ registrationEnabled: null })

      // Set to false
      vi.mocked(authService.isRegistrationEnabled).mockResolvedValue(false)
      await useAuthStore.getState().checkRegistrationEnabled()
      expect(useAuthStore.getState().registrationEnabled).toBe(false)
    })
  })
})
