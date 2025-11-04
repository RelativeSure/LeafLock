import { describe, it, expect, beforeEach, vi } from 'vitest'

vi.mock('@/lib/config', () => ({
  config: {
    apiUrl: 'http://localhost:8080/api/v1',
  },
}))

vi.mock('@/lib/navigation', () => ({
  clearAuthStorage: vi.fn(),
  safeRedirectToLogin: vi.fn(),
  isOnAuthRoute: vi.fn(),
}))

const setupAuthService = async () => {
  const module = await import('../authService')
  const requestSpy = vi.spyOn(module.authService as any, 'request')
  return { authService: module.authService, requestSpy }
}

describe('authService', () => {
  const mockToken = 'test-jwt-token'

  beforeEach(() => {
    localStorage.clear()
    vi.clearAllMocks()
  })

  describe('login', () => {
    it('logs in successfully and stores token', async () => {
      const { authService, requestSpy } = await setupAuthService()
      const mockResponse = {
        token: mockToken,
        user_id: '123',
        is_admin: false,
        mfa_required: false,
        encryption_salt: 'test-salt',
        encryption_version: 1,
      }

      requestSpy.mockResolvedValue(mockResponse)

      const result = await authService.login('test@example.com', 'password123')

      expect(requestSpy).toHaveBeenCalledWith(
        '/auth/login',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ email: 'test@example.com', password: 'password123' }),
        })
      )

      expect(result.token).toBe(mockToken)
      expect(result.user.email).toBe('test@example.com')
      expect(localStorage.getItem('token')).toBe(mockToken)
      expect(localStorage.getItem('user')).toContain('test@example.com')
    })

    it('handles MFA required login flow', async () => {
      vi.resetModules()
      const { authService, requestSpy } = await setupAuthService()
      const mockResponse = {
        requires_mfa: true,
        user_id: '123',
        is_admin: false,
        mfa_required: true,
        encryption_salt: 'test-salt',
        encryption_version: 1,
      }

      requestSpy.mockResolvedValue(mockResponse)

      const result = await authService.login('test@example.com', 'password123')

      expect(result).toMatchObject({ requires_mfa: true, encryption_salt: 'test-salt' })
    })

    it('propagates login errors', async () => {
      const { authService, requestSpy } = await setupAuthService()
      requestSpy.mockRejectedValue(new Error('Invalid credentials'))

      await expect(authService.login('test@example.com', 'wrong-password')).rejects.toThrow(
        'Invalid credentials'
      )
    })

    it('propagates network errors', async () => {
      const { authService, requestSpy } = await setupAuthService()
      requestSpy.mockRejectedValue(new Error('Network error'))

      await expect(authService.login('test@example.com', 'password123')).rejects.toThrow(
        'Network error'
      )
    })
  })

  describe('register', () => {
    it('returns success message', async () => {
      const { authService, requestSpy } = await setupAuthService()
      requestSpy.mockResolvedValue({ message: 'Registration request accepted' })

      const result = await authService.register('new@example.com', 'password123', 'New User')

      expect(requestSpy).toHaveBeenCalledWith(
        '/auth/register',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            email: 'new@example.com',
            password: 'password123',
            name: 'New User',
          }),
        })
      )
      expect(result.message).toBe('Registration request accepted')
    })

    it('propagates registration errors', async () => {
      const { authService, requestSpy } = await setupAuthService()
      requestSpy.mockRejectedValue(new Error('Password too weak'))

      await expect(
        authService.register('existing@example.com', 'password123', 'Test User')
      ).rejects.toThrow('Password too weak')
    })
  })

  describe('verifyMFA', () => {
    it('verifies MFA and stores updated user', async () => {
      const { authService, requestSpy } = await setupAuthService()
      const mockResponse = {
        token: mockToken,
        user_id: '123',
        is_admin: true,
        encryption_salt: 'salt',
        encryption_version: 2,
      }

      localStorage.setItem(
        'user',
        JSON.stringify({
          id: '123',
          email: 'test@example.com',
          name: 'Test User',
          createdAt: '2024-01-01T00:00:00Z',
        })
      )

      requestSpy.mockResolvedValue(mockResponse)

      const result = await authService.verifyMFA('123456')

      expect(requestSpy).toHaveBeenCalledWith(
        '/auth/mfa/verify',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ code: '123456' }),
        })
      )
      expect(result.token).toBe(mockToken)
      expect(result.user.mfaEnabled).toBe(true)
      expect(localStorage.getItem('token')).toBe(mockToken)
      expect(localStorage.getItem('user')).toContain('"email":"test@example.com"')
    })
  })

  describe('logout', () => {
    it('clears token and user data', async () => {
      localStorage.setItem('token', mockToken)
      localStorage.setItem('user', JSON.stringify({ id: '123', email: 'test@example.com' }))

      const { authService } = await setupAuthService()
      authService.logout()

      expect(localStorage.getItem('token')).toBeNull()
      expect(localStorage.getItem('user')).toBeNull()
    })
  })

  describe('MFA utilities', () => {
    it('fetches MFA status', async () => {
      const { authService, requestSpy } = await setupAuthService()
      requestSpy.mockResolvedValue({ enabled: true, backupCodes: ['code'] })

      const result = await authService.getMFAStatus()

      expect(requestSpy).toHaveBeenCalledWith('/auth/mfa/status')
      expect(result.enabled).toBe(true)
    })

    it('begins MFA setup and returns secret', async () => {
      const { authService, requestSpy } = await setupAuthService()
      requestSpy.mockResolvedValue({ secret: 'secret', qrCode: 'qr' })

      const result = await authService.beginMFASetup()

      expect(requestSpy).toHaveBeenCalledWith(
        '/auth/mfa/begin',
        expect.objectContaining({ method: 'POST' })
      )
      expect(result.secret).toBe('secret')
    })

    it('enables MFA by posting code', async () => {
      const { authService, requestSpy } = await setupAuthService()
      requestSpy.mockResolvedValue({})

      await authService.enableMFA('123456')

      expect(requestSpy).toHaveBeenCalledWith(
        '/auth/mfa/enable',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ code: '123456' }),
        })
      )
    })

    it('disables MFA', async () => {
      const { authService, requestSpy } = await setupAuthService()
      requestSpy.mockResolvedValue({})

      await authService.disableMFA()

      expect(requestSpy).toHaveBeenCalledWith(
        '/auth/mfa/disable',
        expect.objectContaining({ method: 'POST' })
      )
    })

    it('retrieves backup codes', async () => {
      const { authService, requestSpy } = await setupAuthService()
      requestSpy.mockResolvedValue({ backupCodes: ['123'] })

      const codes = await authService.getBackupCodes()

      expect(codes).toEqual(['123'])
    })

    it('regenerates backup codes', async () => {
      const { authService, requestSpy } = await setupAuthService()
      requestSpy.mockResolvedValue({ backupCodes: ['456'] })

      const codes = await authService.regenerateBackupCodes()

      expect(requestSpy).toHaveBeenCalledWith(
        '/auth/mfa/backup-codes/regenerate',
        expect.objectContaining({ method: 'POST' })
      )
      expect(codes).toEqual(['456'])
    })
  })

  describe('Account utilities', () => {
    it('requests password reset', async () => {
      const { authService, requestSpy } = await setupAuthService()
      requestSpy.mockResolvedValue({})

      await authService.requestPasswordReset('reset@example.com')

      expect(requestSpy).toHaveBeenCalledWith(
        '/auth/password/reset-request',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ email: 'reset@example.com' }),
        })
      )
    })

    it('checks if registration is enabled', async () => {
      const { authService, requestSpy } = await setupAuthService()
      requestSpy.mockResolvedValue({ enabled: true })

      const enabled = await authService.isRegistrationEnabled()

      expect(enabled).toBe(true)
    })
  })
})
