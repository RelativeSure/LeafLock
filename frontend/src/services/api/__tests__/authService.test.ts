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

describe('authService (Clerk-compatible)', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.clearAllMocks()
  })

  describe('registration', () => {
    it('should register user successfully', async () => {
      const { authService, requestSpy } = await setupAuthService()

      const mockResponse = {
        message: 'Registration request accepted. Check your email for verification.',
      }

      requestSpy.mockResolvedValue(mockResponse)

      const result = await authService.register('test@example.com', 'password123', 'Test User')

      expect(requestSpy).toHaveBeenCalledWith(
        '/auth/register',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ 
            email: 'test@example.com', 
            password: 'password123', 
            name: 'Test User' 
          }),
        })
      )

      expect(result.message).toContain('Registration request accepted')
    })

    it('should handle registration errors gracefully', async () => {
      const { authService, requestSpy } = await setupAuthService()

      requestSpy.mockRejectedValue(new Error('Email already registered'))

      await expect(
        authService.register('existing@example.com', 'password123', 'Test User')
      ).rejects.toThrow('Email already registered')
    })

    it('should provide default message when response is empty', async () => {
      const { authService, requestSpy } = await setupAuthService()

      requestSpy.mockResolvedValue({})

      const result = await authService.register('test@example.com', 'password123', 'Test User')

      expect(result.message).toBe('Registration request accepted. If this email is eligible, you will receive further instructions shortly.')
    })
  })

  describe('MFA functionality', () => {
    it('should get MFA status successfully', async () => {
      const { authService, requestSpy } = await setupAuthService()

      const mockResponse = { enabled: false }
      requestSpy.mockResolvedValue(mockResponse)

      const result = await authService.getMFAStatus()

      expect(requestSpy).toHaveBeenCalledWith('/auth/mfa/status')
      expect(result).toEqual(mockResponse)
    })

    it('should begin MFA setup successfully', async () => {
      const { authService, requestSpy } = await setupAuthService()

      const mockResponse = {
        secret: 'mfa-secret-key',
        qrCode: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==',
      }

      requestSpy.mockResolvedValue(mockResponse)

      const result = await authService.beginMFASetup()

      expect(requestSpy).toHaveBeenCalledWith('/auth/mfa/begin', {
        method: 'POST',
      })
      expect(result).toEqual(mockResponse)
    })

    it('should enable MFA successfully', async () => {
      const { authService, requestSpy } = await setupAuthService()

      requestSpy.mockResolvedValue(undefined)

      await authService.enableMFA('123456')

      expect(requestSpy).toHaveBeenCalledWith('/auth/mfa/enable', {
        method: 'POST',
        body: JSON.stringify({ code: '123456' }),
      })
    })

    it('should disable MFA successfully', async () => {
      const { authService, requestSpy } = await setupAuthService()

      requestSpy.mockResolvedValue(undefined)

      await authService.disableMFA()

      expect(requestSpy).toHaveBeenCalledWith('/auth/mfa/disable', {
        method: 'POST',
      })
    })

    it('should handle MFA errors gracefully', async () => {
      const { authService, requestSpy } = await setupAuthService()

      requestSpy.mockRejectedValue(new Error('Invalid MFA code'))

      await expect(authService.enableMFA('000000')).rejects.toThrow('Invalid MFA code')
    })
  })
})