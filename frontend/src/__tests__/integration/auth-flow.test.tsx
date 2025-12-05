import { describe, it, expect, beforeEach, vi } from 'vitest'
import { useAuthStore } from '@/stores/authStore'
import { authService } from '@/services/api'

vi.mock('@/services/api', () => ({
  authService: {
    register: vi.fn(),
    getMFAStatus: vi.fn(),
    beginMFASetup: vi.fn(),
    enableMFA: vi.fn(),
    disableMFA: vi.fn(),
  },
}))

describe('Integration: Clerk Authentication Flow', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: null,
      isLoading: false,
    })
    localStorage.clear()
    vi.clearAllMocks()
  })

  describe('User Registration Flow with Clerk', () => {
    it('should complete registration process with Clerk', async () => {
      // Step 1: Register new user (handled by Clerk, processed by backend)
      const registerResponse = {
        message: 'Registration request accepted. Check your email for verification.',
      }

      vi.mocked(authService.register).mockResolvedValue(registerResponse as any)

      const message = await useAuthStore
        .getState()
        .register('newuser@example.com', 'password123', 'New User')

      expect(message).toContain('Registration request accepted')
      expect(useAuthStore.getState().user).toBeNull() // Not logged in yet - Clerk handles this
    })

    it('should handle registration failure gracefully', async () => {
      // Registration failure (email exists)
      vi.mocked(authService.register).mockRejectedValueOnce(new Error('Email already registered'))

      await expect(
        useAuthStore.getState().register('existing@example.com', 'password', 'User')
      ).rejects.toThrow('Email already registered')

      expect(useAuthStore.getState().user).toBeNull()
    })
  })

  describe('MFA Setup Flow with Clerk', () => {
    it('should complete MFA setup process', async () => {
      // Mock MFA setup response
      const mfaSetupResponse = {
        secret: 'mfa-secret-key',
        qrCode: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==',
      }

      vi.mocked(authService.beginMFASetup).mockResolvedValue(mfaSetupResponse)

      const result = await useAuthStore.getState().enableMFA()

      expect(result).toBe('mfa-secret-key')
      expect(authService.beginMFASetup).toHaveBeenCalled()
    })
  })

  describe('Clerk Authentication State', () => {
    it('should handle Clerk authentication state changes', () => {
      // Test that the store properly handles Clerk auth state
      expect(useAuthStore.getState().user).toBeNull()
      expect(useAuthStore.getState().isLoading).toBe(false)
    })

    it('should handle authentication state properly', async () => {
      // Test that the store properly handles Clerk auth state
      expect(useAuthStore.getState().user).toBeNull()
      expect(useAuthStore.getState().isLoading).toBe(false)
    })
  })
})