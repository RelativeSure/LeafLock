import { describe, it, expect, beforeEach, vi } from 'vitest'
import { useAuthStore } from '../authStore'
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

describe('authStore - Advanced Scenarios (Clerk-compatible)', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: null,
      isLoading: false,
      registrationEnabled: null,
      pendingEncryption: null,
      mfaSession: null,
    })
    localStorage.clear()
    vi.clearAllMocks()
  })

  describe('Registration Status Management', () => {
    it('should check registration status and return true when enabled', async () => {
      vi.mocked(authService.isRegistrationEnabled).mockResolvedValue(true)

      const result = await useAuthStore.getState().checkRegistrationEnabled()

      expect(result).toBe(true)
      expect(authService.isRegistrationEnabled).toHaveBeenCalled()
    })

    it('should check registration status and return false when disabled', async () => {
      vi.mocked(authService.isRegistrationEnabled).mockResolvedValue(false)

      const result = await useAuthStore.getState().checkRegistrationEnabled()

      expect(result).toBe(false)
      expect(authService.isRegistrationEnabled).toHaveBeenCalled()
    })

    it('should cache registration status results', async () => {
      vi.mocked(authService.isRegistrationEnabled).mockResolvedValue(true)

      // First call
      const result1 = await useAuthStore.getState().checkRegistrationEnabled()
      expect(result1).toBe(true)

      // Second call should use cached value
      const result2 = await useAuthStore.getState().checkRegistrationEnabled()
      expect(result2).toBe(true)
      expect(authService.isRegistrationEnabled).toHaveBeenCalledTimes(1) // Should not call API again
    })

    it('should handle registration status check errors', async () => {
      vi.mocked(authService.isRegistrationEnabled).mockRejectedValue(new Error('Network error'))

      const result = await useAuthStore.getState().checkRegistrationEnabled()

      expect(result).toBe(false) // Should default to false on error
      expect(authService.isRegistrationEnabled).toHaveBeenCalled()
    })
  })

  describe('Store State Management', () => {
    it('should have correct initial state', () => {
      const state = useAuthStore.getState()
      expect(state.user).toBeNull()
      expect(state.isLoading).toBe(false)
      expect(state.registrationEnabled).toBeNull()
      expect(state.pendingEncryption).toBeNull()
      expect(state.mfaSession).toBeNull()
    })

    it('should clear all state on logout', () => {
      // Set some state
      useAuthStore.setState({
        user: { 
          id: '123', 
          email: 'test@example.com', 
          name: 'Test User',
          role: 'user' as const,
          isAdmin: false,
          mfaEnabled: false,
          createdAt: '2024-01-01'
        },
        isLoading: true,
      })

      useAuthStore.getState().logout()

      const state = useAuthStore.getState()
      expect(state.user).toBeNull()
      expect(state.isLoading).toBe(false)
      expect(state.pendingEncryption).toBeNull()
      expect(state.mfaSession).toBeNull()
    })
  })
})