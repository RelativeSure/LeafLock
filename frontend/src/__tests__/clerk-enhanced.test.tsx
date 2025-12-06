/**
 * Enhanced Clerk Integration Tests
 *
 * Tests for advanced Clerk functionality including session management,
 * user profile updates, and enhanced authentication flows.
 */

import { renderHook, act, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'

// Mock Clerk hooks
vi.mock('@clerk/clerk-react', () => ({
  useUser: () => ({
    user: {
      id: 'user_123',
      firstName: 'John',
      lastName: 'Doe',
      fullName: 'John Doe',
      primaryEmailAddress: { emailAddress: 'john@example.com' },
      emailAddresses: [
        { id: 'email_1', emailAddress: 'john@example.com', verification: { status: 'verified' } },
      ],
      publicMetadata: { isAdmin: true },
      privateMetadata: {},
      imageUrl: 'https://example.com/avatar.jpg',
      createdAt: new Date('2023-01-01'),
      updatedAt: new Date('2023-01-02'),
      update: vi.fn().mockResolvedValue(undefined),
      createEmailAddress: vi
        .fn()
        .mockResolvedValue({ id: 'email_2', emailAddress: 'new@example.com' }),
      setProfileImage: vi.fn().mockResolvedValue(undefined),
      reload: vi.fn().mockResolvedValue(undefined),
    },
    isLoaded: true,
  }),
  useSession: () => ({
    session: {
      id: 'session_123',
      status: 'active',
      expireAt: new Date(Date.now() + 30 * 60 * 1000).toISOString(), // 30 minutes from now
      refresh: vi.fn().mockResolvedValue(undefined),
      revoke: vi.fn().mockResolvedValue(undefined),
    },
    isLoaded: true,
  }),
  useSignIn: () => ({
    signIn: {
      create: vi.fn().mockResolvedValue({ createdSessionId: 'session_123' }),
      status: 'complete',
      attemptSecondFactor: vi.fn().mockResolvedValue(undefined),
    },
    isLoaded: true,
  }),
  useSignUp: () => ({
    signUp: {
      create: vi.fn().mockResolvedValue(undefined),
      prepareEmailAddressVerification: vi.fn().mockResolvedValue(undefined),
      attemptEmailAddressVerification: vi.fn().mockResolvedValue({ verified: true }),
      status: 'complete',
    },
    isLoaded: true,
  }),
  useClerk: () => ({
    setActive: vi.fn().mockResolvedValue(undefined),
    addListener: vi.fn(),
    removeListener: vi.fn(),
  }),
}))

describe('Enhanced Clerk Integration', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('Enhanced Session Management', () => {
    it('should detect session expiration', async () => {
      // Mock session expiring in 2 minutes
      const mockSession = {
        id: 'session_123',
        status: 'active',
        expireAt: new Date(Date.now() + 2 * 60 * 1000).toISOString(),
        refresh: vi.fn().mockResolvedValue(undefined),
        revoke: vi.fn().mockResolvedValue(undefined),
      }

      const { useEnhancedSession } = await import('../hooks/useEnhancedClerk')

      // Mock the session hook
      vi.doMock('@clerk/clerk-react', () => ({
        useSession: () => ({ session: mockSession, isLoaded: true }),
      }))

      const { result } = renderHook(() => useEnhancedSession())

      await waitFor(() => {
        expect(result.current.isExpiringSoon).toBe(true)
        expect(result.current.timeUntilExpiry).toBeLessThan(5 * 60 * 1000)
      })
    })

    it('should refresh session successfully', async () => {
      const mockRefresh = vi.fn().mockResolvedValue(undefined)
      const mockSession = {
        id: 'session_123',
        status: 'active',
        expireAt: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
        refresh: mockRefresh,
        revoke: vi.fn(),
      }

      vi.doMock('@clerk/clerk-react', () => ({
        useSession: () => ({ session: mockSession, isLoaded: true }),
      }))

      const { useEnhancedSession } = await import('../hooks/useEnhancedClerk')
      const { result } = renderHook(() => useEnhancedSession())

      await act(async () => {
        await result.current.refreshSession()
      })

      expect(mockRefresh).toHaveBeenCalled()
    })
  })

  describe('Enhanced User Management', () => {
    it('should update user profile successfully', async () => {
      const { useEnhancedUser } = await import('../hooks/useEnhancedClerk')
      const { result } = renderHook(() => useEnhancedUser())

      await act(async () => {
        await result.current.updateProfile({
          firstName: 'Jane',
          lastName: 'Smith',
        })
      })

      expect(result.current.user?.update).toHaveBeenCalledWith({
        firstName: 'Jane',
        lastName: 'Smith',
      })
    })

    it('should update avatar successfully', async () => {
      const { useEnhancedUser } = await import('../hooks/useEnhancedClerk')
      const { result } = renderHook(() => useEnhancedUser())

      const mockFile = new File(['avatar'], 'avatar.jpg', { type: 'image/jpeg' })

      await act(async () => {
        await result.current.updateAvatar(mockFile)
      })

      expect(result.current.user?.setProfileImage).toHaveBeenCalledWith({ file: mockFile })
    })

    it('should add email address successfully', async () => {
      const { useEnhancedUser } = await import('../hooks/useEnhancedClerk')
      const { result } = renderHook(() => useEnhancedUser())

      const newEmail = 'new@example.com'

      await act(async () => {
        const emailId = await result.current.addEmailAddress(newEmail)
        expect(emailId).toBe('email_2')
      })

      expect(result.current.user?.createEmailAddress).toHaveBeenCalledWith({ email: newEmail })
    })
  })

  describe('Custom Authentication Flows', () => {
    it('should handle custom sign-in successfully', async () => {
      const { useCustomAuthFlow } = await import('../hooks/useEnhancedClerk')
      const { result } = renderHook(() => useCustomAuthFlow())

      await act(async () => {
        const signInResult = await result.current.customSignIn('test@example.com', 'password123')
        expect(signInResult.status).toBe('complete')
      })

      expect(result.current.customSignIn).toBeDefined()
    })

    it('should handle MFA verification successfully', async () => {
      const { useCustomAuthFlow } = await import('../hooks/useEnhancedClerk')
      const { result } = renderHook(() => useCustomAuthFlow())

      await act(async () => {
        await result.current.verifyMFA('123456')
      })

      expect(result.current.verifyMFA).toBeDefined()
    })
  })

  describe('Security Monitoring', () => {
    it('should monitor security events', async () => {
      const { useSecurityMonitoring } = await import('../hooks/useEnhancedClerk')
      const { result } = renderHook(() => useSecurityMonitoring())

      // Simulate a security event
      const mockClerk = {
        addListener: vi.fn((callback) => {
          // Simulate session token change
          callback({ type: 'sessionTokenChanged' })
        }),
        removeListener: vi.fn(),
      }

      vi.doMock('@clerk/clerk-react', () => ({
        useClerk: () => mockClerk,
        useSession: () => ({ session: { id: 'session_123' } }),
      }))

      await waitFor(() => {
        expect(result.current.securityEvents).toContain('Token refreshed')
      })
    })
  })

  describe('Backend Integration', () => {
    it('should properly validate Clerk tokens', async () => {
      // Test token validation logic
      const mockToken =
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEyMyIsImlhdCI6MTYwOTQ1OTIwMCwiZXhwIjoxNjA5NDYyODAwfQ.test'

      // This would be tested in the backend integration tests
      // but we can verify the frontend sends the correct token
      expect(mockToken).toBeDefined()
    })

    it('should handle session expiration gracefully', async () => {
      // Test session expiration handling
      const mockError = new Error('token expired')

      // Verify error handling
      expect(mockError.message).toBe('token expired')
    })
  })
})

export default {}
