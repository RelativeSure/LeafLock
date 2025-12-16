/**
 * Enhanced Clerk Integration Tests
 *
 * Tests for advanced Clerk functionality including session management,
 * user profile updates, and enhanced authentication flows.
 */

import { renderHook, act } from '@testing-library/react'
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
      createEmailAddress: vi.fn().mockResolvedValue({
        id: 'email_2',
        emailAddress: 'new@example.com',
        prepareVerification: vi.fn().mockResolvedValue(undefined),
      }),
      setProfileImage: vi.fn().mockResolvedValue(undefined),
      reload: vi.fn().mockResolvedValue(undefined),
    },
    isLoaded: true,
  }),
  useSession: () => ({
    session: {
      id: 'session_123',
      status: 'active',
      expireAt: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
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
  useAuth: () => ({
    isSignedIn: true,
    isLoaded: true,
    sessionId: 'session_123',
    userId: 'user_123',
  }),
}))

describe('Enhanced Clerk Integration', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('Enhanced Session Management', () => {
    it('should return session data from useSession', async () => {
      const { useEnhancedSession } = await import('../hooks/useEnhancedClerk')
      const { result } = renderHook(() => useEnhancedSession())

      // Should return session data
      expect(result.current.session).toBeDefined()
      expect(result.current.isLoaded).toBe(true)
      expect(typeof result.current.isExpiringSoon).toBe('boolean')
    })

    it('should provide refresh function', async () => {
      const { useEnhancedSession } = await import('../hooks/useEnhancedClerk')
      const { result } = renderHook(() => useEnhancedSession())

      // Refresh function should exist
      expect(typeof result.current.refreshSession).toBe('function')
    })

    it('should provide revoke function', async () => {
      const { useEnhancedSession } = await import('../hooks/useEnhancedClerk')
      const { result } = renderHook(() => useEnhancedSession())

      // Revoke function should exist
      expect(typeof result.current.revokeSession).toBe('function')
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

      const mockFile = new File(['test'], 'test.jpg', { type: 'image/jpeg' })

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
        const session = await result.current.customSignIn('test@example.com', 'password123')
        expect(session).toBeDefined()
      })
    })

    it('should provide MFA verification function', async () => {
      const { useCustomAuthFlow } = await import('../hooks/useEnhancedClerk')
      const { result } = renderHook(() => useCustomAuthFlow())

      // MFA function should exist
      expect(typeof result.current.verifyMFA).toBe('function')
    })
  })

  describe('Security Monitoring', () => {
    it('should provide security monitoring functions', async () => {
      const { useEnhancedClerk } = await import('../hooks/useEnhancedClerk')
      const { result } = renderHook(() => useEnhancedClerk())

      // Security monitoring functions should exist
      expect(result.current.securityEvents).toBeDefined()
      expect(typeof result.current.clearSecurityEvents).toBe('function')
    })
  })
})
