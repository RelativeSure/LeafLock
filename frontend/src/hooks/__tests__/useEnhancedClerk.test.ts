import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'

// Create stable mock objects that won't change between calls
const mockUser = {
  id: 'test-user-id',
  emailAddresses: [
    { id: 'email-1', emailAddress: 'test@example.com', attemptVerification: vi.fn() },
    { id: 'email-2', emailAddress: 'other@example.com', attemptVerification: vi.fn() },
  ],
  fullName: 'Test User',
  update: vi.fn(),
  setProfileImage: vi.fn(),
  createEmailAddress: vi.fn(),
} as any

const mockSignIn = {
  status: 'complete',
  createdSessionId: 'new-session-id',
  create: vi.fn(),
  attemptSecondFactor: vi.fn(),
} as any

const mockSignUp = {
  status: 'complete',
  createdSessionId: 'new-session-id',
  create: vi.fn(),
  prepareEmailAddressVerification: vi.fn(),
  attemptEmailAddressVerification: vi.fn(),
} as any

const mockClerk = {
  setActive: vi.fn(),
  addListener: vi.fn(),
}

// Mock @clerk/clerk-react with stable references
vi.mock('@clerk/clerk-react', () => ({
  useSession: vi.fn(() => ({
    session: {
      id: 'test-session-id',
      expireAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes from now
      user: {
        id: 'test-user-id',
        emailAddresses: [{ emailAddress: 'test@example.com' }],
        fullName: 'Test User',
      },
    } as any,
    isLoaded: true,
    isSignedIn: true,
  })),
  useUser: vi.fn(() => ({
    user: mockUser,
    isLoaded: true,
    isSignedIn: true,
  })),
  useSignIn: vi.fn(() => ({
    signIn: mockSignIn,
    isLoaded: true,
  })),
  useSignUp: vi.fn(() => ({
    signUp: mockSignUp,
    isLoaded: true,
  })),
  useClerk: vi.fn(() => mockClerk),
}))

// Import after mocks
import {
  useEnhancedSession,
  useEnhancedUser,
  useCustomAuthFlow,
  useSecurityMonitoring,
  useEnhancedClerk,
} from '../useEnhancedClerk'
import { useSession, useUser, useSignIn, useSignUp } from '@clerk/clerk-react'

describe('useEnhancedSession', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.useFakeTimers()
    // Reset to default mock values
    vi.mocked(useSession).mockReturnValue({
      session: {
        id: 'test-session-id',
        expireAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes from now
        user: {
          id: 'test-user-id',
          emailAddresses: [{ emailAddress: 'test@example.com' }],
          fullName: 'Test User',
        },
      } as any,
      isLoaded: true,
      isSignedIn: true,
    })
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('should return session data when loaded', () => {
    const { result } = renderHook(() => useEnhancedSession())

    expect(result.current.session).toBeDefined()
    expect(result.current.isLoaded).toBe(true)
    expect(result.current.isExpiringSoon).toBe(false)
    expect(result.current.timeUntilExpiry).toBeGreaterThan(0)
  })

  it('should handle session expiration logic', () => {
    // Mock session expiring in 3 minutes (should trigger isExpiringSoon)
    const expiringSession = {
      id: 'test-session-id',
      expireAt: new Date(Date.now() + 3 * 60 * 1000),
      user: {
        id: 'test-user-id',
        emailAddresses: [{ emailAddress: 'test@example.com' }],
        fullName: 'Test User',
      },
    }
    vi.mocked(useSession).mockReturnValue({
      session: expiringSession as any,
      isLoaded: true,
      isSignedIn: true,
    })

    const { result } = renderHook(() => useEnhancedSession())

    expect(result.current.isExpiringSoon).toBe(true)
    expect(result.current.timeUntilExpiry).toBeLessThan(5 * 60 * 1000)
  })

  it('should handle session expiration updates over time', () => {
    // Mock session expiring in 6 minutes (should not trigger isExpiringSoon initially)
    const expiringSession = {
      id: 'test-session-id',
      expireAt: new Date(Date.now() + 6 * 60 * 1000),
      user: {
        id: 'test-user-id',
        emailAddresses: [{ emailAddress: 'test@example.com' }],
        fullName: 'Test User',
      },
    }
    vi.mocked(useSession).mockReturnValue({
      session: expiringSession as any,
      isLoaded: true,
      isSignedIn: true,
    })

    const { result } = renderHook(() => useEnhancedSession())

    expect(result.current.isExpiringSoon).toBe(false)

    // Advance time by 2 minutes to make it expire in 4 minutes
    act(() => {
      vi.advanceTimersByTime(2 * 60 * 1000)
    })

    // Should now be expiring soon
    expect(result.current.isExpiringSoon).toBe(true)
  })

  it('should handle no session', () => {
    vi.mocked(useSession).mockReturnValue({ session: null, isLoaded: true, isSignedIn: false })

    const { result } = renderHook(() => useEnhancedSession())

    expect(result.current.session).toBeNull()
    expect(result.current.isExpiringSoon).toBe(false)
    expect(result.current.timeUntilExpiry).toBeNull()
  })

  it('should handle session not loaded', () => {
    vi.mocked(useSession).mockReturnValue({
      session: undefined,
      isLoaded: false,
      isSignedIn: undefined,
    } as any)

    const { result } = renderHook(() => useEnhancedSession())

    expect(result.current.session).toBeNull()
    expect(result.current.isLoaded).toBe(false)
    expect(result.current.isExpiringSoon).toBe(false)
    expect(result.current.timeUntilExpiry).toBeNull()
  })

  it('should refresh session successfully', async () => {
    const { result } = renderHook(() => useEnhancedSession())

    await act(async () => {
      await result.current.refreshSession()
    })

    // Should not throw
    expect(result.current.session).toBeDefined()
  })

  it('should throw error when refreshing session without active session', async () => {
    vi.mocked(useSession).mockReturnValue({ session: null, isLoaded: true, isSignedIn: false })

    const { result } = renderHook(() => useEnhancedSession())

    await expect(result.current.refreshSession()).rejects.toThrow('No active session')
  })

  it('should revoke session successfully', async () => {
    const { result } = renderHook(() => useEnhancedSession())

    await act(async () => {
      await result.current.revokeSession()
    })

    // Should not throw
    expect(result.current.session).toBeDefined()
  })

  it('should revoke specific session successfully', async () => {
    const { result } = renderHook(() => useEnhancedSession())

    await act(async () => {
      await result.current.revokeSession('specific-session-id')
    })

    // Should not throw
    expect(result.current.session).toBeDefined()
  })

  it('should throw error when revoking session without active session', async () => {
    vi.mocked(useSession).mockReturnValue({
      session: null,
      isLoaded: true as const,
      isSignedIn: false,
    } as any)

    const { result } = renderHook(() => useEnhancedSession())

    await expect(result.current.revokeSession()).rejects.toThrow('No active session')
  })

  it('should cleanup interval on unmount', () => {
    const { unmount } = renderHook(() => useEnhancedSession())

    unmount()

    // Should not throw any errors
    expect(true).toBe(true)
  })
})

describe('useEnhancedUser', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Reset to default mock values
    vi.mocked(useUser).mockReturnValue({
      user: mockUser,
      isLoaded: true as const,
      isSignedIn: true,
    } as any)
  })

  it('should return user data when loaded', () => {
    const { result } = renderHook(() => useEnhancedUser())

    expect(result.current.user).toBeDefined()
    expect(result.current.isLoaded).toBe(true)
    expect(result.current.isUpdating).toBe(false)
  })

  it('should update profile successfully', async () => {
    const { result } = renderHook(() => useEnhancedUser())

    const updates = {
      firstName: 'Updated',
      lastName: 'Name',
      publicMetadata: { theme: 'dark' },
      privateMetadata: { internalId: '123' },
    }

    await act(async () => {
      await result.current.updateProfile(updates)
    })

    expect(mockUser.update).toHaveBeenCalledWith(updates)
    expect(result.current.isUpdating).toBe(false)
  })

  it('should throw error when updating profile without user', async () => {
    vi.mocked(useUser).mockReturnValue({ user: null, isLoaded: true, isSignedIn: false })

    const { result } = renderHook(() => useEnhancedUser())

    await expect(result.current.updateProfile({ firstName: 'Test' })).rejects.toThrow(
      'No user logged in'
    )
  })

  it('should handle profile update errors', async () => {
    const error = new Error('Update failed')
    mockUser.update.mockRejectedValueOnce(error)

    const { result } = renderHook(() => useEnhancedUser())

    await expect(result.current.updateProfile({ firstName: 'Test' })).rejects.toThrow(
      'Update failed'
    )
    expect(result.current.isUpdating).toBe(false)
  })

  it('should update avatar successfully', async () => {
    const { result } = renderHook(() => useEnhancedUser())

    const file = new File(['avatar'], 'avatar.png', { type: 'image/png' })

    await act(async () => {
      await result.current.updateAvatar(file)
    })

    expect(mockUser.setProfileImage).toHaveBeenCalledWith({ file })
  })

  it('should validate avatar file type', async () => {
    const { result } = renderHook(() => useEnhancedUser())

    const invalidFile = new File(['content'], 'document.pdf', { type: 'application/pdf' })

    await expect(result.current.updateAvatar(invalidFile)).rejects.toThrow('Invalid file type')
  })

  it('should validate avatar file size', async () => {
    const { result } = renderHook(() => useEnhancedUser())

    const largeFile = new File([new ArrayBuffer(11 * 1024 * 1024)], 'large.png', {
      type: 'image/png',
    })

    await expect(result.current.updateAvatar(largeFile)).rejects.toThrow('File size too large')
  })

  it('should throw error when updating avatar without user', async () => {
    vi.mocked(useUser).mockReturnValue({ user: null, isLoaded: true, isSignedIn: false })

    const { result } = renderHook(() => useEnhancedUser())

    const file = new File(['avatar'], 'avatar.png', { type: 'image/png' })
    await expect(result.current.updateAvatar(file)).rejects.toThrow('No user logged in')
  })

  it('should handle avatar update errors', async () => {
    const error = new Error('Avatar update failed')
    mockUser.setProfileImage.mockRejectedValueOnce(error)

    const { result } = renderHook(() => useEnhancedUser())

    const file = new File(['avatar'], 'avatar.png', { type: 'image/png' })
    await expect(result.current.updateAvatar(file)).rejects.toThrow('Avatar update failed')
  })

  it('should add email address successfully', async () => {
    const { result } = renderHook(() => useEnhancedUser())

    const mockEmailAddress = {
      id: 'new-email-id',
      prepareVerification: vi.fn(),
    }
    mockUser.createEmailAddress.mockResolvedValueOnce(mockEmailAddress)

    const emailId = await result.current.addEmailAddress('new@example.com')

    expect(mockUser.createEmailAddress).toHaveBeenCalledWith({ email: 'new@example.com' })
    expect(mockEmailAddress.prepareVerification).toHaveBeenCalledWith({ strategy: 'email_code' })
    expect(emailId).toBe('new-email-id')
  })

  it('should throw error when adding email without user', async () => {
    vi.mocked(useUser).mockReturnValue({ user: null, isLoaded: true, isSignedIn: false })

    const { result } = renderHook(() => useEnhancedUser())

    await expect(result.current.addEmailAddress('new@example.com')).rejects.toThrow(
      'No user logged in'
    )
  })

  it('should handle email addition errors', async () => {
    const error = new Error('Email addition failed')
    mockUser.createEmailAddress.mockRejectedValueOnce(error)

    const { result } = renderHook(() => useEnhancedUser())

    await expect(result.current.addEmailAddress('new@example.com')).rejects.toThrow(
      'Email addition failed'
    )
  })

  it('should verify email address successfully', async () => {
    const { result } = renderHook(() => useEnhancedUser())

    const mockEmailAddress = mockUser.emailAddresses[0]
    mockEmailAddress.attemptVerification.mockResolvedValueOnce({ verified: true } as any)

    await act(async () => {
      await result.current.verifyEmailAddress('email-1', '123456')
    })

    expect(mockEmailAddress.attemptVerification).toHaveBeenCalledWith({ code: '123456' })
  })

  it('should throw error when email address not found', async () => {
    const { result } = renderHook(() => useEnhancedUser())

    await expect(result.current.verifyEmailAddress('non-existent', '123456')).rejects.toThrow(
      'Email address not found'
    )
  })

  it('should throw error when verifying email without user', async () => {
    vi.mocked(useUser).mockReturnValue({ user: null, isLoaded: true, isSignedIn: false })

    const { result } = renderHook(() => useEnhancedUser())

    await expect(result.current.verifyEmailAddress('email-1', '123456')).rejects.toThrow(
      'No user logged in'
    )
  })

  it('should handle email verification errors', async () => {
    const error = new Error('Invalid verification code')
    const mockEmailAddress = mockUser.emailAddresses[0]
    mockEmailAddress.attemptVerification.mockRejectedValueOnce(error)

    const { result } = renderHook(() => useEnhancedUser())

    await expect(result.current.verifyEmailAddress('email-1', '123456')).rejects.toThrow(
      'Invalid verification code'
    )
  })

  it('should handle verification result with error', async () => {
    const mockEmailAddress = mockUser.emailAddresses[0]
    mockEmailAddress.attemptVerification.mockResolvedValueOnce({ error: 'Invalid code' } as any)

    const { result } = renderHook(() => useEnhancedUser())

    await expect(result.current.verifyEmailAddress('email-1', '123456')).rejects.toThrow(
      'Invalid verification code'
    )
  })
})

describe('useCustomAuthFlow', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Reset to default mock values
    vi.mocked(useSignIn).mockReturnValue({
      signIn: mockSignIn,
      isLoaded: true as const,
      setActive: vi.fn(),
    } as any)
    vi.mocked(useSignUp).mockReturnValue({
      signUp: mockSignUp,
      isLoaded: true as const,
      setActive: vi.fn(),
    } as any)
  })

  it('should sign in with password successfully', async () => {
    const { result } = renderHook(() => useCustomAuthFlow())

    mockSignIn.create.mockResolvedValueOnce(undefined)
    mockSignIn.status = 'complete'

    const resultData = await result.current.customSignIn('test@example.com', 'password123')

    expect(mockSignIn.create).toHaveBeenCalledWith({
      identifier: 'test@example.com',
      password: 'password123',
      strategy: 'password',
    })
    expect(mockClerk.setActive).toHaveBeenCalledWith({ session: 'new-session-id' })
    expect(resultData).toEqual({ status: 'complete' })
  })

  it('should sign in with email code successfully', async () => {
    const { result } = renderHook(() => useCustomAuthFlow())

    mockSignIn.create.mockResolvedValueOnce(undefined)
    mockSignIn.status = 'incomplete'

    const resultData = await result.current.customSignIn('test@example.com', '', 'email_code')

    expect(mockSignIn.create).toHaveBeenCalledWith({
      identifier: 'test@example.com',
      password: undefined,
      strategy: 'email_code',
    })
    expect(resultData).toEqual({ status: 'incomplete', signIn: mockSignIn })
  })

  it('should handle MFA requirement during sign in', async () => {
    const { result } = renderHook(() => useCustomAuthFlow())

    mockSignIn.create.mockResolvedValueOnce(undefined)
    mockSignIn.status = 'needs_second_factor'

    const resultData = await result.current.customSignIn('test@example.com', 'password123')

    expect(resultData).toEqual({ status: 'needs_mfa', signIn: mockSignIn })
  })

  it('should throw error when sign in not loaded', async () => {
    vi.mocked(useSignIn).mockReturnValue({
      signIn: undefined,
      isLoaded: false as const,
      setActive: undefined,
    } as any)

    const { result } = renderHook(() => useCustomAuthFlow())

    await expect(result.current.customSignIn('test@example.com', 'password123')).rejects.toThrow(
      'SignIn not loaded'
    )
  })

  it('should handle sign in errors', async () => {
    const error = new Error('Sign in failed')
    mockSignIn.create.mockRejectedValueOnce(error)

    const { result } = renderHook(() => useCustomAuthFlow())

    await expect(result.current.customSignIn('test@example.com', 'password123')).rejects.toThrow(
      'Sign in failed'
    )
  })

  it('should verify MFA successfully', async () => {
    const { result } = renderHook(() => useCustomAuthFlow())

    mockSignIn.status = 'needs_second_factor'
    mockSignIn.attemptSecondFactor.mockResolvedValueOnce(undefined)

    await act(async () => {
      await result.current.verifyMFA('123456')
    })

    expect(mockSignIn.attemptSecondFactor).toHaveBeenCalledWith({
      strategy: 'email_code',
      code: '123456',
    })
    expect(mockClerk.setActive).toHaveBeenCalledWith({ session: 'new-session-id' })
  })

  it('should throw error when MFA not required', async () => {
    const { result } = renderHook(() => useCustomAuthFlow())

    mockSignIn.status = 'complete'

    await expect(result.current.verifyMFA('123456')).rejects.toThrow('MFA not required')
  })

  it('should handle MFA verification errors', async () => {
    const error = new Error('MFA verification failed')
    mockSignIn.status = 'needs_second_factor'
    mockSignIn.attemptSecondFactor.mockRejectedValueOnce(error)

    const { result } = renderHook(() => useCustomAuthFlow())

    await expect(result.current.verifyMFA('123456')).rejects.toThrow('MFA verification failed')
  })

  it('should sign up successfully', async () => {
    const { result } = renderHook(() => useCustomAuthFlow())

    mockSignUp.create.mockResolvedValueOnce(undefined)
    mockSignUp.prepareEmailAddressVerification.mockResolvedValueOnce(undefined)

    const signUpData = {
      emailAddress: 'newuser@example.com',
      password: 'password123',
      firstName: 'New',
      lastName: 'User',
    }

    const resultData = await result.current.customSignUp(signUpData)

    expect(mockSignUp.create).toHaveBeenCalledWith(signUpData)
    expect(mockSignUp.prepareEmailAddressVerification).toHaveBeenCalledWith({
      strategy: 'email_code',
    })
    expect(resultData).toEqual({ status: 'needs_verification', signUp: mockSignUp })
  })

  it('should throw error when sign up not loaded', async () => {
    vi.mocked(useSignUp).mockReturnValue({ signUp: mockSignUp, isLoaded: false } as any)

    const { result } = renderHook(() => useCustomAuthFlow())

    await expect(
      result.current.customSignUp({ emailAddress: 'test@example.com', password: 'password123' })
    ).rejects.toThrow('SignUp not loaded')
  })

  it('should handle sign up errors', async () => {
    const error = new Error('Sign up failed')
    mockSignUp.create.mockRejectedValueOnce(error)

    const { result } = renderHook(() => useCustomAuthFlow())

    await expect(
      result.current.customSignUp({ emailAddress: 'test@example.com', password: 'password123' })
    ).rejects.toThrow('Sign up failed')
  })

  it('should complete sign up successfully', async () => {
    const { result } = renderHook(() => useCustomAuthFlow())

    mockSignUp.status = 'missing_requirements'
    mockSignUp.attemptEmailAddressVerification.mockResolvedValueOnce(undefined)

    await act(async () => {
      await result.current.completeSignUp('123456')
    })

    expect(mockSignUp.attemptEmailAddressVerification).toHaveBeenCalledWith({ code: '123456' })
    expect(mockClerk.setActive).toHaveBeenCalledWith({ session: 'new-session-id' })
  })

  it('should throw error when sign up not in correct state', async () => {
    const { result } = renderHook(() => useCustomAuthFlow())

    mockSignUp.status = 'complete'

    await expect(result.current.completeSignUp('123456')).rejects.toThrow(
      'Sign-up not in correct state'
    )
  })

  it('should handle sign up completion errors', async () => {
    const error = new Error('Verification failed')
    mockSignUp.status = 'missing_requirements'
    mockSignUp.attemptEmailAddressVerification.mockRejectedValueOnce(error)

    const { result } = renderHook(() => useCustomAuthFlow())

    await expect(result.current.completeSignUp('123456')).rejects.toThrow('Verification failed')
  })
})

describe('useSecurityMonitoring', () => {
  let addListenerMock: any
  let handleSecurityEvent: any

  beforeEach(() => {
    vi.clearAllMocks()
    // Reset to default mock values
    vi.mocked(useSession).mockReturnValue({
      session: {
        id: 'test-session-id',
        expireAt: new Date(Date.now() + 10 * 60 * 1000),
        user: {
          id: 'test-user-id',
          emailAddresses: [{ emailAddress: 'test@example.com' }],
          fullName: 'Test User',
        },
      } as any,
      isLoaded: true,
      isSignedIn: true,
    })

    // Capture the listener function
    addListenerMock = vi.fn()
    mockClerk.addListener = addListenerMock
  })

  it('should return initial security events', () => {
    vi.mocked(useSession).mockReturnValue({ session: null, isLoaded: true, isSignedIn: false })

    const { result } = renderHook(() => useSecurityMonitoring())

    expect(result.current.securityEvents).toEqual([])
    expect(typeof result.current.clearSecurityEvents).toBe('function')
  })

  it('should handle session token changed event', () => {
    const { result } = renderHook(() => useSecurityMonitoring())

    // Get the listener function that was registered
    expect(addListenerMock).toHaveBeenCalledTimes(1)
    handleSecurityEvent = addListenerMock.mock.calls[0][0]

    act(() => {
      handleSecurityEvent({ type: 'sessionTokenChanged' })
    })

    expect(result.current.securityEvents).toContain('Token refreshed')
  })

  it('should handle user signed out event', () => {
    const { result } = renderHook(() => useSecurityMonitoring())
    handleSecurityEvent = addListenerMock.mock.calls[0][0]

    act(() => {
      handleSecurityEvent({ type: 'userSignedOut' })
    })

    expect(result.current.securityEvents).toContain('User signed out')
  })

  it('should handle session created event', () => {
    const { result } = renderHook(() => useSecurityMonitoring())
    handleSecurityEvent = addListenerMock.mock.calls[0][0]

    act(() => {
      handleSecurityEvent({ type: 'sessionCreated' })
    })

    expect(result.current.securityEvents).toContain('New session created')
  })

  it('should handle session revoked event', () => {
    const { result } = renderHook(() => useSecurityMonitoring())
    handleSecurityEvent = addListenerMock.mock.calls[0][0]

    act(() => {
      handleSecurityEvent({ type: 'sessionRevoked' })
    })

    expect(result.current.securityEvents).toContain('Session revoked')
  })

  it('should handle security events with security in name', () => {
    const { result } = renderHook(() => useSecurityMonitoring())
    handleSecurityEvent = addListenerMock.mock.calls[0][0]

    act(() => {
      handleSecurityEvent({ type: 'securityAlert' })
    })

    expect(result.current.securityEvents).toContain('Security event: securityAlert')
  })

  it('should handle suspicious events', () => {
    const { result } = renderHook(() => useSecurityMonitoring())
    handleSecurityEvent = addListenerMock.mock.calls[0][0]

    act(() => {
      handleSecurityEvent({ type: 'suspiciousActivity' })
    })

    expect(result.current.securityEvents).toContain('Security event: suspiciousActivity')
  })

  it('should skip events without type', () => {
    const { result } = renderHook(() => useSecurityMonitoring())
    handleSecurityEvent = addListenerMock.mock.calls[0][0]

    act(() => {
      handleSecurityEvent({ data: 'some data' })
    })

    expect(result.current.securityEvents).toEqual([])
  })

  it('should handle events with name instead of type', () => {
    const { result } = renderHook(() => useSecurityMonitoring())
    handleSecurityEvent = addListenerMock.mock.calls[0][0]

    act(() => {
      handleSecurityEvent({ name: 'sessionTokenChanged' })
    })

    expect(result.current.securityEvents).toContain('Token refreshed')
  })

  it('should clear security events', () => {
    const { result } = renderHook(() => useSecurityMonitoring())
    handleSecurityEvent = addListenerMock.mock.calls[0][0]

    // Add some events first
    act(() => {
      handleSecurityEvent({ type: 'sessionTokenChanged' })
      handleSecurityEvent({ type: 'userSignedOut' })
    })

    expect(result.current.securityEvents.length).toBe(2)

    // Clear events
    act(() => {
      result.current.clearSecurityEvents()
    })

    expect(result.current.securityEvents).toEqual([])
  })

  it('should not set up listener when no session', () => {
    vi.mocked(useSession).mockReturnValue({ session: null, isLoaded: true, isSignedIn: false })

    renderHook(() => useSecurityMonitoring())

    expect(addListenerMock).not.toHaveBeenCalled()
  })

  it('should handle cleanup on unmount', () => {
    const { unmount } = renderHook(() => useSecurityMonitoring())

    unmount()

    // Should not throw any errors
    expect(true).toBe(true)
  })
})

describe('useEnhancedClerk', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Reset to default mock values
    vi.mocked(useSession).mockReturnValue({
      session: {
        id: 'test-session-id',
        expireAt: new Date(Date.now() + 10 * 60 * 1000),
        user: {
          id: 'test-user-id',
          emailAddresses: [{ emailAddress: 'test@example.com' }],
          fullName: 'Test User',
        },
      } as any,
      isLoaded: true,
      isSignedIn: true,
    })
    vi.mocked(useUser).mockReturnValue({ user: mockUser, isLoaded: true, isSignedIn: true })
    vi.mocked(useSignIn).mockReturnValue({
      signIn: mockSignIn,
      isLoaded: true,
      setActive: vi.fn(),
    } as any)
    vi.mocked(useSignUp).mockReturnValue({
      signUp: mockSignUp,
      isLoaded: true,
      setActive: vi.fn(),
    } as any)
  })

  it('should combine all enhanced features', () => {
    const { result } = renderHook(() => useEnhancedClerk())

    // Check that all enhanced features are present
    expect(result.current.session).toBeDefined()
    expect(result.current.isLoaded).toBeDefined()
    expect(result.current.isExpiringSoon).toBeDefined()
    expect(result.current.timeUntilExpiry).toBeDefined()
    expect(result.current.refreshSession).toBeDefined()
    expect(result.current.revokeSession).toBeDefined()
    expect(result.current.user).toBeDefined()
    expect(result.current.isUpdating).toBeDefined()
    expect(result.current.updateProfile).toBeDefined()
    expect(result.current.updateAvatar).toBeDefined()
    expect(result.current.addEmailAddress).toBeDefined()
    expect(result.current.verifyEmailAddress).toBeDefined()
    expect(result.current.customSignIn).toBeDefined()
    expect(result.current.verifyMFA).toBeDefined()
    expect(result.current.customSignUp).toBeDefined()
    expect(result.current.completeSignUp).toBeDefined()
    expect(result.current.securityEvents).toBeDefined()
    expect(result.current.clearSecurityEvents).toBeDefined()
  })

  it('should have all properties from individual hooks', () => {
    const { result } = renderHook(() => useEnhancedClerk())

    // Test a few key properties to ensure they're properly combined
    expect(result.current.session).toBeDefined()
    expect(result.current.user).toBeDefined()
    expect(result.current.securityEvents).toEqual([])
  })
})
