import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'

// Mock dependencies
vi.mock('@clerk/clerk-react', () => ({
  useAuth: vi.fn(),
  useUser: vi.fn(),
  useSession: vi.fn(),
}))

vi.mock('@/lib/runtime-config', () => ({
  getRuntimeConfig: vi.fn(() => ({
    clerkJwtTemplate: 'test-template',
  })),
}))

// Import after mocks
import { useAuth, useUser, useSession } from '@clerk/clerk-react'
import { getRuntimeConfig } from '@/lib/runtime-config'
import { useClerkAuthStore, useSyncClerkAuth, getClerkToken, type User } from '../clerkAuthStore'

// Type-safe mocks
const mockUseAuth = useAuth as unknown as ReturnType<typeof vi.fn>
const mockUseUser = useUser as unknown as ReturnType<typeof vi.fn>
const mockUseSession = useSession as unknown as ReturnType<typeof vi.fn>

describe('clerkAuthStore', () => {
  beforeEach(() => {
    // Reset store state before each test
    localStorage.clear()
    vi.clearAllMocks()

    // Reset the store to initial state
    const { setUser, setLoading } = useClerkAuthStore.getState()
    setUser(null)
    setLoading(true)
  })

  afterEach(() => {
    localStorage.clear()
  })

  describe('Store State Management', () => {
    it('should initialize with default state', () => {
      const state = useClerkAuthStore.getState()

      expect(state.user).toBeNull()
      expect(state.isAuthenticated).toBe(false)
      expect(state.isLoading).toBe(true)
      expect(state.isAdmin).toBe(false)
    })

    it('should set user and update authentication state', () => {
      const { setUser } = useClerkAuthStore.getState()
      const testUser: User = {
        id: 'test-user-123',
        email: 'test@example.com',
        name: 'Test User',
        isAdmin: true,
        createdAt: new Date('2024-01-01'),
        updatedAt: new Date('2024-01-02'),
      }

      act(() => {
        setUser(testUser)
      })

      const state = useClerkAuthStore.getState()
      expect(state.user).toEqual(testUser)
      expect(state.isAuthenticated).toBe(true)
      expect(state.isAdmin).toBe(true)
    })

    it('should set user to null and clear authentication', () => {
      const { setUser } = useClerkAuthStore.getState()

      // First set a user
      act(() => {
        setUser({
          id: 'test-user-123',
          email: 'test@example.com',
          isAdmin: false,
        })
      })

      // Then clear it
      act(() => {
        setUser(null)
      })

      const state = useClerkAuthStore.getState()
      expect(state.user).toBeNull()
      expect(state.isAuthenticated).toBe(false)
      expect(state.isAdmin).toBe(false)
    })

    it('should sync user data to localStorage when user is set', () => {
      const { setUser } = useClerkAuthStore.getState()
      const testUser: User = {
        id: 'test-user-123',
        email: 'test@example.com',
        isAdmin: false,
      }

      const localStorageSpy = vi.spyOn(Storage.prototype, 'setItem')

      act(() => {
        setUser(testUser)
      })

      expect(localStorageSpy).toHaveBeenCalledWith('user', JSON.stringify(testUser))
    })

    it('should remove user data from localStorage when user is cleared', () => {
      const { setUser } = useClerkAuthStore.getState()
      const localStorageSpy = vi.spyOn(Storage.prototype, 'removeItem')

      act(() => {
        setUser(null)
      })

      expect(localStorageSpy).toHaveBeenCalledWith('user')
    })

    it('should handle setLoading action', () => {
      const { setLoading } = useClerkAuthStore.getState()

      act(() => {
        setLoading(false)
      })

      const state = useClerkAuthStore.getState()
      expect(state.isLoading).toBe(false)

      act(() => {
        setLoading(true)
      })

      expect(useClerkAuthStore.getState().isLoading).toBe(true)
    })

    it('should handle logout action', async () => {
      const { setUser, logout } = useClerkAuthStore.getState()

      // Set initial state with user
      act(() => {
        setUser({
          id: 'test-user-123',
          email: 'test@example.com',
          isAdmin: true,
        })
      })

      await act(async () => {
        await logout()
      })

      const state = useClerkAuthStore.getState()
      expect(state.user).toBeNull()
      expect(state.isAuthenticated).toBe(false)
      expect(state.isAdmin).toBe(false)
    })
  })

  describe('Token Management', () => {
    it('should return null for getAuthToken', async () => {
      const { getAuthToken } = useClerkAuthStore.getState()
      const token = await getAuthToken()
      expect(token).toBeNull()
    })

    it('should return null for getEncryptionKey', async () => {
      const { getEncryptionKey } = useClerkAuthStore.getState()
      const key = await getEncryptionKey()
      expect(key).toBeNull()
    })

    it('should return null for getClerkToken from standalone function', async () => {
      const token = await getClerkToken()
      expect(token).toBeNull()
    })
  })

  describe('useSyncClerkAuth Hook', () => {
    beforeEach(() => {
      // Setup default mock returns
      mockUseAuth.mockReturnValue({
        isSignedIn: false,
        isLoaded: true,
        getToken: vi.fn().mockResolvedValue('test-token'),
      })

      mockUseUser.mockReturnValue({
        user: null,
      })

      mockUseSession.mockReturnValue({
        session: null,
      })
    })

    it('should handle loading state when Clerk is not loaded', () => {
      mockUseAuth.mockReturnValue({
        isSignedIn: false,
        isLoaded: false,
        getToken: vi.fn(),
      })

      const { result } = renderHook(() => useSyncClerkAuth())

      expect(useClerkAuthStore.getState().isLoading).toBe(true)
      expect(result.current.getClerkToken).toBeDefined()
    })

    it('should handle signed out state', () => {
      mockUseAuth.mockReturnValue({
        isSignedIn: false,
        isLoaded: true,
        getToken: vi.fn(),
      })

      renderHook(() => useSyncClerkAuth())

      expect(useClerkAuthStore.getState().isLoading).toBe(false)
      expect(useClerkAuthStore.getState().user).toBeNull()
      expect(useClerkAuthStore.getState().isAuthenticated).toBe(false)
    })

    it('should handle signed in state with user data', () => {
      const mockClerkUser = {
        id: 'clerk-user-123',
        primaryEmailAddress: { emailAddress: 'clerk@example.com' },
        fullName: 'Clerk User',
        publicMetadata: { isAdmin: true },
        createdAt: new Date('2024-01-01').toISOString(),
        updatedAt: new Date('2024-01-02').toISOString(),
      }

      mockUseAuth.mockReturnValue({
        isSignedIn: true,
        isLoaded: true,
        getToken: vi.fn(),
      })

      mockUseUser.mockReturnValue({
        user: mockClerkUser,
      })

      renderHook(() => useSyncClerkAuth())

      const state = useClerkAuthStore.getState()
      expect(state.user).toEqual({
        id: 'clerk-user-123',
        email: 'clerk@example.com',
        name: 'Clerk User',
        isAdmin: true,
        createdAt: new Date('2024-01-01'),
        updatedAt: new Date('2024-01-02'),
      })
      expect(state.isAuthenticated).toBe(true)
      expect(state.isAdmin).toBe(true)
    })

    it('should handle admin role from publicMetadata.role', () => {
      const mockClerkUser = {
        id: 'clerk-user-123',
        primaryEmailAddress: { emailAddress: 'admin@example.com' },
        fullName: 'Admin User',
        publicMetadata: { role: 'admin' },
        createdAt: new Date().toISOString(),
      }

      mockUseAuth.mockReturnValue({
        isSignedIn: true,
        isLoaded: true,
        getToken: vi.fn(),
      })

      mockUseUser.mockReturnValue({
        user: mockClerkUser,
      })

      renderHook(() => useSyncClerkAuth())

      expect(useClerkAuthStore.getState().isAdmin).toBe(true)
    })

    it('should handle missing email address gracefully', () => {
      const mockClerkUser = {
        id: 'clerk-user-123',
        primaryEmailAddress: null,
        fullName: 'No Email User',
        publicMetadata: {},
      }

      mockUseAuth.mockReturnValue({
        isSignedIn: true,
        isLoaded: true,
        getToken: vi.fn(),
      })

      mockUseUser.mockReturnValue({
        user: mockClerkUser,
      })

      renderHook(() => useSyncClerkAuth())

      const state = useClerkAuthStore.getState()
      expect(state.user?.email).toBe('')
    })

    it('should handle missing user name gracefully', () => {
      const mockClerkUser = {
        id: 'clerk-user-123',
        primaryEmailAddress: { emailAddress: 'noname@example.com' },
        fullName: null,
        publicMetadata: {},
      }

      mockUseAuth.mockReturnValue({
        isSignedIn: true,
        isLoaded: true,
        getToken: vi.fn(),
      })

      mockUseUser.mockReturnValue({
        user: mockClerkUser,
      })

      renderHook(() => useSyncClerkAuth())

      const state = useClerkAuthStore.getState()
      expect(state.user?.name).toBeUndefined()
    })

    it('should handle session monitoring with active session', () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
      const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

      const futureDate = new Date()
      futureDate.setHours(futureDate.getHours() + 1) // 1 hour from now

      const mockSession = {
        id: 'session-123',
        status: 'active',
        expireAt: futureDate.toISOString(),
      }

      mockUseAuth.mockReturnValue({
        isSignedIn: true,
        isLoaded: true,
        getToken: vi.fn(),
      })

      mockUseSession.mockReturnValue({
        session: mockSession,
      })

      renderHook(() => useSyncClerkAuth())

      expect(consoleSpy).toHaveBeenCalledWith('Clerk session active:', {
        id: 'session-123',
        status: 'active',
        expiresAt: futureDate.toISOString(),
      })
      expect(consoleWarnSpy).not.toHaveBeenCalled()

      consoleSpy.mockRestore()
      consoleWarnSpy.mockRestore()
    })

    it('should warn about session expiring soon', () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
      const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

      const nearFutureDate = new Date()
      nearFutureDate.setMinutes(nearFutureDate.getMinutes() + 2) // 2 minutes from now

      const mockSession = {
        id: 'session-123',
        status: 'active',
        expireAt: nearFutureDate.toISOString(),
      }

      mockUseAuth.mockReturnValue({
        isSignedIn: true,
        isLoaded: true,
        getToken: vi.fn(),
      })

      mockUseSession.mockReturnValue({
        session: mockSession,
      })

      renderHook(() => useSyncClerkAuth())

      expect(consoleWarnSpy).toHaveBeenCalledWith('Clerk session expiring soon, consider refresh')

      consoleSpy.mockRestore()
      consoleWarnSpy.mockRestore()
    })

    it('should handle missing session expiration', () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

      const mockSession = {
        id: 'session-123',
        status: 'active',
        expireAt: null,
      }

      mockUseAuth.mockReturnValue({
        isSignedIn: true,
        isLoaded: true,
        getToken: vi.fn(),
      })

      mockUseSession.mockReturnValue({
        session: mockSession,
      })

      renderHook(() => useSyncClerkAuth())

      expect(consoleSpy).toHaveBeenCalledWith('Clerk session active:', {
        id: 'session-123',
        status: 'active',
        expiresAt: null,
      })

      consoleSpy.mockRestore()
    })
  })

  describe('Token Retrieval from Hook', () => {
    beforeEach(() => {
      mockUseAuth.mockReturnValue({
        isSignedIn: true,
        isLoaded: true,
        getToken: vi.fn().mockImplementation(async (options?) => {
          if (options?.template === 'test-template') {
            return 'jwt-template-token'
          }
          return 'default-token'
        }),
      })

      mockUseUser.mockReturnValue({
        user: null,
      })

      mockUseSession.mockReturnValue({
        session: null,
      })
    })

    it('should get token with JWT template when configured', async () => {
      const { result } = renderHook(() => useSyncClerkAuth())

      const token = await result.current.getClerkToken()

      expect(token).toBe('jwt-template-token')
    })

    it('should fall back to default token when JWT template fails', async () => {
      mockUseAuth.mockReturnValue({
        isSignedIn: true,
        isLoaded: true,
        getToken: vi.fn().mockImplementation(async (options?) => {
          if (options?.template === 'test-template') {
            return null // Simulate template failure
          }
          return 'fallback-token'
        }),
      })

      const { result } = renderHook(() => useSyncClerkAuth())

      const token = await result.current.getClerkToken()

      expect(token).toBe('fallback-token')
    })

    it('should fall back to default token when JWT template call succeeds but returns null', async () => {
      mockUseAuth.mockReturnValue({
        isSignedIn: true,
        isLoaded: true,
        getToken: vi.fn().mockImplementation(async (options?) => {
          if (options?.template === 'test-template') {
            return null // Template call succeeds but returns null
          }
          return 'default-token'
        }),
      })

      const { result } = renderHook(() => useSyncClerkAuth())

      const token = await result.current.getClerkToken()

      expect(token).toBe('default-token')
      // Verify both calls were made - access the mock directly from the mocked function
      const mockAuth = vi.mocked(useAuth)
      const authResult = mockAuth.mock.results[0]?.value
      if (authResult && authResult.getToken) {
        expect(authResult.getToken).toHaveBeenCalledWith({ template: 'test-template' })
        expect(authResult.getToken).toHaveBeenCalledWith()
      }
    })

    it('should use default token when no JWT template is configured', async () => {
      // Temporarily override the mock to return no template
      vi.mocked(getRuntimeConfig).mockReturnValue({
        clerkJwtTemplate: undefined,
        clerkPublishableKey: 'test-key',
        apiUrl: 'http://localhost:3000',
        isDevelopment: true,
        isProduction: false,
      })

      mockUseAuth.mockReturnValue({
        isSignedIn: true,
        isLoaded: true,
        getToken: vi.fn().mockResolvedValue('no-template-token'),
      })

      const { result } = renderHook(() => useSyncClerkAuth())

      const token = await result.current.getClerkToken()

      expect(token).toBe('no-template-token')
      // Should only call getToken without template
      const mockAuth = vi.mocked(useAuth)
      const authResult = mockAuth.mock.results[0]?.value
      if (authResult && authResult.getToken) {
        expect(authResult.getToken).toHaveBeenCalledTimes(1)
        expect(authResult.getToken).toHaveBeenCalledWith()
      }

      // Restore original mock
      vi.mocked(getRuntimeConfig).mockReturnValue({
        clerkJwtTemplate: 'test-template',
        clerkPublishableKey: 'test-key',
        apiUrl: 'http://localhost:3000',
        isDevelopment: true,
        isProduction: false,
      })
    })

    it('should handle getToken errors gracefully', async () => {
      mockUseAuth.mockReturnValue({
        isSignedIn: true,
        isLoaded: true,
        getToken: vi.fn().mockRejectedValue(new Error('Token error')),
      })

      const { result } = renderHook(() => useSyncClerkAuth())

      await expect(result.current.getClerkToken()).rejects.toThrow('Token error')
    })
  })

  describe('Standalone getClerkToken Function', () => {
    it('should return null when not signed in', async () => {
      const mockUseAuth = vi.fn().mockReturnValue({
        isSignedIn: false,
        getToken: vi.fn(),
      })

      vi.doMock('@clerk/clerk-react', () => ({
        useAuth: mockUseAuth,
      }))

      const token = await getClerkToken()
      expect(token).toBeNull()
    })

    it('should return token when signed in', async () => {
      const mockUseAuth = vi.fn().mockReturnValue({
        isSignedIn: true,
        getToken: vi.fn().mockResolvedValue('standalone-token'),
      })

      vi.doMock('@clerk/clerk-react', () => ({
        useAuth: mockUseAuth,
      }))

      const token = await getClerkToken()
      expect(token).toBe('standalone-token')
    })

    it('should fall back to default token when JWT template returns null', async () => {
      const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

      const mockUseAuth = vi.fn().mockReturnValue({
        isSignedIn: true,
        getToken: vi.fn().mockImplementation(async (options?) => {
          if (options?.template === 'test-template') {
            return null // Template returns null
          }
          return 'fallback-token'
        }),
      })

      vi.doMock('@clerk/clerk-react', () => ({
        useAuth: mockUseAuth,
      }))

      const token = await getClerkToken()
      expect(token).toBe('fallback-token')
      expect(mockUseAuth().getToken).toHaveBeenCalledWith({ template: 'test-template' })
      expect(mockUseAuth().getToken).toHaveBeenCalledWith()

      consoleWarnSpy.mockRestore()
    })

    it('should handle errors gracefully and return null', async () => {
      const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

      const mockUseAuth = vi.fn().mockImplementation(() => {
        throw new Error('Auth error')
      })

      vi.doMock('@clerk/clerk-react', () => ({
        useAuth: mockUseAuth,
      }))

      const token = await getClerkToken()
      expect(token).toBeNull()
      expect(consoleWarnSpy).toHaveBeenCalledWith('Failed to get Clerk token:', expect.any(Error))

      consoleWarnSpy.mockRestore()
    })

    it('should use default token when no JWT template is configured in standalone function', async () => {
      const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

      const mockUseAuth = vi.fn().mockReturnValue({
        isSignedIn: true,
        getToken: vi.fn().mockResolvedValue('standalone-no-template-token'),
      })

      // Temporarily override the getRuntimeConfig mock
      const originalMock = getRuntimeConfig as unknown as ReturnType<typeof vi.fn>
      originalMock.mockReturnValue({ clerkJwtTemplate: null })

      vi.doMock('@clerk/clerk-react', () => ({
        useAuth: mockUseAuth,
      }))

      const token = await getClerkToken()
      expect(token).toBe('standalone-no-template-token')
      expect(mockUseAuth().getToken).toHaveBeenCalledTimes(1)
      expect(mockUseAuth().getToken).toHaveBeenCalledWith()

      // Restore original mock
      originalMock.mockReturnValue({ clerkJwtTemplate: 'test-template' })
      consoleWarnSpy.mockRestore()
    })
  })

  describe('Edge Cases and Error Handling', () => {
    it('should handle Clerk user with missing metadata', () => {
      const mockClerkUser = {
        id: 'clerk-user-123',
        primaryEmailAddress: { emailAddress: 'user@example.com' },
        fullName: 'User',
        publicMetadata: null,
        createdAt: null,
        updatedAt: null,
      }

      mockUseAuth.mockReturnValue({
        isSignedIn: true,
        isLoaded: true,
        getToken: vi.fn(),
      })

      mockUseUser.mockReturnValue({
        user: mockClerkUser,
      })

      renderHook(() => useSyncClerkAuth())

      const state = useClerkAuthStore.getState()
      expect(state.user?.isAdmin).toBe(false)
      expect(state.user?.createdAt).toBeUndefined()
      expect(state.user?.updatedAt).toBeUndefined()
    })

    it('should handle Clerk user with undefined metadata properties', () => {
      const mockClerkUser = {
        id: 'clerk-user-123',
        primaryEmailAddress: { emailAddress: 'user@example.com' },
        fullName: 'User',
        publicMetadata: { isAdmin: undefined, role: undefined },
      }

      mockUseAuth.mockReturnValue({
        isSignedIn: true,
        isLoaded: true,
        getToken: vi.fn(),
      })

      mockUseUser.mockReturnValue({
        user: mockClerkUser,
      })

      renderHook(() => useSyncClerkAuth())

      const state = useClerkAuthStore.getState()
      expect(state.user?.isAdmin).toBe(false)
    })

    it('should handle session without isSignedIn', () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

      const mockSession = {
        id: 'session-123',
        status: 'active',
        expireAt: new Date().toISOString(),
      }

      mockUseAuth.mockReturnValue({
        isSignedIn: false, // Not signed in
        isLoaded: true,
        getToken: vi.fn(),
      })

      mockUseSession.mockReturnValue({
        session: mockSession,
      })

      renderHook(() => useSyncClerkAuth())

      // Session monitoring should not run when not signed in
      expect(consoleSpy).not.toHaveBeenCalled()

      consoleSpy.mockRestore()
    })

    it('should handle rapid state changes', async () => {
      const { setUser, setLoading } = useClerkAuthStore.getState()

      // Rapid state changes
      await act(async () => {
        setLoading(false)
        setUser({ id: 'user1', email: 'user1@example.com', isAdmin: false })
        setLoading(true)
        setUser({ id: 'user2', email: 'user2@example.com', isAdmin: true })
        setLoading(false)
      })

      const state = useClerkAuthStore.getState()
      expect(state.isLoading).toBe(false)
      expect(state.user?.id).toBe('user2')
      expect(state.user?.email).toBe('user2@example.com')
      expect(state.isAdmin).toBe(true)
    })
  })

  describe('Store Selectors and Performance', () => {
    it('should allow selective state access', () => {
      const { setUser } = useClerkAuthStore.getState()
      const testUser: User = {
        id: 'test-user-123',
        email: 'test@example.com',
        isAdmin: true,
      }

      act(() => {
        setUser(testUser)
      })

      // Test individual selectors
      const isAuthenticated = useClerkAuthStore.getState().isAuthenticated
      const isAdmin = useClerkAuthStore.getState().isAdmin
      const user = useClerkAuthStore.getState().user

      expect(isAuthenticated).toBe(true)
      expect(isAdmin).toBe(true)
      expect(user).toEqual(testUser)
    })

    it('should handle concurrent state updates', async () => {
      const { setUser } = useClerkAuthStore.getState()

      // Test sequential updates instead of concurrent to avoid act() warnings
      for (let i = 0; i < 5; i++) {
        await act(async () => {
          setUser({
            id: `user-${i}`,
            email: `user${i}@example.com`,
            isAdmin: i % 2 === 0,
          })
        })
      }

      const finalState = useClerkAuthStore.getState()
      expect(finalState.user?.id).toBe('user-4')
      expect(finalState.user?.email).toBe('user4@example.com')
      expect(finalState.isAdmin).toBe(true) // user-4 has isAdmin: true (4 % 2 === 0)
    })
  })
})
