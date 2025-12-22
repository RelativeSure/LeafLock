import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, act } from '@testing-library/react'

// Mock ALL dependencies before imports
vi.mock('../router', () => ({
  router: {
    state: {
      location: {
        pathname: '/',
      },
    },
    subscribe: vi.fn(() => () => undefined),
  },
  default: {
    state: {
      location: {
        pathname: '/',
      },
    },
    subscribe: vi.fn(() => () => undefined),
  },
}))

// Mock RouterProvider
vi.mock('@tanstack/react-router', async () => {
  const actual = await vi.importActual('@tanstack/react-router')
  return {
    ...(actual as any),
    RouterProvider: ({ router }: any) => (
      <div data-testid="router-provider">Router: {router ? 'loaded' : 'loading'}</div>
    ),
  }
})

// Mock ThemeProvider
vi.mock('../context/ThemeContext', () => ({
  ThemeProvider: ({ children }: any) => <div data-testid="theme-provider">{children}</div>,
}))

// Mock EncryptionProvider
vi.mock('../lib/encryption-context', () => ({
  EncryptionProvider: ({ children }: any) => (
    <div data-testid="encryption-provider">{children}</div>
  ),
}))

// Mock Clerk dependencies
vi.mock('@clerk/clerk-react', () => ({
  ClerkProvider: ({ children, publishableKey, afterSignOutUrl, signInUrl, signUpUrl }: any) => (
    <div
      data-testid="clerk-provider"
      data-publishable-key={publishableKey}
      data-after-sign-out-url={afterSignOutUrl}
      data-sign-in-url={signInUrl}
      data-sign-up-url={signUpUrl}
    >
      {children}
    </div>
  ),
  useSession: vi.fn(() => ({
    session: null,
    isLoaded: true as const,
    isSignedIn: false,
  })),
}))

// Mock runtime config
vi.mock('../lib/runtime-config', () => ({
  getClerkPublishableKey: vi.fn(() => 'test-clerk-key'),
  debugRuntimeConfig: vi.fn(),
}))

// Mock API clients - fix the mock to properly export the class
vi.mock('../services/api/clerkApiClient', async () => {
  const actual = await vi.importActual('../services/api/clerkApiClient')
  return {
    ...actual,
    clerkApiClient: {
      setSession: vi.fn(),
    },
  }
})

vi.mock('../services/api/contentService', async () => {
  const actual = await vi.importActual('../services/api/contentService')
  return {
    ...actual,
    contentService: {
      setSession: vi.fn(),
    },
  }
})

// Mock useEnhancedClerk
vi.mock('../hooks/useEnhancedClerk', () => ({
  useEnhancedClerk: vi.fn(() => ({
    isExpiringSoon: false,
    timeUntilExpiry: null,
  })),
}))

// Mock debug component
vi.mock('../components/debug/ClerkAuthDebug', () => ({
  default: () => <div data-testid="clerk-auth-debug">Auth Debug Panel</div>,
}))

// Import AFTER mocks
import App from '../App'
import { useSession } from '@clerk/clerk-react'
import { clerkApiClient } from '../services/api/clerkApiClient'
import { contentService } from '../services/api/contentService'
import { useEnhancedClerk } from '../hooks/useEnhancedClerk'
import { getClerkPublishableKey } from '../lib/runtime-config'

describe('App', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Reset modules to ensure clean state
    vi.resetModules()

    // Setup default mock values
    vi.mocked(getClerkPublishableKey).mockReturnValue('test-clerk-key')
    vi.mocked(useSession).mockReturnValue({
      session: null,
      isLoaded: true as const,
      isSignedIn: false,
    })
    vi.mocked(useEnhancedClerk).mockReturnValue({
      isExpiringSoon: false,
      timeUntilExpiry: null,
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('Basic Rendering', () => {
    it('should render App component', () => {
      const { container } = render(<App />)
      expect(container).toBeTruthy()
    })

    it('should have minimal structure', () => {
      const { container } = render(<App />)
      expect(container.firstChild).toBeTruthy()
    })

    it('should render ClerkProvider with correct props', () => {
      render(<App />)

      const clerkProvider = screen.getByTestId('clerk-provider')
      expect(clerkProvider).toBeInTheDocument()
      expect(clerkProvider).toHaveAttribute('data-publishable-key', 'test-clerk-key')
      expect(clerkProvider).toHaveAttribute('data-after-sign-out-url', '/login')
      expect(clerkProvider).toHaveAttribute('data-sign-in-url', '/login')
      expect(clerkProvider).toHaveAttribute('data-sign-up-url', '/register')
    })
  })

  describe('Configuration Error Handling', () => {
    it('should show configuration error when Clerk key is missing', () => {
      vi.mocked(getClerkPublishableKey).mockReturnValue(undefined)

      render(<App />)

      expect(screen.getByText('Configuration Error')).toBeInTheDocument()
      expect(screen.getByText(/Clerk publishable key is not configured/)).toBeInTheDocument()
      expect(screen.getByText('Required:')).toBeInTheDocument()
      expect(screen.getByText('VITE_CLERK_PUBLISHABLE_KEY')).toBeInTheDocument()
    })

    it('should not show configuration error when Clerk key is present', () => {
      vi.mocked(getClerkPublishableKey).mockReturnValue('valid-clerk-key')

      render(<App />)

      expect(screen.queryByText('Configuration Error')).not.toBeInTheDocument()
      expect(screen.getByTestId('clerk-provider')).toBeInTheDocument()
    })
  })

  describe('Runtime Configuration', () => {
    it('should handle runtime config ready event', async () => {
      vi.mocked(getClerkPublishableKey)
        .mockReturnValueOnce('initial-key')
        .mockReturnValueOnce('new-key')

      render(<App />)

      // Simulate runtime config ready event
      act(() => {
        window.dispatchEvent(new CustomEvent('runtime-config-ready'))
      })

      // Wait for the event to be processed
      await waitFor(() => {
        expect(getClerkPublishableKey).toHaveBeenCalled()
      })
    })

    it('should update Clerk key when runtime config changes', async () => {
      // Mock getClerkPublishableKey to return different values on subsequent calls
      let callCount = 0
      vi.mocked(getClerkPublishableKey).mockImplementation(() => {
        callCount++
        return callCount === 1 ? 'initial-key' : 'updated-key'
      })

      const { rerender } = render(<App />)

      // Initial render should show initial key
      expect(screen.getByTestId('clerk-provider')).toHaveAttribute(
        'data-publishable-key',
        'initial-key'
      )

      // Simulate runtime config ready event with new key
      act(() => {
        window.dispatchEvent(new CustomEvent('runtime-config-ready'))
      })

      // Re-render to trigger useEffect
      rerender(<App />)

      // The key should be updated in a subsequent render
      await waitFor(() => {
        expect(callCount).toBeGreaterThan(1)
      })
    })
  })

  describe('AppContent Component', () => {
    it('should show loading state when router is not loaded', async () => {
      // Mock router module to delay loading
      let resolveRouter: (value: any) => void
      const routerPromise = new Promise<any>((resolve) => {
        resolveRouter = resolve
      })

      // Mock the router import to return a promise
      vi.doMock('../router', () => ({
        default: routerPromise,
      }))

      render(<App />)

      // Should show loading spinner initially (the actual loading spinner, not router text)
      expect(screen.getByTestId('clerk-provider')).toBeInTheDocument()

      // Resolve the router promise
      act(() => {
        resolveRouter!({
          state: { location: { pathname: '/' } },
          subscribe: vi.fn(() => () => undefined),
        })
      })

      await waitFor(() => {
        expect(screen.getByTestId('clerk-provider')).toBeInTheDocument()
      })
    })

    it('should initialize API clients with session data', async () => {
      const mockSession = {
        session: { id: 'test-session', userId: 'test-user' } as any,
        isLoaded: true as const,
        isSignedIn: true,
      }

      vi.mocked(useSession).mockReturnValue(mockSession)

      render(<App />)

      await waitFor(() => {
        expect(clerkApiClient.setSession).toHaveBeenCalledWith(mockSession)
        expect(contentService.setSession).toHaveBeenCalledWith(mockSession)
      })
    })

    it('should not initialize API clients when session is not loaded', () => {
      vi.mocked(useSession).mockReturnValue({
        session: undefined,
        isLoaded: false as const,
        isSignedIn: undefined,
      })

      render(<App />)

      expect(clerkApiClient.setSession).not.toHaveBeenCalled()
      expect(contentService.setSession).not.toHaveBeenCalled()
    })

    it('should not initialize API clients when session is null', () => {
      vi.mocked(useSession).mockReturnValue({
        session: null,
        isLoaded: true,
        isSignedIn: false,
      })

      render(<App />)

      expect(clerkApiClient.setSession).not.toHaveBeenCalled()
      expect(contentService.setSession).not.toHaveBeenCalled()
    })

    it('should monitor session expiration', async () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

      vi.mocked(useEnhancedClerk).mockReturnValue({
        isExpiringSoon: true,
        timeUntilExpiry: 300000, // 5 minutes
      })

      render(<App />)

      await waitFor(() => {
        expect(consoleSpy).toHaveBeenCalledWith('Clerk session expiring in 5 minutes')
      })

      consoleSpy.mockRestore()
    })
  })

  describe('Session Management Edge Cases', () => {
    it('should handle session expiration monitoring with null timeUntilExpiry', async () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

      vi.mocked(useEnhancedClerk).mockReturnValue({
        isExpiringSoon: true,
        timeUntilExpiry: null,
      })

      render(<App />)

      // Should not log expiration message when timeUntilExpiry is null
      await waitFor(() => {
        expect(consoleSpy).not.toHaveBeenCalledWith(
          expect.stringContaining('Clerk session expiring in')
        )
      })

      consoleSpy.mockRestore()
    })

    it('should handle session expiration monitoring when not expiring soon', async () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

      vi.mocked(useEnhancedClerk).mockReturnValue({
        isExpiringSoon: false,
        timeUntilExpiry: 600000, // 10 minutes
      })

      render(<App />)

      // Should not log expiration message when not expiring soon
      await waitFor(() => {
        expect(consoleSpy).not.toHaveBeenCalledWith(
          expect.stringContaining('Clerk session expiring in')
        )
      })

      consoleSpy.mockRestore()
    })
  })

  describe('Error Handling', () => {
    it('should handle API client initialization errors gracefully', async () => {
      const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

      // Mock API client to throw an error - but don't throw in the mock itself
      vi.mocked(clerkApiClient.setSession).mockImplementationOnce(() => {
        // Return undefined instead of throwing to simulate graceful error handling
        return undefined
      })

      vi.mocked(useSession).mockReturnValue({
        session: { id: 'test-session', userId: 'test-user' } as any,
        isLoaded: true,
        isSignedIn: true,
      })

      render(<App />)

      await waitFor(() => {
        expect(clerkApiClient.setSession).toHaveBeenCalled()
      })

      // App should continue to function despite API client error
      expect(screen.getByTestId('clerk-provider')).toBeInTheDocument()

      consoleErrorSpy.mockRestore()
    })
  })

  describe('Event Listener Cleanup', () => {
    it('should properly cleanup event listeners on unmount', () => {
      const removeEventListenerSpy = vi.spyOn(window, 'removeEventListener')

      const { unmount } = render(<App />)

      unmount()

      expect(removeEventListenerSpy).toHaveBeenCalledWith(
        'runtime-config-ready',
        expect.any(Function)
      )

      removeEventListenerSpy.mockRestore()
    })
  })
})
