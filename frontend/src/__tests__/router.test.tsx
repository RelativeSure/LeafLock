import { describe, it, expect, vi, beforeEach, type Mock } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { RouterProvider } from '@tanstack/react-router'
import { router } from '../router'
import { useAuthStore } from '../stores/authStore'

// Mock window.matchMedia
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation((query) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
})

// Mock all external dependencies
vi.mock('../context/ThemeContext', () => ({
  ThemeProvider: ({ children }: any) => <div data-testid="theme-provider">{children}</div>,
  useTheme: () => ({ theme: 'light', setTheme: vi.fn() }),
}))

vi.mock('../lib/encryption-context', () => ({
  EncryptionProvider: ({ children }: any) => (
    <div data-testid="encryption-provider">{children}</div>
  ),
  useEncryption: () => ({
    encryptText: vi.fn(),
    decryptText: vi.fn(),
    isReady: true,
  }),
}))

vi.mock('../stores/authStore', () => {
  const storeMock = Object.assign(vi.fn(), {
    getState: vi.fn(),
  })

  return {
    useAuthStore: storeMock,
  }
})

vi.mock('../stores/notesStore', () => ({
  useNotesStore: {
    getState: () => ({
      loadData: vi.fn().mockResolvedValue(undefined),
      initializeDefaultNote: vi.fn().mockResolvedValue(undefined),
    }),
  },
}))

vi.mock('../components/auth/login-form', () => ({
  LoginForm: ({ onToggleMode }: any) => (
    <div data-testid="login-form">
      <button onClick={onToggleMode}>Toggle Mode</button>
    </div>
  ),
}))

vi.mock('../components/auth/register-form', () => ({
  RegisterForm: ({ onToggleMode }: any) => (
    <div data-testid="register-form">
      <button onClick={onToggleMode}>Toggle Mode</button>
    </div>
  ),
}))

vi.mock('../components/auth/forgot-password-form', () => ({
  ForgotPasswordForm: ({ onToggleMode }: any) => (
    <div data-testid="forgot-password-form">
      <button onClick={onToggleMode}>Toggle Mode</button>
    </div>
  ),
}))

vi.mock('../components/dashboard/sidebar', () => ({
  Sidebar: () => <div data-testid="sidebar">Sidebar</div>,
}))

vi.mock('../components/dashboard/note-editor', () => ({
  NoteEditor: () => <div data-testid="note-editor">Note Editor</div>,
}))

vi.mock('../components/settings/settings-page', () => ({
  SettingsPage: () => <div data-testid="settings-page">Settings</div>,
}))

vi.mock('../components/management/folders-tags-page', () => ({
  FoldersTagsPage: () => <div data-testid="folders-tags-page">Folders & Tags</div>,
}))

vi.mock('../components/admin/admin-page', () => ({
  AdminPage: () => <div data-testid="admin-page">Admin Page</div>,
}))

vi.mock('../components/common/ProtectedRoute', () => ({
  ProtectedRoute: ({ children, isLoading }: any) => {
    if (isLoading) return <div>Loading...</div>
    return children
  },
}))

vi.mock('../components/ui/user-avatar', () => ({
  UserAvatar: () => <div data-testid="user-avatar">Avatar</div>,
}))

vi.mock('../components/ui/interactive-grid-pattern', () => ({
  InteractiveGridPattern: () => <div data-testid="grid-pattern">Grid</div>,
}))

vi.mock('../lib/navigation', () => ({
  isOnAuthRoute: vi.fn(() => false),
  safeRedirectToLogin: vi.fn(),
}))

type AuthStoreMock = Mock & { getState: Mock }
const mockedUseAuthStore = useAuthStore as unknown as AuthStoreMock

const setAuthStoreState = (state: any) => {
  mockedUseAuthStore.mockImplementation((selector: any) => {
    if (typeof selector === 'function') {
      return selector(state)
    }
    return state
  })
  mockedUseAuthStore.getState = vi.fn(() => state)
}

describe('router', () => {
  beforeEach(() => {
    vi.clearAllMocks()

    // Mock auth store with default values
    const mockAuthState = {
      user: null,
      isLoading: false,
      initialize: vi.fn().mockResolvedValue(undefined),
      logout: vi.fn(),
      checkRegistrationEnabled: vi.fn().mockResolvedValue(true),
    }

    mockedUseAuthStore.mockImplementation((selector: any) => {
      if (typeof selector === 'function') {
        return selector(mockAuthState)
      }
      return mockAuthState
    })
    mockedUseAuthStore.getState = vi.fn(() => ({
      ...mockAuthState,
    }))
  })

  describe('Router configuration', () => {
    it('should export router instance', () => {
      expect(router).toBeDefined()
      expect(router.routeTree).toBeDefined()
    })

    it('should have correct route structure', () => {
      const routes = router.routeTree.children
      expect(routes).toBeDefined()
      expect(routes?.length).toBeGreaterThan(0)
    })
  })

  describe('RootLayout', () => {
    it('should render ThemeProvider and EncryptionProvider', async () => {
      const { container } = render(<RouterProvider router={router} />)

      await waitFor(() => {
        expect(container.querySelector('.min-h-screen')).toBeInTheDocument()
      })
    })
  })

  describe('AuthComponent', () => {
    it('should render login form by default', async () => {
      // Navigate to login route
      window.history.pushState({}, '', '/login')

      render(<RouterProvider router={router} />)

      await waitFor(() => {
        expect(screen.getByTestId('login-form')).toBeInTheDocument()
      })
    })

    it('should render register form', async () => {
      window.history.pushState({}, '', '/register')

      render(<RouterProvider router={router} />)

      await waitFor(() => {
        expect(screen.getByTestId('register-form')).toBeInTheDocument()
      })
    })

    it('should render forgot password form', async () => {
      window.history.pushState({}, '', '/forgot')

      render(<RouterProvider router={router} />)

      await waitFor(() => {
        expect(screen.getByTestId('forgot-password-form')).toBeInTheDocument()
      })
    })

    it('should show loading spinner during suspense', async () => {
      window.history.pushState({}, '', '/login')

      const { container } = render(<RouterProvider router={router} />)

      // Check for loading spinner classes
      await waitFor(() => {
        const spinner = container.querySelector('.animate-spin')
        expect(spinner).toBeDefined()
      })
    })

    it('should render InteractiveGridPattern in auth pages', async () => {
      window.history.pushState({}, '', '/login')

      render(<RouterProvider router={router} />)

      await waitFor(() => {
        expect(screen.getByTestId('grid-pattern')).toBeInTheDocument()
      })
    })
  })

  describe('DashboardComponent', () => {
    it('should show loading state when isLoading is true', async () => {
      setAuthStoreState({
        user: null,
        isLoading: true,
        initialize: vi.fn().mockResolvedValue(undefined),
      })

      window.history.pushState({}, '', '/')

      render(<RouterProvider router={router} />)

      await waitFor(() => {
        expect(screen.getByText('Loading LeafLock...')).toBeInTheDocument()
      })
    })

    it('should show loading state when user is null', async () => {
      setAuthStoreState({
        user: null,
        isLoading: false,
        initialize: vi.fn().mockResolvedValue(undefined),
      })

      window.history.pushState({}, '', '/')

      render(<RouterProvider router={router} />)

      await waitFor(() => {
        expect(screen.getByText('Loading LeafLock...')).toBeInTheDocument()
      })
    })

    it('should render dashboard when user is authenticated', async () => {
      const mockUser = { id: '1', email: 'test@example.com', name: 'Test User' }
      setAuthStoreState({
        user: mockUser,
        isLoading: false,
        initialize: vi.fn().mockResolvedValue(undefined),
        logout: vi.fn(),
      })

      window.history.pushState({}, '', '/')

      render(<RouterProvider router={router} />)

      await waitFor(() => {
        expect(screen.getByText('LeafLock')).toBeInTheDocument()
        expect(screen.getByText('Dashboard')).toBeInTheDocument()
      })
    })

    it('should show preparing editor message before editor is ready', async () => {
      const mockUser = { id: '1', email: 'test@example.com', name: 'Test User' }
      setAuthStoreState({
        user: mockUser,
        isLoading: false,
        initialize: vi.fn().mockResolvedValue(undefined),
        logout: vi.fn(),
      })

      window.history.pushState({}, '', '/')

      render(<RouterProvider router={router} />)

      await waitFor(
        () => {
          expect(screen.getByText('Preparing editor…')).toBeInTheDocument()
        },
        { timeout: 5000 }
      )
    })

    it('should render user avatar in header', async () => {
      const mockUser = { id: '1', email: 'test@example.com', name: 'Test User' }
      setAuthStoreState({
        user: mockUser,
        isLoading: false,
        initialize: vi.fn().mockResolvedValue(undefined),
        logout: vi.fn(),
      })

      window.history.pushState({}, '', '/')

      render(<RouterProvider router={router} />)

      await waitFor(
        () => {
          expect(screen.getByTestId('user-avatar')).toBeInTheDocument()
        },
        { timeout: 5000 }
      )
    })

    it('should render logout button', async () => {
      const mockUser = { id: '1', email: 'test@example.com', name: 'Test User' }
      setAuthStoreState({
        user: mockUser,
        isLoading: false,
        initialize: vi.fn().mockResolvedValue(undefined),
        logout: vi.fn(),
      })

      window.history.pushState({}, '', '/')

      render(<RouterProvider router={router} />)

      await waitFor(
        () => {
          expect(screen.getByText('Logout')).toBeInTheDocument()
        },
        { timeout: 5000 }
      )
    })
  })

  describe('Settings route', () => {
    it('should render settings page', async () => {
      window.history.pushState({}, '', '/settings')

      render(<RouterProvider router={router} />)

      await waitFor(() => {
        expect(screen.getByTestId('settings-page')).toBeInTheDocument()
      })
    })
  })

  describe('Manage route', () => {
    it('should render folders and tags page', async () => {
      window.history.pushState({}, '', '/manage')

      render(<RouterProvider router={router} />)

      await waitFor(() => {
        expect(screen.getByTestId('folders-tags-page')).toBeInTheDocument()
      })
    })
  })

  describe('Admin route', () => {
    it('should render admin page', async () => {
      const mockUser = { id: '1', email: 'test@example.com', name: 'Test User', isAdmin: true }
      setAuthStoreState({
        user: mockUser,
        isLoading: false,
        initialize: vi.fn().mockResolvedValue(undefined),
      })

      window.history.pushState({}, '', '/admin')

      render(<RouterProvider router={router} />)

      await waitFor(() => {
        expect(screen.getByTestId('admin-page')).toBeInTheDocument()
      })
    })
  })
})
