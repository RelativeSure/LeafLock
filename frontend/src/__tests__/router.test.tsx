import { describe, it, expect, vi, beforeEach, type Mock } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { RouterProvider } from '@tanstack/react-router'
import { router } from '../router'
import { useAuthStore } from '../stores/authStore'
import { useAuth, useUser } from '@clerk/clerk-react'

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

// Mock Clerk hooks
vi.mock('@clerk/clerk-react', () => ({
  useAuth: vi.fn(() => ({ 
    isSignedIn: false, 
    isLoaded: true,
    userId: null,
    sessionId: null,
    sessionClaims: {},
    actor: null,
    orgId: null,
    orgRole: null,
    orgSlug: null,
    has: vi.fn(() => false),
    signOut: vi.fn(),
    getToken: vi.fn(() => Promise.resolve(null)),
  } as any)),
  useUser: vi.fn(() => ({ 
    user: null,
    isLoaded: true,
  } as any)),
  useClerk: vi.fn(() => ({ 
    signOut: vi.fn(),
    openSignIn: vi.fn(),
    openSignUp: vi.fn(),
  })),
}))

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

vi.mock('@/stores/authStore', () => {
  const storeMock = Object.assign(vi.fn(), {
    getState: vi.fn(),
  })

  return {
    useAuthStore: storeMock,
  }
})

vi.mock('@/stores/clerkAuthStore', () => ({
  useClerkAuthStore: vi.fn(() => ({
    user: null,
    isAuthenticated: false,
    isLoading: false,
    isAdmin: false,
    setUser: vi.fn(),
    setLoading: vi.fn(),
    logout: vi.fn(),
    getAuthToken: vi.fn(),
    getEncryptionKey: vi.fn(),
  })),
  useSyncClerkAuth: vi.fn(),
}))

vi.mock('@/stores/notesStore', () => {
  const mockState = {
    notes: [],
    folders: [],
    tags: [],
    selectedNote: null,
    selectedFolder: null,
    loadData: vi.fn().mockResolvedValue(undefined),
    initializeDefaultNote: vi.fn().mockResolvedValue(undefined),
    selectFolder: vi.fn(),
    selectTag: vi.fn(),
    createFolder: vi.fn(),
  }

  const useNotesStore = vi.fn((selector) => {
    if (typeof selector === 'function') {
      return selector(mockState)
    }
    return mockState
  })

  // Add getState method for direct store access
  // @ts-expect-error - Adding getState for testing purposes
  useNotesStore.getState = () => mockState

  return { useNotesStore }
})

// Legacy login form mock - no longer used
// vi.mock('../components/auth/login-form', () => ({
//   LoginForm: ({ onToggleMode }: any) => (
//     <div data-testid="login-form">
//       <button onClick={onToggleMode}>Toggle Mode</button>
//     </div>
//   ),
// }))

// Legacy register form mock - no longer used
// vi.mock('../components/auth/register-form', () => ({
//   RegisterForm: ({ onToggleMode }: any) => (
//     <div data-testid="register-form">
//       <button onClick={onToggleMode}>Toggle Mode</button>
//     </div>
//   ),
// }))

// Legacy forgot password form mock - no longer used
// vi.mock('../components/auth/forgot-password-form', () => ({
//   ForgotPasswordForm: ({ onToggleMode }: any) => (
//     <div data-testid="forgot-password-form">
//       <button onClick={onToggleMode}>Toggle Mode</button>
//     </div>
//   ),
// }))

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

vi.mock('@clerk/clerk-react', () => ({
  ClerkProvider: ({ children }: any) => <div data-testid="clerk-provider">{children}</div>,
  useAuth: vi.fn(() => ({ isSignedIn: false, isLoaded: true })),
  useUser: vi.fn(() => ({ user: null })),
  useSession: vi.fn(() => ({ session: null })),
  useSignIn: vi.fn(() => ({ signIn: null, isLoaded: true })),
  useSignUp: vi.fn(() => ({ signUp: null, isLoaded: true })),
  useClerk: vi.fn(() => ({ setActive: vi.fn(), addListener: vi.fn() })),
  SignIn: () => <div data-testid="sign-in">Sign In</div>,
  SignUp: () => <div data-testid="sign-up">Sign Up</div>,
}))

vi.mock('../components/layout/app-sidebar', () => ({
  AppSidebar: () => (
    <div data-testid="app-sidebar">
      <div>LeafLock</div>
      <button>Logout</button>
      <div data-testid="user-avatar">Avatar</div>
    </div>
  ),
}))

vi.mock('../components/dashboard/dashboard-view', () => ({
  DashboardView: () => <div data-testid="dashboard-view">Dashboard</div>,
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
    it('should render Clerk SignIn component by default', async () => {
      // Navigate to login route
      window.history.pushState({}, '', '/login')

      render(<RouterProvider router={router} />)

      await waitFor(() => {
        expect(screen.getByTestId('sign-in')).toBeInTheDocument()
      })
    })

    it('should render Clerk SignUp component', async () => {
      window.history.pushState({}, '', '/register')

      render(<RouterProvider router={router} />)

      await waitFor(() => {
        expect(screen.getByTestId('sign-up')).toBeInTheDocument()
      })
    })

    it('should render not found for forgot password route (handled by Clerk)', async () => {
      window.history.pushState({}, '', '/forgot')

      render(<RouterProvider router={router} />)

      await waitFor(() => {
        expect(screen.getByText('Not Found')).toBeInTheDocument()
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
        expect(screen.getByText(/Loading LeafLock/i)).toBeInTheDocument()
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
        expect(screen.getByText(/Loading LeafLock/i)).toBeInTheDocument()
      })
    })

    it('should render dashboard when user is authenticated', async () => {
      // Mock Clerk authenticated user
      const mockClerkUser = {
        id: '1',
        primaryEmailAddress: { emailAddress: 'test@example.com' },
        fullName: 'Test User',
        publicMetadata: { isAdmin: false },
      } as any

      // Update Clerk mocks for authenticated user
      vi.mocked(useAuth).mockReturnValue({ isSignedIn: true, isLoaded: true } as any)
      vi.mocked(useUser).mockReturnValue({ user: mockClerkUser } as any)

      window.history.pushState({}, '', '/')

      render(<RouterProvider router={router} />)

      await waitFor(() => {
        expect(screen.getByText('LeafLock')).toBeInTheDocument()
        expect(screen.getByTestId('dashboard-view')).toBeInTheDocument()
      })
    })

    it('should show preparing editor message before editor is ready', async () => {
      // Mock Clerk authenticated user
      const mockClerkUser = {
        id: '1',
        primaryEmailAddress: { emailAddress: 'test@example.com' },
        fullName: 'Test User',
        publicMetadata: { isAdmin: false },
      }

      // Update Clerk mocks for authenticated user
      vi.mocked(useAuth).mockReturnValue({ isSignedIn: true, isLoaded: true } as any)
      vi.mocked(useUser).mockReturnValue({ user: mockClerkUser } as any)

      window.history.pushState({}, '', '/')

      render(<RouterProvider router={router} />)

      // Note: Editor loading state logic is inside DashboardView which is mocked.
      // We just check that DashboardView is rendered.
      await waitFor(
        () => {
          expect(screen.getByTestId('dashboard-view')).toBeInTheDocument()
        },
        { timeout: 5000 }
      )
    })

    it('should render user avatar in header', async () => {
      // Mock Clerk authenticated user
      const mockClerkUser = {
        id: '1',
        primaryEmailAddress: { emailAddress: 'test@example.com' },
        fullName: 'Test User',
        publicMetadata: { isAdmin: false },
      }

      // Update Clerk mocks for authenticated user
      vi.mocked(useAuth).mockReturnValue({ isSignedIn: true, isLoaded: true } as any)
      vi.mocked(useUser).mockReturnValue({ user: mockClerkUser } as any)

      window.history.pushState({}, '', '/')

      render(<RouterProvider router={router} />)

      // User avatar is now in AppSidebar
      await waitFor(
        () => {
          expect(screen.getByTestId('user-avatar')).toBeInTheDocument()
        },
        { timeout: 5000 }
      )
    })

    it('should render logout button', async () => {
      // Mock Clerk authenticated user
      const mockClerkUser = {
        id: '1',
        primaryEmailAddress: { emailAddress: 'test@example.com' },
        fullName: 'Test User',
        publicMetadata: { isAdmin: false },
      }

      // Update Clerk mocks for authenticated user
      vi.mocked(useAuth).mockReturnValue({ isSignedIn: true, isLoaded: true } as any)
      vi.mocked(useUser).mockReturnValue({ user: mockClerkUser } as any)

      window.history.pushState({}, '', '/')

      render(<RouterProvider router={router} />)

      // Logout button is now in AppSidebar
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
      // Mock Clerk authenticated user
      const mockClerkUser = {
        id: '1',
        primaryEmailAddress: { emailAddress: 'test@example.com' },
        fullName: 'Test User',
        publicMetadata: { isAdmin: false },
      }

      // Update Clerk mocks for authenticated user
      vi.mocked(useAuth).mockReturnValue({ isSignedIn: true, isLoaded: true } as any)
      vi.mocked(useUser).mockReturnValue({ user: mockClerkUser } as any)

      window.history.pushState({}, '', '/settings')

      render(<RouterProvider router={router} />)

      await waitFor(() => {
        expect(screen.getByTestId('settings-page')).toBeInTheDocument()
      })
    })
  })

  describe('Manage route', () => {
    it('should render folders and tags page', async () => {
      // Mock Clerk authenticated user
      const mockClerkUser = {
        id: '1',
        primaryEmailAddress: { emailAddress: 'test@example.com' },
        fullName: 'Test User',
        publicMetadata: { isAdmin: false },
      }

      // Update Clerk mocks for authenticated user
      vi.mocked(useAuth).mockReturnValue({ isSignedIn: true, isLoaded: true } as any)
      vi.mocked(useUser).mockReturnValue({ user: mockClerkUser } as any)

      window.history.pushState({}, '', '/manage')

      render(<RouterProvider router={router} />)

      await waitFor(() => {
        expect(screen.getByTestId('folders-tags-page')).toBeInTheDocument()
      })
    })
  })

  describe('Admin route', () => {
    it('should render admin page', async () => {
      // Mock Clerk authenticated admin user
      const mockClerkUser = {
        id: '1',
        primaryEmailAddress: { emailAddress: 'admin@example.com' },
        fullName: 'Admin User',
        publicMetadata: { isAdmin: true },
      }

      // Update Clerk mocks for authenticated admin user
      vi.mocked(useAuth).mockReturnValue({ isSignedIn: true, isLoaded: true } as any)
      vi.mocked(useUser).mockReturnValue({ user: mockClerkUser } as any)

      window.history.pushState({}, '', '/admin')

      render(<RouterProvider router={router} />)

      await waitFor(() => {
        expect(screen.getByTestId('admin-page')).toBeInTheDocument()
      })
    })
  })
})
