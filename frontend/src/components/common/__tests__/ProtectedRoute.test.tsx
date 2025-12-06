import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { ProtectedRoute } from '../ProtectedRoute'
import { useClerkAuthStore } from '@/stores/clerkAuthStore'

vi.mock('@/stores/clerkAuthStore', () => ({
  useClerkAuthStore: vi.fn(),
}))

vi.mock('@tanstack/react-router', () => ({
  Navigate: ({ to }: any) => <div>Navigate to {to}</div>,
}))

vi.mock('@/components/ui/card', () => ({
  Card: ({ children, className }: any) => <div className={className}>{children}</div>,
  CardHeader: ({ children }: any) => <div>{children}</div>,
  CardTitle: ({ children, className }: any) => <h3 className={className}>{children}</h3>,
  CardContent: ({ children, className }: any) => <div className={className}>{children}</div>,
}))

vi.mock('@/components/ui/alert', () => ({
  Alert: ({ children, variant }: any) => <div data-variant={variant}>{children}</div>,
  AlertDescription: ({ children }: any) => <p>{children}</p>,
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, onClick, className }: any) => (
    <button onClick={onClick} className={className}>
      {children}
    </button>
  ),
}))

vi.mock('lucide-react', () => ({
  AlertTriangle: () => <span>alert-triangle-icon</span>,
}))

describe('ProtectedRoute', () => {
  const mockUser = {
    id: '123',
    email: 'test@example.com',
    name: 'Test User',
    role: 'user' as const,
    isAdmin: false,
    mfaEnabled: false,
    createdAt: '2024-01-01',
  }

  beforeEach(() => {
    vi.clearAllMocks()

    // Mock window.location.href
    delete (window as any).location
    window.location = { href: '' } as any
  })

  it('should render children for authenticated user', () => {
    vi.mocked(useClerkAuthStore).mockReturnValue({
      isAuthenticated: true,
      user: mockUser,
    } as any)

    render(
      <ProtectedRoute user={mockUser}>
        <div>Protected Content</div>
      </ProtectedRoute>
    )

    expect(screen.getByText('Protected Content')).toBeInTheDocument()
  })

  it('should redirect unauthenticated user', () => {
    vi.mocked(useClerkAuthStore).mockReturnValue({
      isAuthenticated: false,
      user: null,
    } as any)

    render(
      <ProtectedRoute user={null}>
        <div>Protected Content</div>
      </ProtectedRoute>
    )

    expect(screen.getByText('Unauthorized')).toBeInTheDocument()
  })

  it('should allow admin access', () => {
    const adminUser = { ...mockUser, role: 'admin' as const, isAdmin: true }
    vi.mocked(useClerkAuthStore).mockReturnValue({
      isAuthenticated: true,
      user: adminUser,
    } as any)

    render(
      <ProtectedRoute user={adminUser} requiredRole="admin">
        <div>Admin Content</div>
      </ProtectedRoute>
    )

    expect(screen.getByText('Admin Content')).toBeInTheDocument()
  })

  it('should block non-admin from admin route', () => {
    vi.mocked(useClerkAuthStore).mockReturnValue({
      isAuthenticated: true,
      user: mockUser,
    } as any)

    render(
      <ProtectedRoute user={mockUser} requiredRole="admin">
        <div>Admin Content</div>
      </ProtectedRoute>
    )

    // Should not render admin content
    expect(screen.queryByText('Admin Content')).not.toBeInTheDocument()
  })

  it('should show loading spinner when isLoading is true', () => {
    vi.mocked(useClerkAuthStore).mockReturnValue({
      isAuthenticated: false,
      user: null,
    } as any)

    const { container } = render(
      <ProtectedRoute user={null} isLoading={true}>
        <div>Protected Content</div>
      </ProtectedRoute>
    )

    const spinner = container.querySelector('.animate-spin')
    expect(spinner).toBeInTheDocument()
  })

  it('should not render children when loading', () => {
    vi.mocked(useClerkAuthStore).mockReturnValue({
      isAuthenticated: false,
      user: null,
    } as any)

    render(
      <ProtectedRoute user={null} isLoading={true}>
        <div>Protected Content</div>
      </ProtectedRoute>
    )

    expect(screen.queryByText('Protected Content')).not.toBeInTheDocument()
  })

  it('should display unauthorized message for unauthenticated user', () => {
    vi.mocked(useClerkAuthStore).mockReturnValue({
      isAuthenticated: false,
      user: null,
    } as any)

    render(
      <ProtectedRoute user={null}>
        <div>Protected Content</div>
      </ProtectedRoute>
    )

    expect(screen.getByText('You must be logged in to access this page.')).toBeInTheDocument()
  })

  it('should display login button for unauthenticated user', () => {
    vi.mocked(useClerkAuthStore).mockReturnValue({
      isAuthenticated: false,
      user: null,
    } as any)

    render(
      <ProtectedRoute user={null}>
        <div>Protected Content</div>
      </ProtectedRoute>
    )

    expect(screen.getByText('Go to Login')).toBeInTheDocument()
  })

  it('should redirect to login when login button clicked', () => {
    vi.mocked(useClerkAuthStore).mockReturnValue({
      isAuthenticated: false,
      user: null,
    } as any)

    render(
      <ProtectedRoute user={null}>
        <div>Protected Content</div>
      </ProtectedRoute>
    )

    const loginButton = screen.getByText('Go to Login')
    fireEvent.click(loginButton)

    expect(window.location.href).toBe('/login')
  })

  it('should display access denied message for non-admin on admin route', () => {
    vi.mocked(useClerkAuthStore).mockReturnValue({
      isAuthenticated: true,
      user: mockUser,
    } as any)

    render(
      <ProtectedRoute user={mockUser} requiredRole="admin">
        <div>Admin Content</div>
      </ProtectedRoute>
    )

    expect(screen.getByText('Access Denied')).toBeInTheDocument()
  })

  it('should display permission denied message for non-admin', () => {
    vi.mocked(useClerkAuthStore).mockReturnValue({
      isAuthenticated: true,
      user: mockUser,
    } as any)

    render(
      <ProtectedRoute user={mockUser} requiredRole="admin">
        <div>Admin Content</div>
      </ProtectedRoute>
    )

    expect(screen.getByText(/You do not have permission to access this page/i)).toBeInTheDocument()
  })

  it('should display go back button for access denied', () => {
    vi.mocked(useClerkAuthStore).mockReturnValue({
      isAuthenticated: true,
      user: mockUser,
    } as any)

    render(
      <ProtectedRoute user={mockUser} requiredRole="admin">
        <div>Admin Content</div>
      </ProtectedRoute>
    )

    expect(screen.getByText('Go Back')).toBeInTheDocument()
  })

  it('should redirect to fallback route when go back clicked', () => {
    vi.mocked(useClerkAuthStore).mockReturnValue({
      isAuthenticated: true,
      user: mockUser,
    } as any)

    render(
      <ProtectedRoute user={mockUser} requiredRole="admin" fallbackRoute="/dashboard">
        <div>Admin Content</div>
      </ProtectedRoute>
    )

    const goBackButton = screen.getByText('Go Back')
    fireEvent.click(goBackButton)

    expect(window.location.href).toBe('/dashboard')
  })

  it('should redirect to root when go back clicked with no fallback', () => {
    vi.mocked(useClerkAuthStore).mockReturnValue({
      isAuthenticated: true,
      user: mockUser,
    } as any)

    render(
      <ProtectedRoute user={mockUser} requiredRole="admin">
        <div>Admin Content</div>
      </ProtectedRoute>
    )

    const goBackButton = screen.getByText('Go Back')
    fireEvent.click(goBackButton)

    expect(window.location.href).toBe('/')
  })

  it('should render alert triangle icon for unauthorized', () => {
    vi.mocked(useClerkAuthStore).mockReturnValue({
      isAuthenticated: false,
      user: null,
    } as any)

    render(
      <ProtectedRoute user={null}>
        <div>Protected Content</div>
      </ProtectedRoute>
    )

    expect(screen.getByText('alert-triangle-icon')).toBeInTheDocument()
  })

  it('should render alert triangle icon for access denied', () => {
    vi.mocked(useClerkAuthStore).mockReturnValue({
      isAuthenticated: true,
      user: mockUser,
    } as any)

    render(
      <ProtectedRoute user={mockUser} requiredRole="admin">
        <div>Admin Content</div>
      </ProtectedRoute>
    )

    expect(screen.getByText('alert-triangle-icon')).toBeInTheDocument()
  })

  it('should render user content when requiredRole is user', () => {
    vi.mocked(useClerkAuthStore).mockReturnValue({
      isAuthenticated: true,
      user: mockUser,
    } as any)

    render(
      <ProtectedRoute user={mockUser} requiredRole="user">
        <div>User Content</div>
      </ProtectedRoute>
    )

    expect(screen.getByText('User Content')).toBeInTheDocument()
  })

  it('should render admin content for admin user with default requiredRole', () => {
    const adminUser = { ...mockUser, role: 'admin' as const, isAdmin: true }
    vi.mocked(useClerkAuthStore).mockReturnValue({
      isAuthenticated: true,
      user: adminUser,
    } as any)

    render(
      <ProtectedRoute user={adminUser}>
        <div>Some Content</div>
      </ProtectedRoute>
    )

    expect(screen.getByText('Some Content')).toBeInTheDocument()
  })

  it('should use default fallbackRoute when not specified', () => {
    vi.mocked(useClerkAuthStore).mockReturnValue({
      isAuthenticated: true,
      user: mockUser,
    } as any)

    render(
      <ProtectedRoute user={mockUser} requiredRole="admin">
        <div>Admin Content</div>
      </ProtectedRoute>
    )

    const goBackButton = screen.getByText('Go Back')
    fireEvent.click(goBackButton)

    expect(window.location.href).toBe('/')
  })

  it('should render loading with correct styling', () => {
    vi.mocked(useClerkAuthStore).mockReturnValue({
      isAuthenticated: false,
      user: null,
    } as any)

    const { container } = render(
      <ProtectedRoute user={null} isLoading={true}>
        <div>Protected Content</div>
      </ProtectedRoute>
    )

    const loadingContainer = container.querySelector('.flex.items-center.justify-center')
    expect(loadingContainer).toBeInTheDocument()
  })

  it('should not show loading when isLoading is false', () => {
    vi.mocked(useClerkAuthStore).mockReturnValue({
      isAuthenticated: true,
      user: mockUser,
    } as any)

    const { container } = render(
      <ProtectedRoute user={mockUser} isLoading={false}>
        <div>Protected Content</div>
      </ProtectedRoute>
    )

    const spinner = container.querySelector('.animate-spin')
    expect(spinner).not.toBeInTheDocument()
  })

  it('should render multiple children', () => {
    vi.mocked(useClerkAuthStore).mockReturnValue({
      isAuthenticated: true,
      user: mockUser,
    } as any)

    render(
      <ProtectedRoute user={mockUser}>
        <div>First Child</div>
        <div>Second Child</div>
      </ProtectedRoute>
    )

    expect(screen.getByText('First Child')).toBeInTheDocument()
    expect(screen.getByText('Second Child')).toBeInTheDocument()
  })

  it('should display admin requirement message', () => {
    vi.mocked(useClerkAuthStore).mockReturnValue({
      isAuthenticated: true,
      user: mockUser,
    } as any)

    render(
      <ProtectedRoute user={mockUser} requiredRole="admin">
        <div>Admin Content</div>
      </ProtectedRoute>
    )

    expect(screen.getByText(/Only administrators can access this resource/i)).toBeInTheDocument()
  })
})
