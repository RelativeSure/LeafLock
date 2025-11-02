import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ProtectedRoute } from '../ProtectedRoute'
import { useAuthStore } from '@/stores/authStore'

vi.mock('@/stores/authStore', () => ({
  useAuthStore: vi.fn(),
}))

vi.mock('@tanstack/react-router', () => ({
  Navigate: ({ to }: any) => <div>Navigate to {to}</div>,
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
  })

  it('should render children for authenticated user', () => {
    vi.mocked(useAuthStore).mockReturnValue({
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
    vi.mocked(useAuthStore).mockReturnValue({
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
    vi.mocked(useAuthStore).mockReturnValue({
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
    vi.mocked(useAuthStore).mockReturnValue({
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
})
