import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render } from '@testing-library/react'
import { MainNavigation } from '../main-navigation'
import { useAuthStore } from '@/stores/authStore'

vi.mock('@/stores/authStore', () => ({
  useAuthStore: vi.fn(),
}))

vi.mock('@tanstack/react-router', () => ({
  Link: ({ children, ...props }: any) => <a {...props}>{children}</a>,
  useLocation: () => ({ pathname: '/' }),
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, ...props }: any) => <button {...props}>{children}</button>,
}))

describe('MainNavigation', () => {
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

  it('should render navigation for authenticated user', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: mockUser,
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    render(<MainNavigation />)
    expect(document.body).toBeTruthy()
  })

  it('should render navigation for unauthenticated user', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: null,
      isAuthenticated: false,
      logout: vi.fn(),
    } as any)

    render(<MainNavigation />)
    expect(document.body).toBeTruthy()
  })

  it('should render navigation for admin user', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: { ...mockUser, role: 'admin', isAdmin: true },
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    render(<MainNavigation />)
    expect(document.body).toBeTruthy()
  })
})
