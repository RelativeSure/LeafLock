import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render } from '@testing-library/react'
import { AdminPage } from '../admin-page'
import { useAuthStore } from '@/stores/authStore'

vi.mock('@/stores/authStore', () => ({
  useAuthStore: vi.fn(),
}))

vi.mock('@/components/ui/card', () => ({
  Card: ({ children }: any) => <div data-testid="card">{children}</div>,
  CardHeader: ({ children }: any) => <div>{children}</div>,
  CardTitle: ({ children }: any) => <h3>{children}</h3>,
  CardDescription: ({ children }: any) => <p>{children}</p>,
  CardContent: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/tabs', () => ({
  Tabs: ({ children }: any) => <div data-testid="tabs">{children}</div>,
  TabsList: ({ children }: any) => <div>{children}</div>,
  TabsTrigger: ({ children }: any) => <button>{children}</button>,
  TabsContent: ({ children }: any) => <div>{children}</div>,
}))

describe('AdminPage', () => {
  const mockAdminUser = {
    id: '123',
    email: 'admin@example.com',
    name: 'Admin User',
    role: 'admin' as const,
    isAdmin: true,
    mfaEnabled: false,
    createdAt: '2024-01-01',
  }

  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(useAuthStore).mockReturnValue({
      user: mockAdminUser,
      isAuthenticated: true,
    } as any)
  })

  it('should render admin page', () => {
    const { getByTestId } = render(<AdminPage />)
    expect(getByTestId('card')).toBeInTheDocument()
  })

  it('should render tabs', () => {
    const { getByTestId } = render(<AdminPage />)
    expect(getByTestId('tabs')).toBeInTheDocument()
  })
})
