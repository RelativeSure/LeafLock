import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render } from '@testing-library/react'
import { SettingsPage } from '../settings-page'
import { useAuthStore } from '@/stores/authStore'
import { useSettingsStore } from '@/stores/settingsStore'

vi.mock('@/stores/authStore', () => ({
  useAuthStore: vi.fn(),
}))

vi.mock('@/stores/settingsStore', () => ({
  useSettingsStore: vi.fn(),
}))

// Mock all UI components
vi.mock('@/components/ui/tabs', () => ({
  Tabs: ({ children }: any) => <div data-testid="tabs">{children}</div>,
  TabsList: ({ children }: any) => <div data-testid="tabs-list">{children}</div>,
  TabsTrigger: ({ children }: any) => <button>{children}</button>,
  TabsContent: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/card', () => ({
  Card: ({ children }: any) => <div data-testid="card">{children}</div>,
  CardHeader: ({ children }: any) => <div>{children}</div>,
  CardTitle: ({ children }: any) => <h3>{children}</h3>,
  CardDescription: ({ children }: any) => <p>{children}</p>,
  CardContent: ({ children }: any) => <div>{children}</div>,
}))

describe('SettingsPage', () => {
  const mockUser = {
    id: '123',
    email: 'test@example.com',
    name: 'Test User',
    role: 'user' as const,
    isAdmin: false,
    mfaEnabled: false,
    createdAt: '2024-01-01T00:00:00Z',
  }

  const mockSettings = {
    theme: 'light' as const,
    profilePicture: {
      type: 'gravatar' as const,
      customUrl: null,
    },
    defaultNoteBehavior: 'last-seen' as const,
  }

  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(useAuthStore).mockReturnValue({
      user: mockUser,
      isAuthenticated: true,
    } as any)

    vi.mocked(useSettingsStore).mockReturnValue({
      settings: mockSettings,
      updateSettings: vi.fn(),
    } as any)
  })

  it('should render settings page', () => {
    const { getByTestId } = render(<SettingsPage />)
    expect(getByTestId('tabs')).toBeInTheDocument()
  })

  it('should render with user', () => {
    const { getByTestId } = render(<SettingsPage />)
    expect(getByTestId('tabs')).toBeInTheDocument()
  })

  it('should render tabs list', () => {
    const { getByTestId } = render(<SettingsPage />)
    expect(getByTestId('tabs-list')).toBeInTheDocument()
  })
})
