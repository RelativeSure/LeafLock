import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
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

vi.mock('@/components/ui/navigation-menu', () => ({
  NavigationMenu: ({ children }: any) => <nav>{children}</nav>,
  NavigationMenuList: ({ children }: any) => <ul>{children}</ul>,
  NavigationMenuItem: ({ children }: any) => <li>{children}</li>,
  NavigationMenuTrigger: ({ children, className }: any) => (
    <button className={className}>{children}</button>
  ),
  NavigationMenuContent: ({ children }: any) => <div>{children}</div>,
  NavigationMenuLink: ({ children, asChild }: any) => {
    if (asChild) {
      return children
    }
    return <div>{children}</div>
  },
}))

vi.mock('lucide-react', () => ({
  FileText: () => <span>file-text-icon</span>,
  Tag: () => <span>tag-icon</span>,
  Settings: () => <span>settings-icon</span>,
  ShieldCheck: () => <span>shield-check-icon</span>,
  BookOpen: () => <span>book-open-icon</span>,
  Github: () => <span>github-icon</span>,
  ChevronDown: () => <span>chevron-down-icon</span>,
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

  it('should render Tools menu', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: mockUser,
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    render(<MainNavigation />)
    expect(screen.getByText('Tools')).toBeInTheDocument()
  })

  it('should render Resources menu', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: mockUser,
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    render(<MainNavigation />)
    expect(screen.getByText('Resources')).toBeInTheDocument()
  })

  it('should render Templates link in Tools menu', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: mockUser,
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    render(<MainNavigation />)
    expect(screen.getByText('Templates')).toBeInTheDocument()
  })

  it('should render Tags link in Tools menu', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: mockUser,
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    render(<MainNavigation />)
    expect(screen.getByText('Tags')).toBeInTheDocument()
  })

  it('should render Settings link in Tools menu', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: mockUser,
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    render(<MainNavigation />)
    expect(screen.getByText('Settings')).toBeInTheDocument()
  })

  it('should render Templates description', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: mockUser,
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    render(<MainNavigation />)
    expect(screen.getByText(/Manage and create note templates/i)).toBeInTheDocument()
  })

  it('should render Tags description', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: mockUser,
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    render(<MainNavigation />)
    expect(screen.getByText(/Organize your notes with custom tags/i)).toBeInTheDocument()
  })

  it('should render Settings description', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: mockUser,
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    render(<MainNavigation />)
    expect(screen.getByText(/Manage your account settings/i)).toBeInTheDocument()
  })

  it('should render Documentation link in Resources menu', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: mockUser,
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    render(<MainNavigation />)
    expect(screen.getByText('Documentation')).toBeInTheDocument()
  })

  it('should render GitHub link in Resources menu', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: mockUser,
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    render(<MainNavigation />)
    expect(screen.getByText('GitHub')).toBeInTheDocument()
  })

  it('should render Documentation description', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: mockUser,
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    render(<MainNavigation />)
    expect(screen.getByText(/Learn how to use LeafLock/i)).toBeInTheDocument()
  })

  it('should render GitHub description', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: mockUser,
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    render(<MainNavigation />)
    expect(screen.getByText(/View source code and contribute/i)).toBeInTheDocument()
  })

  it('should not render Admin menu for regular users', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: mockUser,
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    render(<MainNavigation />)
    expect(screen.queryByText('Admin')).not.toBeInTheDocument()
  })

  it('should render Admin menu for admin users', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: { ...mockUser, role: 'admin', isAdmin: true },
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    render(<MainNavigation />)
    expect(screen.getByText('Admin')).toBeInTheDocument()
  })

  it('should render Admin Dashboard link for admin users', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: { ...mockUser, role: 'admin', isAdmin: true },
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    render(<MainNavigation />)
    expect(screen.getByText('Admin Dashboard')).toBeInTheDocument()
  })

  it('should render Admin Dashboard description for admin users', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: { ...mockUser, role: 'admin', isAdmin: true },
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    render(<MainNavigation />)
    expect(screen.getByText(/Manage users, system settings/i)).toBeInTheDocument()
  })

  it('should have Templates link with correct href', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: mockUser,
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    const { container } = render(<MainNavigation />)
    const link = Array.from(container.querySelectorAll('a')).find((a) =>
      a.textContent?.includes('Templates')
    )
    expect(link).toHaveAttribute('href', '/templates')
  })

  it('should have Tags link with correct href', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: mockUser,
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    const { container } = render(<MainNavigation />)
    const link = Array.from(container.querySelectorAll('a')).find((a) =>
      a.textContent?.includes('Tags')
    )
    expect(link).toHaveAttribute('href', '/tags')
  })

  it('should have Settings link with correct href', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: mockUser,
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    const { container } = render(<MainNavigation />)
    const links = Array.from(container.querySelectorAll('a'))
    const settingsLink = links.find((a) => a.getAttribute('href') === '/settings')
    expect(settingsLink).toBeTruthy()
  })

  it('should have Documentation link as external', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: mockUser,
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    const { container } = render(<MainNavigation />)
    const link = Array.from(container.querySelectorAll('a')).find((a) =>
      a.textContent?.includes('Documentation')
    )
    expect(link).toHaveAttribute('target', '_blank')
    expect(link).toHaveAttribute('rel', 'noopener noreferrer')
  })

  it('should have GitHub link as external', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: mockUser,
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    const { container } = render(<MainNavigation />)
    const link = Array.from(container.querySelectorAll('a')).find((a) =>
      a.textContent?.includes('GitHub')
    )
    expect(link).toHaveAttribute('target', '_blank')
    expect(link).toHaveAttribute('rel', 'noopener noreferrer')
  })

  it('should have Documentation link with correct href', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: mockUser,
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    const { container } = render(<MainNavigation />)
    const link = Array.from(container.querySelectorAll('a')).find((a) =>
      a.textContent?.includes('Documentation')
    )
    expect(link).toHaveAttribute('href', 'https://docs.leaflock.app')
  })

  it('should have GitHub link with correct href', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: mockUser,
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    const { container } = render(<MainNavigation />)
    const link = Array.from(container.querySelectorAll('a')).find((a) =>
      a.textContent?.includes('GitHub')
    )
    expect(link).toHaveAttribute('href', 'https://github.com/RelativeSure/LeafLock')
  })

  it('should have Admin Dashboard link with correct href for admin', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: { ...mockUser, role: 'admin', isAdmin: true },
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    const { container } = render(<MainNavigation />)
    const link = Array.from(container.querySelectorAll('a')).find((a) =>
      a.textContent?.includes('Admin Dashboard')
    )
    expect(link).toHaveAttribute('href', '/admin')
  })

  it('should render icons for menu items', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: mockUser,
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    render(<MainNavigation />)
    expect(screen.getAllByText('file-text-icon').length).toBeGreaterThan(0)
    expect(screen.getAllByText('book-open-icon').length).toBeGreaterThan(0)
  })

  it('should render chevron down icons', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: mockUser,
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    render(<MainNavigation />)
    expect(screen.getAllByText('chevron-down-icon').length).toBeGreaterThan(0)
  })

  it('should render both external links correctly', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: mockUser,
      isAuthenticated: true,
      logout: vi.fn(),
    } as any)

    const { container } = render(<MainNavigation />)
    const externalLinks = Array.from(container.querySelectorAll('a[target="_blank"]'))
    expect(externalLinks.length).toBeGreaterThan(0)
  })

  it('should render navigation when user is null', () => {
    vi.mocked(useAuthStore).mockReturnValue({
      user: null,
      isAuthenticated: false,
      logout: vi.fn(),
    } as any)

    render(<MainNavigation />)
    expect(screen.getByText('Tools')).toBeInTheDocument()
    expect(screen.getByText('Resources')).toBeInTheDocument()
    expect(screen.queryByText('Admin')).not.toBeInTheDocument()
  })
})
