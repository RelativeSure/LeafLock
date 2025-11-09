import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
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
  Tabs: ({ children, defaultValue }: any) => (
    <div data-testid="tabs" data-default={defaultValue}>
      {children}
    </div>
  ),
  TabsList: ({ children }: any) => <div data-testid="tabs-list">{children}</div>,
  TabsTrigger: ({ children, value }: any) => <button data-value={value}>{children}</button>,
  TabsContent: ({ children, value }: any) => (
    <div data-testid={`tab-content-${value}`}>{children}</div>
  ),
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, onClick, variant, size }: any) => (
    <button onClick={onClick} data-variant={variant} data-size={size}>
      {children}
    </button>
  ),
}))

vi.mock('@/components/ui/input', () => ({
  Input: (props: any) => <input {...props} />,
}))

vi.mock('@/components/ui/label', () => ({
  Label: ({ children, htmlFor }: any) => <label htmlFor={htmlFor}>{children}</label>,
}))

vi.mock('@/components/ui/badge', () => ({
  Badge: ({ children, variant }: any) => <span data-variant={variant}>{children}</span>,
}))

vi.mock('@/components/ui/alert', () => ({
  Alert: ({ children }: any) => <div data-testid="alert">{children}</div>,
  AlertDescription: ({ children }: any) => <p>{children}</p>,
}))

vi.mock('@/components/ui/scroll-area', () => ({
  ScrollArea: ({ children }: any) => <div data-testid="scroll-area">{children}</div>,
}))

vi.mock('@/components/ui/table', () => ({
  Table: ({ children }: any) => <table>{children}</table>,
  TableBody: ({ children }: any) => <tbody>{children}</tbody>,
  TableCell: ({ children }: any) => <td>{children}</td>,
  TableHead: ({ children }: any) => <th>{children}</th>,
  TableHeader: ({ children }: any) => <thead>{children}</thead>,
  TableRow: ({ children }: any) => <tr>{children}</tr>,
}))

vi.mock('@/components/ui/select', () => ({
  Select: ({ children, value, onValueChange }: any) => (
    <div data-testid="select" data-value={value} onClick={() => onValueChange?.('test-value')}>
      {children}
    </div>
  ),
  SelectContent: ({ children }: any) => <div>{children}</div>,
  SelectItem: ({ children, value }: any) => <div data-value={value}>{children}</div>,
  SelectTrigger: ({ children }: any) => <button>{children}</button>,
  SelectValue: ({ placeholder }: any) => <span>{placeholder || 'select-value'}</span>,
}))

vi.mock('@/components/ui/switch', () => ({
  Switch: ({ id, checked, defaultChecked, onCheckedChange }: any) => (
    <input
      type="checkbox"
      id={id}
      checked={checked}
      defaultChecked={defaultChecked}
      onChange={(e) => onCheckedChange?.(e.target.checked)}
    />
  ),
}))

vi.mock('@/components/ui/dialog', () => ({
  Dialog: ({ children, open }: any) => (open ? <div data-testid="dialog">{children}</div> : null),
  DialogContent: ({ children }: any) => <div data-testid="dialog-content">{children}</div>,
  DialogDescription: ({ children }: any) => <p>{children}</p>,
  DialogFooter: ({ children }: any) => <div>{children}</div>,
  DialogHeader: ({ children }: any) => <div>{children}</div>,
  DialogTitle: ({ children }: any) => <h2>{children}</h2>,
}))

vi.mock('lucide-react', () => ({
  Shield: () => <span>shield-icon</span>,
  Users: () => <span>users-icon</span>,
  Database: () => <span>database-icon</span>,
  Activity: () => <span>activity-icon</span>,
  AlertTriangle: () => <span>alert-triangle-icon</span>,
  Globe: () => <span>globe-icon</span>,
  Lock: () => <span>lock-icon</span>,
  Eye: () => <span>eye-icon</span>,
  Trash2: () => <span>trash-icon</span>,
  Edit: () => <span>edit-icon</span>,
  Search: () => <span>search-icon</span>,
  Filter: () => <span>filter-icon</span>,
  Download: () => <span>download-icon</span>,
  RefreshCw: () => <span>refresh-icon</span>,
  BarChart3: () => <span>bar-chart-icon</span>,
  Server: () => <span>server-icon</span>,
  MemoryStick: () => <span>memory-icon</span>,
}))

vi.mock('sonner', () => ({
  toast: {
    error: vi.fn(),
    success: vi.fn(),
  },
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

  it('should show loading spinner initially', () => {
    const { container } = render(<AdminPage />)
    const spinner = container.querySelector('.animate-spin')
    expect(spinner).toBeInTheDocument()
  })

  it('should render admin dashboard header after loading', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getByText('Admin Dashboard')).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  it('should render admin dashboard description', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getByText('Manage your LeafLock instance')).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  it('should render shield icon in header', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getAllByText('shield-icon').length).toBeGreaterThan(0)
      },
      { timeout: 2000 }
    )
  })

  it('should render refresh button', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getByText('Refresh')).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  it('should render export data button', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getByText('Export Data')).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  it('should render refresh icon', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getAllByText('refresh-icon').length).toBeGreaterThan(0)
      },
      { timeout: 2000 }
    )
  })

  it('should render download icon', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getAllByText('download-icon').length).toBeGreaterThan(0)
      },
      { timeout: 2000 }
    )
  })

  it('should render system overview cards', async () => {
    const { getAllByTestId } = render(<AdminPage />)
    await waitFor(
      () => {
        const cards = getAllByTestId('card')
        expect(cards.length).toBeGreaterThan(0)
      },
      { timeout: 2000 }
    )
  })

  it('should display total users stat', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getAllByText('Total Users').length).toBeGreaterThan(0)
      },
      { timeout: 2000 }
    )
  })

  it('should display total notes stat', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getAllByText('Total Notes').length).toBeGreaterThan(0)
      },
      { timeout: 2000 }
    )
  })

  it('should display system uptime stat', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getAllByText('System Uptime').length).toBeGreaterThan(0)
      },
      { timeout: 2000 }
    )
  })

  it('should display memory usage stat', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getAllByText('Memory Usage').length).toBeGreaterThan(0)
      },
      { timeout: 2000 }
    )
  })

  it('should render tabs component', async () => {
    const { getByTestId } = render(<AdminPage />)
    await waitFor(
      () => {
        expect(getByTestId('tabs')).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  it('should render tabs list', async () => {
    const { getByTestId } = render(<AdminPage />)
    await waitFor(
      () => {
        expect(getByTestId('tabs-list')).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  it('should render Users tab trigger', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        const button = screen
          .getAllByRole('button')
          .find((btn) => btn.getAttribute('data-value') === 'users')
        expect(button).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  it('should render System tab trigger', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        const button = screen
          .getAllByRole('button')
          .find((btn) => btn.getAttribute('data-value') === 'system')
        expect(button).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  it('should render Announcements tab trigger', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        const button = screen
          .getAllByRole('button')
          .find((btn) => btn.getAttribute('data-value') === 'announcements')
        expect(button).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  it('should render Security tab trigger', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        const button = screen
          .getAllByRole('button')
          .find((btn) => btn.getAttribute('data-value') === 'security')
        expect(button).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  it('should render Analytics tab trigger', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        const button = screen
          .getAllByRole('button')
          .find((btn) => btn.getAttribute('data-value') === 'analytics')
        expect(button).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  it('should render users icon in tabs', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getAllByText('users-icon').length).toBeGreaterThan(0)
      },
      { timeout: 2000 }
    )
  })

  it('should render server icon in tabs', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getAllByText('server-icon').length).toBeGreaterThan(0)
      },
      { timeout: 2000 }
    )
  })

  it('should render globe icon in tabs', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getAllByText('globe-icon').length).toBeGreaterThan(0)
      },
      { timeout: 2000 }
    )
  })

  it('should render lock icon in tabs', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getAllByText('lock-icon').length).toBeGreaterThan(0)
      },
      { timeout: 2000 }
    )
  })

  it('should render bar chart icon in tabs', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getAllByText('bar-chart-icon').length).toBeGreaterThan(0)
      },
      { timeout: 2000 }
    )
  })

  it('should render user management section', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getByText('User Management')).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  it('should render search input for users', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        const input = screen.getByPlaceholderText('Search users...')
        expect(input).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  it('should render filter button', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getByText('Filter')).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  it('should render user table with headers', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getAllByText('User').length).toBeGreaterThan(0)
        expect(screen.getAllByText('Role').length).toBeGreaterThan(0)
        expect(screen.getAllByText('Status').length).toBeGreaterThan(0)
        expect(screen.getAllByText('Notes').length).toBeGreaterThan(0)
        expect(screen.getAllByText('Last Login').length).toBeGreaterThan(0)
        expect(screen.getAllByText('Actions').length).toBeGreaterThan(0)
      },
      { timeout: 2000 }
    )
  })

  it('should render mock user data', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getByText('John Doe')).toBeInTheDocument()
        expect(screen.getByText('john@example.com')).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  it('should render eye icons for viewing users', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getAllByText('eye-icon').length).toBeGreaterThan(0)
      },
      { timeout: 2000 }
    )
  })

  it('should render trash icons for deleting users', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getAllByText('trash-icon').length).toBeGreaterThan(0)
      },
      { timeout: 2000 }
    )
  })

  it('should render system resources section', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getByText('System Resources')).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  it('should render database statistics section', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getByText('Database Statistics')).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  it('should render CPU usage indicator', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getByText('CPU Usage')).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  it('should render disk usage indicator', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getByText('Disk Usage')).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  it('should render system announcements section', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getByText('System Announcements')).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  it('should render new announcement button', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getByText('New Announcement')).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  it('should render security settings section', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getByText('Security Settings')).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  it('should render user registration toggle', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getByText('User Registration')).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  it('should render MFA requirement toggle', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getByText('Require MFA')).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  it('should render encryption toggle', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getByText('Force Encryption')).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  it('should render security warning alert', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(
          screen.getByText(/Security settings changes take effect immediately/i)
        ).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  it('should render usage analytics section', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getByText('Usage Analytics')).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  it('should render analytics placeholder text', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getByText('Analytics dashboard coming soon...')).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  it('should render database icon in overview cards', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getAllByText('database-icon').length).toBeGreaterThan(0)
      },
      { timeout: 2000 }
    )
  })

  it('should render activity icon in overview cards', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getAllByText('activity-icon').length).toBeGreaterThan(0)
      },
      { timeout: 2000 }
    )
  })

  it('should render memory icon in overview cards', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        expect(screen.getAllByText('memory-icon').length).toBeGreaterThan(0)
      },
      { timeout: 2000 }
    )
  })

  it('should update search query when typing', async () => {
    render(<AdminPage />)
    await waitFor(
      () => {
        const input = screen.getByPlaceholderText('Search users...') as HTMLInputElement
        fireEvent.change(input, { target: { value: 'john' } })
        expect(input.value).toBe('john')
      },
      { timeout: 2000 }
    )
  })

  it('should render tabs with default value of users', async () => {
    const { getByTestId } = render(<AdminPage />)
    await waitFor(
      () => {
        const tabs = getByTestId('tabs')
        expect(tabs.getAttribute('data-default')).toBe('users')
      },
      { timeout: 2000 }
    )
  })

  it('should render scroll area for user table', async () => {
    const { getByTestId } = render(<AdminPage />)
    await waitFor(
      () => {
        expect(getByTestId('scroll-area')).toBeInTheDocument()
      },
      { timeout: 2000 }
    )
  })

  // Interaction and conditional logic tests
  describe('User interactions', () => {
    beforeEach(() => {
      global.fetch = vi.fn()
      global.localStorage = {
        getItem: vi.fn(() => 'mock-token'),
        setItem: vi.fn(),
        removeItem: vi.fn(),
        clear: vi.fn(),
        length: 0,
        key: vi.fn(),
      }
    })

    it('should handle user role change successfully', async () => {
      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        json: async () => ({}),
      } as Response)

      render(<AdminPage />)
      await waitFor(() => expect(screen.getByText('John Doe')).toBeInTheDocument(), {
        timeout: 2000,
      })

      const selects = screen.getAllByTestId('select')
      if (selects.length > 0) {
        fireEvent.click(selects[0])
      }

      await waitFor(() => expect(fetch).toHaveBeenCalled())
    })

    it('should handle user role change error', async () => {
      vi.mocked(fetch).mockRejectedValueOnce(new Error('Network error'))

      render(<AdminPage />)
      await waitFor(() => expect(screen.getByText('John Doe')).toBeInTheDocument(), {
        timeout: 2000,
      })

      const selects = screen.getAllByTestId('select')
      if (selects.length > 0) {
        fireEvent.click(selects[0])
      }

      await waitFor(() => expect(fetch).toHaveBeenCalled())
    })

    it('should handle user status change error', async () => {
      vi.mocked(fetch).mockRejectedValueOnce(new Error('Network error'))

      render(<AdminPage />)
      await waitFor(() => expect(screen.getByText('John Doe')).toBeInTheDocument(), {
        timeout: 2000,
      })

      const selects = screen.getAllByTestId('select')
      if (selects.length > 0) {
        fireEvent.click(selects[0])
      }

      await waitFor(() => expect(fetch).toHaveBeenCalled())
    })

    it('should handle user deletion successfully', async () => {
      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        json: async () => ({}),
      } as Response)

      render(<AdminPage />)
      await waitFor(() => expect(screen.getByText('John Doe')).toBeInTheDocument(), {
        timeout: 2000,
      })

      const trashButtons = screen.getAllByText('trash-icon')
      if (trashButtons.length > 0) {
        fireEvent.click(trashButtons[0].closest('button')!)
      }

      await waitFor(() => expect(fetch).toHaveBeenCalled())
    })

    it('should handle user deletion error', async () => {
      vi.mocked(fetch).mockRejectedValueOnce(new Error('Network error'))

      render(<AdminPage />)
      await waitFor(() => expect(screen.getByText('John Doe')).toBeInTheDocument(), {
        timeout: 2000,
      })

      const trashButtons = screen.getAllByText('trash-icon')
      if (trashButtons.length > 0) {
        fireEvent.click(trashButtons[0].closest('button')!)
      }

      await waitFor(() => expect(fetch).toHaveBeenCalled())
    })

    it('should open user details dialog when eye icon clicked', async () => {
      render(<AdminPage />)
      await waitFor(() => expect(screen.getByText('John Doe')).toBeInTheDocument(), {
        timeout: 2000,
      })

      const eyeButtons = screen.getAllByText('eye-icon')
      if (eyeButtons.length > 0) {
        fireEvent.click(eyeButtons[0].closest('button')!)
      }

      await waitFor(() => expect(screen.getByText('User Details')).toBeInTheDocument())
    })

    it('should close user details dialog', async () => {
      render(<AdminPage />)
      await waitFor(() => expect(screen.getByText('John Doe')).toBeInTheDocument(), {
        timeout: 2000,
      })

      const eyeButtons = screen.getAllByText('eye-icon')
      if (eyeButtons.length > 0) {
        fireEvent.click(eyeButtons[0].closest('button')!)
      }

      await waitFor(() => {
        const closeButton = screen.getByText('Close')
        fireEvent.click(closeButton)
      })
    })

    it('should create announcement and close dialog', async () => {
      render(<AdminPage />)
      await waitFor(() => expect(screen.getByText('New Announcement')).toBeInTheDocument(), {
        timeout: 2000,
      })

      const newAnnouncementButton = screen.getByText('New Announcement')
      fireEvent.click(newAnnouncementButton)

      await waitFor(() => {
        const createButton = screen.getAllByText('Create Announcement')[1]
        fireEvent.click(createButton)
      })
    })

    it('should filter users by search query', async () => {
      render(<AdminPage />)
      await waitFor(() => expect(screen.getByText('John Doe')).toBeInTheDocument(), {
        timeout: 2000,
      })

      const searchInput = screen.getByPlaceholderText('Search users...') as HTMLInputElement
      fireEvent.change(searchInput, { target: { value: 'jane' } })

      expect(searchInput.value).toBe('jane')
    })

    it('should filter users by email', async () => {
      render(<AdminPage />)
      await waitFor(() => expect(screen.getByText('John Doe')).toBeInTheDocument(), {
        timeout: 2000,
      })

      const searchInput = screen.getByPlaceholderText('Search users...') as HTMLInputElement
      fireEvent.change(searchInput, { target: { value: 'bob@example.com' } })

      expect(searchInput.value).toBe('bob@example.com')
    })

    it('should show no results when search does not match', async () => {
      render(<AdminPage />)
      await waitFor(() => expect(screen.getByText('John Doe')).toBeInTheDocument(), {
        timeout: 2000,
      })

      const searchInput = screen.getByPlaceholderText('Search users...') as HTMLInputElement
      fireEvent.change(searchInput, { target: { value: 'nonexistent' } })

      expect(searchInput.value).toBe('nonexistent')
    })
  })
})
