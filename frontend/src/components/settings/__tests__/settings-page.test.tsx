import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SettingsPage } from '../settings-page'
import { useAuthStore } from '@/stores/authStore'
import { useSettingsStore } from '@/stores/settingsStore'
import { useNotesStore } from '@/stores/notesStore'
import { useTemplatesStore } from '@/stores/templatesStore'

vi.mock('@/stores/authStore', () => ({
  useAuthStore: vi.fn(),
}))

vi.mock('@/stores/settingsStore', () => ({
  useSettingsStore: vi.fn(),
}))

vi.mock('@/stores/notesStore', () => ({
  useNotesStore: vi.fn(),
}))

vi.mock('@/stores/templatesStore', () => ({
  useTemplatesStore: vi.fn(),
}))

vi.mock('@/hooks/use-toast', () => ({
  useToast: () => ({ toast: { success: vi.fn(), error: vi.fn() } }),
}))

// Mock all UI components
vi.mock('@/components/ui/tabs', () => ({
  Tabs: ({ children }: any) => <div data-testid="tabs">{children}</div>,
  TabsList: ({ children }: any) => <div data-testid="tabs-list">{children}</div>,
  TabsTrigger: ({ children, value }: any) => <button data-value={value}>{children}</button>,
  TabsContent: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/card', () => ({
  Card: ({ children }: any) => <div data-testid="card">{children}</div>,
  CardHeader: ({ children }: any) => <div>{children}</div>,
  CardTitle: ({ children }: any) => <h3>{children}</h3>,
  CardDescription: ({ children }: any) => <p>{children}</p>,
  CardContent: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children }: any) => <button>{children}</button>,
}))

vi.mock('@/components/ui/input', () => ({
  Input: (props: any) => <input {...props} />,
}))

vi.mock('@/components/ui/label', () => ({
  Label: ({ children }: any) => <label>{children}</label>,
}))

vi.mock('@/components/ui/switch', () => ({
  Switch: (props: any) => <input type="checkbox" {...props} />,
}))

vi.mock('@/components/ui/select', () => ({
  Select: ({ children }: any) => <div>{children}</div>,
  SelectContent: ({ children }: any) => <div>{children}</div>,
  SelectItem: ({ children }: any) => <div>{children}</div>,
  SelectTrigger: ({ children }: any) => <button>{children}</button>,
  SelectValue: () => <span>select-value</span>,
}))

vi.mock('@/components/ui/separator', () => ({
  Separator: () => <hr />,
}))

vi.mock('@/components/ui/user-avatar', () => ({
  UserAvatar: () => <div>user-avatar</div>,
}))

vi.mock('lucide-react', () => ({
  Download: () => <span>download-icon</span>,
  User: () => <span>user-icon</span>,
  Shield: () => <span>shield-icon</span>,
  Settings: () => <span>settings-icon</span>,
  Database: () => <span>database-icon</span>,
  FolderPlus: () => <span>folder-plus-icon</span>,
  Tag: () => <span>tag-icon</span>,
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

    vi.mocked(useNotesStore).mockReturnValue({
      notes: [],
      folders: [],
      tags: [],
      createNote: vi.fn(),
      createFolder: vi.fn(),
      createTag: vi.fn(),
    } as any)

    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: [],
      createTemplate: vi.fn(),
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

  it('should render Profile tab trigger', () => {
    render(<SettingsPage />)
    const button = screen
      .getAllByRole('button')
      .find((btn) => btn.getAttribute('data-value') === 'profile')
    expect(button).toBeInTheDocument()
  })

  it('should render Backup tab trigger', () => {
    render(<SettingsPage />)
    const button = screen
      .getAllByRole('button')
      .find((btn) => btn.getAttribute('data-value') === 'backup')
    expect(button).toBeInTheDocument()
  })

  it('should render Security tab trigger', () => {
    render(<SettingsPage />)
    const button = screen
      .getAllByRole('button')
      .find((btn) => btn.getAttribute('data-value') === 'security')
    expect(button).toBeInTheDocument()
  })

  it('should render Preferences tab trigger', () => {
    render(<SettingsPage />)
    const button = screen
      .getAllByRole('button')
      .find((btn) => btn.getAttribute('data-value') === 'preferences')
    expect(button).toBeInTheDocument()
  })

  it('should render Manage tab trigger', () => {
    render(<SettingsPage />)
    const button = screen
      .getAllByRole('button')
      .find((btn) => btn.getAttribute('data-value') === 'manage')
    expect(button).toBeInTheDocument()
  })

  it('should render profile icon in Profile tab', () => {
    render(<SettingsPage />)
    expect(screen.getAllByText('user-icon').length).toBeGreaterThan(0)
  })

  it('should render database icon in Backup tab', () => {
    render(<SettingsPage />)
    expect(screen.getAllByText('database-icon').length).toBeGreaterThan(0)
  })

  it('should render shield icon in Security tab', () => {
    render(<SettingsPage />)
    expect(screen.getAllByText('shield-icon').length).toBeGreaterThan(0)
  })

  it('should render settings icon in Preferences tab', () => {
    render(<SettingsPage />)
    expect(screen.getAllByText('settings-icon').length).toBeGreaterThan(0)
  })

  it('should render folder-plus icon in Manage tab', () => {
    render(<SettingsPage />)
    expect(screen.getAllByText('folder-plus-icon').length).toBeGreaterThan(0)
  })

  it('should render user avatar', () => {
    render(<SettingsPage />)
    expect(screen.getByText('user-avatar')).toBeInTheDocument()
  })

  it('should render user information', () => {
    render(<SettingsPage />)
    expect(screen.getByText('user-avatar')).toBeInTheDocument()
  })

  it('should render cards for settings sections', () => {
    const { getAllByTestId } = render(<SettingsPage />)
    const cards = getAllByTestId('card')
    expect(cards.length).toBeGreaterThan(0)
  })

  it('should render separators', () => {
    const { container } = render(<SettingsPage />)
    const separators = container.querySelectorAll('hr')
    expect(separators.length).toBeGreaterThan(0)
  })

  it('should display all tab triggers', () => {
    render(<SettingsPage />)
    const buttons = screen.getAllByRole('button')
    const tabValues = buttons.map((btn) => btn.getAttribute('data-value')).filter(Boolean)
    expect(tabValues).toContain('profile')
    expect(tabValues).toContain('backup')
    expect(tabValues).toContain('security')
    expect(tabValues).toContain('preferences')
    expect(tabValues).toContain('manage')
  })

  it('should render download icon', () => {
    render(<SettingsPage />)
    expect(screen.getByText('download-icon')).toBeInTheDocument()
  })

  it('should render tag icon', () => {
    render(<SettingsPage />)
    expect(screen.getByText('tag-icon')).toBeInTheDocument()
  })

  it('should render with empty notes array', () => {
    render(<SettingsPage />)
    expect(screen.getByTestId('tabs')).toBeInTheDocument()
  })

  it('should render with notes data', () => {
    vi.mocked(useNotesStore).mockReturnValue({
      notes: [
        {
          id: '1',
          title: 'Test Note',
          content: 'Content',
          userId: '123',
          folderId: null,
          tags: [],
          isTrashed: false,
          isEncrypted: false,
          createdAt: '2024-01-01',
          updatedAt: '2024-01-01',
        },
      ],
      folders: [],
      tags: [],
      createNote: vi.fn(),
      createFolder: vi.fn(),
      createTag: vi.fn(),
    } as any)

    render(<SettingsPage />)
    expect(screen.getByTestId('tabs')).toBeInTheDocument()
  })

  it('should render with folders data', () => {
    vi.mocked(useNotesStore).mockReturnValue({
      notes: [],
      folders: [
        {
          id: '1',
          name: 'Test Folder',
          color: '#ff0000',
          userId: '123',
          parentId: null,
          createdAt: '2024-01-01',
          updatedAt: '2024-01-01',
        },
      ],
      tags: [],
      createNote: vi.fn(),
      createFolder: vi.fn(),
      createTag: vi.fn(),
    } as any)

    render(<SettingsPage />)
    expect(screen.getByTestId('tabs')).toBeInTheDocument()
  })

  it('should render with tags data', () => {
    vi.mocked(useNotesStore).mockReturnValue({
      notes: [],
      folders: [],
      tags: [
        {
          id: '1',
          name: 'test-tag',
          color: '#00ff00',
          userId: '123',
          createdAt: '2024-01-01',
          updatedAt: '2024-01-01',
        },
      ],
      createNote: vi.fn(),
      createFolder: vi.fn(),
      createTag: vi.fn(),
    } as any)

    render(<SettingsPage />)
    expect(screen.getByTestId('tabs')).toBeInTheDocument()
  })

  it('should render with templates data', () => {
    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: [
        {
          id: '1',
          title: 'Test Template',
          content: 'Template content',
          userId: '123',
          tags: [],
          createdAt: '2024-01-01',
          updatedAt: '2024-01-01',
        },
      ],
      createTemplate: vi.fn(),
    } as any)

    render(<SettingsPage />)
    expect(screen.getByTestId('tabs')).toBeInTheDocument()
  })

})
