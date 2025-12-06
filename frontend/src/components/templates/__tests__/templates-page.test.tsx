import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { TemplatesPage } from '../templates-page'
import { useTemplatesStore } from '@/stores/templatesStore'
import { useClerkAuthStore } from '@/stores/clerkAuthStore'

const loadTemplatesMock = vi.fn()

vi.mock('@/stores/templatesStore')
vi.mock('@/stores/clerkAuthStore')

vi.mock('@/components/ui/card', () => ({
  Card: ({ children, ...props }: any) => (
    <div data-testid="card" {...props}>
      {children}
    </div>
  ),
  CardHeader: ({ children }: any) => <div>{children}</div>,
  CardTitle: ({ children }: any) => <h3>{children}</h3>,
  CardDescription: ({ children }: any) => <p>{children}</p>,
  CardContent: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, ...props }: any) => <button {...props}>{children}</button>,
}))

vi.mock('@/components/ui/input', () => ({
  Input: ({ value, onChange, ...props }: any) => (
    <input value={value} onChange={onChange} {...props} />
  ),
}))

vi.mock('@/components/ui/badge', () => ({
  Badge: ({ children }: any) => <span>{children}</span>,
}))

vi.mock('lucide-react', () => ({
  FileText: () => <span>file-icon</span>,
  Plus: () => <span>plus-icon</span>,
  Search: () => <span>search-icon</span>,
  Globe: () => <span>globe-icon</span>,
  Lock: () => <span>lock-icon</span>,
}))

describe('TemplatesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()

    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: [],
      starterTemplates: [],
      communityTemplates: [],
      loadTemplates: loadTemplatesMock,
    } as any)

    vi.mocked(useClerkAuthStore).mockReturnValue({
      user: { id: 'user-123' },
    } as any)

    loadTemplatesMock.mockResolvedValue(undefined)
  })

  it('should render templates page', () => {
    render(<TemplatesPage />)
    expect(screen.getByText('Templates')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Search templates...')).toBeInTheDocument()
    expect(screen.getByText('Create Template')).toBeInTheDocument()
  })

  it('should load templates on mount', async () => {
    render(<TemplatesPage />)
    await waitFor(() => {
      expect(loadTemplatesMock).toHaveBeenCalled()
    })
  })

  it('should render starter templates section', () => {
    const mockStarter = [
      {
        id: 'starter-1',
        name: 'Meeting Notes',
        content: 'Template content',
        description: 'Take meeting notes',
        icon: '📝',
        tags: ['work', 'meetings'],
        createdAt: '2024-01-01T00:00:00Z',
      },
    ]

    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: [],
      starterTemplates: mockStarter,
      communityTemplates: [],
      loadTemplates: loadTemplatesMock,
    } as any)

    render(<TemplatesPage />)

    expect(screen.getByText('Starter Templates')).toBeInTheDocument()
    expect(screen.getByText('Meeting Notes')).toBeInTheDocument()
    expect(screen.getByText('Take meeting notes')).toBeInTheDocument()
    expect(screen.getByText('work')).toBeInTheDocument()
    expect(screen.getByText('meetings')).toBeInTheDocument()
  })

  it('should render my templates section', () => {
    const mockTemplates = [
      {
        id: 'my-1',
        name: 'My Template',
        content: '<p>HTML content</p>',
        description: 'My custom template',
        icon: '✨',
        tags: ['personal'],
        isPublic: false,
        createdAt: '2024-01-01T00:00:00Z',
        userId: 'user-123',
      },
    ]

    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: mockTemplates,
      starterTemplates: [],
      communityTemplates: [],
      loadTemplates: loadTemplatesMock,
    } as any)

    render(<TemplatesPage />)

    expect(screen.getByText('My Templates')).toBeInTheDocument()
    expect(screen.getByText('My Template')).toBeInTheDocument()
    expect(screen.getByText('My custom template')).toBeInTheDocument()
    expect(screen.getByText('personal')).toBeInTheDocument()
  })

  it('should render community templates section', () => {
    const mockCommunity = [
      {
        id: 'community-1',
        name: 'Community Template',
        content: 'Shared content',
        description: 'A public template',
        icon: '🌍',
        tags: ['public'],
        isPublic: true,
        createdAt: '2024-01-01T00:00:00Z',
        userId: 'other-user',
      },
    ]

    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: [],
      starterTemplates: [],
      communityTemplates: mockCommunity,
      loadTemplates: loadTemplatesMock,
    } as any)

    render(<TemplatesPage />)

    expect(screen.getByText('Community Templates')).toBeInTheDocument()
    expect(screen.getByText('Community Template')).toBeInTheDocument()
    expect(screen.getByText('A public template')).toBeInTheDocument()
  })

  it('should filter templates by search query', async () => {
    const mockStarter = [
      {
        id: 'starter-1',
        name: 'Meeting Notes',
        content: 'Meeting template',
        createdAt: '2024-01-01T00:00:00Z',
      },
      {
        id: 'starter-2',
        name: 'Daily Journal',
        content: 'Journal template',
        createdAt: '2024-01-01T00:00:00Z',
      },
    ]

    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: [],
      starterTemplates: mockStarter,
      communityTemplates: [],
      loadTemplates: loadTemplatesMock,
    } as any)

    render(<TemplatesPage />)

    const searchInput = screen.getByPlaceholderText('Search templates...')
    fireEvent.change(searchInput, { target: { value: 'meeting' } })

    await waitFor(() => {
      expect(screen.getByText('Meeting Notes')).toBeInTheDocument()
      expect(screen.queryByText('Daily Journal')).not.toBeInTheDocument()
    })
  })

  it('should search in template content', async () => {
    const mockTemplates = [
      {
        id: 'temp-1',
        name: 'Template A',
        content: 'Contains keyword important',
        createdAt: '2024-01-01T00:00:00Z',
        userId: 'user-123',
      },
      {
        id: 'temp-2',
        name: 'Template B',
        content: 'Different content',
        createdAt: '2024-01-01T00:00:00Z',
        userId: 'user-123',
      },
    ]

    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: mockTemplates,
      starterTemplates: [],
      communityTemplates: [],
      loadTemplates: loadTemplatesMock,
    } as any)

    render(<TemplatesPage />)

    const searchInput = screen.getByPlaceholderText('Search templates...')
    fireEvent.change(searchInput, { target: { value: 'important' } })

    await waitFor(() => {
      expect(screen.getByText('Template A')).toBeInTheDocument()
      expect(screen.queryByText('Template B')).not.toBeInTheDocument()
    })
  })

  it('should search in tags', async () => {
    const mockTemplates = [
      {
        id: 'temp-1',
        name: 'Tagged Template',
        content: 'Content',
        tags: ['urgent', 'work'],
        createdAt: '2024-01-01T00:00:00Z',
        userId: 'user-123',
      },
      {
        id: 'temp-2',
        name: 'Other Template',
        content: 'Content',
        tags: ['personal'],
        createdAt: '2024-01-01T00:00:00Z',
        userId: 'user-123',
      },
    ]

    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: mockTemplates,
      starterTemplates: [],
      communityTemplates: [],
      loadTemplates: loadTemplatesMock,
    } as any)

    render(<TemplatesPage />)

    const searchInput = screen.getByPlaceholderText('Search templates...')
    fireEvent.change(searchInput, { target: { value: 'urgent' } })

    await waitFor(() => {
      expect(screen.getByText('Tagged Template')).toBeInTheDocument()
      expect(screen.queryByText('Other Template')).not.toBeInTheDocument()
    })
  })

  it('should show empty state for starter templates', () => {
    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: [],
      starterTemplates: [],
      communityTemplates: [],
      loadTemplates: loadTemplatesMock,
    } as any)

    render(<TemplatesPage />)
    expect(screen.getByText('No starter templates found.')).toBeInTheDocument()
  })

  it('should show empty state for my templates', () => {
    render(<TemplatesPage />)
    expect(screen.getByText("You haven't created any templates yet.")).toBeInTheDocument()
  })

  it('should show empty state for community templates', () => {
    render(<TemplatesPage />)
    expect(screen.getByText('No community templates available.')).toBeInTheDocument()
  })

  it('should show search-specific empty message', () => {
    const mockStarter = [
      {
        id: 'starter-1',
        name: 'Template',
        content: 'Content',
        createdAt: '2024-01-01T00:00:00Z',
      },
    ]

    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: [],
      starterTemplates: mockStarter,
      communityTemplates: [],
      loadTemplates: loadTemplatesMock,
    } as any)

    render(<TemplatesPage />)

    const searchInput = screen.getByPlaceholderText('Search templates...')
    fireEvent.change(searchInput, { target: { value: 'nonexistent' } })

    const emptyMessages = screen.getAllByText('No templates match your search.')
    expect(emptyMessages.length).toBeGreaterThan(0)
  })

  it('should strip HTML from template preview', () => {
    const mockTemplates = [
      {
        id: 'temp-1',
        name: 'HTML Template',
        content: '<p>This is <strong>bold</strong> text</p>',
        userId: 'user-123',
        createdAt: '2024-01-01T00:00:00Z',
      },
    ]

    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: mockTemplates,
      starterTemplates: [],
      communityTemplates: [],
      loadTemplates: loadTemplatesMock,
    } as any)

    render(<TemplatesPage />)
    expect(screen.getByText('This is bold text')).toBeInTheDocument()
  })

  it('should truncate long template content', () => {
    const longContent = 'a'.repeat(200)
    const mockTemplates = [
      {
        id: 'temp-1',
        name: 'Long Template',
        content: longContent,
        userId: 'user-123',
        createdAt: '2024-01-01T00:00:00Z',
      },
    ]

    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: mockTemplates,
      starterTemplates: [],
      communityTemplates: [],
      loadTemplates: loadTemplatesMock,
    } as any)

    render(<TemplatesPage />)
    const preview = screen.getByText(/a{140}…/)
    expect(preview).toBeInTheDocument()
  })

  it('should show template counts in section descriptions', () => {
    const mockStarter = [{ id: '1', name: 'T1', content: '', createdAt: '2024-01-01T00:00:00Z' }]
    const mockTemplates = [
      { id: '2', name: 'T2', content: '', userId: 'user-123', createdAt: '2024-01-01T00:00:00Z' },
      { id: '3', name: 'T3', content: '', userId: 'user-123', createdAt: '2024-01-01T00:00:00Z' },
    ]
    const mockCommunity = [
      { id: '4', name: 'T4', content: '', userId: 'other', createdAt: '2024-01-01T00:00:00Z' },
    ]

    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: mockTemplates,
      starterTemplates: mockStarter,
      communityTemplates: mockCommunity,
      loadTemplates: loadTemplatesMock,
    } as any)

    render(<TemplatesPage />)
    expect(screen.getByText(/Built-in templates.*\(1\)/)).toBeInTheDocument()
    expect(screen.getByText(/Templates you've created \(2\)/)).toBeInTheDocument()
    expect(screen.getByText(/Public templates.*\(1\)/)).toBeInTheDocument()
  })

  it('should show +N badge for templates with more than 2 tags', () => {
    const mockTemplates = [
      {
        id: 'temp-1',
        name: 'Many Tags',
        content: 'Content',
        tags: ['tag1', 'tag2', 'tag3', 'tag4'],
        userId: 'user-123',
        createdAt: '2024-01-01T00:00:00Z',
      },
    ]

    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: mockTemplates,
      starterTemplates: [],
      communityTemplates: [],
      loadTemplates: loadTemplatesMock,
    } as any)

    render(<TemplatesPage />)
    expect(screen.getByText('tag1')).toBeInTheDocument()
    expect(screen.getByText('tag2')).toBeInTheDocument()
    expect(screen.getByText('+2')).toBeInTheDocument()
  })

  it('should show public icon for public templates', () => {
    const mockTemplates = [
      {
        id: 'temp-1',
        name: 'Public Template',
        content: 'Content',
        isPublic: true,
        userId: 'user-123',
        createdAt: '2024-01-01T00:00:00Z',
      },
    ]

    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: mockTemplates,
      starterTemplates: [],
      communityTemplates: [],
      loadTemplates: loadTemplatesMock,
    } as any)

    render(<TemplatesPage />)
    const icons = screen.getAllByText('globe-icon')
    expect(icons.length).toBeGreaterThan(0)
  })

  it('should show lock icon for private templates', () => {
    const mockTemplates = [
      {
        id: 'temp-1',
        name: 'Private Template',
        content: 'Content',
        isPublic: false,
        userId: 'user-123',
        createdAt: '2024-01-01T00:00:00Z',
      },
    ]

    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: mockTemplates,
      starterTemplates: [],
      communityTemplates: [],
      loadTemplates: loadTemplatesMock,
    } as any)

    render(<TemplatesPage />)
    expect(screen.getByText('lock-icon')).toBeInTheDocument()
  })

  it('should format timestamps correctly', () => {
    const mockTemplates = [
      {
        id: 'temp-1',
        name: 'Template',
        content: 'Content',
        userId: 'user-123',
        createdAt: new Date(Date.now() - 1000 * 60 * 60).toISOString(), // 1 hour ago
      },
    ]

    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: mockTemplates,
      starterTemplates: [],
      communityTemplates: [],
      loadTemplates: loadTemplatesMock,
    } as any)

    render(<TemplatesPage />)
    expect(screen.getByText(/ago/)).toBeInTheDocument()
  })

  it('should show Unknown for missing timestamps', () => {
    const mockTemplates = [
      {
        id: 'temp-1',
        name: 'Template',
        content: 'Content',
        userId: 'user-123',
        createdAt: undefined,
      },
    ]

    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: mockTemplates,
      starterTemplates: [],
      communityTemplates: [],
      loadTemplates: loadTemplatesMock,
    } as any)

    render(<TemplatesPage />)
    expect(screen.getByText('Unknown')).toBeInTheDocument()
  })

  it('should show Unknown for invalid timestamps', () => {
    const mockTemplates = [
      {
        id: 'temp-1',
        name: 'Template',
        content: 'Content',
        userId: 'user-123',
        createdAt: 'invalid-date',
      },
    ]

    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: mockTemplates,
      starterTemplates: [],
      communityTemplates: [],
      loadTemplates: loadTemplatesMock,
    } as any)

    render(<TemplatesPage />)
    expect(screen.getByText('Unknown')).toBeInTheDocument()
  })

  it('should exclude current user templates from community section', () => {
    const mockCommunity = [
      {
        id: 'community-1',
        name: 'Other User Template',
        content: 'Content',
        userId: 'other-user',
        createdAt: '2024-01-01T00:00:00Z',
      },
      {
        id: 'community-2',
        name: 'My Public Template',
        content: 'Content',
        userId: 'user-123', // Current user
        createdAt: '2024-01-01T00:00:00Z',
      },
    ]

    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: [],
      starterTemplates: [],
      communityTemplates: mockCommunity,
      loadTemplates: loadTemplatesMock,
    } as any)

    render(<TemplatesPage />)
    expect(screen.getByText('Other User Template')).toBeInTheDocument()
    expect(screen.queryByText('My Public Template')).not.toBeInTheDocument()
  })

  it('should use description if available, fallback to content', () => {
    const mockTemplates = [
      {
        id: 'temp-1',
        name: 'With Description',
        content: 'Long content that should not be shown',
        description: 'Short description',
        userId: 'user-123',
        createdAt: '2024-01-01T00:00:00Z',
      },
    ]

    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: mockTemplates,
      starterTemplates: [],
      communityTemplates: [],
      loadTemplates: loadTemplatesMock,
    } as any)

    render(<TemplatesPage />)
    expect(screen.getByText('Short description')).toBeInTheDocument()
    expect(screen.queryByText('Long content that should not be shown')).not.toBeInTheDocument()
  })

  it('should show No preview available for empty content', () => {
    const mockTemplates = [
      {
        id: 'temp-1',
        name: 'Empty Template',
        content: '',
        userId: 'user-123',
        createdAt: '2024-01-01T00:00:00Z',
      },
    ]

    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: mockTemplates,
      starterTemplates: [],
      communityTemplates: [],
      loadTemplates: loadTemplatesMock,
    } as any)

    render(<TemplatesPage />)
    expect(screen.getByText('No preview available')).toBeInTheDocument()
  })
})
