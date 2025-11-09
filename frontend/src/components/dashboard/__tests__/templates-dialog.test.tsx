import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { TemplatesDialog } from '../templates-dialog'
import { useTemplatesStore } from '@/stores/templatesStore'
import { useNotesStore } from '@/stores/notesStore'
import { useAuthStore } from '@/stores/authStore'

const loadTemplatesMock = vi.fn()
const applyTemplateMock = vi.fn()
const deleteTemplateMock = vi.fn()
const shareTemplateMock = vi.fn()
const createNoteMock = vi.fn()
const selectNoteMock = vi.fn()

vi.mock('@/stores/templatesStore')
vi.mock('@/stores/notesStore')
vi.mock('@/stores/authStore')

vi.mock('@/components/ui/dialog', () => ({
  Dialog: ({ children, open }: any) => (open ? <div data-testid="dialog">{children}</div> : null),
  DialogContent: ({ children }: any) => <div>{children}</div>,
  DialogHeader: ({ children }: any) => <div>{children}</div>,
  DialogTitle: ({ children }: any) => <h2>{children}</h2>,
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, onClick, ...props }: any) => (
    <button type="button" onClick={onClick} {...props}>
      {children}
    </button>
  ),
}))

vi.mock('@/components/ui/input', () => ({
  Input: ({ value, onChange, ...props }: any) => (
    <input value={value} onChange={onChange} {...props} />
  ),
}))

vi.mock('@/components/ui/tabs', () => ({
  Tabs: ({ children }: any) => <div>{children}</div>,
  TabsList: ({ children }: any) => <div>{children}</div>,
  TabsTrigger: ({ children, onClick }: any) => (
    <button type="button" onClick={onClick}>
      {children}
    </button>
  ),
  TabsContent: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/scroll-area', () => ({
  ScrollArea: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/badge', () => ({
  Badge: ({ children }: any) => <span>{children}</span>,
}))

vi.mock('@/components/ui/dropdown-menu', () => ({
  DropdownMenu: ({ children }: any) => <div>{children}</div>,
  DropdownMenuTrigger: ({ children }: any) => <div>{children}</div>,
  DropdownMenuContent: ({ children }: any) => <div>{children}</div>,
  DropdownMenuItem: ({ children, onClick }: any) => (
    <div role="menuitem" onClick={onClick}>
      {children}
    </div>
  ),
}))

vi.mock('lucide-react', () => ({
  FileText: () => <span />,
  Globe: () => <span />,
  Lock: () => <span />,
  Search: () => <span />,
  Trash2: () => <span>Delete</span>,
  Share2: () => <span>Share</span>,
  Copy: () => <span />,
  TagIcon: () => <span />,
}))

describe('TemplatesDialog', () => {
  const mockTemplatesStore = (overrides?: any) => {
    vi.mocked(useTemplatesStore).mockImplementation((selector?: any) => {
      const state = {
        templates: [],
        starterTemplates: [],
        communityTemplates: [],
        deleteTemplate: deleteTemplateMock,
        shareTemplate: shareTemplateMock,
        applyTemplate: applyTemplateMock,
        loadTemplates: loadTemplatesMock,
        ...overrides,
      }
      return selector ? selector(state) : state
    })
  }

  beforeEach(() => {
    vi.clearAllMocks()

    loadTemplatesMock.mockResolvedValue(undefined)
    applyTemplateMock.mockResolvedValue({ content: '<p>Template</p>', tags: ['tag'] })
    createNoteMock.mockResolvedValue({ id: 'note-created' })

    // Default mock
    mockTemplatesStore()

    vi.mocked(useNotesStore).mockReturnValue({
      createNote: createNoteMock,
      selectNote: selectNoteMock,
    } as any)

    vi.mocked(useAuthStore).mockReturnValue({
      user: { id: 'user-1' },
    } as any)
  })

  it('renders template list when open', () => {
    mockTemplatesStore({
      templates: [
        {
          id: 'tpl-1',
          name: 'Daily Journal',
          content: 'start writing',
          description: 'A simple journaling template',
          tags: ['journal'],
          isPublic: false,
          createdAt: new Date().toISOString(),
          usageCount: 0,
          userId: 'user-1',
        },
      ],
    })

    render(<TemplatesDialog open onOpenChange={vi.fn()} />)

    expect(screen.getByText('Daily Journal')).toBeInTheDocument()
  })

  it('applies template and creates note', async () => {
    mockTemplatesStore({
      templates: [
        {
          id: 'tpl-use',
          name: 'Meeting Notes',
          content: '<p>Agenda</p>',
          description: 'Meeting agenda',
          tags: ['work'],
          isPublic: false,
          createdAt: new Date().toISOString(),
          usageCount: 0,
          userId: 'user-1',
        },
      ],
    })

    render(<TemplatesDialog open onOpenChange={vi.fn()} />)

    const useButton = screen.getByRole('button', { name: /use/i })
    fireEvent.click(useButton)

    await waitFor(() => {
      expect(applyTemplateMock).toHaveBeenCalledWith('tpl-use')
      expect(createNoteMock).toHaveBeenCalledWith({ content: '<p>Template</p>', tags: ['tag'] })
      expect(selectNoteMock).toHaveBeenCalledWith('note-created')
    })
  })

  it('loads templates when dialog opens', async () => {
    render(<TemplatesDialog open onOpenChange={vi.fn()} />)

    await waitFor(() => {
      expect(loadTemplatesMock).toHaveBeenCalled()
    })
  })

  it('does not render when closed', () => {
    render(<TemplatesDialog open={false} onOpenChange={vi.fn()} />)
    expect(screen.queryByTestId('dialog')).not.toBeInTheDocument()
  })

  it('displays search input', () => {
    render(<TemplatesDialog open onOpenChange={vi.fn()} />)
    expect(screen.getByPlaceholderText('Search templates...')).toBeInTheDocument()
  })

  it('filters templates by name', () => {
    mockTemplatesStore({
      templates: [
        {
          id: 'tpl-1',
          name: 'Meeting Notes',
          content: '',
          description: '',
          tags: [],
          isPublic: false,
          createdAt: new Date().toISOString(),
          usageCount: 0,
          userId: 'user-1',
        },
        {
          id: 'tpl-2',
          name: 'Daily Journal',
          content: '',
          description: '',
          tags: [],
          isPublic: false,
          createdAt: new Date().toISOString(),
          usageCount: 0,
          userId: 'user-1',
        },
      ],
    })

    render(<TemplatesDialog open onOpenChange={vi.fn()} />)

    const searchInput = screen.getByPlaceholderText('Search templates...')
    fireEvent.change(searchInput, { target: { value: 'meeting' } })

    expect(screen.getByText('Meeting Notes')).toBeInTheDocument()
    expect(screen.queryByText('Daily Journal')).not.toBeInTheDocument()
  })

  it('filters templates by description', () => {
    mockTemplatesStore({
      templates: [
        {
          id: 'tpl-1',
          name: 'Template A',
          content: '',
          description: 'For project planning',
          tags: [],
          isPublic: false,
          createdAt: new Date().toISOString(),
          usageCount: 0,
          userId: 'user-1',
        },
        {
          id: 'tpl-2',
          name: 'Template B',
          content: '',
          description: 'For daily tasks',
          tags: [],
          isPublic: false,
          createdAt: new Date().toISOString(),
          usageCount: 0,
          userId: 'user-1',
        },
      ],
    })

    render(<TemplatesDialog open onOpenChange={vi.fn()} />)

    const searchInput = screen.getByPlaceholderText('Search templates...')
    fireEvent.change(searchInput, { target: { value: 'project' } })

    expect(screen.getByText('Template A')).toBeInTheDocument()
    expect(screen.queryByText('Template B')).not.toBeInTheDocument()
  })

  it('filters templates by tags', () => {
    mockTemplatesStore({
      templates: [
        {
          id: 'tpl-1',
          name: 'Work Template',
          content: '',
          description: '',
          tags: ['work', 'productivity'],
          isPublic: false,
          createdAt: new Date().toISOString(),
          usageCount: 0,
          userId: 'user-1',
        },
        {
          id: 'tpl-2',
          name: 'Personal Template',
          content: '',
          description: '',
          tags: ['personal'],
          isPublic: false,
          createdAt: new Date().toISOString(),
          usageCount: 0,
          userId: 'user-1',
        },
      ],
    })

    render(<TemplatesDialog open onOpenChange={vi.fn()} />)

    const searchInput = screen.getByPlaceholderText('Search templates...')
    fireEvent.change(searchInput, { target: { value: 'productivity' } })

    expect(screen.getByText('Work Template')).toBeInTheDocument()
    expect(screen.queryByText('Personal Template')).not.toBeInTheDocument()
  })

  it('shows empty state for my templates', () => {
    render(<TemplatesDialog open onOpenChange={vi.fn()} />)
    expect(screen.getByText('No templates yet')).toBeInTheDocument()
  })

  it('shows empty state for starter templates', () => {
    render(<TemplatesDialog open onOpenChange={vi.fn()} />)
    expect(screen.getByText('No starter templates available.')).toBeInTheDocument()
  })

  it('shows empty state for community templates', () => {
    render(<TemplatesDialog open onOpenChange={vi.fn()} />)
    expect(screen.getByText('No community templates yet')).toBeInTheDocument()
  })

  it('displays tab counts', () => {
    mockTemplatesStore({
      templates: [
        {
          id: 't1',
          name: 'T1',
          content: '',
          isPublic: false,
          createdAt: new Date().toISOString(),
          usageCount: 0,
          userId: 'user-1',
        },
      ],
      starterTemplates: [
        {
          id: 's1',
          name: 'S1',
          content: '',
          isPublic: false,
          createdAt: new Date().toISOString(),
          usageCount: 0,
        },
      ],
      communityTemplates: [
        {
          id: 'c1',
          name: 'C1',
          content: '',
          isPublic: true,
          createdAt: new Date().toISOString(),
          usageCount: 0,
          userId: 'other',
        },
      ],
    })

    render(<TemplatesDialog open onOpenChange={vi.fn()} />)

    expect(screen.getByText(/Starter \(1\)/)).toBeInTheDocument()
    expect(screen.getByText(/My Templates \(1\)/)).toBeInTheDocument()
    expect(screen.getByText(/Community \(1\)/)).toBeInTheDocument()
  })

  it('excludes current user templates from community tab', () => {
    mockTemplatesStore({
      communityTemplates: [
        {
          id: 'c1',
          name: 'Other User Template',
          content: '',
          isPublic: true,
          createdAt: new Date().toISOString(),
          usageCount: 0,
          userId: 'other-user',
        },
        {
          id: 'c2',
          name: 'My Public Template',
          content: '',
          isPublic: true,
          createdAt: new Date().toISOString(),
          usageCount: 0,
          userId: 'user-1',
        },
      ],
    })

    render(<TemplatesDialog open onOpenChange={vi.fn()} />)

    expect(screen.getByText('Other User Template')).toBeInTheDocument()
    expect(screen.queryByText('My Public Template')).not.toBeInTheDocument()
  })

  it('displays public badge for public templates', () => {
    mockTemplatesStore({
      templates: [
        {
          id: 'tpl-public',
          name: 'Public Template',
          content: '',
          description: '',
          tags: [],
          isPublic: true,
          createdAt: new Date().toISOString(),
          usageCount: 0,
          userId: 'user-1',
        },
      ],
    })

    render(<TemplatesDialog open onOpenChange={vi.fn()} />)
    expect(screen.getByText('Public')).toBeInTheDocument()
  })

  it('displays usage count when greater than 0', () => {
    mockTemplatesStore({
      templates: [
        {
          id: 'tpl-used',
          name: 'Popular Template',
          content: '',
          description: '',
          tags: [],
          isPublic: false,
          createdAt: new Date().toISOString(),
          usageCount: 42,
          userId: 'user-1',
        },
      ],
    })

    render(<TemplatesDialog open onOpenChange={vi.fn()} />)
    expect(screen.getByText('42 uses')).toBeInTheDocument()
  })

  it('displays template tags', () => {
    mockTemplatesStore({
      templates: [
        {
          id: 'tpl-tags',
          name: 'Tagged Template',
          content: '',
          description: '',
          tags: ['work', 'meeting'],
          isPublic: false,
          createdAt: new Date().toISOString(),
          usageCount: 0,
          userId: 'user-1',
        },
      ],
    })

    render(<TemplatesDialog open onOpenChange={vi.fn()} />)
    expect(screen.getByText('work')).toBeInTheDocument()
    expect(screen.getByText('meeting')).toBeInTheDocument()
  })

  it('deletes template when delete clicked', async () => {
    mockTemplatesStore({
      templates: [
        {
          id: 'tpl-delete',
          name: 'Delete Me',
          content: '',
          description: '',
          tags: [],
          isPublic: false,
          createdAt: new Date().toISOString(),
          usageCount: 0,
          userId: 'user-1',
        },
      ],
    })

    render(<TemplatesDialog open onOpenChange={vi.fn()} />)

    const deleteButton = screen.getByRole('menuitem', { name: /delete/i })
    fireEvent.click(deleteButton)

    await waitFor(() => {
      expect(deleteTemplateMock).toHaveBeenCalledWith('tpl-delete')
    })
  })

  it('toggles template to public when share clicked', async () => {
    mockTemplatesStore({
      templates: [
        {
          id: 'tpl-share',
          name: 'Share Me',
          content: '',
          description: '',
          tags: [],
          isPublic: false,
          createdAt: new Date().toISOString(),
          usageCount: 0,
          userId: 'user-1',
        },
      ],
    })

    render(<TemplatesDialog open onOpenChange={vi.fn()} />)

    const shareButton = screen.getByRole('menuitem', { name: /share publicly/i })
    fireEvent.click(shareButton)

    await waitFor(() => {
      expect(shareTemplateMock).toHaveBeenCalledWith('tpl-share', true)
    })
  })

  it('toggles template to private when make private clicked', async () => {
    mockTemplatesStore({
      templates: [
        {
          id: 'tpl-private',
          name: 'Make Private',
          content: '',
          description: '',
          tags: [],
          isPublic: true,
          createdAt: new Date().toISOString(),
          usageCount: 0,
          userId: 'user-1',
        },
      ],
    })

    render(<TemplatesDialog open onOpenChange={vi.fn()} />)

    const privateButton = screen.getByRole('menuitem', { name: /make private/i })
    fireEvent.click(privateButton)

    await waitFor(() => {
      expect(shareTemplateMock).toHaveBeenCalledWith('tpl-private', false)
    })
  })

  it('closes dialog after using template', async () => {
    const onOpenChangeMock = vi.fn()
    mockTemplatesStore({
      templates: [
        {
          id: 'tpl-close',
          name: 'Close Test',
          content: '',
          description: '',
          tags: [],
          isPublic: false,
          createdAt: new Date().toISOString(),
          usageCount: 0,
          userId: 'user-1',
        },
      ],
    })

    render(<TemplatesDialog open onOpenChange={onOpenChangeMock} />)

    const useButton = screen.getByRole('button', { name: /use/i })
    fireEvent.click(useButton)

    await waitFor(() => {
      expect(onOpenChangeMock).toHaveBeenCalledWith(false)
    })
  })

  it('handles apply template error gracefully', async () => {
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    applyTemplateMock.mockRejectedValue(new Error('Apply failed'))

    mockTemplatesStore({
      templates: [
        {
          id: 'tpl-error',
          name: 'Error Template',
          content: '',
          description: '',
          tags: [],
          isPublic: false,
          createdAt: new Date().toISOString(),
          usageCount: 0,
          userId: 'user-1',
        },
      ],
    })

    render(<TemplatesDialog open onOpenChange={vi.fn()} />)

    const useButton = screen.getByRole('button', { name: /use/i })
    fireEvent.click(useButton)

    await waitFor(() => {
      expect(consoleErrorSpy).toHaveBeenCalledWith('Failed to use template:', expect.any(Error))
    })

    consoleErrorSpy.mockRestore()
  })

  it('handles delete template error gracefully', async () => {
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    deleteTemplateMock.mockRejectedValue(new Error('Delete failed'))

    mockTemplatesStore({
      templates: [
        {
          id: 'tpl-delete-error',
          name: 'Delete Error',
          content: '',
          description: '',
          tags: [],
          isPublic: false,
          createdAt: new Date().toISOString(),
          usageCount: 0,
          userId: 'user-1',
        },
      ],
    })

    render(<TemplatesDialog open onOpenChange={vi.fn()} />)

    const deleteButton = screen.getByRole('menuitem', { name: /delete/i })
    fireEvent.click(deleteButton)

    await waitFor(() => {
      expect(consoleErrorSpy).toHaveBeenCalledWith('Failed to delete template:', expect.any(Error))
    })

    consoleErrorSpy.mockRestore()
  })

  it('handles toggle share error gracefully', async () => {
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    shareTemplateMock.mockRejectedValue(new Error('Share failed'))

    mockTemplatesStore({
      templates: [
        {
          id: 'tpl-share-error',
          name: 'Share Error',
          content: '',
          description: '',
          tags: [],
          isPublic: false,
          createdAt: new Date().toISOString(),
          usageCount: 0,
          userId: 'user-1',
        },
      ],
    })

    render(<TemplatesDialog open onOpenChange={vi.fn()} />)

    const shareButton = screen.getByRole('menuitem', { name: /share publicly/i })
    fireEvent.click(shareButton)

    await waitFor(() => {
      expect(consoleErrorSpy).toHaveBeenCalledWith('Failed to toggle share:', expect.any(Error))
    })

    consoleErrorSpy.mockRestore()
  })

  it('displays formatted creation date', () => {
    mockTemplatesStore({
      templates: [
        {
          id: 'tpl-date',
          name: 'Date Template',
          content: '',
          description: '',
          tags: [],
          isPublic: false,
          createdAt: new Date(Date.now() - 1000 * 60 * 60).toISOString(), // 1 hour ago
          usageCount: 0,
          userId: 'user-1',
        },
      ],
    })

    render(<TemplatesDialog open onOpenChange={vi.fn()} />)
    expect(screen.getByText(/ago/)).toBeInTheDocument()
  })

  it('shows Unknown for missing createdAt', () => {
    mockTemplatesStore({
      templates: [
        {
          id: 'tpl-no-date',
          name: 'No Date',
          content: '',
          description: '',
          tags: [],
          isPublic: false,
          createdAt: null,
          usageCount: 0,
          userId: 'user-1',
        },
      ],
    })

    render(<TemplatesDialog open onOpenChange={vi.fn()} />)
    expect(screen.getByText('Unknown')).toBeInTheDocument()
  })

  it('displays template icon when present', () => {
    mockTemplatesStore({
      templates: [
        {
          id: 'tpl-icon',
          name: 'Icon Template',
          content: '',
          description: '',
          tags: [],
          icon: '🚀',
          isPublic: false,
          createdAt: new Date().toISOString(),
          usageCount: 0,
          userId: 'user-1',
        },
      ],
    })

    render(<TemplatesDialog open onOpenChange={vi.fn()} />)
    const iconElement = screen.getByRole('img', { name: 'Icon Template' })
    expect(iconElement).toHaveTextContent('🚀')
  })

  it('truncates long descriptions', () => {
    const longDescription = 'a'.repeat(150)
    mockTemplatesStore({
      templates: [
        {
          id: 'tpl-long',
          name: 'Long Desc',
          content: '',
          description: longDescription,
          tags: [],
          isPublic: false,
          createdAt: new Date().toISOString(),
          usageCount: 0,
          userId: 'user-1',
        },
      ],
    })

    render(<TemplatesDialog open onOpenChange={vi.fn()} />)
    const truncatedText = screen.getByText(/a{120}…/)
    expect(truncatedText).toBeInTheDocument()
  })
})
