import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { TemplatesDialog } from '../templates-dialog'

const loadTemplatesMock = vi.fn()
const applyTemplateMock = vi.fn()
const deleteTemplateMock = vi.fn()
const shareTemplateMock = vi.fn()
const createNoteMock = vi.fn()
const selectNoteMock = vi.fn()

let templatesState: any
let notesState: any
let authState: any

const useTemplatesStoreMock = vi.fn((selector?: any) => {
  const state = templatesState
  return selector ? selector(state) : state
})

const useNotesStoreMock = vi.fn(() => notesState)
const useAuthStoreMock = vi.fn(() => authState)

vi.mock('../../stores/templatesStore', () => ({
  useTemplatesStore: useTemplatesStoreMock,
}))

vi.mock('../../stores/notesStore', () => ({
  useNotesStore: useNotesStoreMock,
}))

vi.mock('../../stores/authStore', () => ({
  useAuthStore: useAuthStoreMock,
}))

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
  beforeEach(() => {
    vi.clearAllMocks()

    templatesState = {
      templates: [],
      starterTemplates: [],
      communityTemplates: [],
      deleteTemplate: deleteTemplateMock,
      shareTemplate: shareTemplateMock,
      applyTemplate: applyTemplateMock,
      loadTemplates: loadTemplatesMock,
    }

    notesState = {
      createNote: createNoteMock,
      selectNote: selectNoteMock,
    }

    authState = { user: { id: 'user-1' } }

    loadTemplatesMock.mockResolvedValue(undefined)
    applyTemplateMock.mockResolvedValue({ content: '<p>Template</p>', tags: ['tag'] })
    createNoteMock.mockResolvedValue({ id: 'note-created' })
  })

  it('renders template list when open', () => {
    templatesState.templates = [
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
    ]

    render(<TemplatesDialog open onOpenChange={vi.fn()} />)

    expect(screen.getByText('Daily Journal')).toBeInTheDocument()
  })

  it('applies template and creates note', async () => {
    templatesState.templates = [
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
    ]

    render(<TemplatesDialog open onOpenChange={vi.fn()} />)

    const useButton = screen.getByRole('button', { name: /use/i })
    fireEvent.click(useButton)

    await waitFor(() => {
      expect(applyTemplateMock).toHaveBeenCalledWith('tpl-use')
      expect(createNoteMock).toHaveBeenCalledWith({ content: '<p>Template</p>', tags: ['tag'] })
      expect(selectNoteMock).toHaveBeenCalledWith('note-created')
    })
  })
})
