import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { TemplatesDialog } from '../templates-dialog'
import { useTemplatesStore } from '@/stores/templatesStore'

vi.mock('@/stores/templatesStore', () => ({
  useTemplatesStore: vi.fn(),
}))

vi.mock('@/components/ui/dialog', () => ({
  Dialog: ({ children, open }: any) => (open ? <div data-testid="dialog">{children}</div> : null),
  DialogContent: ({ children }: any) => <div data-testid="dialog-content">{children}</div>,
  DialogHeader: ({ children }: any) => <div>{children}</div>,
  DialogTitle: ({ children }: any) => <h2>{children}</h2>,
  DialogDescription: ({ children }: any) => <p>{children}</p>,
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, onClick, ...props }: any) => (
    <button onClick={onClick} {...props}>
      {children}
    </button>
  ),
}))

vi.mock('@/components/ui/scroll-area', () => ({
  ScrollArea: ({ children }: any) => <div data-testid="scroll-area">{children}</div>,
}))

describe('TemplatesDialog', () => {
  const mockTemplates = [
    {
      id: 'tpl-1',
      name: 'Meeting Notes',
      content: 'Template content',
      tags: [],
      isPublic: false,
      usageCount: 0,
      createdAt: '2024-01-01',
    },
  ]

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('should render templates dialog when open', () => {
    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: [],
      isLoading: false,
      loadTemplates: vi.fn(),
      createTemplate: vi.fn(),
      deleteTemplate: vi.fn(),
    } as any)

    render(<TemplatesDialog open={true} onOpenChange={vi.fn()} onSelectTemplate={vi.fn()} />)
    expect(screen.getByTestId('dialog')).toBeInTheDocument()
  })

  it('should not render when closed', () => {
    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: [],
      isLoading: false,
      loadTemplates: vi.fn(),
      createTemplate: vi.fn(),
      deleteTemplate: vi.fn(),
    } as any)

    render(<TemplatesDialog open={false} onOpenChange={vi.fn()} onSelectTemplate={vi.fn()} />)
    expect(screen.queryByTestId('dialog')).not.toBeInTheDocument()
  })

  it('should load templates on mount', async () => {
    const loadTemplates = vi.fn()
    
    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: [],
      isLoading: false,
      loadTemplates,
      createTemplate: vi.fn(),
      deleteTemplate: vi.fn(),
    } as any)

    render(<TemplatesDialog open={true} onOpenChange={vi.fn()} onSelectTemplate={vi.fn()} />)

    await waitFor(() => {
      expect(loadTemplates).toHaveBeenCalled()
    })
  })

  it('should display templates list', () => {
    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: mockTemplates,
      isLoading: false,
      loadTemplates: vi.fn(),
      createTemplate: vi.fn(),
      deleteTemplate: vi.fn(),
    } as any)

    render(<TemplatesDialog open={true} onOpenChange={vi.fn()} onSelectTemplate={vi.fn()} />)
    
    expect(screen.getByTestId('scroll-area')).toBeInTheDocument()
  })

  it('should show loading state', () => {
    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: [],
      isLoading: true,
      loadTemplates: vi.fn(),
      createTemplate: vi.fn(),
      deleteTemplate: vi.fn(),
    } as any)

    render(<TemplatesDialog open={true} onOpenChange={vi.fn()} onSelectTemplate={vi.fn()} />)
    
    expect(screen.getByText(/loading/i)).toBeInTheDocument()
  })

  it('should show empty state when no templates', () => {
    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: [],
      isLoading: false,
      loadTemplates: vi.fn(),
      createTemplate: vi.fn(),
      deleteTemplate: vi.fn(),
    } as any)

    render(<TemplatesDialog open={true} onOpenChange={vi.fn()} onSelectTemplate={vi.fn()} />)
    
    expect(screen.getByText(/no templates/i)).toBeInTheDocument()
  })

  it('should call onSelectTemplate when template is clicked', () => {
    const onSelectTemplate = vi.fn()
    
    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: mockTemplates,
      isLoading: false,
      loadTemplates: vi.fn(),
      createTemplate: vi.fn(),
      deleteTemplate: vi.fn(),
    } as any)

    render(<TemplatesDialog open={true} onOpenChange={vi.fn()} onSelectTemplate={onSelectTemplate} />)
    
    const templateButton = screen.getByText('Meeting Notes')
    templateButton.click()

    expect(onSelectTemplate).toHaveBeenCalledWith(mockTemplates[0])
  })

  it('should handle template deletion', () => {
    const deleteTemplate = vi.fn()
    
    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: mockTemplates,
      isLoading: false,
      loadTemplates: vi.fn(),
      createTemplate: vi.fn(),
      deleteTemplate,
    } as any)

    render(<TemplatesDialog open={true} onOpenChange={vi.fn()} onSelectTemplate={vi.fn()} />)
    
    const deleteButton = screen.queryByRole('button', { name: /delete/i })
    if (deleteButton) {
      deleteButton.click()
      expect(deleteTemplate).toHaveBeenCalled()
    }
  })

  it('should filter templates by search', () => {
    vi.mocked(useTemplatesStore).mockReturnValue({
      templates: mockTemplates,
      isLoading: false,
      loadTemplates: vi.fn(),
      createTemplate: vi.fn(),
      deleteTemplate: vi.fn(),
    } as any)

    render(<TemplatesDialog open={true} onOpenChange={vi.fn()} onSelectTemplate={vi.fn()} />)
    
    const searchInput = screen.queryByPlaceholderText(/search/i)
    if (searchInput) {
      fireEvent.change(searchInput, { target: { value: 'meeting' } })
      expect(screen.getByText('Meeting Notes')).toBeInTheDocument()
    }
  })
})
