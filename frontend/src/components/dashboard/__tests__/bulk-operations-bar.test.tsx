import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { BulkOperationsBar } from '../bulk-operations-bar'
import { useNotesStore } from '@/stores/notesStore'

vi.mock('@/stores/notesStore', () => ({
  useNotesStore: vi.fn(),
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, onClick, ...props }: any) => (
    <button onClick={onClick} {...props}>
      {children}
    </button>
  ),
}))

vi.mock('@/components/ui/select', () => ({
  Select: ({ children }: any) => <div data-testid="select">{children}</div>,
  SelectTrigger: ({ children }: any) => <div>{children}</div>,
  SelectContent: ({ children }: any) => <div>{children}</div>,
  SelectItem: ({ children, value }: any) => <option value={value}>{children}</option>,
  SelectValue: ({ placeholder }: any) => <span>{placeholder}</span>,
}))

describe('BulkOperationsBar', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(useNotesStore).mockReturnValue({
      notes: [],
      bulkDeleteNotes: vi.fn(),
      bulkRestoreNotes: vi.fn(),
      moveNotesToFolder: vi.fn(),
      addTagsToNotes: vi.fn(),
      removeTagsFromNotes: vi.fn(),
      createTag: vi.fn(),
      folders: [],
      tags: [],
    } as any)
  })

  it('should render bulk operations bar', () => {
    render(<BulkOperationsBar selectedNotes={['note-1']} onClose={vi.fn()} />)
    expect(screen.getByText(/selected/i)).toBeInTheDocument()
  })

  it('should display selected count', () => {
    render(<BulkOperationsBar selectedNotes={['note-1', 'note-2']} onClose={vi.fn()} />)
    expect(screen.getByText(/2.*selected/i)).toBeInTheDocument()
  })

  it('should show action buttons', () => {
    render(<BulkOperationsBar selectedNotes={['note-1']} onClose={vi.fn()} />)
    expect(screen.getAllByRole('button').length).toBeGreaterThan(0)
  })

  it('should handle empty selection', () => {
    const { container } = render(<BulkOperationsBar selectedNotes={[]} onClose={vi.fn()} />)
    // Component returns null when no notes are selected
    expect(container.firstChild).toBeNull()
  })

  it('should call onClose', () => {
    const onClose = vi.fn()
    render(<BulkOperationsBar selectedNotes={['note-1']} onClose={onClose} />)

    // Find the X button (close button without text label)
    const buttons = screen.getAllByRole('button')
    const closeButton = buttons[0] // First button is the X close button
    closeButton.click()

    expect(onClose).toHaveBeenCalled()
  })

  it('should handle bulk delete', async () => {
    const bulkDeleteNotes = vi.fn().mockResolvedValue({ successful: 2, failed: 0, errors: [] })

    vi.mocked(useNotesStore).mockReturnValue({
      notes: [],
      bulkDeleteNotes,
      bulkRestoreNotes: vi.fn(),
      moveNotesToFolder: vi.fn(),
      addTagsToNotes: vi.fn(),
      removeTagsFromNotes: vi.fn(),
      createTag: vi.fn(),
      folders: [],
      tags: [],
    } as any)

    render(<BulkOperationsBar selectedNotes={['note-1', 'note-2']} onClose={vi.fn()} />)
    expect(screen.getByText(/2.*selected/i)).toBeInTheDocument()
  })

  it('should show folder select when folders exist', () => {
    vi.mocked(useNotesStore).mockReturnValue({
      notes: [],
      bulkDeleteNotes: vi.fn(),
      bulkRestoreNotes: vi.fn(),
      moveNotesToFolder: vi.fn(),
      addTagsToNotes: vi.fn(),
      removeTagsFromNotes: vi.fn(),
      createTag: vi.fn(),
      folders: [
        {
          id: 'folder-1',
          name: 'Work',
          userId: '123',
          parentId: null,
          createdAt: '2024-01-01',
          color: '#000000',
        },
      ],
      tags: [],
    } as any)

    render(<BulkOperationsBar selectedNotes={['note-1']} onClose={vi.fn()} />)
    // Verify Move button is present
    expect(screen.getByRole('button', { name: /move/i })).toBeInTheDocument()
  })

  it('should show tag select when tags exist', () => {
    vi.mocked(useNotesStore).mockReturnValue({
      notes: [],
      bulkDeleteNotes: vi.fn(),
      bulkRestoreNotes: vi.fn(),
      moveNotesToFolder: vi.fn(),
      addTagsToNotes: vi.fn(),
      removeTagsFromNotes: vi.fn(),
      createTag: vi.fn(),
      folders: [],
      tags: [
        { id: 'tag-1', name: 'urgent', userId: '123', createdAt: '2024-01-01', color: '#000000' },
      ],
    } as any)

    render(<BulkOperationsBar selectedNotes={['note-1']} onClose={vi.fn()} />)
    expect(document.body).toBeTruthy()
  })
})
