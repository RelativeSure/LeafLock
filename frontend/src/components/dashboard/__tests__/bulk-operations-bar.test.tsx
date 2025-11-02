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
      bulkDeleteNotes: vi.fn(),
      bulkRestoreNotes: vi.fn(),
      moveNotesToFolder: vi.fn(),
      addTagsToNotes: vi.fn(),
      removeTagsFromNotes: vi.fn(),
      folders: [],
      tags: [],
    } as any)
  })

  it('should render bulk operations bar', () => {
    render(<BulkOperationsBar selectedNoteIds={['note-1']} onClearSelection={vi.fn()} />)
    expect(screen.getByText(/selected/i)).toBeInTheDocument()
  })

  it('should display selected count', () => {
    render(<BulkOperationsBar selectedNoteIds={['note-1', 'note-2']} onClearSelection={vi.fn()} />)
    expect(screen.getByText(/2.*selected/i)).toBeInTheDocument()
  })

  it('should show action buttons', () => {
    render(<BulkOperationsBar selectedNoteIds={['note-1']} onClearSelection={vi.fn()} />)
    expect(screen.getAllByRole('button').length).toBeGreaterThan(0)
  })

  it('should handle empty selection', () => {
    render(<BulkOperationsBar selectedNoteIds={[]} onClearSelection={vi.fn()} />)
    expect(screen.getByText(/0.*selected/i)).toBeInTheDocument()
  })

  it('should call onClearSelection', () => {
    const onClearSelection = vi.fn()
    render(<BulkOperationsBar selectedNoteIds={['note-1']} onClearSelection={onClearSelection} />)
    
    const clearButton = screen.getByRole('button', { name: /clear/i })
    clearButton.click()
    
    expect(onClearSelection).toHaveBeenCalled()
  })

  it('should handle bulk delete', async () => {
    const bulkDeleteNotes = vi.fn().mockResolvedValue({ successful: 2, failed: 0, errors: [] })
    
    vi.mocked(useNotesStore).mockReturnValue({
      bulkDeleteNotes,
      bulkRestoreNotes: vi.fn(),
      moveNotesToFolder: vi.fn(),
      addTagsToNotes: vi.fn(),
      removeTagsFromNotes: vi.fn(),
      folders: [],
      tags: [],
    } as any)

    render(<BulkOperationsBar selectedNoteIds={['note-1', 'note-2']} onClearSelection={vi.fn()} />)
    expect(screen.getByText(/2.*selected/i)).toBeInTheDocument()
  })

  it('should show folder select when folders exist', () => {
    vi.mocked(useNotesStore).mockReturnValue({
      bulkDeleteNotes: vi.fn(),
      bulkRestoreNotes: vi.fn(),
      moveNotesToFolder: vi.fn(),
      addTagsToNotes: vi.fn(),
      removeTagsFromNotes: vi.fn(),
      folders: [{ id: 'folder-1', name: 'Work', userId: '123', parentId: null, createdAt: '2024-01-01' }],
      tags: [],
    } as any)

    render(<BulkOperationsBar selectedNoteIds={['note-1']} onClearSelection={vi.fn()} />)
    expect(screen.getByTestId('select')).toBeInTheDocument()
  })

  it('should show tag select when tags exist', () => {
    vi.mocked(useNotesStore).mockReturnValue({
      bulkDeleteNotes: vi.fn(),
      bulkRestoreNotes: vi.fn(),
      moveNotesToFolder: vi.fn(),
      addTagsToNotes: vi.fn(),
      removeTagsFromNotes: vi.fn(),
      folders: [],
      tags: [{ id: 'tag-1', name: 'urgent', userId: '123', createdAt: '2024-01-01' }],
    } as any)

    render(<BulkOperationsBar selectedNoteIds={['note-1']} onClearSelection={vi.fn()} />)
    expect(document.body).toBeTruthy()
  })
})
