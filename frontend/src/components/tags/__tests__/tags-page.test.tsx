import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { TagsPage } from '../tags-page'
import { useNotesStore } from '@/stores/notesStore'

const createTagMock = vi.fn()
const deleteTagMock = vi.fn()

vi.mock('@/stores/notesStore')

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
  Button: ({ children, onClick, disabled, ...props }: any) => (
    <button onClick={onClick} disabled={disabled} {...props}>
      {children}
    </button>
  ),
}))

vi.mock('@/components/ui/input', () => ({
  Input: ({ value, onChange, ...props }: any) => (
    <input value={value} onChange={onChange} {...props} />
  ),
}))

vi.mock('@/components/ui/label', () => ({
  Label: ({ children, ...props }: any) => <label {...props}>{children}</label>,
}))

vi.mock('lucide-react', () => ({
  Tag: () => <span>tag-icon</span>,
  Plus: () => <span>plus-icon</span>,
  Search: () => <span>search-icon</span>,
  Edit2: () => <span>edit-icon</span>,
  Trash2: () => <span>trash-icon</span>,
}))

describe('TagsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()

    vi.mocked(useNotesStore).mockReturnValue({
      tags: [],
      notes: [],
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    createTagMock.mockResolvedValue(undefined)
    deleteTagMock.mockResolvedValue(undefined)
  })

  it('should render tags page', () => {
    render(<TagsPage />)
    expect(screen.getByText('Tags')).toBeInTheDocument()
    expect(screen.getByText('Create New Tag')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Enter tag name...')).toBeInTheDocument()
  })

  it('should render empty state when no tags', () => {
    render(<TagsPage />)
    expect(screen.getByText("You haven't created any tags yet.")).toBeInTheDocument()
  })

  it('should render tags list', () => {
    const mockTags = [
      {
        id: 'tag-1',
        name: 'work',
        color: '#3b82f6',
        createdAt: new Date().toISOString(),
      },
      {
        id: 'tag-2',
        name: 'personal',
        color: '#10b981',
        createdAt: new Date().toISOString(),
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      tags: mockTags,
      notes: [],
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<TagsPage />)
    expect(screen.getByText('work')).toBeInTheDocument()
    expect(screen.getByText('personal')).toBeInTheDocument()
  })

  it('should create new tag when form submitted', async () => {
    render(<TagsPage />)

    const nameInput = screen.getByPlaceholderText('Enter tag name...')
    fireEvent.change(nameInput, { target: { value: 'urgent' } })

    const createButton = screen.getByText('Create Tag')
    fireEvent.click(createButton)

    await waitFor(() => {
      expect(createTagMock).toHaveBeenCalledWith({
        name: 'urgent',
        color: '#3b82f6',
      })
    })
  })

  it('should trim tag name when creating', async () => {
    render(<TagsPage />)

    const nameInput = screen.getByPlaceholderText('Enter tag name...')
    fireEvent.change(nameInput, { target: { value: '  urgent  ' } })

    const createButton = screen.getByText('Create Tag')
    fireEvent.click(createButton)

    await waitFor(() => {
      expect(createTagMock).toHaveBeenCalledWith({
        name: 'urgent',
        color: '#3b82f6',
      })
    })
  })

  it('should disable create button when name is empty', () => {
    render(<TagsPage />)
    const createButton = screen.getByText('Create Tag')
    expect(createButton).toBeDisabled()
  })

  it('should enable create button when name is entered', () => {
    render(<TagsPage />)

    const nameInput = screen.getByPlaceholderText('Enter tag name...')
    fireEvent.change(nameInput, { target: { value: 'work' } })

    const createButton = screen.getByText('Create Tag')
    expect(createButton).not.toBeDisabled()
  })

  it('should clear form after creating tag', async () => {
    render(<TagsPage />)

    const nameInput = screen.getByPlaceholderText('Enter tag name...') as HTMLInputElement
    fireEvent.change(nameInput, { target: { value: 'urgent' } })

    const createButton = screen.getByText('Create Tag')
    fireEvent.click(createButton)

    await waitFor(() => {
      expect(nameInput.value).toBe('')
    })
  })

  it('should change tag color', () => {
    render(<TagsPage />)

    const colorInput = screen.getByLabelText('Color') as HTMLInputElement
    fireEvent.change(colorInput, { target: { value: '#ff0000' } })

    expect(colorInput.value).toBe('#ff0000')
  })

  it('should set preset colors when clicked', async () => {
    render(<TagsPage />)

    const nameInput = screen.getByPlaceholderText('Enter tag name...')
    fireEvent.change(nameInput, { target: { value: 'test' } })

    // Find color preset buttons
    const colorButtons = screen.getAllByRole('button').filter((btn) => {
      const style = btn.getAttribute('style')
      return style && style.includes('backgroundColor')
    })

    // Click the red preset
    const redButton = colorButtons.find((btn) => btn.getAttribute('style')?.includes('#ef4444'))
    if (redButton) {
      fireEvent.click(redButton)

      const createButton = screen.getByText('Create Tag')
      fireEvent.click(createButton)

      await waitFor(() => {
        expect(createTagMock).toHaveBeenCalledWith({
          name: 'test',
          color: '#ef4444',
        })
      })
    }
  })

  it('should delete tag when delete button clicked', async () => {
    const mockTags = [
      {
        id: 'tag-1',
        name: 'work',
        color: '#3b82f6',
        createdAt: new Date().toISOString(),
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      tags: mockTags,
      notes: [],
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<TagsPage />)

    const deleteButtons = screen.getAllByText('trash-icon')
    fireEvent.click(deleteButtons[0].parentElement!)

    await waitFor(() => {
      expect(deleteTagMock).toHaveBeenCalledWith('tag-1')
    })
  })

  it('should filter tags by search query', () => {
    const mockTags = [
      {
        id: 'tag-1',
        name: 'work',
        color: '#3b82f6',
        createdAt: new Date().toISOString(),
      },
      {
        id: 'tag-2',
        name: 'personal',
        color: '#10b981',
        createdAt: new Date().toISOString(),
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      tags: mockTags,
      notes: [],
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<TagsPage />)

    const searchInput = screen.getByPlaceholderText('Search tags...')
    fireEvent.change(searchInput, { target: { value: 'work' } })

    expect(screen.getByText('work')).toBeInTheDocument()
    expect(screen.queryByText('personal')).not.toBeInTheDocument()
  })

  it('should show empty search message', () => {
    const mockTags = [
      {
        id: 'tag-1',
        name: 'work',
        color: '#3b82f6',
        createdAt: new Date().toISOString(),
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      tags: mockTags,
      notes: [],
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<TagsPage />)

    const searchInput = screen.getByPlaceholderText('Search tags...')
    fireEvent.change(searchInput, { target: { value: 'nonexistent' } })

    expect(screen.getByText('No tags match your search.')).toBeInTheDocument()
  })

  it('should display tag usage count', () => {
    const mockTags = [
      {
        id: 'tag-1',
        name: 'work',
        color: '#3b82f6',
        createdAt: new Date().toISOString(),
      },
    ]

    const mockNotes = [
      {
        id: 'note-1',
        title: 'Note 1',
        content: '',
        tags: ['work'],
        isTrashed: false,
      },
      {
        id: 'note-2',
        title: 'Note 2',
        content: '',
        tags: ['work'],
        isTrashed: false,
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      tags: mockTags,
      notes: mockNotes,
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<TagsPage />)
    expect(screen.getByText('Used in 2 notes')).toBeInTheDocument()
  })

  it('should show singular note for usage count of 1', () => {
    const mockTags = [
      {
        id: 'tag-1',
        name: 'work',
        color: '#3b82f6',
        createdAt: new Date().toISOString(),
      },
    ]

    const mockNotes = [
      {
        id: 'note-1',
        title: 'Note 1',
        content: '',
        tags: ['work'],
        isTrashed: false,
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      tags: mockTags,
      notes: mockNotes,
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<TagsPage />)
    expect(screen.getByText('Used in 1 note')).toBeInTheDocument()
  })

  it('should exclude trashed notes from usage count', () => {
    const mockTags = [
      {
        id: 'tag-1',
        name: 'work',
        color: '#3b82f6',
        createdAt: new Date().toISOString(),
      },
    ]

    const mockNotes = [
      {
        id: 'note-1',
        title: 'Note 1',
        content: '',
        tags: ['work'],
        isTrashed: false,
      },
      {
        id: 'note-2',
        title: 'Note 2',
        content: '',
        tags: ['work'],
        isTrashed: true, // Trashed note
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      tags: mockTags,
      notes: mockNotes,
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<TagsPage />)
    expect(screen.getByText('Used in 1 note')).toBeInTheDocument()
  })

  it('should format tag creation timestamp', () => {
    const mockTags = [
      {
        id: 'tag-1',
        name: 'work',
        color: '#3b82f6',
        createdAt: new Date(Date.now() - 1000 * 60 * 60).toISOString(), // 1 hour ago
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      tags: mockTags,
      notes: [],
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<TagsPage />)
    expect(screen.getByText(/ago/)).toBeInTheDocument()
  })

  it('should show Unknown for missing timestamp', () => {
    const mockTags = [
      {
        id: 'tag-1',
        name: 'work',
        color: '#3b82f6',
        createdAt: null,
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      tags: mockTags,
      notes: [],
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<TagsPage />)
    expect(screen.getByText('Unknown')).toBeInTheDocument()
  })

  it('should show total tag count', () => {
    const mockTags = [
      {
        id: 'tag-1',
        name: 'work',
        color: '#3b82f6',
        createdAt: new Date().toISOString(),
      },
      {
        id: 'tag-2',
        name: 'personal',
        color: '#10b981',
        createdAt: new Date().toISOString(),
      },
      {
        id: 'tag-3',
        name: 'urgent',
        color: '#ef4444',
        createdAt: new Date().toISOString(),
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      tags: mockTags,
      notes: [],
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<TagsPage />)
    expect(screen.getByText(/\(3 total\)/)).toBeInTheDocument()
  })

  it('should handle case-insensitive search', () => {
    const mockTags = [
      {
        id: 'tag-1',
        name: 'Work',
        color: '#3b82f6',
        createdAt: new Date().toISOString(),
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      tags: mockTags,
      notes: [],
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<TagsPage />)

    const searchInput = screen.getByPlaceholderText('Search tags...')
    fireEvent.change(searchInput, { target: { value: 'work' } })

    expect(screen.getByText('Work')).toBeInTheDocument()
  })
})
