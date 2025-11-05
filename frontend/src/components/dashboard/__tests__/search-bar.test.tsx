import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { SearchBar } from '../search-bar'
import { useNotesStore } from '@/stores/notesStore'
import { useDecryptedNotes } from '@/hooks/use-decrypted-notes'

const selectNoteMock = vi.fn()

vi.mock('@/stores/notesStore')
vi.mock('@/hooks/use-decrypted-notes')

vi.mock('@/components/ui/input', () => ({
  Input: ({ value, onChange, ...props }: any) => (
    <input value={value} onChange={onChange} {...props} />
  ),
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, onClick, ...props }: any) => (
    <button type="button" onClick={onClick} {...props}>
      {children}
    </button>
  ),
}))

vi.mock('@/components/ui/dialog', () => ({
  Dialog: ({ children, open }: any) => (open ? <div data-testid="dialog">{children}</div> : null),
  DialogContent: ({ children }: any) => <div>{children}</div>,
  DialogHeader: ({ children }: any) => <div>{children}</div>,
  DialogTitle: ({ children }: any) => <h2>{children}</h2>,
}))

vi.mock('@/components/ui/scroll-area', () => ({
  ScrollArea: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/badge', () => ({
  Badge: ({ children }: any) => <span>{children}</span>,
}))

vi.mock('lucide-react', () => ({
  Search: () => <span />,
  X: () => <span />,
  Lock: () => <span />,
}))

describe('SearchBar', () => {
  beforeEach(() => {
    vi.clearAllMocks()

    // Default mocks
    vi.mocked(useNotesStore).mockReturnValue({
      notes: [],
      selectNote: selectNoteMock,
    } as any)

    vi.mocked(useDecryptedNotes).mockReturnValue({
      decryptedNotes: {},
      isUnlocked: true,
      isDecrypting: false,
    })
  })

  it('renders the search input', () => {
    render(<SearchBar />)
    expect(screen.getByPlaceholderText('Search notes...')).toBeInTheDocument()
  })

  it('shows unlock message when vault is locked', async () => {
    vi.mocked(useDecryptedNotes).mockReturnValue({
      decryptedNotes: {},
      isUnlocked: false,
      isDecrypting: false,
    })

    render(<SearchBar />)

    const input = screen.getByPlaceholderText('Search notes...')
    fireEvent.change(input, { target: { value: 'project' } })

    expect(screen.getByTestId('dialog')).toBeInTheDocument()
    await screen.findByText('Unlock your vault to search notes.')
  })

  it('displays search results when unlocked', async () => {
    const noteId = 'note-1'
    vi.mocked(useNotesStore).mockReturnValue({
      notes: [{ id: noteId, updatedAt: new Date().toISOString(), tags: [] }],
      selectNote: selectNoteMock,
    } as any)
    vi.mocked(useDecryptedNotes).mockReturnValue({
      decryptedNotes: {
        [noteId]: {
          title: 'Project Meeting',
          content: 'Discuss roadmap',
        },
      },
      isUnlocked: true,
      isDecrypting: false,
    })

    render(<SearchBar />)

    const input = screen.getByPlaceholderText('Search notes...')
    fireEvent.change(input, { target: { value: 'project' } })

    const result = await screen.findByRole('button', { name: /project meeting/i })
    expect(result).toBeInTheDocument()
  })

  it('selects note and clears query when a result is clicked', async () => {
    const noteId = 'note-42'
    vi.mocked(useNotesStore).mockReturnValue({
      notes: [{ id: noteId, updatedAt: new Date().toISOString(), tags: ['work'] }],
      selectNote: selectNoteMock,
    } as any)
    vi.mocked(useDecryptedNotes).mockReturnValue({
      decryptedNotes: {
        [noteId]: {
          title: 'Weekly Sync',
          content: 'Agenda and action items',
        },
      },
      isUnlocked: true,
      isDecrypting: false,
    })

    render(<SearchBar />)

    const input = screen.getByPlaceholderText('Search notes...')
    fireEvent.change(input, { target: { value: 'weekly' } })

    const result = await screen.findByRole('button', { name: /weekly sync/i })
    fireEvent.click(result)

    await waitFor(() => expect(selectNoteMock).toHaveBeenCalledWith(noteId))
    expect(input).toHaveValue('')
  })

  it('shows clear button when query exists', () => {
    render(<SearchBar />)
    const input = screen.getByPlaceholderText('Search notes...')

    // No clear button initially
    expect(screen.queryByRole('button', { name: '' })).not.toBeInTheDocument()

    // Type something
    fireEvent.change(input, { target: { value: 'test' } })

    // Clear button should appear (the X button)
    const buttons = screen.getAllByRole('button')
    expect(buttons.length).toBeGreaterThan(0)
  })

  it('clears query when clear button is clicked', () => {
    render(<SearchBar />)
    const input = screen.getByPlaceholderText('Search notes...')

    fireEvent.change(input, { target: { value: 'test query' } })
    expect(input).toHaveValue('test query')

    // Find and click the clear button (last button added)
    const buttons = screen.getAllByRole('button')
    const clearButton = buttons[buttons.length - 1]
    fireEvent.click(clearButton)

    expect(input).toHaveValue('')
  })

  it('opens dialog on focus', () => {
    vi.mocked(useNotesStore).mockReturnValue({
      notes: [{ id: 'note-1', updatedAt: new Date().toISOString(), tags: [] }],
      selectNote: selectNoteMock,
    } as any)
    vi.mocked(useDecryptedNotes).mockReturnValue({
      decryptedNotes: { 'note-1': { title: 'Test', content: '' } },
      isUnlocked: true,
      isDecrypting: false,
    })

    render(<SearchBar />)
    const input = screen.getByPlaceholderText('Search notes...')

    // Set query first
    fireEvent.change(input, { target: { value: 'test' } })

    // Dialog should be open
    expect(screen.getByTestId('dialog')).toBeInTheDocument()
  })

  it('shows decrypting message when isDecrypting is true', async () => {
    vi.mocked(useDecryptedNotes).mockReturnValue({
      decryptedNotes: {},
      isUnlocked: true,
      isDecrypting: true,
    })

    render(<SearchBar />)
    const input = screen.getByPlaceholderText('Search notes...')
    fireEvent.change(input, { target: { value: 'test' } })

    expect(await screen.findByText('Decrypting notes…')).toBeInTheDocument()
  })

  it('shows no results message when no matches found', async () => {
    vi.mocked(useNotesStore).mockReturnValue({
      notes: [{ id: 'note-1', updatedAt: new Date().toISOString(), tags: [] }],
      selectNote: selectNoteMock,
    } as any)
    vi.mocked(useDecryptedNotes).mockReturnValue({
      decryptedNotes: { 'note-1': { title: 'Different', content: 'Content' } },
      isUnlocked: true,
      isDecrypting: false,
    })

    render(<SearchBar />)
    const input = screen.getByPlaceholderText('Search notes...')
    fireEvent.change(input, { target: { value: 'nonexistent' } })

    expect(await screen.findByText(/No notes found for "nonexistent"/i)).toBeInTheDocument()
  })

  it('searches in content as well as title', async () => {
    const noteId = 'note-content'
    vi.mocked(useNotesStore).mockReturnValue({
      notes: [{ id: noteId, updatedAt: new Date().toISOString(), tags: [] }],
      selectNote: selectNoteMock,
    } as any)
    vi.mocked(useDecryptedNotes).mockReturnValue({
      decryptedNotes: {
        [noteId]: {
          title: 'Meeting Notes',
          content: 'Discussed the quarterly roadmap',
        },
      },
      isUnlocked: true,
      isDecrypting: false,
    })

    render(<SearchBar />)
    const input = screen.getByPlaceholderText('Search notes...')

    // Search for word only in content
    fireEvent.change(input, { target: { value: 'roadmap' } })

    const result = await screen.findByRole('button', { name: /meeting notes/i })
    expect(result).toBeInTheDocument()
  })

  it('searches in tags', async () => {
    const noteId = 'note-with-tag'
    vi.mocked(useNotesStore).mockReturnValue({
      notes: [{ id: noteId, updatedAt: new Date().toISOString(), tags: ['important', 'work'] }],
      selectNote: selectNoteMock,
    } as any)
    vi.mocked(useDecryptedNotes).mockReturnValue({
      decryptedNotes: {
        [noteId]: {
          title: 'Task List',
          content: 'Things to do',
        },
      },
      isUnlocked: true,
      isDecrypting: false,
    })

    render(<SearchBar />)
    const input = screen.getByPlaceholderText('Search notes...')

    // Search for tag
    fireEvent.change(input, { target: { value: 'important' } })

    const result = await screen.findByRole('button', { name: /task list/i })
    expect(result).toBeInTheDocument()
  })

  it('displays tags as badges in results', async () => {
    const noteId = 'note-tags'
    vi.mocked(useNotesStore).mockReturnValue({
      notes: [{ id: noteId, updatedAt: new Date().toISOString(), tags: ['tag1', 'tag2'] }],
      selectNote: selectNoteMock,
    } as any)
    vi.mocked(useDecryptedNotes).mockReturnValue({
      decryptedNotes: {
        [noteId]: {
          title: 'Tagged Note',
          content: 'Content',
        },
      },
      isUnlocked: true,
      isDecrypting: false,
    })

    render(<SearchBar />)
    const input = screen.getByPlaceholderText('Search notes...')
    fireEvent.change(input, { target: { value: 'tagged' } })

    await screen.findByRole('button', { name: /tagged note/i })
    expect(screen.getByText('tag1')).toBeInTheDocument()
    expect(screen.getByText('tag2')).toBeInTheDocument()
  })

  it('shows +N indicator when more than 2 tags', async () => {
    const noteId = 'note-many-tags'
    vi.mocked(useNotesStore).mockReturnValue({
      notes: [{ id: noteId, updatedAt: new Date().toISOString(), tags: ['a', 'b', 'c', 'd'] }],
      selectNote: selectNoteMock,
    } as any)
    vi.mocked(useDecryptedNotes).mockReturnValue({
      decryptedNotes: {
        [noteId]: {
          title: 'Many Tags',
          content: 'Content',
        },
      },
      isUnlocked: true,
      isDecrypting: false,
    })

    render(<SearchBar />)
    const input = screen.getByPlaceholderText('Search notes...')
    fireEvent.change(input, { target: { value: 'many' } })

    await screen.findByRole('button', { name: /many tags/i })
    expect(screen.getByText('a')).toBeInTheDocument()
    expect(screen.getByText('b')).toBeInTheDocument()
    expect(screen.getByText('+2')).toBeInTheDocument()
  })

  it('sorts results by most recent first', async () => {
    const oldDate = '2024-01-01T00:00:00Z'
    const newDate = '2024-12-01T00:00:00Z'

    vi.mocked(useNotesStore).mockReturnValue({
      notes: [
        { id: 'old', updatedAt: oldDate, tags: [] },
        { id: 'new', updatedAt: newDate, tags: [] },
      ],
      selectNote: selectNoteMock,
    } as any)
    vi.mocked(useDecryptedNotes).mockReturnValue({
      decryptedNotes: {
        old: { title: 'Old Note', content: 'test' },
        new: { title: 'New Note', content: 'test' },
      },
      isUnlocked: true,
      isDecrypting: false,
    })

    render(<SearchBar />)
    const input = screen.getByPlaceholderText('Search notes...')
    fireEvent.change(input, { target: { value: 'test' } })

    const results = await screen.findAllByRole('button')
    // Filter out UI buttons (like clear button) and get note results
    const noteResults = results.filter((btn) => btn.textContent?.includes('Note'))
    expect(noteResults[0]).toHaveTextContent(/new note/i)
    expect(noteResults[1]).toHaveTextContent(/old note/i)
  })

  it('limits results to 20 items', async () => {
    // Create 25 notes
    const notes = Array.from({ length: 25 }, (_, i) => ({
      id: `note-${i}`,
      updatedAt: new Date().toISOString(),
      tags: [],
    }))

    const decryptedNotes: Record<string, any> = {}
    for (let i = 0; i < 25; i++) {
      decryptedNotes[`note-${i}`] = {
        title: `Note ${i}`,
        content: 'searchable content',
      }
    }

    vi.mocked(useNotesStore).mockReturnValue({
      notes,
      selectNote: selectNoteMock,
    } as any)
    vi.mocked(useDecryptedNotes).mockReturnValue({
      decryptedNotes,
      isUnlocked: true,
      isDecrypting: false,
    })

    render(<SearchBar />)
    const input = screen.getByPlaceholderText('Search notes...')
    fireEvent.change(input, { target: { value: 'searchable' } })

    await waitFor(() => {
      const results = screen.getAllByRole('button')
      // Should have 20 results max (plus potential UI buttons)
      const noteResults = results.filter((btn) => btn.textContent?.includes('Note'))
      expect(noteResults.length).toBeLessThanOrEqual(20)
    })
  })
})
