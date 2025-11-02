import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { SearchBar } from '../search-bar'

const selectNoteMock = vi.fn()
let notesState: Array<Record<string, any>> = []
let decryptedReturn = {
  decryptedNotes: {} as Record<string, { title?: string; content?: string }>,
  isUnlocked: true,
  isDecrypting: false,
}

vi.mock('../../stores/notesStore', () => ({
  useNotesStore: vi.fn(() => ({
    notes: notesState,
    selectNote: selectNoteMock,
  })),
}))

vi.mock('@/hooks/use-decrypted-notes', () => ({
  useDecryptedNotes: vi.fn(() => decryptedReturn),
}))

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
    notesState = []
    decryptedReturn = {
      decryptedNotes: {},
      isUnlocked: true,
      isDecrypting: false,
    }
  })

  it('renders the search input', () => {
    render(<SearchBar />)
    expect(screen.getByPlaceholderText('Search notes...')).toBeInTheDocument()
  })

  it('shows unlock message when vault is locked', async () => {
    decryptedReturn = {
      decryptedNotes: {},
      isUnlocked: false,
      isDecrypting: false,
    }

    render(<SearchBar />)

    const input = screen.getByPlaceholderText('Search notes...')
    fireEvent.change(input, { target: { value: 'project' } })

    expect(screen.getByTestId('dialog')).toBeInTheDocument()
    await screen.findByText('Unlock your vault to search notes.')
  })

  it('displays search results when unlocked', async () => {
    const noteId = 'note-1'
    notesState = [{ id: noteId, updatedAt: new Date().toISOString(), tags: [] }]
    decryptedReturn = {
      decryptedNotes: {
        [noteId]: {
          title: 'Project Meeting',
          content: 'Discuss roadmap',
        },
      },
      isUnlocked: true,
      isDecrypting: false,
    }

    render(<SearchBar />)

    const input = screen.getByPlaceholderText('Search notes...')
    fireEvent.change(input, { target: { value: 'project' } })

    const result = await screen.findByRole('button', { name: /project meeting/i })
    expect(result).toBeInTheDocument()
  })

  it('selects note and clears query when a result is clicked', async () => {
    const noteId = 'note-42'
    notesState = [{ id: noteId, updatedAt: new Date().toISOString(), tags: ['work'] }]
    decryptedReturn = {
      decryptedNotes: {
        [noteId]: {
          title: 'Weekly Sync',
          content: 'Agenda and action items',
        },
      },
      isUnlocked: true,
      isDecrypting: false,
    }

    render(<SearchBar />)

    const input = screen.getByPlaceholderText('Search notes...')
    fireEvent.change(input, { target: { value: 'weekly' } })

    const result = await screen.findByRole('button', { name: /weekly sync/i })
    fireEvent.click(result)

    await waitFor(() => expect(selectNoteMock).toHaveBeenCalledWith(noteId))
    expect(input).toHaveValue('')
  })
})
