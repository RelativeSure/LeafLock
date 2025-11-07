import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { AdvancedSearchBar } from '../advanced-search-bar'

const useNotesStoreMock = vi.fn()
const useDecryptedNotesMock = vi.fn()

vi.mock('@/stores/notesStore', () => ({
  useNotesStore: (...args: unknown[]) => useNotesStoreMock(...args),
}))

vi.mock('@/hooks/use-decrypted-notes', () => ({
  useDecryptedNotes: (...args: unknown[]) => useDecryptedNotesMock(...args),
}))

vi.mock('@/lib/encryption-context', () => ({
  useEncryption: () => ({
    isUnlocked: true,
    unlock: vi.fn(),
    lock: vi.fn(),
  }),
}))

vi.mock('@/components/ui/input', () => ({
  Input: ({ onChange, value, onFocus, placeholder, className }: any) => (
    <input
      aria-label={placeholder}
      placeholder={placeholder}
      value={value}
      onChange={onChange}
      onFocus={onFocus}
      className={className}
    />
  ),
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, onClick, ...props }: any) => (
    <button onClick={onClick} {...props}>
      {children}
    </button>
  ),
}))

vi.mock('@/components/ui/badge', () => ({
  Badge: ({ children, ...props }: any) => (
    <span data-testid="badge" {...props}>
      {children}
    </span>
  ),
}))

vi.mock('@/components/ui/card', () => ({
  Card: ({ children }: any) => <div>{children}</div>,
  CardHeader: ({ children }: any) => <div>{children}</div>,
  CardTitle: ({ children }: any) => <div>{children}</div>,
  CardContent: ({ children }: any) => <div>{children}</div>,
  CardDescription: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/scroll-area', () => ({
  ScrollArea: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/dialog', () => ({
  Dialog: ({ children, open }: any) => <div>{open && children}</div>,
  DialogContent: ({ children }: any) => <div>{children}</div>,
  DialogHeader: ({ children }: any) => <div>{children}</div>,
  DialogTitle: ({ children }: any) => <div>{children}</div>,
  DialogTrigger: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/select', () => ({
  Select: ({ children }: any) => <div>{children}</div>,
  SelectTrigger: ({ children }: any) => <div>{children}</div>,
  SelectContent: ({ children }: any) => <div>{children}</div>,
  SelectItem: ({ children }: any) => <div>{children}</div>,
  SelectValue: ({ placeholder }: any) => <span>{placeholder}</span>,
}))

vi.mock('date-fns', () => ({
  formatDistanceToNow: () => 'moments ago',
}))

const selectNoteMock = vi.fn()

const sampleNotes = [
  {
    id: 'note-1',
    folderId: 'folder-1',
    tags: ['urgent', 'project'],
    updatedAt: new Date().toISOString(),
    createdAt: new Date().toISOString(),
    encrypted: true,
    pinned: true,
    isTrashed: false,
  },
  {
    id: 'note-2',
    folderId: 'folder-2',
    tags: ['ideas'],
    updatedAt: new Date(Date.now() - 86400000).toISOString(),
    createdAt: new Date(Date.now() - 86400000).toISOString(),
    encrypted: false,
    pinned: false,
    isTrashed: false,
  },
] as any

const setupDefaults = () => {
  useNotesStoreMock.mockReturnValue({
    notes: sampleNotes,
    folders: [
      { id: 'folder-1', name: 'Projects' },
      { id: 'folder-2', name: 'Archive' },
    ],
    tags: [
      { id: 'tag-1', name: 'urgent' },
      { id: 'tag-2', name: 'ideas' },
    ],
    selectNote: selectNoteMock,
  })

  useDecryptedNotesMock.mockReturnValue({
    decryptedNotes: {
      'note-1': { title: 'Meeting Notes', content: '<p>Discuss roadmap</p>' },
      'note-2': { title: 'Random Ideas', content: '<p>Brainstorm session</p>' },
    },
    isUnlocked: true,
    isDecrypting: false,
  })
}

const openSearch = () => {
  const input = screen.getByPlaceholderText('Search notes...')
  fireEvent.focus(input)
  return input
}

describe('AdvancedSearchBar', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    setupDefaults()
  })

  it('renders matching results for a query and selects a note', async () => {
    render(<AdvancedSearchBar />)

    const input = openSearch()
    await waitFor(() => expect(screen.getByText(/results/i)).toBeInTheDocument())
    fireEvent.change(input, { target: { value: 'meeting' } })

    await waitFor(() => {
      expect(screen.getByText('Meeting Notes')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('Meeting Notes'))
    expect(selectNoteMock).toHaveBeenCalledWith('note-1')
  })

  it('shows locked messaging when workspace is locked', async () => {
    useDecryptedNotesMock.mockReturnValue({
      decryptedNotes: {},
      isUnlocked: false,
      isDecrypting: false,
    })

    render(<AdvancedSearchBar />)
    openSearch()
    await waitFor(() => expect(screen.getByText(/results/i)).toBeInTheDocument())

    await waitFor(() => {
      expect(screen.getByText('Encrypted notes are locked')).toBeInTheDocument()
    })
  })

  it('shows decrypting state while unlocking notes', async () => {
    useDecryptedNotesMock.mockReturnValue({
      decryptedNotes: {},
      isUnlocked: true,
      isDecrypting: true,
    })

    render(<AdvancedSearchBar />)
    openSearch()
    await waitFor(() => expect(screen.getByText(/results/i)).toBeInTheDocument())

    await waitFor(() => {
      expect(screen.getByText('Decrypting notes…')).toBeInTheDocument()
    })
  })

  it('clears applied filters and removes filter badge', async () => {
    render(<AdvancedSearchBar />)

    openSearch()
    await waitFor(() => expect(screen.getByText(/results/i)).toBeInTheDocument())
    const encryptedCheckbox = screen.getByLabelText('Encrypted only') as HTMLInputElement
    const pinnedCheckbox = screen.getByLabelText('Pinned only') as HTMLInputElement

    fireEvent.click(encryptedCheckbox)
    fireEvent.click(pinnedCheckbox)

    await waitFor(() => {
      const badges = screen.getAllByTestId('badge')
      expect(
        badges.some((badge) => /filters$/i.test((badge.textContent || '').trim()))
      ).toBe(true)
    })

    fireEvent.click(screen.getByRole('button', { name: /clear filters/i }))

    await waitFor(() => {
      expect(encryptedCheckbox.checked).toBe(false)
      expect(pinnedCheckbox.checked).toBe(false)
      const badges = screen.queryAllByTestId('badge')
      expect(
        badges.some((badge) => /filters$/i.test((badge.textContent || '').trim()))
      ).toBe(false)
    })
  })

  it('filters results by pinned status when pinned only is enabled', async () => {
    render(<AdvancedSearchBar />)

    openSearch()
    await waitFor(() => expect(screen.getByText(/results/i)).toBeInTheDocument())
    const pinnedCheckbox = screen.getByLabelText('Pinned only')
    fireEvent.click(pinnedCheckbox)

    await waitFor(() => {
      expect(screen.getByText('Meeting Notes')).toBeInTheDocument()
      expect(screen.queryByText('Random Ideas')).toBeNull()
    })
  })
})
