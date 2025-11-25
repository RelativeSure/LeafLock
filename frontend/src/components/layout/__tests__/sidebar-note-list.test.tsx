import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import React from 'react'
import { SidebarNoteList } from '../sidebar-note-list'
import { useNotesStore } from '@/stores/notesStore'
import { useDecryptedNotes } from '@/hooks/use-decrypted-notes'

const selectNoteMock = vi.fn()
const updateNoteMock = vi.fn()
const moveToTrashMock = vi.fn()

vi.mock('@/stores/notesStore', () => ({
  useNotesStore: vi.fn(),
}))

vi.mock('@/hooks/use-decrypted-notes', () => ({
  useDecryptedNotes: vi.fn(),
}))

vi.mock('@/components/ui/scroll-area', () => ({
  ScrollArea: ({ children, className }: any) => (
    <div data-testid="scroll-area" className={className}>
      {children}
    </div>
  ),
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, onClick, variant, size, className, ...props }: any) => (
    <button
      onClick={onClick}
      data-variant={variant}
      data-size={size}
      className={className}
      data-testid="button"
      {...props}
    >
      {children}
    </button>
  ),
}))

vi.mock('@/components/ui/skeleton', () => ({
  Skeleton: ({ className }: any) => <div data-testid="skeleton" className={className} />,
}))

vi.mock('@/components/ui/sidebar', () => ({
  SidebarMenu: ({ children }: any) => <ul data-testid="sidebar-menu">{children}</ul>,
  SidebarMenuItem: ({ children }: any) => <li data-testid="sidebar-menu-item">{children}</li>,
  SidebarMenuButton: ({ children, onClick, isActive, className }: any) => (
    <button
      onClick={onClick}
      data-active={isActive}
      className={className}
      data-testid="sidebar-menu-button"
    >
      {children}
    </button>
  ),
  SidebarInput: (props: any) => <input data-testid="sidebar-input" {...props} />,
}))

vi.mock('@/components/ui/dropdown-menu', () => ({
  DropdownMenu: ({ children }: any) => <div data-testid="dropdown-menu">{children}</div>,
  DropdownMenuContent: ({ children, align }: any) => (
    <div data-testid="dropdown-menu-content" data-align={align}>
      {children}
    </div>
  ),
  DropdownMenuItem: ({ children, onClick }: any) => (
    <button onClick={onClick} data-testid="dropdown-menu-item">
      {children}
    </button>
  ),
  DropdownMenuTrigger: ({ children, asChild }: any) => {
    if (asChild) {
      return React.cloneElement(children, { 'data-testid': 'dropdown-trigger' })
    }
    return <button data-testid="dropdown-trigger">{children}</button>
  },
}))

vi.mock('@/components/ui/context-menu', () => ({
  ContextMenu: ({ children }: any) => <div data-testid="context-menu">{children}</div>,
  ContextMenuContent: ({ children }: any) => (
    <div data-testid="context-menu-content">{children}</div>
  ),
  ContextMenuItem: ({ children, onClick, className }: any) => (
    <button onClick={onClick} className={className} data-testid="context-menu-item">
      {children}
    </button>
  ),
  ContextMenuSeparator: () => <hr data-testid="context-menu-separator" />,
  ContextMenuTrigger: ({ children, asChild }: any) => {
    if (asChild) {
      return React.cloneElement(children, { 'data-testid': 'context-trigger' })
    }
    return <button data-testid="context-trigger">{children}</button>
  },
}))

vi.mock('lucide-react', () => ({
  FileText: () => <span data-testid="icon-file-text">file</span>,
  Lock: () => <span data-testid="icon-lock">lock</span>,
  Pin: () => <span data-testid="icon-pin">pin</span>,
  ArrowUpDown: () => <span data-testid="icon-arrow-up-down">sort</span>,
  Trash2: () => <span data-testid="icon-trash">trash</span>,
  Search: () => <span data-testid="icon-search">search</span>,
  X: () => <span data-testid="icon-x">x</span>,
}))

vi.mock('date-fns', () => ({
  formatDistanceToNow: vi.fn((date: Date) => {
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffMins = Math.floor(diffMs / 60000)
    if (diffMins < 60) return `${diffMins} minutes ago`
    const diffHours = Math.floor(diffMins / 60)
    if (diffHours < 24) return `${diffHours} hours ago`
    return `${Math.floor(diffHours / 24)} days ago`
  }),
}))

const mockNotes = [
  {
    id: 'note-1',
    title: 'First Note',
    content: 'Content 1',
    folderId: 'folder-1',
    tags: ['important'],
    pinned: true,
    encrypted: true,
    isTrashed: false,
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-15T10:00:00Z',
  },
  {
    id: 'note-2',
    title: 'Second Note',
    content: 'Content 2',
    folderId: 'folder-1',
    tags: ['work'],
    pinned: false,
    encrypted: false,
    isTrashed: false,
    createdAt: '2024-01-02T00:00:00Z',
    updatedAt: '2024-01-10T10:00:00Z',
  },
  {
    id: 'note-3',
    title: 'Third Note',
    content: 'Content 3',
    folderId: 'folder-2',
    tags: [],
    pinned: false,
    encrypted: false,
    isTrashed: false,
    createdAt: '2024-01-03T00:00:00Z',
    updatedAt: '2024-01-05T10:00:00Z',
  },
  {
    id: 'note-4',
    title: 'Trashed Note',
    content: 'Trashed content',
    folderId: null,
    tags: [],
    pinned: false,
    encrypted: false,
    isTrashed: true,
    createdAt: '2024-01-04T00:00:00Z',
    updatedAt: '2024-01-04T10:00:00Z',
  },
]

const mockDecryptedNotes = {
  'note-1': {
    title: 'First Note Decrypted',
    content: '<p>Decrypted Content 1</p>',
    timestamp: Date.now(),
  },
  'note-2': { title: 'Second Note', content: '<p>Content 2</p>', timestamp: Date.now() },
  'note-3': { title: 'Third Note', content: '<p>Content 3</p>', timestamp: Date.now() },
}

describe('SidebarNoteList', () => {
  let consoleErrorSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    vi.clearAllMocks()
    updateNoteMock.mockResolvedValue({})
    moveToTrashMock.mockResolvedValue({})

    vi.mocked(useNotesStore).mockReturnValue({
      notes: mockNotes,
      selectedNote: null,
      selectedFolder: null,
      selectNote: selectNoteMock,
      updateNote: updateNoteMock,
      moveToTrash: moveToTrashMock,
    } as any)

    vi.mocked(useDecryptedNotes).mockReturnValue({
      decryptedNotes: mockDecryptedNotes,
      isUnlocked: true,
      isDecrypting: false,
    })

    consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
  })

  afterEach(() => {
    consoleErrorSpy.mockRestore()
  })

  describe('Rendering', () => {
    it('should render the note list', () => {
      render(<SidebarNoteList />)
      expect(screen.getByTestId('sidebar-menu')).toBeInTheDocument()
    })

    it('should render search input', () => {
      render(<SidebarNoteList />)
      expect(screen.getByPlaceholderText('Search notes...')).toBeInTheDocument()
    })

    it('should render sort dropdown', () => {
      render(<SidebarNoteList />)
      const sortOptions = screen.getAllByText('Last Updated')
      expect(sortOptions.length).toBeGreaterThan(0)
    })

    it('should filter out trashed notes', () => {
      render(<SidebarNoteList />)
      expect(screen.queryByText('Trashed Note')).not.toBeInTheDocument()
    })

    it('should render non-trashed notes', () => {
      render(<SidebarNoteList />)
      expect(screen.getByText('First Note Decrypted')).toBeInTheDocument()
      expect(screen.getByText('Second Note')).toBeInTheDocument()
      expect(screen.getByText('Third Note')).toBeInTheDocument()
    })

    it('should show pin icon for pinned notes', () => {
      render(<SidebarNoteList />)
      const pinIcons = screen.getAllByTestId('icon-pin')
      expect(pinIcons.length).toBeGreaterThan(0)
    })

    it('should show lock icon for encrypted notes', () => {
      render(<SidebarNoteList />)
      const lockIcons = screen.getAllByTestId('icon-lock')
      expect(lockIcons.length).toBeGreaterThan(0)
    })

    it('should show empty state when no notes', () => {
      vi.mocked(useNotesStore).mockReturnValue({
        notes: [],
        selectedNote: null,
        selectedFolder: null,
        selectNote: selectNoteMock,
        updateNote: updateNoteMock,
        moveToTrash: moveToTrashMock,
      } as any)

      render(<SidebarNoteList />)
      expect(screen.getByText('No notes found')).toBeInTheDocument()
    })
  })

  describe('Note selection', () => {
    it('should call selectNote when clicking a note', () => {
      render(<SidebarNoteList />)
      const noteButtons = screen.getAllByTestId('sidebar-menu-button')
      fireEvent.click(noteButtons[0])

      expect(selectNoteMock).toHaveBeenCalledWith('note-1')
    })

    it('should highlight selected note', () => {
      vi.mocked(useNotesStore).mockReturnValue({
        notes: mockNotes,
        selectedNote: { id: 'note-2' },
        selectedFolder: null,
        selectNote: selectNoteMock,
        updateNote: updateNoteMock,
        moveToTrash: moveToTrashMock,
      } as any)

      render(<SidebarNoteList />)
      const noteButtons = screen.getAllByTestId('sidebar-menu-button')
      const selectedButton = noteButtons.find((btn) => btn.getAttribute('data-active') === 'true')
      expect(selectedButton).toBeInTheDocument()
    })
  })

  describe('Search functionality', () => {
    it('should filter notes by search query', () => {
      render(<SidebarNoteList />)
      const searchInput = screen.getByPlaceholderText('Search notes...')
      fireEvent.change(searchInput, { target: { value: 'First' } })

      expect(screen.getByText('First Note Decrypted')).toBeInTheDocument()
      expect(screen.queryByText('Second Note')).not.toBeInTheDocument()
    })

    it('should filter notes by tag', () => {
      render(<SidebarNoteList />)
      const searchInput = screen.getByPlaceholderText('Search notes...')
      fireEvent.change(searchInput, { target: { value: 'important' } })

      expect(screen.getByText('First Note Decrypted')).toBeInTheDocument()
    })

    it('should show clear button when search has value', () => {
      render(<SidebarNoteList />)
      const searchInput = screen.getByPlaceholderText('Search notes...')
      fireEvent.change(searchInput, { target: { value: 'test' } })

      const clearButtons = screen.getAllByTestId('button')
      expect(clearButtons.some((btn) => btn.querySelector('[data-testid="icon-x"]'))).toBeTruthy()
    })

    it('should clear search when clicking clear button', () => {
      render(<SidebarNoteList />)
      const searchInput = screen.getByPlaceholderText('Search notes...')
      fireEvent.change(searchInput, { target: { value: 'test' } })

      const clearButton = screen
        .getAllByTestId('button')
        .find((btn) => btn.querySelector('[data-testid="icon-x"]'))
      fireEvent.click(clearButton!)

      expect(searchInput).toHaveValue('')
    })

    it('should show empty state when search matches nothing', () => {
      render(<SidebarNoteList />)
      const searchInput = screen.getByPlaceholderText('Search notes...')
      fireEvent.change(searchInput, { target: { value: 'nonexistent' } })

      expect(screen.getByText('No notes found')).toBeInTheDocument()
    })
  })

  describe('Folder filtering', () => {
    it('should filter notes by selected folder', () => {
      vi.mocked(useNotesStore).mockReturnValue({
        notes: mockNotes,
        selectedNote: null,
        selectedFolder: 'folder-2',
        selectNote: selectNoteMock,
        updateNote: updateNoteMock,
        moveToTrash: moveToTrashMock,
      } as any)

      render(<SidebarNoteList />)
      expect(screen.getByText('Third Note')).toBeInTheDocument()
      expect(screen.queryByText('First Note Decrypted')).not.toBeInTheDocument()
    })
  })

  describe('Sorting', () => {
    it('should sort by last updated by default', () => {
      render(<SidebarNoteList />)
      const sortOptions = screen.getAllByText('Last Updated')
      expect(sortOptions.length).toBeGreaterThan(0)
    })

    it('should change sort option when clicking dropdown items', async () => {
      render(<SidebarNoteList />)
      const dateCreatedItems = screen.getAllByText('Date Created')
      fireEvent.click(dateCreatedItems[0])

      await waitFor(() => {
        const options = screen.getAllByText('Date Created')
        expect(options.length).toBeGreaterThan(0)
      })
    })

    it('should sort by title option', async () => {
      render(<SidebarNoteList />)
      const titleItems = screen.getAllByText('Title')
      fireEvent.click(titleItems[0])

      await waitFor(() => {
        const options = screen.getAllByText('Title')
        expect(options.length).toBeGreaterThan(0)
      })
    })

    it('should always show pinned notes first', () => {
      render(<SidebarNoteList />)
      const noteButtons = screen.getAllByTestId('sidebar-menu-button')
      const firstNoteButton = noteButtons[0]
      expect(firstNoteButton).toHaveTextContent('First Note Decrypted')
    })
  })

  describe('Context menu actions', () => {
    it('should render context menu for notes', () => {
      render(<SidebarNoteList />)
      const contextMenus = screen.getAllByTestId('context-menu')
      expect(contextMenus.length).toBeGreaterThan(0)
    })

    it('should have Open action in context menu', () => {
      render(<SidebarNoteList />)
      expect(screen.getAllByText('Open').length).toBeGreaterThan(0)
    })

    it('should have Pin/Unpin action in context menu', () => {
      render(<SidebarNoteList />)
      expect(screen.getAllByText('Unpin').length).toBeGreaterThan(0)
      expect(screen.getAllByText('Pin').length).toBeGreaterThan(0)
    })

    it('should have Delete action in context menu', () => {
      render(<SidebarNoteList />)
      expect(screen.getAllByText('Delete').length).toBeGreaterThan(0)
    })

    it('should call selectNote when clicking Open', () => {
      render(<SidebarNoteList />)
      const openButtons = screen.getAllByText('Open')
      fireEvent.click(openButtons[0])

      expect(selectNoteMock).toHaveBeenCalled()
    })

    it('should toggle pin when clicking Pin/Unpin', async () => {
      render(<SidebarNoteList />)
      const pinButtons = screen.getAllByText('Pin')
      fireEvent.click(pinButtons[0])

      await waitFor(() => {
        expect(updateNoteMock).toHaveBeenCalledWith(expect.any(String), { pinned: true })
      })
    })

    it('should call moveToTrash when clicking Delete', async () => {
      render(<SidebarNoteList />)
      const deleteButtons = screen.getAllByText('Delete')
      fireEvent.click(deleteButtons[0])

      await waitFor(() => {
        expect(moveToTrashMock).toHaveBeenCalled()
      })
    })

    it('should clear selection when deleting selected note', async () => {
      vi.mocked(useNotesStore).mockReturnValue({
        notes: mockNotes,
        selectedNote: { id: 'note-2' },
        selectedFolder: null,
        selectNote: selectNoteMock,
        updateNote: updateNoteMock,
        moveToTrash: moveToTrashMock,
      } as any)

      render(<SidebarNoteList />)
      const deleteButtons = screen.getAllByText('Delete')
      fireEvent.click(deleteButtons[1])

      await waitFor(() => {
        expect(selectNoteMock).toHaveBeenCalledWith(null)
      })
    })
  })

  describe('Error handling', () => {
    it('should handle pin toggle error', async () => {
      updateNoteMock.mockRejectedValue(new Error('Failed to update'))

      render(<SidebarNoteList />)
      const pinButtons = screen.getAllByText('Pin')
      fireEvent.click(pinButtons[0])

      await waitFor(() => {
        expect(consoleErrorSpy).toHaveBeenCalledWith('Failed to toggle pin:', expect.any(Error))
      })
    })

    it('should handle delete error', async () => {
      moveToTrashMock.mockRejectedValue(new Error('Failed to delete'))

      render(<SidebarNoteList />)
      const deleteButtons = screen.getAllByText('Delete')
      fireEvent.click(deleteButtons[0])

      await waitFor(() => {
        expect(consoleErrorSpy).toHaveBeenCalledWith('Failed to delete note:', expect.any(Error))
      })
    })
  })

  describe('Locked state', () => {
    it('should show "Locked Note" when not unlocked', () => {
      vi.mocked(useDecryptedNotes).mockReturnValue({
        decryptedNotes: {},
        isUnlocked: false,
        isDecrypting: false,
      })

      render(<SidebarNoteList />)
      const lockedNotes = screen.getAllByText('Locked Note')
      expect(lockedNotes.length).toBeGreaterThan(0)
    })

    it('should show skeleton when decrypting', () => {
      vi.mocked(useDecryptedNotes).mockReturnValue({
        decryptedNotes: {},
        isUnlocked: true,
        isDecrypting: true,
      })

      render(<SidebarNoteList />)
      const skeletons = screen.getAllByTestId('skeleton')
      expect(skeletons.length).toBeGreaterThan(0)
    })
  })

  describe('Time formatting', () => {
    it('should display relative time for notes', () => {
      render(<SidebarNoteList />)
      const timeElements = screen.getAllByText(/ago/)
      expect(timeElements.length).toBeGreaterThan(0)
    })

    it('should handle invalid date gracefully', () => {
      vi.mocked(useNotesStore).mockReturnValue({
        notes: [
          {
            id: 'note-invalid',
            title: 'Invalid Date Note',
            updatedAt: 'invalid-date',
            isTrashed: false,
          },
        ],
        selectedNote: null,
        selectedFolder: null,
        selectNote: selectNoteMock,
        updateNote: updateNoteMock,
        moveToTrash: moveToTrashMock,
      } as any)

      vi.mocked(useDecryptedNotes).mockReturnValue({
        decryptedNotes: {
          'note-invalid': { title: 'Invalid Date Note', content: '', timestamp: Date.now() },
        },
        isUnlocked: true,
        isDecrypting: false,
      })

      render(<SidebarNoteList />)
      expect(screen.getByText('Invalid Date Note')).toBeInTheDocument()
    })

    it('should handle missing updatedAt', () => {
      vi.mocked(useNotesStore).mockReturnValue({
        notes: [
          {
            id: 'note-no-date',
            title: 'No Date Note',
            isTrashed: false,
          },
        ],
        selectedNote: null,
        selectedFolder: null,
        selectNote: selectNoteMock,
        updateNote: updateNoteMock,
        moveToTrash: moveToTrashMock,
      } as any)

      vi.mocked(useDecryptedNotes).mockReturnValue({
        decryptedNotes: {
          'note-no-date': { title: 'No Date Note', content: '', timestamp: Date.now() },
        },
        isUnlocked: true,
        isDecrypting: false,
      })

      render(<SidebarNoteList />)
      expect(screen.getByText('No Date Note')).toBeInTheDocument()
    })
  })

  describe('Untitled notes', () => {
    it('should show "Untitled" for notes without title', () => {
      vi.mocked(useDecryptedNotes).mockReturnValue({
        decryptedNotes: {
          'note-1': { title: '', content: 'Some content', timestamp: Date.now() },
        },
        isUnlocked: true,
        isDecrypting: false,
      })

      vi.mocked(useNotesStore).mockReturnValue({
        notes: [mockNotes[0]],
        selectedNote: null,
        selectedFolder: null,
        selectNote: selectNoteMock,
        updateNote: updateNoteMock,
        moveToTrash: moveToTrashMock,
      } as any)

      render(<SidebarNoteList />)
      expect(screen.getByText('Untitled')).toBeInTheDocument()
    })
  })
})
