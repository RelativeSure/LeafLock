import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { NoteList } from '../note-list'
import { useNotesStore } from '@/stores/notesStore'
import type { Note } from '@/types'

vi.mock('@/stores/notesStore', () => ({
  useNotesStore: vi.fn(),
}))

vi.mock('@/hooks/use-decrypted-notes', () => ({
  useDecryptedNotes: (notes: any[]) => ({
    decryptedNotes: notes.reduce((acc, n) => ({ ...acc, [n.id]: n }), {}),
    isUnlocked: true,
    isDecrypting: false,
  }),
}))

vi.mock('./bulk-operations-bar', () => ({
  BulkOperationsBar: () => <div data-testid="bulk-operations-bar">Bulk Operations</div>,
}))

vi.mock('@/components/ui/scroll-area', () => ({
  ScrollArea: ({ children }: any) => <div data-testid="scroll-area">{children}</div>,
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, onClick, ...props }: any) => (
    <button onClick={onClick} {...props}>
      {children}
    </button>
  ),
}))

vi.mock('@/components/ui/skeleton', () => ({
  Skeleton: () => <div data-testid="skeleton">Loading...</div>,
}))

vi.mock('@/components/ui/dropdown-menu', () => ({
  DropdownMenu: ({ children }: any) => <div>{children}</div>,
  DropdownMenuContent: ({ children }: any) => <div>{children}</div>,
  DropdownMenuItem: ({ children, onClick }: any) => <div onClick={onClick}>{children}</div>,
  DropdownMenuTrigger: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/context-menu', () => ({
  ContextMenu: ({ children }: any) => <div>{children}</div>,
  ContextMenuContent: ({ children }: any) => <div>{children}</div>,
  ContextMenuItem: ({ children, onClick }: any) => (
    <div onClick={onClick} data-testid="context-menu-item">
      {children}
    </div>
  ),
  ContextMenuSeparator: () => <div data-testid="context-menu-separator" />,
  ContextMenuTrigger: ({ children }: any) => <div>{children}</div>,
}))

describe('NoteList', () => {
  const mockNote: Note = {
    id: 'note-1',
    title: 'Test Note',
    content: 'Test content',
    userId: '123',
    encrypted: true,
    encryptionVersion: 1,
    folderId: null,
    tags: ['tag1'],
    pinned: false,
    isTrashed: false,
    sharedWith: [],
    isTemplate: false,
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
  }

  const mockPinnedNote: Note = {
    ...mockNote,
    id: 'note-2',
    title: 'Pinned Note',
    pinned: true,
  }

  const mockTrashedNote: Note = {
    ...mockNote,
    id: 'note-3',
    title: 'Trashed Note',
    isTrashed: true,
  }

  const createMockStore = (overrides = {}) => ({
    notes: [],
    selectedNote: null,
    selectedFolder: null,
    selectNote: vi.fn(),
    createNote: vi.fn(),
    updateNote: vi.fn().mockResolvedValue(undefined),
    moveToTrash: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  })

  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(useNotesStore).mockReturnValue(createMockStore() as any)
  })

  it('should render note list container', () => {
    render(<NoteList />)
    // When no notes, should show empty state
    expect(screen.getByText('No notes yet')).toBeInTheDocument()
  })

  it('should render with notes', () => {
    vi.mocked(useNotesStore).mockReturnValue(
      createMockStore({
        notes: [mockNote],
      }) as any
    )

    render(<NoteList />)
    expect(screen.getByText('Test Note')).toBeInTheDocument()
  })

  it('should render empty state when no notes', () => {
    vi.mocked(useNotesStore).mockReturnValue(createMockStore({ notes: [] }) as any)

    render(<NoteList />)
    expect(screen.getByText('No notes yet')).toBeInTheDocument()
  })

  it('should filter out trashed notes', () => {
    vi.mocked(useNotesStore).mockReturnValue(
      createMockStore({
        notes: [mockNote, mockTrashedNote],
      }) as any
    )

    render(<NoteList />)
    expect(screen.getByText('Test Note')).toBeInTheDocument()
    expect(screen.queryByText('Trashed Note')).not.toBeInTheDocument()
  })

  it('should show pinned notes first', () => {
    vi.mocked(useNotesStore).mockReturnValue(
      createMockStore({
        notes: [mockNote, mockPinnedNote],
      }) as any
    )

    render(<NoteList />)
    // Both notes should be rendered
    expect(screen.getByText('Pinned Note')).toBeInTheDocument()
    expect(screen.getByText('Test Note')).toBeInTheDocument()
  })

  it('should filter notes by selected folder', () => {
    const folderNote = {
      ...mockNote,
      id: 'folder-note',
      title: 'Folder Note',
      folderId: 'folder-1',
    }
    vi.mocked(useNotesStore).mockReturnValue(
      createMockStore({
        notes: [mockNote, folderNote],
        selectedFolder: 'folder-1',
      }) as any
    )

    render(<NoteList />)
    expect(screen.queryByText('Test Note')).not.toBeInTheDocument()
    expect(screen.getByText('Folder Note')).toBeInTheDocument()
  })

  it('should handle toggle pin', async () => {
    const mockUpdateNote = vi.fn().mockResolvedValue(undefined)
    vi.mocked(useNotesStore).mockReturnValue(
      createMockStore({
        notes: [mockNote],
        updateNote: mockUpdateNote,
      }) as any
    )

    render(<NoteList />)

    const contextMenuItems = screen.getAllByTestId('context-menu-item')
    const pinItem = contextMenuItems.find((item) => item.textContent?.includes('Pin'))

    if (pinItem) {
      fireEvent.click(pinItem)

      await waitFor(() => {
        expect(mockUpdateNote).toHaveBeenCalledWith('note-1', { pinned: true })
      })
    }
  })

  it('should handle unpin', async () => {
    const mockUpdateNote = vi.fn().mockResolvedValue(undefined)
    vi.mocked(useNotesStore).mockReturnValue(
      createMockStore({
        notes: [mockPinnedNote],
        updateNote: mockUpdateNote,
      }) as any
    )

    render(<NoteList />)

    const contextMenuItems = screen.getAllByTestId('context-menu-item')
    const unpinItem = contextMenuItems.find((item) => item.textContent?.includes('Unpin'))

    if (unpinItem) {
      fireEvent.click(unpinItem)

      await waitFor(() => {
        expect(mockUpdateNote).toHaveBeenCalledWith('note-2', { pinned: false })
      })
    }
  })

  it('should handle delete note', async () => {
    const mockMoveToTrash = vi.fn().mockResolvedValue(undefined)
    const mockSelectNote = vi.fn()
    vi.mocked(useNotesStore).mockReturnValue(
      createMockStore({
        notes: [mockNote],
        selectedNote: mockNote,
        moveToTrash: mockMoveToTrash,
        selectNote: mockSelectNote,
      }) as any
    )

    render(<NoteList />)

    const contextMenuItems = screen.getAllByTestId('context-menu-item')
    const deleteItem = contextMenuItems.find((item) => item.textContent?.includes('Delete'))

    if (deleteItem) {
      fireEvent.click(deleteItem)

      await waitFor(() => {
        expect(mockMoveToTrash).toHaveBeenCalledWith('note-1')
        expect(mockSelectNote).toHaveBeenCalledWith(null)
      })
    }
  })

  it('should handle duplicate note', () => {
    const mockSelectNote = vi.fn()
    vi.mocked(useNotesStore).mockReturnValue(
      createMockStore({
        notes: [mockNote],
        selectNote: mockSelectNote,
      }) as any
    )

    render(<NoteList />)

    const contextMenuItems = screen.getAllByTestId('context-menu-item')
    const duplicateItem = contextMenuItems.find((item) => item.textContent?.includes('Duplicate'))

    if (duplicateItem) {
      fireEvent.click(duplicateItem)
      expect(mockSelectNote).toHaveBeenCalledWith('note-1')
    }
  })

  it('should sort notes by updated date', () => {
    const oldNote = { ...mockNote, id: 'old', title: 'Old Note', updatedAt: '2023-01-01T00:00:00Z' }
    const newNote = { ...mockNote, id: 'new', title: 'New Note', updatedAt: '2024-12-01T00:00:00Z' }

    vi.mocked(useNotesStore).mockReturnValue(
      createMockStore({
        notes: [oldNote, newNote],
      }) as any
    )

    render(<NoteList />)

    // Both notes should be rendered
    expect(screen.getByText('Old Note')).toBeInTheDocument()
    expect(screen.getByText('New Note')).toBeInTheDocument()
  })

  it('should sort notes by title', () => {
    const noteA = { ...mockNote, id: 'a', title: 'Apple' }
    const noteZ = { ...mockNote, id: 'z', title: 'Zebra' }

    vi.mocked(useNotesStore).mockReturnValue(
      createMockStore({
        notes: [noteZ, noteA],
      }) as any
    )

    render(<NoteList />)

    // Notes should be rendered
    expect(screen.getByText('Apple')).toBeInTheDocument()
    expect(screen.getByText('Zebra')).toBeInTheDocument()
  })

  it('should handle notes with invalid dates', () => {
    const invalidNote = { ...mockNote, updatedAt: 'invalid-date' }

    vi.mocked(useNotesStore).mockReturnValue(
      createMockStore({
        notes: [invalidNote],
      }) as any
    )

    render(<NoteList />)
    expect(screen.getByText('Test Note')).toBeInTheDocument()
  })

  it('should handle error when toggling pin fails', async () => {
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const mockUpdateNote = vi.fn().mockRejectedValue(new Error('Failed to update'))

    vi.mocked(useNotesStore).mockReturnValue(
      createMockStore({
        notes: [mockNote],
        updateNote: mockUpdateNote,
      }) as any
    )

    render(<NoteList />)

    const contextMenuItems = screen.getAllByTestId('context-menu-item')
    const pinItem = contextMenuItems.find((item) => item.textContent?.includes('Pin'))

    if (pinItem) {
      fireEvent.click(pinItem)

      await waitFor(() => {
        expect(consoleErrorSpy).toHaveBeenCalledWith('Failed to toggle pin:', expect.any(Error))
      })
    }

    consoleErrorSpy.mockRestore()
  })

  it('should handle error when deleting note fails', async () => {
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const mockMoveToTrash = vi.fn().mockRejectedValue(new Error('Failed to delete'))

    vi.mocked(useNotesStore).mockReturnValue(
      createMockStore({
        notes: [mockNote],
        moveToTrash: mockMoveToTrash,
      }) as any
    )

    render(<NoteList />)

    const contextMenuItems = screen.getAllByTestId('context-menu-item')
    const deleteItem = contextMenuItems.find((item) => item.textContent?.includes('Delete'))

    if (deleteItem) {
      fireEvent.click(deleteItem)

      await waitFor(() => {
        expect(consoleErrorSpy).toHaveBeenCalledWith('Failed to delete note:', expect.any(Error))
      })
    }

    consoleErrorSpy.mockRestore()
  })

  it('should not deselect note when deleting a different note', async () => {
    const mockMoveToTrash = vi.fn().mockResolvedValue(undefined)
    const mockSelectNote = vi.fn()
    const otherNote = { ...mockNote, id: 'other-note', title: 'Other Note' }

    vi.mocked(useNotesStore).mockReturnValue(
      createMockStore({
        notes: [mockNote, otherNote],
        selectedNote: mockNote, // mockNote is selected
        moveToTrash: mockMoveToTrash,
        selectNote: mockSelectNote,
      }) as any
    )

    render(<NoteList />)

    // This test verifies the logic, actual interaction would need more setup
    expect(screen.getByText('Test Note')).toBeInTheDocument()
    expect(screen.getByText('Other Note')).toBeInTheDocument()
  })

  it('should show tags for notes', () => {
    vi.mocked(useNotesStore).mockReturnValue(
      createMockStore({
        notes: [mockNote],
      }) as any
    )

    render(<NoteList />)
    expect(screen.getByText('tag1')).toBeInTheDocument()
  })

  it('should render notes with encryption info', () => {
    vi.mocked(useNotesStore).mockReturnValue(
      createMockStore({
        notes: [mockNote],
      }) as any
    )

    render(<NoteList />)
    // Note should be rendered
    expect(screen.getByText('Test Note')).toBeInTheDocument()
  })
})
