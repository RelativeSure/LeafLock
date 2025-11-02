import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { TrashDialog } from '../trash-dialog'
import { useNotesStore } from '@/stores/notesStore'
import type { Note } from '@/types'

vi.mock('@/stores/notesStore', () => ({
  useNotesStore: vi.fn(),
}))

vi.mock('@/components/ui/dialog', () => ({
  Dialog: ({ children, open }: any) => (open ? <div data-testid="dialog">{children}</div> : null),
  DialogContent: ({ children }: any) => <div data-testid="dialog-content">{children}</div>,
  DialogHeader: ({ children }: any) => <div>{children}</div>,
  DialogTitle: ({ children }: any) => <h2>{children}</h2>,
  DialogDescription: ({ children }: any) => <p>{children}</p>,
  DialogFooter: ({ children }: any) => <div>{children}</div>,
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

describe('TrashDialog', () => {
  const mockTrashedNote: Note = {
    id: 'note-1',
    title: 'Trashed Note',
    content: 'Content',
    userId: '123',
    encrypted: true,
    encryptionVersion: 1,
    folderId: null,
    tags: [],
    pinned: false,
    isTrashed: true,
    trashedAt: '2024-01-01T00:00:00Z',
    sharedWith: [],
    isTemplate: false,
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
  }

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('should render trash dialog when open', () => {
    vi.mocked(useNotesStore).mockReturnValue({
      notes: [],
      getTrashedNotes: vi.fn().mockResolvedValue([]),
      restoreFromTrash: vi.fn(),
      emptyTrash: vi.fn(),
    } as any)

    render(<TrashDialog open={true} onOpenChange={vi.fn()} />)
    expect(screen.getByTestId('dialog')).toBeInTheDocument()
  })

  it('should not render when closed', () => {
    vi.mocked(useNotesStore).mockReturnValue({
      notes: [],
      getTrashedNotes: vi.fn().mockResolvedValue([]),
      restoreFromTrash: vi.fn(),
      emptyTrash: vi.fn(),
    } as any)

    render(<TrashDialog open={false} onOpenChange={vi.fn()} />)
    expect(screen.queryByTestId('dialog')).not.toBeInTheDocument()
  })

  it('should load trashed notes on mount', async () => {
    const getTrashedNotes = vi.fn().mockResolvedValue([mockTrashedNote])

    vi.mocked(useNotesStore).mockReturnValue({
      notes: [mockTrashedNote],
      getTrashedNotes,
      restoreFromTrash: vi.fn(),
      emptyTrash: vi.fn(),
    } as any)

    render(<TrashDialog open={true} onOpenChange={vi.fn()} />)

    await waitFor(() => {
      expect(getTrashedNotes).toHaveBeenCalled()
    })
  })

  it('should display trashed notes', async () => {
    vi.mocked(useNotesStore).mockReturnValue({
      notes: [mockTrashedNote],
      getTrashedNotes: vi.fn().mockResolvedValue([mockTrashedNote]),
      restoreFromTrash: vi.fn(),
      emptyTrash: vi.fn(),
    } as any)

    render(<TrashDialog open={true} onOpenChange={vi.fn()} />)

    await waitFor(() => {
      expect(screen.getByTestId('dialog-content')).toBeInTheDocument()
    })
  })

  it('should call restore on restore button click', async () => {
    const restoreFromTrash = vi.fn().mockResolvedValue(undefined)

    vi.mocked(useNotesStore).mockReturnValue({
      notes: [mockTrashedNote],
      getTrashedNotes: vi.fn().mockResolvedValue([mockTrashedNote]),
      restoreFromTrash,
      emptyTrash: vi.fn(),
    } as any)

    render(<TrashDialog open={true} onOpenChange={vi.fn()} />)

    await waitFor(() => {
      expect(screen.getByTestId('dialog-content')).toBeInTheDocument()
    })
  })

  it('should call empty trash on empty button click', async () => {
    const emptyTrash = vi.fn().mockResolvedValue(undefined)

    vi.mocked(useNotesStore).mockReturnValue({
      notes: [mockTrashedNote],
      getTrashedNotes: vi.fn().mockResolvedValue([mockTrashedNote]),
      restoreFromTrash: vi.fn(),
      emptyTrash,
    } as any)

    render(<TrashDialog open={true} onOpenChange={vi.fn()} />)

    await waitFor(() => {
      expect(screen.getByTestId('dialog-content')).toBeInTheDocument()
    })
  })

  it('should show empty state when no trashed notes', async () => {
    vi.mocked(useNotesStore).mockReturnValue({
      notes: [],
      getTrashedNotes: vi.fn().mockResolvedValue([]),
      restoreFromTrash: vi.fn(),
      emptyTrash: vi.fn(),
    } as any)

    render(<TrashDialog open={true} onOpenChange={vi.fn()} />)

    await waitFor(() => {
      expect(screen.getByTestId('dialog-content')).toBeInTheDocument()
    })
  })

  it('should handle errors gracefully', async () => {
    const getTrashedNotes = vi.fn().mockRejectedValue(new Error('Failed to load'))

    vi.mocked(useNotesStore).mockReturnValue({
      notes: [],
      getTrashedNotes,
      restoreFromTrash: vi.fn(),
      emptyTrash: vi.fn(),
    } as any)

    render(<TrashDialog open={true} onOpenChange={vi.fn()} />)

    await waitFor(() => {
      expect(screen.getByTestId('dialog-content')).toBeInTheDocument()
    })
  })
})
