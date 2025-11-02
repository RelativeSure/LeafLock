import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { TrashDialog } from '../trash-dialog'

const getTrashedNotesMock = vi.fn()
const restoreFromTrashMock = vi.fn()
const deleteNoteMock = vi.fn()
const emptyTrashMock = vi.fn()
const toastMock = vi.fn()

vi.mock('../../stores/notesStore', () => ({
  useNotesStore: vi.fn(() => ({
    getTrashedNotes: getTrashedNotesMock,
    restoreFromTrash: restoreFromTrashMock,
    deleteNote: deleteNoteMock,
    emptyTrash: emptyTrashMock,
  })),
}))

vi.mock('../../hooks/use-toast', () => ({
  useToast: () => ({
    toast: toastMock,
  }),
}))

vi.mock('@/components/ui/dialog', () => ({
  Dialog: ({ children }: any) => <div data-testid="dialog-root">{children}</div>,
  DialogTrigger: ({ children }: any) => <div>{children}</div>,
  DialogContent: ({ children }: any) => <div>{children}</div>,
  DialogHeader: ({ children }: any) => <div>{children}</div>,
  DialogTitle: ({ children }: any) => <h2>{children}</h2>,
  DialogDescription: ({ children }: any) => <p>{children}</p>,
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, onClick, ...props }: any) => (
    <button type="button" onClick={onClick} {...props}>
      {children}
    </button>
  ),
}))

vi.mock('@/components/ui/scroll-area', () => ({
  ScrollArea: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/alert-dialog', () => ({
  AlertDialog: ({ children }: any) => <div>{children}</div>,
  AlertDialogTrigger: ({ children }: any) => <div>{children}</div>,
  AlertDialogContent: ({ children }: any) => <div>{children}</div>,
  AlertDialogHeader: ({ children }: any) => <div>{children}</div>,
  AlertDialogTitle: ({ children }: any) => <h3>{children}</h3>,
  AlertDialogDescription: ({ children }: any) => <p>{children}</p>,
  AlertDialogFooter: ({ children }: any) => <div>{children}</div>,
  AlertDialogCancel: ({ children, onClick }: any) => (
    <button type="button" onClick={onClick}>
      {children}
    </button>
  ),
  AlertDialogAction: ({ children, onClick }: any) => (
    <button type="button" onClick={onClick}>
      {children}
    </button>
  ),
}))

vi.mock('lucide-react', () => ({
  Trash2: () => <span>trash-icon</span>,
  RotateCcw: () => <span>restore-icon</span>,
  X: () => <span>delete-icon</span>,
}))

describe('TrashDialog', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getTrashedNotesMock.mockResolvedValue([])
    restoreFromTrashMock.mockResolvedValue(undefined)
    deleteNoteMock.mockResolvedValue(undefined)
    emptyTrashMock.mockResolvedValue(undefined)
  })

  it('loads trashed notes on mount', async () => {
    render(<TrashDialog />)

    await waitFor(() => {
      expect(getTrashedNotesMock).toHaveBeenCalled()
    })
  })

  it('renders trashed note information', async () => {
    getTrashedNotesMock.mockResolvedValue([
      {
        id: 'note-1',
        title: 'Old draft',
        content: 'Archived content',
        trashedAt: new Date().toISOString(),
      },
    ])

    render(<TrashDialog />)

    await screen.findByText('Old draft')
    expect(screen.getByText(/Empty Trash/)).toBeInTheDocument()
  })

  it('restores note when restore button clicked', async () => {
    getTrashedNotesMock.mockResolvedValue([
      {
        id: 'note-2',
        title: 'Restore me',
        content: 'note body',
        trashedAt: new Date().toISOString(),
      },
    ])

    render(<TrashDialog />)

    const restoreButton = await screen.findByRole('button', { name: /restore/i })
    fireEvent.click(restoreButton)

    await waitFor(() => {
      expect(restoreFromTrashMock).toHaveBeenCalledWith('note-2')
    })
  })

  it('empties trash when confirmed', async () => {
    getTrashedNotesMock.mockResolvedValue([
      {
        id: 'note-3',
        title: 'Delete me',
        content: 'trash content',
        trashedAt: new Date().toISOString(),
      },
    ])

    render(<TrashDialog />)

    await screen.findByText('Delete me')

    const emptyButtons = screen.getAllByText(/empty trash/i)
    const confirmButton = emptyButtons[emptyButtons.length - 1]
    fireEvent.click(confirmButton)

    await waitFor(() => {
      expect(emptyTrashMock).toHaveBeenCalled()
    })
  })
})
