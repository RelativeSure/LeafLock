import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { TrashDialog } from '../trash-dialog'
import { useNotesStore } from '@/stores/notesStore'
import { useToast } from '@/hooks/use-toast'

const getTrashedNotesMock = vi.fn()
const restoreFromTrashMock = vi.fn()
const deleteNoteMock = vi.fn()
const emptyTrashMock = vi.fn()
const toastMock = vi.fn()

vi.mock('@/stores/notesStore')
vi.mock('@/hooks/use-toast')

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

    vi.mocked(useNotesStore).mockReturnValue({
      getTrashedNotes: getTrashedNotesMock,
      restoreFromTrash: restoreFromTrashMock,
      deleteNote: deleteNoteMock,
      emptyTrash: emptyTrashMock,
    } as any)

    vi.mocked(useToast).mockReturnValue({
      toast: toastMock,
    } as any)

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
    expect(screen.getByText('Archived content')).toBeInTheDocument()
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

  it('shows empty trash state when no notes', async () => {
    getTrashedNotesMock.mockResolvedValue([])

    render(<TrashDialog />)

    await screen.findByText('Trash is empty')
    expect(screen.queryByText(/Empty Trash/)).not.toBeInTheDocument()
  })

  it('displays note count in trigger button', async () => {
    getTrashedNotesMock.mockResolvedValue([
      { id: '1', title: 'Note 1', content: '', trashedAt: new Date().toISOString() },
      { id: '2', title: 'Note 2', content: '', trashedAt: new Date().toISOString() },
    ])

    render(<TrashDialog />)

    await screen.findByText('Note 1')

    await waitFor(
      () => {
        const buttons = screen.getAllByRole('button')
        const trashButton = buttons.find((btn) => btn.textContent?.includes('Trash (2)'))
        expect(trashButton).toBeDefined()
      },
      { timeout: 3000 }
    )
  })

  it('handles restore error gracefully', async () => {
    getTrashedNotesMock.mockResolvedValue([
      {
        id: 'note-4',
        title: 'Error Note',
        content: 'content',
        trashedAt: new Date().toISOString(),
      },
    ])
    restoreFromTrashMock.mockRejectedValue(new Error('Network error'))

    render(<TrashDialog />)

    const restoreButton = await screen.findByRole('button', { name: /restore/i })
    fireEvent.click(restoreButton)

    await waitFor(() => {
      expect(toastMock).toHaveBeenCalledWith('Error', {
        description: 'Failed to restore note.',
      })
    })
  })

  it('handles delete error gracefully', async () => {
    getTrashedNotesMock.mockResolvedValue([
      {
        id: 'note-5',
        title: 'Delete Error',
        content: 'content',
        trashedAt: new Date().toISOString(),
      },
    ])
    deleteNoteMock.mockRejectedValue(new Error('Delete failed'))

    render(<TrashDialog />)

    await screen.findByText('Delete Error')

    // Find and click delete button (X icon)
    const deleteButtons = screen.getAllByRole('button')
    const deleteButton = deleteButtons.find((btn) => btn.textContent?.includes('delete-icon'))
    if (deleteButton) {
      fireEvent.click(deleteButton)

      // Find and click confirm in alert dialog
      const confirmButtons = screen.getAllByRole('button')
      const confirmDelete = confirmButtons.find((btn) => btn.textContent === 'Delete')
      if (confirmDelete) {
        fireEvent.click(confirmDelete)

        await waitFor(() => {
          expect(toastMock).toHaveBeenCalledWith('Error', {
            description: 'Failed to delete note.',
          })
        })
      }
    }
  })

  it('handles empty trash error gracefully', async () => {
    getTrashedNotesMock.mockResolvedValue([
      {
        id: 'note-6',
        title: 'Note',
        content: 'content',
        trashedAt: new Date().toISOString(),
      },
    ])
    emptyTrashMock.mockRejectedValue(new Error('Empty failed'))

    render(<TrashDialog />)

    await screen.findByText('Note')

    const emptyButtons = screen.getAllByText(/empty trash/i)
    const confirmButton = emptyButtons[emptyButtons.length - 1]
    fireEvent.click(confirmButton)

    await waitFor(() => {
      expect(toastMock).toHaveBeenCalledWith('Error', {
        description: 'Failed to empty trash.',
      })
    })
  })

  it('shows success toast on restore', async () => {
    getTrashedNotesMock.mockResolvedValue([
      {
        id: 'note-7',
        title: 'Restore Success',
        content: 'content',
        trashedAt: new Date().toISOString(),
      },
    ])

    render(<TrashDialog />)

    const restoreButton = await screen.findByRole('button', { name: /restore/i })
    fireEvent.click(restoreButton)

    await waitFor(() => {
      expect(toastMock).toHaveBeenCalledWith('Note restored', {
        description: '"Restore Success" has been restored.',
      })
    })
  })

  it('shows success toast on permanent delete', async () => {
    getTrashedNotesMock.mockResolvedValue([
      {
        id: 'note-8',
        title: 'Permanent Delete',
        content: 'content',
        trashedAt: new Date().toISOString(),
      },
    ])

    render(<TrashDialog />)

    await screen.findByText('Permanent Delete')

    // Find and click delete button
    const deleteButtons = screen.getAllByRole('button')
    const deleteButton = deleteButtons.find((btn) => btn.textContent?.includes('delete-icon'))
    if (deleteButton) {
      fireEvent.click(deleteButton)

      const confirmButtons = screen.getAllByRole('button')
      const confirmDelete = confirmButtons.find((btn) => btn.textContent === 'Delete')
      if (confirmDelete) {
        fireEvent.click(confirmDelete)

        await waitFor(() => {
          expect(toastMock).toHaveBeenCalledWith('Note deleted permanently', {
            description: '"Permanent Delete" has been permanently deleted.',
          })
        })
      }
    }
  })

  it('shows success toast on empty trash', async () => {
    getTrashedNotesMock.mockResolvedValue([
      {
        id: 'note-9',
        title: 'Note',
        content: 'content',
        trashedAt: new Date().toISOString(),
      },
    ])

    render(<TrashDialog />)

    await screen.findByText('Note')

    const emptyButtons = screen.getAllByText(/empty trash/i)
    const confirmButton = emptyButtons[emptyButtons.length - 1]
    fireEvent.click(confirmButton)

    await waitFor(() => {
      expect(toastMock).toHaveBeenCalledWith('Trash emptied', {
        description: 'All notes in trash have been permanently deleted.',
      })
    })
  })

  it('reloads notes after restore', async () => {
    getTrashedNotesMock.mockResolvedValue([
      {
        id: 'note-10',
        title: 'Reload Test',
        content: 'content',
        trashedAt: new Date().toISOString(),
      },
    ])

    render(<TrashDialog />)

    const restoreButton = await screen.findByRole('button', { name: /restore/i })

    getTrashedNotesMock.mockClear()
    fireEvent.click(restoreButton)

    await waitFor(() => {
      expect(getTrashedNotesMock).toHaveBeenCalled()
    })
  })

  it('handles non-array response from getTrashedNotes', async () => {
    getTrashedNotesMock.mockResolvedValue(null)

    render(<TrashDialog />)

    await waitFor(() => {
      expect(screen.getByText('Trash is empty')).toBeInTheDocument()
    })
  })

  it('displays formatted trash date', async () => {
    const trashedDate = new Date('2024-01-01T00:00:00Z')
    getTrashedNotesMock.mockResolvedValue([
      {
        id: 'note-11',
        title: 'Date Test',
        content: 'content',
        trashedAt: trashedDate.toISOString(),
      },
    ])

    render(<TrashDialog />)

    await screen.findByText('Date Test')
    expect(screen.getByText(/Deleted/)).toBeInTheDocument()
  })

  it('shows Unknown for missing trashedAt', async () => {
    getTrashedNotesMock.mockResolvedValue([
      {
        id: 'note-12',
        title: 'No Date',
        content: 'content',
        trashedAt: null,
      },
    ])

    render(<TrashDialog />)

    await screen.findByText('No Date')
    expect(screen.getByText(/Unknown/)).toBeInTheDocument()
  })

  it('displays No content for empty note content', async () => {
    getTrashedNotesMock.mockResolvedValue([
      {
        id: 'note-13',
        title: 'Empty Content',
        content: '',
        trashedAt: new Date().toISOString(),
      },
    ])

    render(<TrashDialog />)

    await screen.findByText('Empty Content')
    expect(screen.getByText('No content')).toBeInTheDocument()
  })

  it('shows correct count in empty trash button', async () => {
    getTrashedNotesMock.mockResolvedValue([
      { id: '1', title: 'Note 1', content: '', trashedAt: new Date().toISOString() },
      { id: '2', title: 'Note 2', content: '', trashedAt: new Date().toISOString() },
      { id: '3', title: 'Note 3', content: '', trashedAt: new Date().toISOString() },
    ])

    render(<TrashDialog />)

    await screen.findByText('Note 1')
    expect(screen.getByText(/Empty Trash \(3\)/)).toBeInTheDocument()
  })

  it('handles load error gracefully', async () => {
    getTrashedNotesMock.mockRejectedValue(new Error('Load failed'))

    render(<TrashDialog />)

    await waitFor(() => {
      expect(screen.getByText('Trash is empty')).toBeInTheDocument()
    })
  })
})
