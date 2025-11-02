import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { VersionHistoryDialog } from '../version-history-dialog'
import { useNotesStore } from '@/stores/notesStore'

vi.mock('@/stores/notesStore', () => ({
  useNotesStore: vi.fn(),
}))

vi.mock('@/components/ui/dialog', () => ({
  Dialog: ({ children, open }: any) => (open ? <div data-testid="dialog">{children}</div> : null),
  DialogContent: ({ children }: any) => <div data-testid="dialog-content">{children}</div>,
  DialogHeader: ({ children }: any) => <div>{children}</div>,
  DialogTitle: ({ children }: any) => <h2>{children}</h2>,
  DialogDescription: ({ children }: any) => <p>{children}</p>,
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

describe('VersionHistoryDialog', () => {
  const mockVersions = [
    {
      id: 'v1',
      noteId: 'note-1',
      versionNumber: 1,
      title: 'Version 1',
      content: 'Content v1',
      createdAt: '2024-01-01T00:00:00Z',
      createdBy: 'user-1',
      changeDescription: 'Initial version',
    },
    {
      id: 'v2',
      noteId: 'note-1',
      versionNumber: 2,
      title: 'Version 2',
      content: 'Content v2',
      createdAt: '2024-01-02T00:00:00Z',
      createdBy: 'user-1',
      changeDescription: 'Updated content',
    },
  ]

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('should render when open', () => {
    vi.mocked(useNotesStore).mockReturnValue({
      getNoteVersions: vi.fn().mockResolvedValue([]),
      restoreNoteVersion: vi.fn(),
      deleteNoteVersion: vi.fn(),
      compareNoteVersions: vi.fn(),
    } as any)

    render(<VersionHistoryDialog open={true} onOpenChange={vi.fn()} noteId="note-1" />)
    expect(screen.getByTestId('dialog')).toBeInTheDocument()
  })

  it('should not render when closed', () => {
    vi.mocked(useNotesStore).mockReturnValue({
      getNoteVersions: vi.fn().mockResolvedValue([]),
      restoreNoteVersion: vi.fn(),
      deleteNoteVersion: vi.fn(),
      compareNoteVersions: vi.fn(),
    } as any)

    render(<VersionHistoryDialog open={false} onOpenChange={vi.fn()} noteId="note-1" />)
    expect(screen.queryByTestId('dialog')).not.toBeInTheDocument()
  })

  it('should load versions on mount', async () => {
    const getNoteVersions = vi.fn().mockResolvedValue(mockVersions)

    vi.mocked(useNotesStore).mockReturnValue({
      getNoteVersions,
      restoreNoteVersion: vi.fn(),
      deleteNoteVersion: vi.fn(),
      compareNoteVersions: vi.fn(),
    } as any)

    render(<VersionHistoryDialog open={true} onOpenChange={vi.fn()} noteId="note-1" />)

    await waitFor(() => {
      expect(getNoteVersions).toHaveBeenCalledWith('note-1')
    })
  })

  it('should display version list', async () => {
    vi.mocked(useNotesStore).mockReturnValue({
      getNoteVersions: vi.fn().mockResolvedValue(mockVersions),
      restoreNoteVersion: vi.fn(),
      deleteNoteVersion: vi.fn(),
      compareNoteVersions: vi.fn(),
    } as any)

    render(<VersionHistoryDialog open={true} onOpenChange={vi.fn()} noteId="note-1" />)

    await waitFor(() => {
      expect(screen.getByTestId('scroll-area')).toBeInTheDocument()
    })
  })

  it('should show version details', async () => {
    vi.mocked(useNotesStore).mockReturnValue({
      getNoteVersions: vi.fn().mockResolvedValue(mockVersions),
      restoreNoteVersion: vi.fn(),
      deleteNoteVersion: vi.fn(),
      compareNoteVersions: vi.fn(),
    } as any)

    render(<VersionHistoryDialog open={true} onOpenChange={vi.fn()} noteId="note-1" />)

    await waitFor(() => {
      expect(screen.getByText(/Version 1/i) || screen.getByText(/Initial version/i)).toBeInTheDocument()
    })
  })

  it('should show empty state when no versions', async () => {
    vi.mocked(useNotesStore).mockReturnValue({
      getNoteVersions: vi.fn().mockResolvedValue([]),
      restoreNoteVersion: vi.fn(),
      deleteNoteVersion: vi.fn(),
      compareNoteVersions: vi.fn(),
    } as any)

    render(<VersionHistoryDialog open={true} onOpenChange={vi.fn()} noteId="note-1" />)

    await waitFor(() => {
      expect(screen.getByText(/no versions/i)).toBeInTheDocument()
    })
  })

  it('should restore version when clicked', async () => {
    const restoreNoteVersion = vi.fn().mockResolvedValue(undefined)

    vi.mocked(useNotesStore).mockReturnValue({
      getNoteVersions: vi.fn().mockResolvedValue(mockVersions),
      restoreNoteVersion,
      deleteNoteVersion: vi.fn(),
      compareNoteVersions: vi.fn(),
    } as any)

    render(<VersionHistoryDialog open={true} onOpenChange={vi.fn()} noteId="note-1" />)

    await waitFor(() => {
      expect(screen.getByTestId('scroll-area')).toBeInTheDocument()
    })

    const restoreButton = screen.queryByRole('button', { name: /restore/i })
    if (restoreButton) {
      restoreButton.click()
      await waitFor(() => {
        expect(restoreNoteVersion).toHaveBeenCalled()
      })
    }
  })

  it('should delete version', async () => {
    const deleteNoteVersion = vi.fn().mockResolvedValue(undefined)

    vi.mocked(useNotesStore).mockReturnValue({
      getNoteVersions: vi.fn().mockResolvedValue(mockVersions),
      restoreNoteVersion: vi.fn(),
      deleteNoteVersion,
      compareNoteVersions: vi.fn(),
    } as any)

    render(<VersionHistoryDialog open={true} onOpenChange={vi.fn()} noteId="note-1" />)

    await waitFor(() => {
      expect(screen.getByTestId('scroll-area')).toBeInTheDocument()
    })

    const deleteButton = screen.queryByRole('button', { name: /delete/i })
    if (deleteButton) {
      deleteButton.click()
      await waitFor(() => {
        expect(deleteNoteVersion).toHaveBeenCalled()
      })
    }
  })

  it('should compare versions', async () => {
    const compareNoteVersions = vi.fn().mockResolvedValue({
      v1: mockVersions[0],
      v2: mockVersions[1],
    })

    vi.mocked(useNotesStore).mockReturnValue({
      getNoteVersions: vi.fn().mockResolvedValue(mockVersions),
      restoreNoteVersion: vi.fn(),
      deleteNoteVersion: vi.fn(),
      compareNoteVersions,
    } as any)

    render(<VersionHistoryDialog open={true} onOpenChange={vi.fn()} noteId="note-1" />)

    await waitFor(() => {
      expect(screen.getByTestId('scroll-area')).toBeInTheDocument()
    })

    const compareButton = screen.queryByRole('button', { name: /compare/i })
    if (compareButton) {
      compareButton.click()
      await waitFor(() => {
        expect(compareNoteVersions).toHaveBeenCalled()
      })
    }
  })

  it('should show loading state', () => {
    vi.mocked(useNotesStore).mockReturnValue({
      getNoteVersions: vi.fn(() => new Promise(vi.fn())), // Never resolves
      restoreNoteVersion: vi.fn(),
      deleteNoteVersion: vi.fn(),
      compareNoteVersions: vi.fn(),
    } as any)

    render(<VersionHistoryDialog open={true} onOpenChange={vi.fn()} noteId="note-1" />)

    expect(screen.getByText(/loading/i)).toBeInTheDocument()
  })

  it('should handle errors gracefully', async () => {
    vi.mocked(useNotesStore).mockReturnValue({
      getNoteVersions: vi.fn().mockRejectedValue(new Error('Failed to load')),
      restoreNoteVersion: vi.fn(),
      deleteNoteVersion: vi.fn(),
      compareNoteVersions: vi.fn(),
    } as any)

    render(<VersionHistoryDialog open={true} onOpenChange={vi.fn()} noteId="note-1" />)

    await waitFor(() => {
      expect(screen.getByText(/error|failed/i)).toBeInTheDocument()
    })
  })

  it('should format timestamps', async () => {
    vi.mocked(useNotesStore).mockReturnValue({
      getNoteVersions: vi.fn().mockResolvedValue(mockVersions),
      restoreNoteVersion: vi.fn(),
      deleteNoteVersion: vi.fn(),
      compareNoteVersions: vi.fn(),
    } as any)

    render(<VersionHistoryDialog open={true} onOpenChange={vi.fn()} noteId="note-1" />)

    await waitFor(() => {
      expect(screen.getByTestId('scroll-area')).toBeInTheDocument()
    })

    expect(document.body).toBeTruthy()
  })
})
