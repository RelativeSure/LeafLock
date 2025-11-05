import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import React from 'react'
import { VersionHistoryDialog } from '../version-history-dialog'
import { useNotesStore } from '@/stores/notesStore'
import { useToast } from '@/hooks/use-toast'

const createNoteVersionMock = vi.fn()
const getNoteVersionsMock = vi.fn()
const restoreNoteVersionMock = vi.fn()
const deleteNoteVersionMock = vi.fn()
const compareNoteVersionsMock = vi.fn()
const updateRetentionPolicyMock = vi.fn()
const toastMock = {
  error: vi.fn(),
  success: vi.fn(),
}

vi.mock('@/stores/notesStore')
vi.mock('@/hooks/use-toast')

vi.mock('@/components/ui/dialog', () => {
  const DialogTrigger = ({ children, onOpenChange, asChild }: any) => {
    const handleClick = () => {
      onOpenChange?.(true)
    }

    if (asChild) {
      return React.cloneElement(children, { onClick: handleClick, 'data-testid': 'dialog-trigger' })
    }
    return (
      <button type="button" onClick={handleClick} data-testid="dialog-trigger">
        {children}
      </button>
    )
  }
  DialogTrigger.displayName = 'DialogTrigger'

  return {
    Dialog: ({ children, open, onOpenChange }: any) => {
      // Map children to pass onOpenChange to DialogTrigger
      const childrenWithProps = React.Children.map(children, (child) => {
        if (React.isValidElement(child) && (child.type as any)?.displayName === 'DialogTrigger') {
          return React.cloneElement(child, { onOpenChange } as any)
        }
        // Only render non-trigger children when open is true
        if (open) {
          return child
        }
        return null
      })
      return <div>{childrenWithProps}</div>
    },
    DialogContent: ({ children }: any) => <div>{children}</div>,
    DialogHeader: ({ children }: any) => <div>{children}</div>,
    DialogTitle: ({ children }: any) => <h2>{children}</h2>,
    DialogDescription: ({ children }: any) => <p>{children}</p>,
    DialogFooter: ({ children }: any) => <div>{children}</div>,
    DialogTrigger,
  }
})

vi.mock('@/components/ui/tabs', () => ({
  Tabs: ({ children }: any) => <div>{children}</div>,
  TabsList: ({ children }: any) => <div>{children}</div>,
  TabsTrigger: ({ children, value, onClick }: any) => (
    <button type="button" data-value={value} onClick={onClick}>
      {children}
    </button>
  ),
  TabsContent: ({ children, value }: any) => <div data-tab={value}>{children}</div>,
}))

vi.mock('@/components/ui/scroll-area', () => ({
  ScrollArea: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, onClick, disabled, ...props }: any) => (
    <button type="button" onClick={onClick} disabled={disabled} {...props}>
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

vi.mock('@/components/ui/badge', () => ({
  Badge: ({ children }: any) => <span>{children}</span>,
}))

vi.mock('@/components/ui/card', () => ({
  Card: ({ children }: any) => <div>{children}</div>,
  CardHeader: ({ children }: any) => <div>{children}</div>,
  CardTitle: ({ children }: any) => <h3>{children}</h3>,
  CardDescription: ({ children }: any) => <p>{children}</p>,
  CardContent: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/select', () => ({
  Select: ({ children, onValueChange }: any) => <div onClick={() => onValueChange?.('1')}>{children}</div>,
  SelectTrigger: ({ children }: any) => <button type="button">{children}</button>,
  SelectContent: ({ children }: any) => <div>{children}</div>,
  SelectItem: ({ children, value, onSelect }: any) => (
    <div role="option" data-value={value} onClick={onSelect}>
      {children}
    </div>
  ),
  SelectValue: ({ children }: any) => <span>{children}</span>,
}))

vi.mock('@/components/ui/slider', () => ({
  Slider: ({ onValueChange, value }: any) => (
    <input
      type="range"
      value={value?.[0] || 20}
      onChange={(e) => onValueChange?.([Number(e.target.value)])}
    />
  ),
}))

vi.mock('@/components/ui/hover-card', () => ({
  HoverCard: ({ children }: any) => <div>{children}</div>,
  HoverCardTrigger: ({ children }: any) => <div>{children}</div>,
  HoverCardContent: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/alert-dialog', () => ({
  AlertDialog: ({ children, open }: any) => (open ? <div data-testid="alert-dialog">{children}</div> : null),
  AlertDialogContent: ({ children }: any) => <div>{children}</div>,
  AlertDialogHeader: ({ children }: any) => <div>{children}</div>,
  AlertDialogTitle: ({ children }: any) => <h4>{children}</h4>,
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
  History: () => <span>history-icon</span>,
  RotateCcw: () => <span>restore-icon</span>,
  Trash2: () => <span>delete-icon</span>,
  Clock: () => <span>clock-icon</span>,
  User: () => <span>user-icon</span>,
  FileText: () => <span>file-icon</span>,
  Calendar: () => <span>calendar-icon</span>,
  Settings: () => <span>settings-icon</span>,
  GitCompare: () => <span>compare-icon</span>,
}))

describe('VersionHistoryDialog', () => {
  beforeEach(() => {
    vi.clearAllMocks()

    getNoteVersionsMock.mockResolvedValue([])
    createNoteVersionMock.mockResolvedValue(undefined)
    restoreNoteVersionMock.mockResolvedValue(undefined)
    deleteNoteVersionMock.mockResolvedValue(undefined)
    compareNoteVersionsMock.mockResolvedValue({ v1: mockVersion1, v2: mockVersion2 })
    updateRetentionPolicyMock.mockResolvedValue(undefined)

    vi.mocked(useNotesStore).mockReturnValue({
      createNoteVersion: createNoteVersionMock,
      getNoteVersions: getNoteVersionsMock,
      restoreNoteVersion: restoreNoteVersionMock,
      deleteNoteVersion: deleteNoteVersionMock,
      compareNoteVersions: compareNoteVersionsMock,
      updateRetentionPolicy: updateRetentionPolicyMock,
    } as any)

    vi.mocked(useToast).mockReturnValue({
      toast: toastMock,
    } as any)
  })

  const mockVersion1 = {
    id: 'v1',
    versionNumber: 1,
    noteId: 'note-1',
    title: 'Version 1',
    content: '<p>Content 1</p>',
    changeDescription: 'First version',
    createdAt: new Date('2024-01-01').toISOString(),
    createdBy: 'user@example.com',
  }

  const mockVersion2 = {
    id: 'v2',
    versionNumber: 2,
    noteId: 'note-1',
    title: 'Version 2',
    content: '<p>Content 2</p>',
    changeDescription: 'Second version',
    createdAt: new Date('2024-01-02').toISOString(),
    createdBy: 'user@example.com',
  }

  it('renders trigger content', () => {
    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Test Note">
        <span>Open history</span>
      </VersionHistoryDialog>
    )

    expect(screen.getByText('Open history')).toBeInTheDocument()
  })

  it('fetches versions when dialog opens', async () => {
    render(
      <VersionHistoryDialog noteId="note-99" noteTitle="Project Plan">
        <span>Show history</span>
      </VersionHistoryDialog>
    )

    const trigger = screen.getByTestId('dialog-trigger')
    fireEvent.click(trigger)

    await waitFor(() => {
      expect(getNoteVersionsMock).toHaveBeenCalledWith('note-99')
    })
  })

  it('displays note title in dialog header', async () => {
    getNoteVersionsMock.mockResolvedValue([])

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="My Important Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      expect(screen.getByText(/My Important Note/)).toBeInTheDocument()
    })
  })

  it('shows empty state when no versions exist', async () => {
    getNoteVersionsMock.mockResolvedValue([])

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      expect(screen.getByText('No versions available')).toBeInTheDocument()
    })
  })

  it('displays version list when versions exist', async () => {
    getNoteVersionsMock.mockResolvedValue([mockVersion1, mockVersion2])

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      expect(screen.getByText('First version')).toBeInTheDocument()
      expect(screen.getByText('Second version')).toBeInTheDocument()
    })
  })

  it('marks most recent version as current', async () => {
    getNoteVersionsMock.mockResolvedValue([mockVersion2, mockVersion1])

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      expect(screen.getByText('Current')).toBeInTheDocument()
    })
  })

  it('shows version count', async () => {
    getNoteVersionsMock.mockResolvedValue([mockVersion1, mockVersion2])

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      expect(screen.getByText(/2 versions available/)).toBeInTheDocument()
    })
  })

  it('opens create version dialog when button clicked', async () => {
    getNoteVersionsMock.mockResolvedValue([])

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      const createButton = screen.getByText(/Create Version/)
      fireEvent.click(createButton)
    })

    expect(screen.getByText('Create New Version')).toBeInTheDocument()
  })

  it('creates version with description', async () => {
    getNoteVersionsMock.mockResolvedValue([])

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      fireEvent.click(screen.getByText(/Create Version/))
    })

    const input = screen.getByPlaceholderText(/Describe what changed/)
    fireEvent.change(input, { target: { value: 'Added new section' } })

    const submitButton = screen.getByRole('button', { name: 'Create Version' })
    fireEvent.click(submitButton)

    await waitFor(() => {
      expect(createNoteVersionMock).toHaveBeenCalledWith('note-1', 'Added new section')
    })
  })

  it('shows error when creating version without description', async () => {
    getNoteVersionsMock.mockResolvedValue([])

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      fireEvent.click(screen.getByText(/Create Version/))
    })

    const submitButton = screen.getByRole('button', { name: 'Create Version' })
    fireEvent.click(submitButton)

    await waitFor(() => {
      expect(toastMock.error).toHaveBeenCalledWith('Please enter a description for this version.')
    })
  })

  it('shows success toast after creating version', async () => {
    getNoteVersionsMock.mockResolvedValue([])

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      fireEvent.click(screen.getByText(/Create Version/))
    })

    const input = screen.getByPlaceholderText(/Describe what changed/)
    fireEvent.change(input, { target: { value: 'New changes' } })

    const submitButton = screen.getByRole('button', { name: 'Create Version' })
    fireEvent.click(submitButton)

    await waitFor(() => {
      expect(toastMock.success).toHaveBeenCalledWith('Version saved', {
        description: 'A new version has been saved successfully.',
      })
    })
  })

  it('handles create version error', async () => {
    createNoteVersionMock.mockRejectedValue(new Error('Failed'))
    getNoteVersionsMock.mockResolvedValue([])

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      fireEvent.click(screen.getByText(/Create Version/))
    })

    const input = screen.getByPlaceholderText(/Describe what changed/)
    fireEvent.change(input, { target: { value: 'Changes' } })

    const submitButton = screen.getByRole('button', { name: 'Create Version' })
    fireEvent.click(submitButton)

    await waitFor(() => {
      expect(toastMock.error).toHaveBeenCalledWith('Failed to create version.')
    })
  })

  it('opens restore dialog when restore button clicked', async () => {
    getNoteVersionsMock.mockResolvedValue([mockVersion2, mockVersion1])

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      const restoreButtons = screen.getAllByText('restore-icon')
      fireEvent.click(restoreButtons[0].parentElement!)
    })

    expect(screen.getByRole('heading', { name: 'Restore Version' })).toBeInTheDocument()
    expect(screen.getByText(/replace the current content/)).toBeInTheDocument()
  })

  it('restores version when confirmed', async () => {
    getNoteVersionsMock.mockResolvedValue([mockVersion2, mockVersion1])

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      const restoreButtons = screen.getAllByText('restore-icon')
      fireEvent.click(restoreButtons[0].parentElement!)
    })

    const confirmButton = screen.getByRole('button', { name: 'Restore Version' })
    fireEvent.click(confirmButton)

    await waitFor(() => {
      expect(restoreNoteVersionMock).toHaveBeenCalledWith('v1')
    })
  })

  it('shows success toast after restoring version', async () => {
    getNoteVersionsMock.mockResolvedValue([mockVersion2, mockVersion1])

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      const restoreButtons = screen.getAllByText('restore-icon')
      fireEvent.click(restoreButtons[0].parentElement!)
    })

    const confirmButton = screen.getByRole('button', { name: 'Restore Version' })
    fireEvent.click(confirmButton)

    await waitFor(() => {
      expect(toastMock.success).toHaveBeenCalledWith('Version restored', expect.objectContaining({
        description: expect.stringContaining('Restored to version'),
      }))
    })
  })

  it('handles restore version error', async () => {
    restoreNoteVersionMock.mockRejectedValue(new Error('Failed'))
    getNoteVersionsMock.mockResolvedValue([mockVersion2, mockVersion1])

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      const restoreButtons = screen.getAllByText('restore-icon')
      fireEvent.click(restoreButtons[0].parentElement!)
    })

    const confirmButton = screen.getByRole('button', { name: 'Restore Version' })
    fireEvent.click(confirmButton)

    await waitFor(() => {
      expect(toastMock.error).toHaveBeenCalledWith('Failed to restore version.')
    })
  })

  it('opens delete dialog when delete button clicked', async () => {
    getNoteVersionsMock.mockResolvedValue([mockVersion1])

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      const deleteButtons = screen.getAllByText('delete-icon')
      fireEvent.click(deleteButtons[0].parentElement!)
    })

    expect(screen.getByRole('heading', { name: 'Delete Version' })).toBeInTheDocument()
    expect(screen.getByText(/permanently delete this version/)).toBeInTheDocument()
  })

  it('deletes version when confirmed', async () => {
    getNoteVersionsMock.mockResolvedValue([mockVersion1])

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      const deleteButtons = screen.getAllByText('delete-icon')
      fireEvent.click(deleteButtons[0].parentElement!)
    })

    const confirmButton = screen.getByRole('button', { name: 'Delete Version' })
    fireEvent.click(confirmButton)

    await waitFor(() => {
      expect(deleteNoteVersionMock).toHaveBeenCalledWith('v1')
    })
  })

  it('shows success toast after deleting version', async () => {
    getNoteVersionsMock.mockResolvedValue([mockVersion1])

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      const deleteButtons = screen.getAllByText('delete-icon')
      fireEvent.click(deleteButtons[0].parentElement!)
    })

    const confirmButton = screen.getByRole('button', { name: 'Delete Version' })
    fireEvent.click(confirmButton)

    await waitFor(() => {
      expect(toastMock.success).toHaveBeenCalledWith('Version deleted', {
        description: 'Version has been permanently deleted.',
      })
    })
  })

  it('handles delete version error', async () => {
    deleteNoteVersionMock.mockRejectedValue(new Error('Failed'))
    getNoteVersionsMock.mockResolvedValue([mockVersion1])

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      const deleteButtons = screen.getAllByText('delete-icon')
      fireEvent.click(deleteButtons[0].parentElement!)
    })

    const confirmButton = screen.getByRole('button', { name: 'Delete Version' })
    fireEvent.click(confirmButton)

    await waitFor(() => {
      expect(toastMock.error).toHaveBeenCalledWith('Failed to delete version.')
    })
  })

  it('shows loading state while fetching versions', async () => {
    let resolveVersions: any
    getNoteVersionsMock.mockReturnValue(
      new Promise((resolve) => {
        resolveVersions = resolve
      })
    )

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      expect(screen.getByText('0 versions available')).toBeInTheDocument()
    })

    resolveVersions([])
  })

  it('handles load versions error', async () => {
    getNoteVersionsMock.mockRejectedValue(new Error('Failed'))

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      expect(toastMock.error).toHaveBeenCalledWith('Failed to load version history.')
    })
  })

  it('switches to compare tab', async () => {
    getNoteVersionsMock.mockResolvedValue([mockVersion1, mockVersion2])

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      const tabs = screen.getAllByRole('button')
      const compareTab = tabs.find((tab) => tab.getAttribute('data-value') === 'compare')
      fireEvent.click(compareTab!)
    })

    expect(screen.getByRole('button', { name: /Compare Versions/ })).toBeInTheDocument()
  })

  it('compares two versions', async () => {
    getNoteVersionsMock.mockResolvedValue([mockVersion1, mockVersion2])

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      const tabs = screen.getAllByRole('button')
      const compareTab = tabs.find((tab) => tab.getAttribute('data-value') === 'compare')
      fireEvent.click(compareTab!)
    })

    const compareButton = screen.getByRole('button', { name: /Compare Versions/ })
    fireEvent.click(compareButton)

    await waitFor(() => {
      expect(compareNoteVersionsMock).toHaveBeenCalledWith('note-1', 2, 1)
    })
  })

  it('handles compare error', async () => {
    compareNoteVersionsMock.mockRejectedValue(new Error('Failed'))
    getNoteVersionsMock.mockResolvedValue([mockVersion1, mockVersion2])

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      const tabs = screen.getAllByRole('button')
      const compareTab = tabs.find((tab) => tab.getAttribute('data-value') === 'compare')
      fireEvent.click(compareTab!)
    })

    const compareButton = screen.getByRole('button', { name: /Compare Versions/ })
    fireEvent.click(compareButton)

    await waitFor(() => {
      expect(toastMock.error).toHaveBeenCalledWith('Failed to compare versions.')
    })
  })

  it('switches to settings tab', async () => {
    getNoteVersionsMock.mockResolvedValue([])

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      const settingsTab = screen.getByRole('button', { name: /Settings/ })
      fireEvent.click(settingsTab)
    })

    expect(screen.getByText('Version Retention Policy')).toBeInTheDocument()
  })

  it('updates retention policy', async () => {
    getNoteVersionsMock.mockResolvedValue([])

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      const settingsTab = screen.getByRole('button', { name: /Settings/ })
      fireEvent.click(settingsTab)
    })

    const slider = screen.getByRole('slider')
    fireEvent.change(slider, { target: { value: '30' } })

    const saveButton = screen.getByRole('button', { name: /Save Retention Policy/ })
    fireEvent.click(saveButton)

    await waitFor(() => {
      expect(updateRetentionPolicyMock).toHaveBeenCalledWith('note-1', 30)
    })
  })

  it('shows success toast after updating retention policy', async () => {
    getNoteVersionsMock.mockResolvedValue([])

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      const settingsTab = screen.getByRole('button', { name: /Settings/ })
      fireEvent.click(settingsTab)
    })

    const saveButton = screen.getByRole('button', { name: /Save Retention Policy/ })
    fireEvent.click(saveButton)

    await waitFor(() => {
      expect(toastMock.success).toHaveBeenCalledWith('Retention policy updated', {
        description: 'Retention policy updated to 20 versions.',
      })
    })
  })

  it('handles update retention policy error', async () => {
    updateRetentionPolicyMock.mockRejectedValue(new Error('Failed'))
    getNoteVersionsMock.mockResolvedValue([])

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      const settingsTab = screen.getByRole('button', { name: /Settings/ })
      fireEvent.click(settingsTab)
    })

    const saveButton = screen.getByRole('button', { name: /Save Retention Policy/ })
    fireEvent.click(saveButton)

    await waitFor(() => {
      expect(toastMock.error).toHaveBeenCalledWith('Failed to update retention policy.')
    })
  })

  it('closes dialog when close button clicked', async () => {
    getNoteVersionsMock.mockResolvedValue([])

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      const closeButton = screen.getByRole('button', { name: 'Close' })
      fireEvent.click(closeButton)
    })

    expect(screen.queryByTestId('dialog-root')).not.toBeInTheDocument()
  })

  it('does not show restore button for current version', async () => {
    getNoteVersionsMock.mockResolvedValue([mockVersion2, mockVersion1])

    render(
      <VersionHistoryDialog noteId="note-1" noteTitle="Note">
        <span>History</span>
      </VersionHistoryDialog>
    )

    fireEvent.click(screen.getByTestId('dialog-trigger'))

    await waitFor(() => {
      expect(screen.getByText('Current')).toBeInTheDocument()
    })

    // Only one restore button should exist (for the older version)
    const restoreButtons = screen.getAllByText('restore-icon')
    expect(restoreButtons).toHaveLength(1)
  })
})
