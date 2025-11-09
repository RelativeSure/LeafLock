import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { BulkOperationsBar } from '../bulk-operations-bar'

const useNotesStoreMock: any = vi.fn()
const toastSuccessMock = vi.fn()
const toastErrorMock = vi.fn()

const selectHandlers: Array<(value: string) => void> = []

vi.mock('@/stores/notesStore', () => {
  const useNotesStoreProxy = (...args: unknown[]) => useNotesStoreMock(...args)
  useNotesStoreProxy.getState = (...args: unknown[]) =>
    useNotesStoreMock.getState ? useNotesStoreMock.getState(...(args as [])) : undefined
  return {
    useNotesStore: useNotesStoreProxy,
  }
})

vi.mock('@/hooks/use-toast', () => ({
  useToast: () => ({
    toast: {
      success: toastSuccessMock,
      error: toastErrorMock,
    },
  }),
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, onClick, disabled, ...props }: any) => (
    <button disabled={disabled} onClick={onClick} {...props}>
      {children}
    </button>
  ),
}))

vi.mock('@/components/ui/badge', () => ({
  Badge: ({ children, ...props }: any) => (
    <span data-testid="bulk-badge" {...props}>
      {children}
    </span>
  ),
}))

vi.mock('@/components/ui/dialog', () => ({
  Dialog: ({ children, open }: any) => <div>{open && children}</div>,
  DialogContent: ({ children }: any) => <div>{children}</div>,
  DialogHeader: ({ children }: any) => <div>{children}</div>,
  DialogTitle: ({ children }: any) => <h2>{children}</h2>,
  DialogDescription: ({ children }: any) => <p>{children}</p>,
  DialogFooter: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/select', () => ({
  Select: ({ children, onValueChange }: any) => {
    const index = selectHandlers.push(onValueChange) - 1
    return (
      <div data-select-index={index}>{typeof children === 'function' ? children() : children}</div>
    )
  },
  SelectTrigger: ({ children }: any) => <div>{children}</div>,
  SelectContent: ({ children }: any) => <div>{children}</div>,
  SelectItem: ({ children, value }: any) => (
    <button
      type="button"
      onClick={(event) => {
        const container = event.currentTarget.closest('[data-select-index]') as HTMLElement | null
        const idx = Number(container?.dataset.selectIndex ?? selectHandlers.length - 1)
        selectHandlers[idx]?.(value)
      }}
    >
      {children}
    </button>
  ),
  SelectValue: ({ placeholder }: any) => <span>{placeholder}</span>,
}))

vi.mock('@/components/ui/checkbox', () => ({
  Checkbox: ({ checked, onCheckedChange }: any) => (
    <input
      type="checkbox"
      checked={checked}
      onChange={() => onCheckedChange(!checked)}
      aria-checked={checked}
    />
  ),
}))

const baseNotes = [
  { id: 'note-1', title: 'First note' },
  { id: 'note-2', title: 'Second note' },
] as any

const baseFolders = [
  { id: 'folder-1', name: 'Projects', color: '#3b82f6' },
  { id: 'folder-2', name: 'Archive', color: '#ef4444' },
]

const baseTags = [
  { id: 'tag-1', name: 'urgent' },
  { id: 'tag-2', name: 'planning' },
]

const setupStore = (overrides: Partial<any> = {}) => {
  const storeValue = {
    notes: baseNotes,
    folders: baseFolders,
    tags: baseTags,
    moveNotesToFolder: vi.fn().mockResolvedValue(undefined),
    addTagsToNotes: vi.fn().mockResolvedValue(undefined),
    removeTagsFromNotes: vi.fn().mockResolvedValue(undefined),
    createTag: vi.fn().mockResolvedValue({ name: 'new-tag' }),
    bulkDeleteNotes: vi.fn().mockResolvedValue({
      successful: 2,
      failed: 0,
      errors: [],
    }),
    ...overrides,
  }

  useNotesStoreMock.mockReturnValue(storeValue)
  useNotesStoreMock.getState = vi.fn(() => storeValue)

  selectHandlers.length = 0

  return storeValue
}

describe('BulkOperationsBar', () => {
  const onClose = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    selectHandlers.length = 0
  })

  it('renders selected count badge', () => {
    setupStore()
    render(<BulkOperationsBar selectedNotes={['note-1', 'note-2']} onClose={onClose} />)
    expect(screen.getByText('2 selected')).toBeInTheDocument()
  })

  it('moves notes to a selected folder', async () => {
    const store = setupStore()
    render(<BulkOperationsBar selectedNotes={['note-1']} onClose={onClose} />)

    fireEvent.click(screen.getByRole('button', { name: /move/i }))
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /move notes/i })).toBeInTheDocument()
    )
    fireEvent.click(screen.getByText('Projects'))
    fireEvent.click(screen.getByRole('button', { name: /move notes/i }))

    await waitFor(() => {
      expect(store.moveNotesToFolder).toHaveBeenCalledWith(['note-1'], 'folder-1')
    })
    expect(onClose).toHaveBeenCalled()
    expect(toastSuccessMock).toHaveBeenCalledWith('1 note moved to folder.')
  })

  it('adds selected tags to notes', async () => {
    const store = setupStore()

    render(<BulkOperationsBar selectedNotes={['note-1', 'note-2']} onClose={onClose} />)

    fireEvent.click(screen.getByRole('button', { name: /tags/i }))
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /add tags/i })).toBeInTheDocument()
    )
    const tagCheckbox = screen.getAllByRole('checkbox')[0]
    fireEvent.click(tagCheckbox)
    fireEvent.click(screen.getByRole('button', { name: /add tags/i }))

    await waitFor(() => {
      expect(store.addTagsToNotes).toHaveBeenCalledWith(['note-1', 'note-2'], ['urgent'])
    })
    expect(onClose).toHaveBeenCalled()
  })

  it('removes selected tags from notes', async () => {
    const store = setupStore()

    render(<BulkOperationsBar selectedNotes={['note-1']} onClose={onClose} />)

    fireEvent.click(screen.getByRole('button', { name: /tags/i }))
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /remove tags/i })).toBeInTheDocument()
    )
    const tagCheckbox = screen.getAllByRole('checkbox')[1]
    fireEvent.click(tagCheckbox)
    fireEvent.click(screen.getByRole('button', { name: /remove tags/i }))

    await waitFor(() => {
      expect(store.removeTagsFromNotes).toHaveBeenCalledWith(['note-1'], ['planning'])
    })
    expect(onClose).toHaveBeenCalled()
  })

  it('creates a new tag and adds it to selection', async () => {
    const store = setupStore({
      createTag: vi.fn().mockResolvedValue({ name: 'custom-tag' }),
    })

    render(<BulkOperationsBar selectedNotes={['note-1']} onClose={onClose} />)

    fireEvent.click(screen.getByRole('button', { name: /tags/i }))
    await waitFor(() => expect(screen.getByRole('button', { name: /create/i })).toBeInTheDocument())
    const input = screen.getByPlaceholderText('Enter tag name...')
    fireEvent.change(input, { target: { value: 'custom-tag' } })
    fireEvent.click(screen.getByRole('button', { name: /create/i }))

    await waitFor(() => {
      expect(store.createTag).toHaveBeenCalledWith({ name: 'custom-tag' })
    })
  })

  it('confirms bulk delete and invokes store action', async () => {
    const bulkDeleteNotes = vi.fn().mockResolvedValue({
      successful: 2,
      failed: 0,
      errors: [],
    })
    setupStore({ bulkDeleteNotes })
    useNotesStoreMock.getState = vi.fn(() => ({ bulkDeleteNotes }))

    render(<BulkOperationsBar selectedNotes={['note-1', 'note-2']} onClose={onClose} />)

    fireEvent.click(screen.getByRole('button', { name: /delete/i }))
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /move to trash/i })).toBeInTheDocument()
    })
    fireEvent.click(screen.getByRole('button', { name: /move to trash/i }))

    await waitFor(() => {
      expect(bulkDeleteNotes).toHaveBeenCalledWith(['note-1', 'note-2'])
      expect(toastSuccessMock).toHaveBeenCalled()
    })
    expect(onClose).toHaveBeenCalled()
  })

  // Error handling and edge case tests
  describe('Error handling', () => {
    it('handles move to folder error', async () => {
      const store = setupStore({
        moveNotesToFolder: vi.fn().mockRejectedValue(new Error('Move failed')),
      })
      render(<BulkOperationsBar selectedNotes={['note-1']} onClose={onClose} />)

      fireEvent.click(screen.getByRole('button', { name: /move/i }))
      await waitFor(() =>
        expect(screen.getByRole('button', { name: /move notes/i })).toBeInTheDocument()
      )
      fireEvent.click(screen.getByText('Projects'))
      fireEvent.click(screen.getByRole('button', { name: /move notes/i }))

      await waitFor(() => {
        expect(store.moveNotesToFolder).toHaveBeenCalled()
        expect(toastErrorMock).toHaveBeenCalledWith('Failed to move notes.')
      })
    })

    it('handles add tags error', async () => {
      const store = setupStore({
        addTagsToNotes: vi.fn().mockRejectedValue(new Error('Add tags failed')),
      })
      render(<BulkOperationsBar selectedNotes={['note-1']} onClose={onClose} />)

      fireEvent.click(screen.getByRole('button', { name: /tags/i }))
      await waitFor(() =>
        expect(screen.getByRole('button', { name: /add tags/i })).toBeInTheDocument()
      )
      const tagCheckbox = screen.getAllByRole('checkbox')[0]
      fireEvent.click(tagCheckbox)
      fireEvent.click(screen.getByRole('button', { name: /add tags/i }))

      await waitFor(() => {
        expect(store.addTagsToNotes).toHaveBeenCalled()
        expect(toastErrorMock).toHaveBeenCalledWith('Failed to add tags.')
      })
    })

    it('handles remove tags error', async () => {
      const store = setupStore({
        removeTagsFromNotes: vi.fn().mockRejectedValue(new Error('Remove tags failed')),
      })
      render(<BulkOperationsBar selectedNotes={['note-1']} onClose={onClose} />)

      fireEvent.click(screen.getByRole('button', { name: /tags/i }))
      await waitFor(() =>
        expect(screen.getByRole('button', { name: /remove tags/i })).toBeInTheDocument()
      )
      const tagCheckbox = screen.getAllByRole('checkbox')[0]
      fireEvent.click(tagCheckbox)
      fireEvent.click(screen.getByRole('button', { name: /remove tags/i }))

      await waitFor(() => {
        expect(store.removeTagsFromNotes).toHaveBeenCalled()
        expect(toastErrorMock).toHaveBeenCalledWith('Failed to remove tags.')
      })
    })

    it('handles bulk delete error', async () => {
      const bulkDeleteNotes = vi.fn().mockRejectedValue(new Error('Delete failed'))
      setupStore({ bulkDeleteNotes })
      useNotesStoreMock.getState = vi.fn(() => ({ bulkDeleteNotes }))

      render(<BulkOperationsBar selectedNotes={['note-1']} onClose={onClose} />)

      fireEvent.click(screen.getByRole('button', { name: /delete/i }))
      await waitFor(() =>
        expect(screen.getByRole('button', { name: /move to trash/i })).toBeInTheDocument()
      )
      fireEvent.click(screen.getByRole('button', { name: /move to trash/i }))

      await waitFor(() => {
        expect(bulkDeleteNotes).toHaveBeenCalled()
        expect(toastErrorMock).toHaveBeenCalledWith('Failed to delete notes.')
      })
    })

    it('handles create tag error', async () => {
      const store = setupStore({
        createTag: vi.fn().mockRejectedValue(new Error('Create failed')),
      })
      render(<BulkOperationsBar selectedNotes={['note-1']} onClose={onClose} />)

      fireEvent.click(screen.getByRole('button', { name: /tags/i }))
      await waitFor(() => expect(screen.getByRole('button', { name: /create/i })).toBeInTheDocument())
      const input = screen.getByPlaceholderText('Enter tag name...')
      fireEvent.change(input, { target: { value: 'custom-tag' } })
      fireEvent.click(screen.getByRole('button', { name: /create/i }))

      await waitFor(() => {
        expect(store.createTag).toHaveBeenCalled()
        expect(toastErrorMock).toHaveBeenCalledWith('Failed to create tag.')
      })
    })
  })

  describe('Edge cases', () => {
    it('shows singular message for single note', async () => {
      const store = setupStore()
      render(<BulkOperationsBar selectedNotes={['note-1']} onClose={onClose} />)

      fireEvent.click(screen.getByRole('button', { name: /move/i }))
      await waitFor(() =>
        expect(screen.getByRole('button', { name: /move notes/i })).toBeInTheDocument()
      )
      fireEvent.click(screen.getByText('Projects'))
      fireEvent.click(screen.getByRole('button', { name: /move notes/i }))

      await waitFor(() => {
        expect(toastSuccessMock).toHaveBeenCalledWith('1 note moved to folder.')
      })
    })

    it('shows plural message for multiple notes', async () => {
      const store = setupStore()
      render(<BulkOperationsBar selectedNotes={['note-1', 'note-2']} onClose={onClose} />)

      fireEvent.click(screen.getByRole('button', { name: /move/i }))
      await waitFor(() =>
        expect(screen.getByRole('button', { name: /move notes/i })).toBeInTheDocument()
      )
      fireEvent.click(screen.getByText('Projects'))
      fireEvent.click(screen.getByRole('button', { name: /move notes/i }))

      await waitFor(() => {
        expect(toastSuccessMock).toHaveBeenCalledWith('2 notes moved to folder.')
      })
    })

    it('handles bulk delete with some failures', async () => {
      const bulkDeleteNotes = vi.fn().mockResolvedValue({
        successful: 1,
        failed: 1,
        errors: ['Error deleting note-2'],
      })
      setupStore({ bulkDeleteNotes })
      useNotesStoreMock.getState = vi.fn(() => ({ bulkDeleteNotes }))

      render(<BulkOperationsBar selectedNotes={['note-1', 'note-2']} onClose={onClose} />)

      fireEvent.click(screen.getByRole('button', { name: /delete/i }))
      await waitFor(() =>
        expect(screen.getByRole('button', { name: /move to trash/i })).toBeInTheDocument()
      )
      fireEvent.click(screen.getByRole('button', { name: /move to trash/i }))

      await waitFor(() => {
        expect(bulkDeleteNotes).toHaveBeenCalled()
        expect(toastSuccessMock).toHaveBeenCalled()
      })
    })

    it('closes on X button click', () => {
      setupStore()
      render(<BulkOperationsBar selectedNotes={['note-1']} onClose={onClose} />)

      const closeButton = screen.getByRole('button', { name: '' })
      fireEvent.click(closeButton)

      expect(onClose).toHaveBeenCalled()
    })

    it('does not create tag with empty name', async () => {
      const store = setupStore()
      render(<BulkOperationsBar selectedNotes={['note-1']} onClose={onClose} />)

      fireEvent.click(screen.getByRole('button', { name: /tags/i }))
      await waitFor(() => expect(screen.getByRole('button', { name: /create/i })).toBeInTheDocument())

      // Try to create with empty input
      fireEvent.click(screen.getByRole('button', { name: /create/i }))

      // Should not call createTag
      expect(store.createTag).not.toHaveBeenCalled()
    })

    it('toggles tag selection correctly', async () => {
      setupStore()
      render(<BulkOperationsBar selectedNotes={['note-1']} onClose={onClose} />)

      fireEvent.click(screen.getByRole('button', { name: /tags/i }))
      await waitFor(() =>
        expect(screen.getByRole('button', { name: /add tags/i })).toBeInTheDocument()
      )

      const firstCheckbox = screen.getAllByRole('checkbox')[0]

      // Select tag
      fireEvent.click(firstCheckbox)
      expect(firstCheckbox).toBeChecked()

      // Deselect tag
      fireEvent.click(firstCheckbox)
      expect(firstCheckbox).not.toBeChecked()
    })
  })
})
