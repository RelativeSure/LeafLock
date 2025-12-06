import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import React from 'react'
import { Sidebar } from '../sidebar'
import { useNotesStore } from '@/stores/notesStore'
import { useClerkAuthStore } from '@/stores/clerkAuthStore'

const createNoteMock = vi.fn()
const selectNoteMock = vi.fn()
const createFolderMock = vi.fn()
const selectFolderMock = vi.fn()
const selectTagMock = vi.fn()

vi.mock('@/stores/notesStore', () => ({
  useNotesStore: vi.fn(),
}))

vi.mock('@/stores/authStore', () => ({
  useClerkAuthStore: vi.fn(),
}))

// Mock all child components
vi.mock('@/components/ui/scroll-area', () => ({
  ScrollArea: ({ children }: any) => <div data-testid="scroll-area">{children}</div>,
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, onClick, variant, size, disabled, title, ...props }: any) => (
    <button
      onClick={onClick}
      disabled={disabled}
      title={title}
      data-variant={variant}
      data-size={size}
      {...props}
    >
      {children}
    </button>
  ),
}))

vi.mock('@/components/ui/input', () => ({
  Input: ({ value, onChange, placeholder, id, className }: any) => (
    <input
      value={value}
      onChange={onChange}
      placeholder={placeholder}
      id={id}
      className={className}
    />
  ),
}))

vi.mock('@/components/ui/label', () => ({
  Label: ({ children, htmlFor }: any) => <label htmlFor={htmlFor}>{children}</label>,
}))

vi.mock('@/components/ui/dialog', () => {
  const DialogTrigger = ({ children, onOpenChange, asChild }: any) => {
    const handleClick = () => {
      onOpenChange?.(true)
    }

    if (asChild) {
      return React.cloneElement(children, { onClick: handleClick })
    }
    return (
      <button type="button" onClick={handleClick}>
        {children}
      </button>
    )
  }
  DialogTrigger.displayName = 'DialogTrigger'

  return {
    Dialog: ({ children, open, onOpenChange }: any) => {
      const childrenWithProps = React.Children.map(children, (child) => {
        if (React.isValidElement(child) && (child.type as any)?.displayName === 'DialogTrigger') {
          return React.cloneElement(child, { onOpenChange } as any)
        }
        if (open) {
          return child
        }
        return null
      })
      return <div>{childrenWithProps}</div>
    },
    DialogContent: ({ children }: any) => <div data-testid="dialog-content">{children}</div>,
    DialogHeader: ({ children }: any) => <div>{children}</div>,
    DialogTitle: ({ children }: any) => <h2>{children}</h2>,
    DialogTrigger,
  }
})

vi.mock('@/components/ui/sheet', () => ({
  Sheet: ({ children }: any) => <div>{children}</div>,
  SheetContent: ({ children }: any) => <div data-testid="sheet-content">{children}</div>,
  SheetTrigger: ({ children, asChild }: any) => {
    if (asChild) {
      return React.cloneElement(children, { 'data-testid': 'sheet-trigger' })
    }
    return <button data-testid="sheet-trigger">{children}</button>
  },
}))

vi.mock('../note-list', () => ({
  NoteList: () => <div data-testid="note-list">Note List</div>,
}))

vi.mock('../templates-dialog', () => ({
  TemplatesDialog: ({ children }: any) => <div data-testid="templates-dialog">{children}</div>,
}))

vi.mock('../trash-dialog', () => ({
  TrashDialog: ({ children }: any) => <div data-testid="trash-dialog">{children}</div>,
}))

vi.mock('lucide-react', () => ({
  Plus: () => <span>plus-icon</span>,
  FolderPlus: () => <span>folder-plus-icon</span>,
  Tag: () => <span>tag-icon</span>,
  TagIcon: () => <span>tag-item-icon</span>,
  Menu: () => <span>menu-icon</span>,
  Library: () => <span>library-icon</span>,
}))

describe('Sidebar', () => {
  const mockUser = {
    id: '123',
    email: 'test@example.com',
    name: 'Test User',
    role: 'user' as const,
    isAdmin: false,
    mfaEnabled: false,
    createdAt: '2024-01-01T00:00:00Z',
  }

  beforeEach(() => {
    vi.clearAllMocks()
    createNoteMock.mockResolvedValue({ id: 'new-note-id' })

    vi.mocked(useNotesStore).mockReturnValue({
      notes: [],
      folders: [],
      tags: [],
      selectedNote: null,
      selectedFolder: null,
      selectNote: selectNoteMock,
      selectFolder: selectFolderMock,
      selectTag: selectTagMock,
      createNote: createNoteMock,
      createFolder: createFolderMock,
      isLoading: false,
    } as any)

    vi.mocked(useClerkAuthStore).mockReturnValue({
      user: mockUser,
      isAuthenticated: true,
    } as any)

    // Mock window.innerWidth for mobile detection
    Object.defineProperty(window, 'innerWidth', {
      writable: true,
      configurable: true,
      value: 1024,
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('should render sidebar', () => {
    render(<Sidebar />)
    expect(screen.getAllByTestId('scroll-area').length).toBeGreaterThan(0)
  })

  it('should render search input', () => {
    render(<Sidebar />)
    expect(screen.getByPlaceholderText('Search notes...')).toBeInTheDocument()
  })

  it('should render new note button', () => {
    render(<Sidebar />)
    expect(screen.getByTestId('new-note-button')).toBeInTheDocument()
    expect(screen.getByText('New Note')).toBeInTheDocument()
  })

  it('should create note when new note button clicked', async () => {
    render(<Sidebar />)

    const newNoteButton = screen.getByTestId('new-note-button')
    fireEvent.click(newNoteButton)

    await waitFor(() => {
      expect(createNoteMock).toHaveBeenCalledWith({})
      expect(selectNoteMock).toHaveBeenCalledWith('new-note-id')
    })
  })

  it('should handle create note error', async () => {
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    createNoteMock.mockRejectedValueOnce(new Error('Create failed'))

    render(<Sidebar />)

    const newNoteButton = screen.getByTestId('new-note-button')
    fireEvent.click(newNoteButton)

    await waitFor(() => {
      expect(consoleErrorSpy).toHaveBeenCalledWith('Failed to create note:', expect.any(Error))
    })

    consoleErrorSpy.mockRestore()
  })

  it('should disable new note button when loading', () => {
    vi.mocked(useNotesStore).mockReturnValue({
      notes: [],
      folders: [],
      tags: [],
      selectedNote: null,
      selectedFolder: null,
      selectNote: selectNoteMock,
      selectFolder: selectFolderMock,
      selectTag: selectTagMock,
      createNote: createNoteMock,
      createFolder: createFolderMock,
      isLoading: true,
    } as any)

    render(<Sidebar />)
    expect(screen.getByTestId('new-note-button')).toBeDisabled()
  })

  it('should render create folder button', () => {
    render(<Sidebar />)
    const folderButton = screen.getByTitle('Create Folder')
    expect(folderButton).toBeInTheDocument()
  })

  it('should open create folder dialog', async () => {
    render(<Sidebar />)

    const folderButton = screen.getByTitle('Create Folder')
    fireEvent.click(folderButton)

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Create Folder' })).toBeInTheDocument()
      expect(screen.getByLabelText('Folder Name')).toBeInTheDocument()
    })
  })

  it('should create folder with name and color', async () => {
    render(<Sidebar />)

    // Open dialog
    fireEvent.click(screen.getByTitle('Create Folder'))

    await waitFor(() => {
      const input = screen.getByLabelText('Folder Name')
      fireEvent.change(input, { target: { value: 'My Folder' } })
    })

    // Click create button
    const createButtons = screen.getAllByRole('button')
    const createButton = createButtons.find((btn) => btn.textContent === 'Create Folder')
    fireEvent.click(createButton!)

    await waitFor(() => {
      expect(createFolderMock).toHaveBeenCalledWith({
        name: 'My Folder',
        color: '#3b82f6',
      })
    })
  })

  it('should display color options in create folder dialog', async () => {
    render(<Sidebar />)

    fireEvent.click(screen.getByTitle('Create Folder'))

    await waitFor(() => {
      // Color label exists
      expect(screen.getByText('Color')).toBeInTheDocument()
      // Color buttons exist
      const colorButtons = document.querySelectorAll('button[type="button"]')
      expect(colorButtons.length).toBeGreaterThan(0)
    })
  })

  it('should not create folder with empty name', async () => {
    render(<Sidebar />)

    fireEvent.click(screen.getByTitle('Create Folder'))

    await waitFor(() => {
      const createButtons = screen.getAllByRole('button')
      const createButton = createButtons.find((btn) => btn.textContent === 'Create Folder')
      fireEvent.click(createButton!)
    })

    // Should not call createFolder with empty name
    expect(createFolderMock).not.toHaveBeenCalled()
  })

  it('should render create tag button', () => {
    render(<Sidebar />)
    const tagButton = screen.getByTitle('Create Tag')
    expect(tagButton).toBeInTheDocument()
  })

  it('should navigate to manage page when create tag clicked', () => {
    // Mock window.location
    delete (window as any).location
    window.location = { href: '' } as any

    render(<Sidebar />)

    const tagButton = screen.getByTitle('Create Tag')
    fireEvent.click(tagButton)

    expect(window.location.href).toBe('/manage')
  })

  it('should render note list when not loading', () => {
    render(<Sidebar />)
    expect(screen.getByTestId('note-list')).toBeInTheDocument()
  })

  it('should show loading spinner when loading', () => {
    vi.mocked(useNotesStore).mockReturnValue({
      notes: [],
      folders: [],
      tags: [],
      selectedNote: null,
      selectedFolder: null,
      selectNote: selectNoteMock,
      selectFolder: selectFolderMock,
      selectTag: selectTagMock,
      createNote: createNoteMock,
      createFolder: createFolderMock,
      isLoading: true,
    } as any)

    render(<Sidebar />)
    expect(screen.queryByTestId('note-list')).not.toBeInTheDocument()
  })

  it('should render folders section', () => {
    render(<Sidebar />)
    expect(screen.getByText('Folders')).toBeInTheDocument()
    expect(screen.getByText('All Notes')).toBeInTheDocument()
  })

  it('should render folders list', () => {
    const mockFolders = [
      {
        id: 'folder-1',
        name: 'Work',
        userId: '123',
        parentId: null,
        color: '#3b82f6',
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
      {
        id: 'folder-2',
        name: 'Personal',
        userId: '123',
        parentId: null,
        color: '#10b981',
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      notes: [],
      folders: mockFolders,
      tags: [],
      selectedNote: null,
      selectedFolder: null,
      selectNote: selectNoteMock,
      selectFolder: selectFolderMock,
      selectTag: selectTagMock,
      createNote: createNoteMock,
      createFolder: createFolderMock,
      isLoading: false,
    } as any)

    render(<Sidebar />)

    expect(screen.getByText('Work')).toBeInTheDocument()
    expect(screen.getByText('Personal')).toBeInTheDocument()
  })

  it('should display folder with color indicator', () => {
    const mockFolders = [
      {
        id: 'folder-1',
        name: 'Work',
        userId: '123',
        parentId: null,
        color: '#3b82f6',
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      notes: [],
      folders: mockFolders,
      tags: [],
      selectedNote: null,
      selectedFolder: null,
      selectNote: selectNoteMock,
      selectFolder: selectFolderMock,
      selectTag: selectTagMock,
      createNote: createNoteMock,
      createFolder: createFolderMock,
      isLoading: false,
    } as any)

    render(<Sidebar />)

    expect(screen.getByText('Work')).toBeInTheDocument()
    // Color indicator div exists
    const colorDiv = document.querySelector('div[style*="background-color"]')
    expect(colorDiv).toBeTruthy()
  })

  it('should display all notes button', () => {
    render(<Sidebar />)
    expect(screen.getByText('All Notes')).toBeInTheDocument()
  })

  it('should render tags section', () => {
    render(<Sidebar />)
    expect(screen.getByText('Tags')).toBeInTheDocument()
  })

  it('should render tags list', () => {
    const mockTags = [
      {
        id: 'tag-1',
        name: 'urgent',
        userId: '123',
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
      {
        id: 'tag-2',
        name: 'ideas',
        userId: '123',
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      notes: [],
      folders: [],
      tags: mockTags,
      selectedNote: null,
      selectedFolder: null,
      selectNote: selectNoteMock,
      selectFolder: selectFolderMock,
      selectTag: selectTagMock,
      createNote: createNoteMock,
      createFolder: createFolderMock,
      isLoading: false,
    } as any)

    render(<Sidebar />)

    expect(screen.getByText('urgent')).toBeInTheDocument()
    expect(screen.getByText('ideas')).toBeInTheDocument()
  })

  it('should display tag with icon', () => {
    const mockTags = [
      {
        id: 'tag-1',
        name: 'urgent',
        userId: '123',
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      notes: [],
      folders: [],
      tags: mockTags,
      selectedNote: null,
      selectedFolder: null,
      selectNote: selectNoteMock,
      selectFolder: selectFolderMock,
      selectTag: selectTagMock,
      createNote: createNoteMock,
      createFolder: createFolderMock,
      isLoading: false,
    } as any)

    render(<Sidebar />)

    expect(screen.getByText('urgent')).toBeInTheDocument()
    expect(screen.getByText('tag-item-icon')).toBeInTheDocument()
  })

  it('should update search query', () => {
    render(<Sidebar />)

    const searchInput = screen.getByPlaceholderText('Search notes...')
    fireEvent.change(searchInput, { target: { value: 'test query' } })

    expect(searchInput).toHaveValue('test query')
  })

  it('should render search button', () => {
    render(<Sidebar />)
    expect(screen.getByText('Search')).toBeInTheDocument()
  })
})
