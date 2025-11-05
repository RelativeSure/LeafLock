import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import React from 'react'
import { FoldersTagsPage } from '../folders-tags-page'
import { useNotesStore } from '@/stores/notesStore'
import { useToast } from '@/hooks/use-toast'

const createFolderMock = vi.fn()
const deleteFolderMock = vi.fn()
const createTagMock = vi.fn()
const deleteTagMock = vi.fn()
const toastMock = {
  success: vi.fn(),
  error: vi.fn(),
}

vi.mock('@/stores/notesStore', () => ({
  useNotesStore: vi.fn(),
}))

vi.mock('@/hooks/use-toast', () => ({
  useToast: vi.fn(),
}))

vi.mock('@/components/ui/card', () => ({
  Card: ({ children }: any) => <div data-testid="card">{children}</div>,
  CardHeader: ({ children }: any) => <div>{children}</div>,
  CardTitle: ({ children, className }: any) => <h3 className={className}>{children}</h3>,
  CardDescription: ({ children }: any) => <p>{children}</p>,
  CardContent: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, onClick, size, className }: any) => (
    <button onClick={onClick} data-size={size} className={className}>
      {children}
    </button>
  ),
}))

vi.mock('@/components/ui/input', () => ({
  Input: ({ value, onChange, placeholder, id }: any) => (
    <input value={value} onChange={onChange} placeholder={placeholder} id={id} />
  ),
}))

vi.mock('@/components/ui/label', () => ({
  Label: ({ children, htmlFor }: any) => <label htmlFor={htmlFor}>{children}</label>,
}))

vi.mock('@/components/ui/dialog', () => ({
  Dialog: ({ children }: any) => <div>{children}</div>,
  DialogContent: ({ children }: any) => <div data-testid="dialog-content">{children}</div>,
  DialogHeader: ({ children }: any) => <div>{children}</div>,
  DialogTitle: ({ children }: any) => <h2>{children}</h2>,
  DialogDescription: ({ children }: any) => <p>{children}</p>,
  DialogFooter: ({ children }: any) => <div>{children}</div>,
  DialogTrigger: ({ children, asChild }: any) => {
    if (asChild) {
      return React.cloneElement(children)
    }
    return <div>{children}</div>
  },
}))

vi.mock('@/components/ui/dropdown-menu', () => ({
  DropdownMenu: ({ children }: any) => <div>{children}</div>,
  DropdownMenuTrigger: ({ children, asChild }: any) => {
    if (asChild) {
      return React.cloneElement(children, { 'data-testid': 'dropdown-trigger' })
    }
    return <button data-testid="dropdown-trigger">{children}</button>
  },
  DropdownMenuContent: ({ children }: any) => <div data-testid="dropdown-content">{children}</div>,
  DropdownMenuItem: ({ children, onClick, className }: any) => (
    <div onClick={onClick} className={className} role="menuitem">
      {children}
    </div>
  ),
}))

vi.mock('lucide-react', () => ({
  FolderPlus: () => <span>folder-plus-icon</span>,
  Plus: () => <span>plus-icon</span>,
  Folder: () => <span>folder-icon</span>,
  Tag: () => <span>tag-icon</span>,
  Edit2: () => <span>edit-icon</span>,
  Trash2: () => <span>trash-icon</span>,
  MoreHorizontal: () => <span>more-icon</span>,
  FolderOpen: () => <span>folder-open-icon</span>,
  Hash: () => <span>hash-icon</span>,
}))

describe('FoldersTagsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()

    vi.mocked(useNotesStore).mockReturnValue({
      folders: [],
      tags: [],
      notes: [],
      createFolder: createFolderMock,
      deleteFolder: deleteFolderMock,
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    vi.mocked(useToast).mockReturnValue({
      toast: toastMock,
    } as any)
  })

  it('should render page', () => {
    render(<FoldersTagsPage />)
    expect(screen.getByText('Folders & Tags')).toBeInTheDocument()
    expect(screen.getByText('Organize your notes with folders and tags.')).toBeInTheDocument()
  })

  it('should render folders section', () => {
    render(<FoldersTagsPage />)
    expect(screen.getByText('Folders')).toBeInTheDocument()
    expect(screen.getByText('Organize your notes into folders')).toBeInTheDocument()
  })

  it('should render tags section', () => {
    render(<FoldersTagsPage />)
    expect(screen.getByText('Tags')).toBeInTheDocument()
    expect(screen.getByText('Label your notes with tags')).toBeInTheDocument()
  })

  it('should render new folder button', () => {
    render(<FoldersTagsPage />)
    const button = screen
      .getAllByRole('button')
      .find((btn) => btn.textContent?.includes('New Folder'))
    expect(button).toBeInTheDocument()
  })

  it('should render new tag button', () => {
    render(<FoldersTagsPage />)
    const button = screen.getAllByRole('button').find((btn) => btn.textContent?.includes('New Tag'))
    expect(button).toBeInTheDocument()
  })

  it('should display empty state for folders', () => {
    render(<FoldersTagsPage />)
    expect(screen.getByText('No folders yet')).toBeInTheDocument()
    expect(screen.getByText('Create your first folder to get started')).toBeInTheDocument()
  })

  it('should display empty state for tags', () => {
    render(<FoldersTagsPage />)
    expect(screen.getByText('No tags yet')).toBeInTheDocument()
    expect(screen.getByText('Create your first tag to get started')).toBeInTheDocument()
  })

  it('should display folders list', () => {
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
      folders: mockFolders,
      tags: [],
      notes: [],
      createFolder: createFolderMock,
      deleteFolder: deleteFolderMock,
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<FoldersTagsPage />)

    expect(screen.getByText('Work')).toBeInTheDocument()
    expect(screen.getByText('Personal')).toBeInTheDocument()
  })

  it('should display folder note count', () => {
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

    const mockNotes = [
      {
        id: 'note-1',
        title: 'Note 1',
        folderId: 'folder-1',
        isTrashed: false,
        userId: '123',
        content: '',
        isEncrypted: false,
        tags: [],
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
      {
        id: 'note-2',
        title: 'Note 2',
        folderId: 'folder-1',
        isTrashed: false,
        userId: '123',
        content: '',
        isEncrypted: false,
        tags: [],
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      folders: mockFolders,
      tags: [],
      notes: mockNotes,
      createFolder: createFolderMock,
      deleteFolder: deleteFolderMock,
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<FoldersTagsPage />)

    expect(screen.getByText('2 notes')).toBeInTheDocument()
  })

  it('should display singular note count', () => {
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

    const mockNotes = [
      {
        id: 'note-1',
        title: 'Note 1',
        folderId: 'folder-1',
        isTrashed: false,
        userId: '123',
        content: '',
        isEncrypted: false,
        tags: [],
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      folders: mockFolders,
      tags: [],
      notes: mockNotes,
      createFolder: createFolderMock,
      deleteFolder: deleteFolderMock,
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<FoldersTagsPage />)

    expect(screen.getByText('1 note')).toBeInTheDocument()
  })

  it('should filter out trashed notes from folder count', () => {
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

    const mockNotes = [
      {
        id: 'note-1',
        title: 'Note 1',
        folderId: 'folder-1',
        isTrashed: false,
        userId: '123',
        content: '',
        isEncrypted: false,
        tags: [],
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
      {
        id: 'note-2',
        title: 'Note 2',
        folderId: 'folder-1',
        isTrashed: true,
        userId: '123',
        content: '',
        isEncrypted: false,
        tags: [],
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      folders: mockFolders,
      tags: [],
      notes: mockNotes,
      createFolder: createFolderMock,
      deleteFolder: deleteFolderMock,
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<FoldersTagsPage />)

    expect(screen.getByText('1 note')).toBeInTheDocument()
  })

  it('should display folder with color', () => {
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
      folders: mockFolders,
      tags: [],
      notes: [],
      createFolder: createFolderMock,
      deleteFolder: deleteFolderMock,
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<FoldersTagsPage />)

    expect(screen.getByText('Work')).toBeInTheDocument()
    expect(screen.getByText('folder-open-icon')).toBeInTheDocument()
  })

  it('should display tags list', () => {
    const mockTags = [
      {
        id: 'tag-1',
        name: 'important',
        userId: '123',
        color: '#ef4444',
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
      {
        id: 'tag-2',
        name: 'urgent',
        userId: '123',
        color: '#f59e0b',
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      folders: [],
      tags: mockTags,
      notes: [],
      createFolder: createFolderMock,
      deleteFolder: deleteFolderMock,
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<FoldersTagsPage />)

    expect(screen.getByText('important')).toBeInTheDocument()
    expect(screen.getByText('urgent')).toBeInTheDocument()
  })

  it('should display tag note count', () => {
    const mockTags = [
      {
        id: 'tag-1',
        name: 'important',
        userId: '123',
        color: '#ef4444',
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ]

    const mockNotes = [
      {
        id: 'note-1',
        title: 'Note 1',
        folderId: null,
        isTrashed: false,
        userId: '123',
        content: '',
        isEncrypted: false,
        tags: ['important'],
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
      {
        id: 'note-2',
        title: 'Note 2',
        folderId: null,
        isTrashed: false,
        userId: '123',
        content: '',
        isEncrypted: false,
        tags: ['important'],
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      folders: [],
      tags: mockTags,
      notes: mockNotes,
      createFolder: createFolderMock,
      deleteFolder: deleteFolderMock,
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<FoldersTagsPage />)

    expect(screen.getByText('2 notes')).toBeInTheDocument()
  })

  it('should display singular note count for tags', () => {
    const mockTags = [
      {
        id: 'tag-1',
        name: 'important',
        userId: '123',
        color: '#ef4444',
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ]

    const mockNotes = [
      {
        id: 'note-1',
        title: 'Note 1',
        folderId: null,
        isTrashed: false,
        userId: '123',
        content: '',
        isEncrypted: false,
        tags: ['important'],
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      folders: [],
      tags: mockTags,
      notes: mockNotes,
      createFolder: createFolderMock,
      deleteFolder: deleteFolderMock,
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<FoldersTagsPage />)

    expect(screen.getByText('1 note')).toBeInTheDocument()
  })

  it('should filter out trashed notes from tag count', () => {
    const mockTags = [
      {
        id: 'tag-1',
        name: 'important',
        userId: '123',
        color: '#ef4444',
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ]

    const mockNotes = [
      {
        id: 'note-1',
        title: 'Note 1',
        folderId: null,
        isTrashed: false,
        userId: '123',
        content: '',
        isEncrypted: false,
        tags: ['important'],
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
      {
        id: 'note-2',
        title: 'Note 2',
        folderId: null,
        isTrashed: true,
        userId: '123',
        content: '',
        isEncrypted: false,
        tags: ['important'],
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      folders: [],
      tags: mockTags,
      notes: mockNotes,
      createFolder: createFolderMock,
      deleteFolder: deleteFolderMock,
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<FoldersTagsPage />)

    expect(screen.getByText('1 note')).toBeInTheDocument()
  })

  it('should display tag with color', () => {
    const mockTags = [
      {
        id: 'tag-1',
        name: 'important',
        userId: '123',
        color: '#ef4444',
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      folders: [],
      tags: mockTags,
      notes: [],
      createFolder: createFolderMock,
      deleteFolder: deleteFolderMock,
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<FoldersTagsPage />)

    expect(screen.getByText('important')).toBeInTheDocument()
    expect(screen.getByText('hash-icon')).toBeInTheDocument()
  })

  it('should display both folders and tags simultaneously', () => {
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

    const mockTags = [
      {
        id: 'tag-1',
        name: 'important',
        userId: '123',
        color: '#ef4444',
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      folders: mockFolders,
      tags: mockTags,
      notes: [],
      createFolder: createFolderMock,
      deleteFolder: deleteFolderMock,
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<FoldersTagsPage />)

    expect(screen.getByText('Work')).toBeInTheDocument()
    expect(screen.getByText('important')).toBeInTheDocument()
  })

  it('should display multiple folders with note counts', () => {
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

    const mockNotes = [
      {
        id: 'note-1',
        title: 'Note 1',
        folderId: 'folder-1',
        isTrashed: false,
        userId: '123',
        content: '',
        isEncrypted: false,
        tags: [],
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      folders: mockFolders,
      tags: [],
      notes: mockNotes,
      createFolder: createFolderMock,
      deleteFolder: deleteFolderMock,
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<FoldersTagsPage />)

    expect(screen.getByText('Work')).toBeInTheDocument()
    expect(screen.getByText('Personal')).toBeInTheDocument()
    expect(
      screen.getAllByText('1 note').length + screen.getAllByText('0 notes').length
    ).toBeGreaterThan(0)
  })

  it('should handle folders with no notes', () => {
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
      folders: mockFolders,
      tags: [],
      notes: [],
      createFolder: createFolderMock,
      deleteFolder: deleteFolderMock,
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<FoldersTagsPage />)

    expect(screen.getByText('Work')).toBeInTheDocument()
    expect(screen.getByText('0 notes')).toBeInTheDocument()
  })

  it('should handle tags with no notes', () => {
    const mockTags = [
      {
        id: 'tag-1',
        name: 'important',
        userId: '123',
        color: '#ef4444',
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      folders: [],
      tags: mockTags,
      notes: [],
      createFolder: createFolderMock,
      deleteFolder: deleteFolderMock,
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<FoldersTagsPage />)

    expect(screen.getByText('important')).toBeInTheDocument()
    expect(screen.getByText('0 notes')).toBeInTheDocument()
  })

  it('should render folder dropdown menu trigger', () => {
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
      folders: mockFolders,
      tags: [],
      notes: [],
      createFolder: createFolderMock,
      deleteFolder: deleteFolderMock,
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<FoldersTagsPage />)

    expect(screen.getByText('more-icon')).toBeInTheDocument()
  })

  it('should render tag dropdown menu trigger', () => {
    const mockTags = [
      {
        id: 'tag-1',
        name: 'important',
        userId: '123',
        color: '#ef4444',
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      folders: [],
      tags: mockTags,
      notes: [],
      createFolder: createFolderMock,
      deleteFolder: deleteFolderMock,
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<FoldersTagsPage />)

    expect(screen.getByText('more-icon')).toBeInTheDocument()
  })

  it('should render folder and tag cards', () => {
    render(<FoldersTagsPage />)
    const cards = screen.getAllByTestId('card')
    expect(cards).toHaveLength(2)
  })

  it('should call deleteFolder when delete is clicked', () => {
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
      folders: mockFolders,
      tags: [],
      notes: [],
      createFolder: createFolderMock,
      deleteFolder: deleteFolderMock,
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<FoldersTagsPage />)

    const deleteButton = screen.getByText('Delete')
    fireEvent.click(deleteButton)

    expect(deleteFolderMock).toHaveBeenCalledWith('folder-1')
  })

  it('should call deleteTag when delete is clicked', () => {
    const mockTags = [
      {
        id: 'tag-1',
        name: 'important',
        userId: '123',
        color: '#ef4444',
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      folders: [],
      tags: mockTags,
      notes: [],
      createFolder: createFolderMock,
      deleteFolder: deleteFolderMock,
      createTag: createTagMock,
      deleteTag: deleteTagMock,
    } as any)

    render(<FoldersTagsPage />)

    const deleteButton = screen.getByText('Delete')
    fireEvent.click(deleteButton)

    expect(deleteTagMock).toHaveBeenCalledWith('tag-1')
  })
})
