import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Sidebar } from '../sidebar'
import { useNotesStore } from '@/stores/notesStore'
import { useAuthStore } from '@/stores/authStore'

vi.mock('@/stores/notesStore', () => ({
  useNotesStore: vi.fn(),
}))

vi.mock('@/stores/authStore', () => ({
  useAuthStore: vi.fn(),
}))

// Mock all child components
vi.mock('@/components/ui/scroll-area', () => ({
  ScrollArea: ({ children }: any) => <div data-testid="scroll-area">{children}</div>,
}))

vi.mock('@/components/ui/button', () => ({
  Button: ({ children, ...props }: any) => (
    <button {...props} data-testid="button">
      {children}
    </button>
  ),
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
    vi.mocked(useNotesStore).mockReturnValue({
      notes: [],
      folders: [],
      selectedNote: null,
      selectedFolder: null,
      selectNote: vi.fn(),
      selectFolder: vi.fn(),
      createNote: vi.fn(),
    } as any)

    vi.mocked(useAuthStore).mockReturnValue({
      user: mockUser,
      isAuthenticated: true,
    } as any)
  })

  it('should render sidebar', () => {
    render(<Sidebar />)
    expect(screen.getByTestId('scroll-area')).toBeInTheDocument()
  })

  it('should render with notes', () => {
    const mockNotes = [
      {
        id: 'note-1',
        title: 'Test Note',
        content: 'Content',
        userId: '123',
        encrypted: true,
        encryptionVersion: 1,
        folderId: null,
        tags: [],
        pinned: false,
        isTrashed: false,
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      notes: mockNotes,
      folders: [],
      selectedNote: null,
      selectedFolder: null,
      selectNote: vi.fn(),
      selectFolder: vi.fn(),
      createNote: vi.fn(),
    } as any)

    render(<Sidebar />)
    expect(screen.getByTestId('scroll-area')).toBeInTheDocument()
  })

  it('should render with folders', () => {
    const mockFolders = [
      {
        id: 'folder-1',
        name: 'My Folder',
        userId: '123',
        parentId: null,
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      notes: [],
      folders: mockFolders,
      selectedNote: null,
      selectedFolder: null,
      selectNote: vi.fn(),
      selectFolder: vi.fn(),
      createNote: vi.fn(),
    } as any)

    render(<Sidebar />)
    expect(screen.getByTestId('scroll-area')).toBeInTheDocument()
  })
})
