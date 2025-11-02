import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render } from '@testing-library/react'
import { FoldersTagsPage } from '../folders-tags-page'
import { useNotesStore } from '@/stores/notesStore'

vi.mock('@/stores/notesStore', () => ({
  useNotesStore: vi.fn(),
}))

vi.mock('@/components/ui/tabs', () => ({
  Tabs: ({ children }: any) => <div data-testid="tabs">{children}</div>,
  TabsList: ({ children }: any) => <div>{children}</div>,
  TabsTrigger: ({ children }: any) => <button>{children}</button>,
  TabsContent: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/card', () => ({
  Card: ({ children }: any) => <div data-testid="card">{children}</div>,
  CardHeader: ({ children }: any) => <div>{children}</div>,
  CardTitle: ({ children }: any) => <h3>{children}</h3>,
  CardDescription: ({ children }: any) => <p>{children}</p>,
  CardContent: ({ children }: any) => <div>{children}</div>,
}))

describe('FoldersTagsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(useNotesStore).mockReturnValue({
      folders: [],
      tags: [],
      createFolder: vi.fn(),
      deleteFolder: vi.fn(),
      createTag: vi.fn(),
      deleteTag: vi.fn(),
    } as any)
  })

  it('should render folders tags page', () => {
    const { getByTestId } = render(<FoldersTagsPage />)
    expect(getByTestId('tabs')).toBeInTheDocument()
  })

  it('should render with folders', () => {
    const mockFolders = [
      {
        id: 'folder-1',
        name: 'Work',
        userId: '123',
        parentId: null,
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      folders: mockFolders,
      tags: [],
      createFolder: vi.fn(),
      deleteFolder: vi.fn(),
      createTag: vi.fn(),
      deleteTag: vi.fn(),
    } as any)

    const { getByTestId } = render(<FoldersTagsPage />)
    expect(getByTestId('tabs')).toBeInTheDocument()
  })

  it('should render with tags', () => {
    const mockTags = [
      {
        id: 'tag-1',
        name: 'important',
        userId: '123',
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
    ]

    vi.mocked(useNotesStore).mockReturnValue({
      folders: [],
      tags: mockTags,
      createFolder: vi.fn(),
      deleteFolder: vi.fn(),
      createTag: vi.fn(),
      deleteTag: vi.fn(),
    } as any)

    const { getByTestId } = render(<FoldersTagsPage />)
    expect(getByTestId('tabs')).toBeInTheDocument()
  })
})
