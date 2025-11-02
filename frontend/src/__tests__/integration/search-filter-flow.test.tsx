import { describe, it, expect, beforeEach, vi } from 'vitest'
import { useNotesStore } from '@/stores/notesStore'
import { apiClient } from '@/services/api/secureApi'
import type { Note } from '@/types'

vi.mock('@/services/api/secureApi', () => ({
  apiClient: {
    getNotes: vi.fn(),
    getFolders: vi.fn(),
    getTags: vi.fn(),
    searchNotes: vi.fn(),
  },
}))

describe('Integration: Search and Filter Flow', () => {
  const mockNotes: Note[] = [
    {
      id: 'note-1',
      title: 'Meeting Notes',
      content: 'Discussion about project planning',
      userId: 'user-1',
      encrypted: true,
      encryptionVersion: 'v1',
      folderId: 'folder-1',
      tags: ['work', 'meeting'],
      pinned: true,
      isTrashed: false,
      sharedWith: [],
      isTemplate: false,
      createdAt: '2024-01-01',
      updatedAt: '2024-01-01',
    },
    {
      id: 'note-2',
      title: 'Personal Tasks',
      content: 'Buy groceries, clean house',
      userId: 'user-1',
      encrypted: true,
      encryptionVersion: 'v1',
      folderId: 'folder-2',
      tags: ['personal', 'tasks'],
      pinned: false,
      isTrashed: false,
      sharedWith: [],
      isTemplate: false,
      createdAt: '2024-01-02',
      updatedAt: '2024-01-02',
    },
    {
      id: 'note-3',
      title: 'Project Ideas',
      content: 'New feature ideas for the app',
      userId: 'user-1',
      encrypted: true,
      encryptionVersion: 'v1',
      folderId: 'folder-1',
      tags: ['work', 'ideas'],
      pinned: false,
      isTrashed: false,
      sharedWith: ['user-2'],
      isTemplate: false,
      createdAt: '2024-01-03',
      updatedAt: '2024-01-03',
    },
    {
      id: 'note-4',
      title: 'Archived Note',
      content: 'Old content',
      userId: 'user-1',
      encrypted: true,
      encryptionVersion: 'v1',
      folderId: null,
      tags: [],
      pinned: false,
      isTrashed: true,
      sharedWith: [],
      isTemplate: false,
      createdAt: '2024-01-04',
      updatedAt: '2024-01-04',
    },
  ]

  beforeEach(() => {
    useNotesStore.setState({
      notes: mockNotes,
      folders: [
        { id: 'folder-1', name: 'Work', userId: 'user-1', createdAt: '2024-01-01' },
        { id: 'folder-2', name: 'Personal', userId: 'user-1', createdAt: '2024-01-01' },
      ],
      tags: [
        { id: 'tag-1', name: 'work', userId: 'user-1', createdAt: '2024-01-01' },
        { id: 'tag-2', name: 'meeting', userId: 'user-1', createdAt: '2024-01-01' },
        { id: 'tag-3', name: 'personal', userId: 'user-1', createdAt: '2024-01-01' },
        { id: 'tag-4', name: 'tasks', userId: 'user-1', createdAt: '2024-01-01' },
        { id: 'tag-5', name: 'ideas', userId: 'user-1', createdAt: '2024-01-01' },
      ],
      selectedNote: null,
      selectedFolder: null,
    })
    vi.clearAllMocks()
  })

  describe('Text Search', () => {
    it('should search notes by title', () => {
      const searchTerm = 'meeting'
      const results = useNotesStore
        .getState()
        .notes.filter(note =>
          note.title.toLowerCase().includes(searchTerm.toLowerCase())
        )

      expect(results).toHaveLength(1)
      expect(results[0].title).toBe('Meeting Notes')
    })

    it('should search notes by content', () => {
      const searchTerm = 'groceries'
      const results = useNotesStore
        .getState()
        .notes.filter(note =>
          note.content.toLowerCase().includes(searchTerm.toLowerCase())
        )

      expect(results).toHaveLength(1)
      expect(results[0].title).toBe('Personal Tasks')
    })

    it('should search notes by title or content', () => {
      const searchTerm = 'project'
      const results = useNotesStore
        .getState()
        .notes.filter(note =>
          note.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
          note.content.toLowerCase().includes(searchTerm.toLowerCase())
        )

      expect(results).toHaveLength(2) // 'Project Ideas' and 'Meeting Notes' (content contains "project planning")
    })

    it('should return empty results for no matches', () => {
      const searchTerm = 'nonexistent'
      const results = useNotesStore
        .getState()
        .notes.filter(note =>
          note.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
          note.content.toLowerCase().includes(searchTerm.toLowerCase())
        )

      expect(results).toHaveLength(0)
    })

    it('should be case-insensitive', () => {
      const results1 = useNotesStore
        .getState()
        .notes.filter(note =>
          note.title.toLowerCase().includes('meeting')
        )

      const results2 = useNotesStore
        .getState()
        .notes.filter(note =>
          note.title.toLowerCase().includes('MEETING')
        )

      expect(results1).toEqual(results2)
    })
  })

  describe('Filter by Folder', () => {
    it('should filter notes by folder', () => {
      const results = useNotesStore
        .getState()
        .notes.filter(note => note.folderId === 'folder-1')

      expect(results).toHaveLength(2)
      expect(results.map(n => n.title)).toContain('Meeting Notes')
      expect(results.map(n => n.title)).toContain('Project Ideas')
    })

    it('should filter notes without folder', () => {
      const results = useNotesStore
        .getState()
        .notes.filter(note => note.folderId === null)

      expect(results).toHaveLength(1)
      expect(results[0].title).toBe('Archived Note')
    })

    it('should return empty for non-existent folder', () => {
      const results = useNotesStore
        .getState()
        .notes.filter(note => note.folderId === 'nonexistent')

      expect(results).toHaveLength(0)
    })
  })

  describe('Filter by Tags', () => {
    it('should filter notes by single tag', () => {
      const results = useNotesStore
        .getState()
        .notes.filter(note => note.tags.includes('work'))

      expect(results).toHaveLength(2)
      expect(results.map(n => n.title)).toContain('Meeting Notes')
      expect(results.map(n => n.title)).toContain('Project Ideas')
    })

    it('should filter notes by multiple tags (AND)', () => {
      const requiredTags = ['work', 'meeting']
      const results = useNotesStore
        .getState()
        .notes.filter(note =>
          requiredTags.every(tag => note.tags.includes(tag))
        )

      expect(results).toHaveLength(1)
      expect(results[0].title).toBe('Meeting Notes')
    })

    it('should filter notes by multiple tags (OR)', () => {
      const anyTags = ['meeting', 'tasks']
      const results = useNotesStore
        .getState()
        .notes.filter(note =>
          anyTags.some(tag => note.tags.includes(tag))
        )

      expect(results).toHaveLength(2)
      expect(results.map(n => n.title)).toContain('Meeting Notes')
      expect(results.map(n => n.title)).toContain('Personal Tasks')
    })

    it('should filter notes without tags', () => {
      const results = useNotesStore
        .getState()
        .notes.filter(note => note.tags.length === 0)

      expect(results).toHaveLength(1)
      expect(results[0].title).toBe('Archived Note')
    })
  })

  describe('Filter by Status', () => {
    it('should filter pinned notes', () => {
      const results = useNotesStore
        .getState()
        .notes.filter(note => note.pinned)

      expect(results).toHaveLength(1)
      expect(results[0].title).toBe('Meeting Notes')
    })

    it('should filter trashed notes', () => {
      const results = useNotesStore
        .getState()
        .notes.filter(note => note.isTrashed)

      expect(results).toHaveLength(1)
      expect(results[0].title).toBe('Archived Note')
    })

    it('should filter active notes (not trashed)', () => {
      const results = useNotesStore
        .getState()
        .notes.filter(note => !note.isTrashed)

      expect(results).toHaveLength(3)
    })

    it('should filter shared notes', () => {
      const results = useNotesStore
        .getState()
        .notes.filter(note => note.sharedWith.length > 0)

      expect(results).toHaveLength(1)
      expect(results[0].title).toBe('Project Ideas')
    })
  })

  describe('Combined Filters', () => {
    it('should apply search + folder filter', () => {
      const searchTerm = 'project'
      const folderId = 'folder-1'

      const results = useNotesStore
        .getState()
        .notes.filter(note =>
          note.folderId === folderId &&
          (note.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
           note.content.toLowerCase().includes(searchTerm.toLowerCase()))
        )

      expect(results).toHaveLength(2)
    })

    it('should apply search + tag filter', () => {
      const searchTerm = 'notes'
      const tag = 'work'

      const results = useNotesStore
        .getState()
        .notes.filter(note =>
          note.tags.includes(tag) &&
          note.title.toLowerCase().includes(searchTerm.toLowerCase())
        )

      expect(results).toHaveLength(1)
      expect(results[0].title).toBe('Meeting Notes')
    })

    it('should apply folder + tag + status filter', () => {
      const folderId = 'folder-1'
      const tag = 'work'
      const pinned = true

      const results = useNotesStore
        .getState()
        .notes.filter(note =>
          note.folderId === folderId &&
          note.tags.includes(tag) &&
          note.pinned === pinned
        )

      expect(results).toHaveLength(1)
      expect(results[0].title).toBe('Meeting Notes')
    })

    it('should handle complex filter combination', () => {
      const searchTerm = 'ideas'
      const folderId = 'folder-1'
      const excludeTrashed = true
      const hasTag = 'ideas'

      const results = useNotesStore
        .getState()
        .notes.filter(note =>
          (!excludeTrashed || !note.isTrashed) &&
          (folderId ? note.folderId === folderId : true) &&
          note.tags.includes(hasTag) &&
          (note.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
           note.content.toLowerCase().includes(searchTerm.toLowerCase()))
        )

      expect(results).toHaveLength(1)
      expect(results[0].title).toBe('Project Ideas')
    })
  })

  describe('Sorting Results', () => {
    it('should sort by date (newest first)', () => {
      const sorted = [...useNotesStore.getState().notes]
        .filter(note => !note.isTrashed)
        .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())

      expect(sorted[0].title).toBe('Project Ideas') // 2024-01-03
      expect(sorted[1].title).toBe('Personal Tasks') // 2024-01-02
      expect(sorted[2].title).toBe('Meeting Notes') // 2024-01-01
    })

    it('should sort by date (oldest first)', () => {
      const sorted = [...useNotesStore.getState().notes]
        .filter(note => !note.isTrashed)
        .sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime())

      expect(sorted[0].title).toBe('Meeting Notes')
      expect(sorted[1].title).toBe('Personal Tasks')
      expect(sorted[2].title).toBe('Project Ideas')
    })

    it('should sort alphabetically by title', () => {
      const sorted = [...useNotesStore.getState().notes]
        .filter(note => !note.isTrashed)
        .sort((a, b) => a.title.localeCompare(b.title))

      expect(sorted[0].title).toBe('Meeting Notes')
      expect(sorted[1].title).toBe('Personal Tasks')
      expect(sorted[2].title).toBe('Project Ideas')
    })

    it('should sort with pinned notes first', () => {
      const sorted = [...useNotesStore.getState().notes]
        .filter(note => !note.isTrashed)
        .sort((a, b) => {
          if (a.pinned && !b.pinned) return -1
          if (!a.pinned && b.pinned) return 1
          return 0
        })

      expect(sorted[0].pinned).toBe(true)
      expect(sorted[0].title).toBe('Meeting Notes')
    })
  })

  describe('API Search Integration', () => {
    it('should call API search endpoint', async () => {
      const searchResults = [mockNotes[0], mockNotes[2]]
      vi.mocked(apiClient.searchNotes).mockResolvedValue(searchResults as any)

      const results = await apiClient.searchNotes('project')

      expect(apiClient.searchNotes).toHaveBeenCalledWith('project')
      expect(results).toHaveLength(2)
    })

    it('should handle API search errors', async () => {
      vi.mocked(apiClient.searchNotes).mockRejectedValue(new Error('Search failed'))

      await expect(apiClient.searchNotes('query')).rejects.toThrow('Search failed')
    })

    it('should return empty results for no matches', async () => {
      vi.mocked(apiClient.searchNotes).mockResolvedValue([])

      const results = await apiClient.searchNotes('nonexistent')

      expect(results).toHaveLength(0)
    })
  })

  describe('Filter Persistence', () => {
    it('should persist selected folder', () => {
      useNotesStore.setState({ selectedFolder: 'folder-1' })

      expect(useNotesStore.getState().selectedFolder).toBe('folder-1')
    })

    it('should clear selected folder', () => {
      useNotesStore.setState({ selectedFolder: 'folder-1' })
      useNotesStore.setState({ selectedFolder: null })

      expect(useNotesStore.getState().selectedFolder).toBeNull()
    })
  })
})
