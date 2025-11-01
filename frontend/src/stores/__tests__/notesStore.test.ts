import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { useNotesStore } from '../notesStore'
import { apiClient } from '@/services/api/secureApi'
import * as encryptionUtils from '@/lib/encryption-utils'
import type { Note, Folder, Tag } from '../../types'

// Mock dependencies
vi.mock('@/services/api/secureApi', () => ({
  apiClient: {
    getNotes: vi.fn(),
    getFolders: vi.fn(),
    getTags: vi.fn(),
    createNote: vi.fn(),
    updateNote: vi.fn(),
    deleteNote: vi.fn(),
    createFolder: vi.fn(),
    updateFolder: vi.fn(),
    deleteFolder: vi.fn(),
    createTag: vi.fn(),
    deleteTag: vi.fn(),
  },
}))

vi.mock('@/lib/encryption-utils', () => ({
  ENCRYPTION_VERSION: 'v1',
  encryptTextWithStoredKey: vi.fn(),
  decryptText: vi.fn(),
}))

describe('notesStore', () => {
  const mockUser = {
    id: '123',
    email: 'test@example.com',
    name: 'Test User',
    role: 'user' as const,
    isAdmin: false,
    mfaEnabled: false,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }

  const mockNote: Note = {
    id: 'note-1',
    title: 'encrypted-title',
    content: 'encrypted-content',
    userId: '123',
    encrypted: true,
    encryptionVersion: 'v1',
    folderId: null,
    tags: [],
    pinned: false,
    isTrashed: false,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }

  const mockFolder: Folder = {
    id: 'folder-1',
    name: 'Test Folder',
    userId: '123',
    parentId: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }

  const mockTag: Tag = {
    id: 'tag-1',
    name: 'test-tag',
    userId: '123',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }

  beforeEach(() => {
    // Clear store state
    useNotesStore.setState({
      notes: [],
      folders: [],
      tags: [],
      selectedNote: null,
      selectedFolder: null,
      isLoading: false,
    })

    // Clear localStorage
    localStorage.clear()

    // Reset all mocks
    vi.clearAllMocks()

    // Mock console methods to reduce noise
    vi.spyOn(console, 'log').mockImplementation(() => {})
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('Initial state', () => {
    it('should have correct initial state', () => {
      const state = useNotesStore.getState()
      expect(state.notes).toEqual([])
      expect(state.folders).toEqual([])
      expect(state.tags).toEqual([])
      expect(state.selectedNote).toBeNull()
      expect(state.selectedFolder).toBeNull()
      expect(state.isLoading).toBe(false)
    })

    it('should have all required methods', () => {
      const state = useNotesStore.getState()
      expect(typeof state.loadData).toBe('function')
      expect(typeof state.createNote).toBe('function')
      expect(typeof state.updateNote).toBe('function')
      expect(typeof state.deleteNote).toBe('function')
      expect(typeof state.selectNote).toBe('function')
      expect(typeof state.createFolder).toBe('function')
      expect(typeof state.updateFolder).toBe('function')
      expect(typeof state.deleteFolder).toBe('function')
    })
  })

  describe('loadData', () => {
    it('should load notes, folders, and tags successfully', async () => {
      localStorage.setItem('user', JSON.stringify(mockUser))

      vi.mocked(apiClient.getNotes).mockResolvedValue([mockNote])
      vi.mocked(apiClient.getFolders).mockResolvedValue([mockFolder])
      vi.mocked(apiClient.getTags).mockResolvedValue([mockTag])

      await useNotesStore.getState().loadData()

      const state = useNotesStore.getState()
      expect(state.notes).toEqual([mockNote])
      expect(state.folders).toEqual([mockFolder])
      expect(state.tags).toEqual([mockTag])
      expect(state.isLoading).toBe(false)
    })

    it('should not load data if no user is logged in', async () => {
      await useNotesStore.getState().loadData()

      expect(apiClient.getNotes).not.toHaveBeenCalled()
      expect(apiClient.getFolders).not.toHaveBeenCalled()
      expect(apiClient.getTags).not.toHaveBeenCalled()
    })

    it('should handle API errors gracefully', async () => {
      localStorage.setItem('user', JSON.stringify(mockUser))

      vi.mocked(apiClient.getNotes).mockRejectedValue(new Error('API error'))
      vi.mocked(apiClient.getFolders).mockResolvedValue([])
      vi.mocked(apiClient.getTags).mockResolvedValue([])

      await useNotesStore.getState().loadData()

      const state = useNotesStore.getState()
      expect(state.isLoading).toBe(false)
      expect(console.error).toHaveBeenCalled()
    })

    it('should set isLoading state correctly', async () => {
      localStorage.setItem('user', JSON.stringify(mockUser))

      let loadingDuringCall = false

      vi.mocked(apiClient.getNotes).mockImplementation(async () => {
        loadingDuringCall = useNotesStore.getState().isLoading
        return [mockNote]
      })
      vi.mocked(apiClient.getFolders).mockResolvedValue([])
      vi.mocked(apiClient.getTags).mockResolvedValue([])

      await useNotesStore.getState().loadData()

      expect(loadingDuringCall).toBe(true)
      expect(useNotesStore.getState().isLoading).toBe(false)
    })
  })

  describe('createNote', () => {
    beforeEach(() => {
      localStorage.setItem('user', JSON.stringify(mockUser))
    })

    it('should create a note with encryption', async () => {
      const noteInput = {
        title: 'My Note',
        content: 'Note content',
        tags: ['tag1'],
        pinned: false,
      }

      vi.mocked(encryptionUtils.encryptTextWithStoredKey)
        .mockResolvedValueOnce('encrypted-title')
        .mockResolvedValueOnce('encrypted-content')

      vi.mocked(apiClient.createNote).mockResolvedValue(mockNote)

      const createdNote = await useNotesStore.getState().createNote(noteInput)

      expect(encryptionUtils.encryptTextWithStoredKey).toHaveBeenCalledWith('My Note')
      expect(encryptionUtils.encryptTextWithStoredKey).toHaveBeenCalledWith('Note content')
      expect(apiClient.createNote).toHaveBeenCalledWith({
        title: 'encrypted-title',
        content: 'encrypted-content',
        folderId: null,
        tags: ['tag1'],
        pinned: false,
        encrypted: true,
        encryptionVersion: 'v1',
        userId: '123',
      })
      expect(createdNote).toEqual(mockNote)
      expect(useNotesStore.getState().notes).toContain(mockNote)
      expect(useNotesStore.getState().selectedNote).toEqual(mockNote)
    })

    it('should use selected folder when creating note', async () => {
      useNotesStore.setState({ selectedFolder: 'folder-1' })

      vi.mocked(encryptionUtils.encryptTextWithStoredKey)
        .mockResolvedValueOnce('encrypted-title')
        .mockResolvedValueOnce('encrypted-content')

      vi.mocked(apiClient.createNote).mockResolvedValue(mockNote)

      await useNotesStore.getState().createNote({ title: 'Test', content: 'Content' })

      expect(apiClient.createNote).toHaveBeenCalledWith(
        expect.objectContaining({
          folderId: 'folder-1',
        })
      )
    })

    it('should override folder if provided in note input', async () => {
      useNotesStore.setState({ selectedFolder: 'folder-1' })

      vi.mocked(encryptionUtils.encryptTextWithStoredKey)
        .mockResolvedValueOnce('encrypted-title')
        .mockResolvedValueOnce('encrypted-content')

      vi.mocked(apiClient.createNote).mockResolvedValue(mockNote)

      await useNotesStore.getState().createNote({
        title: 'Test',
        content: 'Content',
        folderId: 'folder-2',
      })

      expect(apiClient.createNote).toHaveBeenCalledWith(
        expect.objectContaining({
          folderId: 'folder-2',
        })
      )
    })

    it('should throw error if no user is logged in', async () => {
      localStorage.removeItem('user')

      await expect(useNotesStore.getState().createNote({ title: 'Test' })).rejects.toThrow(
        'No user logged in'
      )
    })

    it('should handle empty title and content', async () => {
      vi.mocked(encryptionUtils.encryptTextWithStoredKey)
        .mockResolvedValueOnce('encrypted-empty')
        .mockResolvedValueOnce('encrypted-empty')

      vi.mocked(apiClient.createNote).mockResolvedValue(mockNote)

      await useNotesStore.getState().createNote({})

      expect(encryptionUtils.encryptTextWithStoredKey).toHaveBeenCalledWith('')
      expect(encryptionUtils.encryptTextWithStoredKey).toHaveBeenCalledTimes(2)
    })
  })

  describe('updateNote', () => {
    beforeEach(() => {
      useNotesStore.setState({ notes: [mockNote] })
    })

    it('should update a note with encryption', async () => {
      const updates = {
        title: 'Updated Title',
        content: 'Updated Content',
      }

      vi.mocked(encryptionUtils.encryptTextWithStoredKey)
        .mockResolvedValueOnce('encrypted-updated-title')
        .mockResolvedValueOnce('encrypted-updated-content')

      const updatedNote = { ...mockNote, ...updates }
      vi.mocked(apiClient.updateNote).mockResolvedValue(updatedNote)

      const result = await useNotesStore.getState().updateNote('note-1', updates)

      expect(encryptionUtils.encryptTextWithStoredKey).toHaveBeenCalledWith('Updated Title')
      expect(encryptionUtils.encryptTextWithStoredKey).toHaveBeenCalledWith('Updated Content')
      expect(apiClient.updateNote).toHaveBeenCalled()
      expect(result).toEqual(updatedNote)
    })

    it('should throw error if note ID is missing', async () => {
      await expect(useNotesStore.getState().updateNote('', {})).rejects.toThrow(
        'Note ID is required'
      )
    })

    it('should throw error if note is not found', async () => {
      await expect(
        useNotesStore.getState().updateNote('non-existent', { title: 'Test' })
      ).rejects.toThrow('Note not found')
    })

    it('should handle updates without encryption for already encrypted content', async () => {
      const updates = {
        title: 'encrypted-already',
        content: 'encrypted-already',
        encrypted: true,
      }

      const updatedNote = { ...mockNote, ...updates }
      vi.mocked(apiClient.updateNote).mockResolvedValue(updatedNote)

      await useNotesStore.getState().updateNote('note-1', updates)

      expect(encryptionUtils.encryptTextWithStoredKey).not.toHaveBeenCalled()
    })

    it('should update note state correctly', async () => {
      const updates = {
        pinned: true,
      }

      const updatedNote = { ...mockNote, pinned: true }
      vi.mocked(apiClient.updateNote).mockResolvedValue(updatedNote)

      await useNotesStore.getState().updateNote('note-1', updates)

      const state = useNotesStore.getState()
      expect(state.notes.find((n) => n.id === 'note-1')?.pinned).toBe(true)
    })

    it('should return current note if no meaningful changes', async () => {
      vi.mocked(apiClient.updateNote).mockResolvedValue(mockNote)

      const result = await useNotesStore.getState().updateNote('note-1', {})

      expect(result).toEqual(mockNote)
    })
  })

  describe('deleteNote', () => {
    beforeEach(() => {
      useNotesStore.setState({ notes: [mockNote], selectedNote: mockNote })
    })

    it('should delete a note successfully', async () => {
      vi.mocked(apiClient.deleteNote).mockResolvedValue(undefined)

      await useNotesStore.getState().deleteNote('note-1')

      expect(apiClient.deleteNote).toHaveBeenCalledWith('note-1')
      expect(useNotesStore.getState().notes).toEqual([])
      expect(useNotesStore.getState().selectedNote).toBeNull()
    })

    it('should not clear selectedNote if deleting different note', async () => {
      const anotherNote = { ...mockNote, id: 'note-2' }
      useNotesStore.setState({ notes: [mockNote, anotherNote], selectedNote: mockNote })

      vi.mocked(apiClient.deleteNote).mockResolvedValue(undefined)

      await useNotesStore.getState().deleteNote('note-2')

      expect(useNotesStore.getState().selectedNote).toEqual(mockNote)
    })

    it('should throw error on API failure', async () => {
      vi.mocked(apiClient.deleteNote).mockRejectedValue(new Error('Delete failed'))

      await expect(useNotesStore.getState().deleteNote('note-1')).rejects.toThrow('Delete failed')
    })
  })

  describe('selectNote', () => {
    beforeEach(() => {
      useNotesStore.setState({ notes: [mockNote, { ...mockNote, id: 'note-2' }] })
    })

    it('should select a note by ID', () => {
      useNotesStore.getState().selectNote('note-1')

      expect(useNotesStore.getState().selectedNote).toEqual(mockNote)
      expect(localStorage.getItem('lastSeenNoteId')).toBe('note-1')
    })

    it('should deselect note when ID is null', () => {
      useNotesStore.setState({ selectedNote: mockNote })

      useNotesStore.getState().selectNote(null)

      expect(useNotesStore.getState().selectedNote).toBeNull()
    })

    it('should not update state if selecting the same note', () => {
      useNotesStore.setState({ selectedNote: mockNote })
      const stateBefore = useNotesStore.getState()

      useNotesStore.getState().selectNote('note-1')

      const stateAfter = useNotesStore.getState()
      expect(stateBefore.selectedNote).toBe(stateAfter.selectedNote)
    })

    it('should handle selecting non-existent note', () => {
      useNotesStore.getState().selectNote('non-existent')

      expect(useNotesStore.getState().selectedNote).toBeNull()
    })

    it('should not save trashed note to lastSeenNoteId', () => {
      const trashedNote = { ...mockNote, isTrashed: true }
      useNotesStore.setState({ notes: [trashedNote] })

      useNotesStore.getState().selectNote(trashedNote.id)

      expect(localStorage.getItem('lastSeenNoteId')).toBeNull()
    })
  })

  describe('createFolder', () => {
    beforeEach(() => {
      localStorage.setItem('user', JSON.stringify(mockUser))
    })

    it('should create a folder successfully', async () => {
      const folderInput = {
        name: 'New Folder',
        parentId: null,
      }

      vi.mocked(apiClient.createFolder).mockResolvedValue(mockFolder)

      const createdFolder = await useNotesStore.getState().createFolder(folderInput)

      expect(apiClient.createFolder).toHaveBeenCalledWith({
        ...folderInput,
        userId: '123',
      })
      expect(createdFolder).toEqual(mockFolder)
      expect(useNotesStore.getState().folders).toContain(mockFolder)
    })

    it('should throw error if no user is logged in', async () => {
      localStorage.removeItem('user')

      await expect(useNotesStore.getState().createFolder({ name: 'Test' })).rejects.toThrow(
        'No user logged in'
      )
    })

    it('should handle API error', async () => {
      vi.mocked(apiClient.createFolder).mockRejectedValue(new Error('Create folder failed'))

      await expect(useNotesStore.getState().createFolder({ name: 'Test' })).rejects.toThrow(
        'Create folder failed'
      )
    })
  })

  describe('selectFolder', () => {
    it('should select a folder by ID', () => {
      useNotesStore.getState().selectFolder('folder-1')

      expect(useNotesStore.getState().selectedFolder).toBe('folder-1')
    })

    it('should deselect folder when ID is null', () => {
      useNotesStore.setState({ selectedFolder: 'folder-1' })

      useNotesStore.getState().selectFolder(null)

      expect(useNotesStore.getState().selectedFolder).toBeNull()
    })
  })
})
