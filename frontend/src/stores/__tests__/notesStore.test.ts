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
    restoreNote: vi.fn(),
    permanentlyDeleteNote: vi.fn(),
    getTrash: vi.fn(),
    createNoteVersion: vi.fn(),
    getNoteVersions: vi.fn(),
    restoreNoteVersion: vi.fn(),
    deleteNoteVersion: vi.fn(),
    compareNoteVersions: vi.fn(),
    updateRetentionPolicy: vi.fn(),
    bulkDeleteNotes: vi.fn(),
    bulkRestoreNotes: vi.fn(),
    bulkPermanentlyDeleteNotes: vi.fn(),
    moveNotesToFolder: vi.fn(),
    addTagsToNotes: vi.fn(),
    removeTagsFromNotes: vi.fn(),
    createNoteLink: vi.fn(),
    getNoteLinks: vi.fn(),
    getNoteBacklinks: vi.fn(),
    deleteNoteLink: vi.fn(),
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
    encryptionVersion: 1,
    folderId: null,
    tags: [],
    pinned: false,
    isTrashed: false,
    sharedWith: [],
    isTemplate: false,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }

  const mockFolder: Folder = {
    id: 'folder-1',
    name: 'Test Folder',
    color: '#3b82f6',
    userId: '123',
    parentId: null,
    createdAt: new Date().toISOString(),
  }

  const mockTag: Tag = {
    id: 'tag-1',
    name: 'test-tag',
    userId: '123',
    color: '#ff0000',
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
    vi.spyOn(console, 'log').mockImplementation(vi.fn())
    vi.spyOn(console, 'error').mockImplementation(vi.fn())
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
        encryptionVersion: encryptionUtils.ENCRYPTION_VERSION,
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

  describe('deleteTag', () => {
    beforeEach(() => {
      const note1 = { ...mockNote, id: 'note-1', tags: ['tag1', 'tag2'] }
      const note2 = { ...mockNote, id: 'note-2', tags: ['tag1'] }
      useNotesStore.setState({ notes: [note1, note2], tags: [mockTag] })
    })

    it('should delete a tag and remove it from all notes', async () => {
      vi.mocked(apiClient.deleteTag).mockResolvedValue(undefined)

      await useNotesStore.getState().deleteTag('tag-1')

      expect(apiClient.deleteTag).toHaveBeenCalledWith('tag-1')
      expect(useNotesStore.getState().tags).toEqual([])
    })

    it('should handle API error', async () => {
      vi.mocked(apiClient.deleteTag).mockRejectedValue(new Error('Delete tag failed'))

      await expect(useNotesStore.getState().deleteTag('tag-1')).rejects.toThrow('Delete tag failed')
    })
  })

  describe('filterByTag', () => {
    beforeEach(() => {
      const note1 = { ...mockNote, id: 'note-1', tags: ['urgent', 'work'] }
      const note2 = { ...mockNote, id: 'note-2', tags: ['personal'] }
      const note3 = { ...mockNote, id: 'note-3', tags: ['urgent'], isTrashed: true }
      useNotesStore.setState({ notes: [note1, note2, note3] })
    })

    it('should filter notes by tag name', () => {
      const result = useNotesStore.getState().filterByTag('urgent')

      expect(result).toHaveLength(1)
      expect(result[0].id).toBe('note-1')
    })

    it('should exclude trashed notes from filter', () => {
      const result = useNotesStore.getState().filterByTag('urgent')

      expect(result.every((n) => !n.isTrashed)).toBe(true)
    })

    it('should return empty array for non-existent tag', () => {
      const result = useNotesStore.getState().filterByTag('non-existent')

      expect(result).toEqual([])
    })
  })

  describe('moveToTrash', () => {
    beforeEach(() => {
      useNotesStore.setState({ notes: [mockNote], selectedNote: mockNote })
    })

    it('should move note to trash', async () => {
      vi.mocked(apiClient.deleteNote).mockResolvedValue(undefined)

      await useNotesStore.getState().moveToTrash('note-1')

      expect(apiClient.deleteNote).toHaveBeenCalledWith('note-1')
      const note = useNotesStore.getState().notes.find((n) => n.id === 'note-1')
      expect(note?.isTrashed).toBe(true)
      expect(note?.trashedAt).toBeDefined()
    })

    it('should clear selectedNote if trashing selected note', async () => {
      vi.mocked(apiClient.deleteNote).mockResolvedValue(undefined)

      await useNotesStore.getState().moveToTrash('note-1')

      expect(useNotesStore.getState().selectedNote).toBeNull()
    })
  })

  describe('restoreFromTrash', () => {
    beforeEach(() => {
      const trashedNote = { ...mockNote, isTrashed: true, trashedAt: new Date().toISOString() }
      useNotesStore.setState({ notes: [trashedNote] })
    })

    it('should restore note from trash', async () => {
      vi.mocked(apiClient.restoreNote).mockResolvedValue(undefined)

      await useNotesStore.getState().restoreFromTrash('note-1')

      expect(apiClient.restoreNote).toHaveBeenCalledWith('note-1')
      const note = useNotesStore.getState().notes.find((n) => n.id === 'note-1')
      expect(note?.isTrashed).toBe(false)
      expect(note?.trashedAt).toBeUndefined()
    })
  })

  describe('emptyTrash', () => {
    beforeEach(() => {
      const trashedNote1 = { ...mockNote, id: 'note-1', isTrashed: true }
      const trashedNote2 = { ...mockNote, id: 'note-2', isTrashed: true }
      const activeNote = { ...mockNote, id: 'note-3', isTrashed: false }
      useNotesStore.setState({ notes: [trashedNote1, trashedNote2, activeNote] })
    })

    it('should permanently delete all trashed notes', async () => {
      vi.mocked(apiClient.permanentlyDeleteNote).mockResolvedValue(undefined)

      await useNotesStore.getState().emptyTrash()

      expect(apiClient.permanentlyDeleteNote).toHaveBeenCalledTimes(2)
      expect(useNotesStore.getState().notes).toHaveLength(1)
      expect(useNotesStore.getState().notes[0].id).toBe('note-3')
    })
  })

  describe('getTrashedNotes', () => {
    it('should get trashed notes from API', async () => {
      const trashedNote = { ...mockNote, isTrashed: true }
      vi.mocked(apiClient.getTrash).mockResolvedValue([trashedNote])

      const result = await useNotesStore.getState().getTrashedNotes()

      expect(apiClient.getTrash).toHaveBeenCalled()
      expect(result).toEqual([trashedNote])
    })

    it('should return empty array on error', async () => {
      vi.mocked(apiClient.getTrash).mockRejectedValue(new Error('API error'))

      const result = await useNotesStore.getState().getTrashedNotes()

      expect(result).toEqual([])
    })
  })

  describe('Note Version Management', () => {
    describe('createNoteVersion', () => {
      beforeEach(() => {
        useNotesStore.setState({ notes: [mockNote] })
      })

      it('should create a note version', async () => {
        const mockVersion = {
          id: 'version-1',
          noteId: 'note-1',
          versionNumber: 1,
          title: mockNote.title,
          content: mockNote.content,
          createdBy: '123',
          changeDescription: 'Initial version',
          createdAt: new Date().toISOString(),
        }
        vi.mocked(apiClient.createNoteVersion).mockResolvedValue(mockVersion)

        const result = await useNotesStore.getState().createNoteVersion('note-1', 'Initial version')

        expect(apiClient.createNoteVersion).toHaveBeenCalledWith({
          noteId: 'note-1',
          title: mockNote.title,
          content: mockNote.content,
          changeDescription: 'Initial version',
        })
        expect(result).toEqual(mockVersion)
      })

      it('should throw error if note not found', async () => {
        await expect(useNotesStore.getState().createNoteVersion('non-existent')).rejects.toThrow(
          'Note not found'
        )
      })
    })

    describe('getNoteVersions', () => {
      it('should get note versions', async () => {
        const versions = [
          { id: 'v1', versionNumber: 1 },
          { id: 'v2', versionNumber: 2 },
        ]
        vi.mocked(apiClient.getNoteVersions).mockResolvedValue(versions as any)

        const result = await useNotesStore.getState().getNoteVersions('note-1')

        expect(apiClient.getNoteVersions).toHaveBeenCalledWith('note-1')
        expect(result).toEqual(versions)
      })

      it('should return empty array on error', async () => {
        vi.mocked(apiClient.getNoteVersions).mockRejectedValue(new Error('API error'))

        const result = await useNotesStore.getState().getNoteVersions('note-1')

        expect(result).toEqual([])
      })
    })

    describe('restoreNoteVersion', () => {
      beforeEach(() => {
        useNotesStore.setState({ notes: [mockNote], selectedNote: mockNote })
      })

      it('should restore a note version', async () => {
        const restoredNote = { ...mockNote, title: 'Restored Title' }
        vi.mocked(apiClient.restoreNoteVersion).mockResolvedValue(restoredNote)

        await useNotesStore.getState().restoreNoteVersion('version-1')

        expect(apiClient.restoreNoteVersion).toHaveBeenCalledWith('version-1')
        expect(useNotesStore.getState().notes[0].title).toBe('Restored Title')
        expect(useNotesStore.getState().selectedNote?.title).toBe('Restored Title')
      })
    })

    describe('deleteNoteVersion', () => {
      it('should delete a note version', async () => {
        vi.mocked(apiClient.deleteNoteVersion).mockResolvedValue(undefined)

        await useNotesStore.getState().deleteNoteVersion('version-1')

        expect(apiClient.deleteNoteVersion).toHaveBeenCalledWith('version-1')
      })
    })

    describe('compareNoteVersions', () => {
      it('should compare two note versions', async () => {
        const comparison = {
          v1: { id: 'v1', versionNumber: 1 } as any,
          v2: { id: 'v2', versionNumber: 2 } as any,
        }
        vi.mocked(apiClient.compareNoteVersions).mockResolvedValue(comparison)

        const result = await useNotesStore.getState().compareNoteVersions('note-1', 1, 2)

        expect(apiClient.compareNoteVersions).toHaveBeenCalledWith('note-1', 1, 2)
        expect(result).toEqual(comparison)
      })
    })
  })

  describe('Bulk Operations', () => {
    beforeEach(() => {
      localStorage.setItem('user', JSON.stringify(mockUser))
    })

    describe('bulkDeleteNotes', () => {
      it('should bulk delete notes', async () => {
        const result = { successful: 2, failed: 0, errors: [] }
        vi.mocked(apiClient.bulkDeleteNotes).mockResolvedValue(result)
        vi.mocked(apiClient.getNotes).mockResolvedValue([])
        vi.mocked(apiClient.getFolders).mockResolvedValue([])
        vi.mocked(apiClient.getTags).mockResolvedValue([])

        const deleteResult = await useNotesStore.getState().bulkDeleteNotes(['note-1', 'note-2'])

        expect(apiClient.bulkDeleteNotes).toHaveBeenCalledWith(['note-1', 'note-2'])
        expect(deleteResult).toEqual(result)
        expect(apiClient.getNotes).toHaveBeenCalled()
      })

      it('should handle bulk delete errors', async () => {
        vi.mocked(apiClient.bulkDeleteNotes).mockRejectedValue(new Error('Bulk delete failed'))

        await expect(
          useNotesStore.getState().bulkDeleteNotes(['note-1', 'note-2'])
        ).rejects.toThrow('Bulk delete failed')
      })
    })

    describe('bulkRestoreNotes', () => {
      it('should bulk restore notes', async () => {
        const result = { successful: 2, failed: 0, errors: [] }
        vi.mocked(apiClient.bulkRestoreNotes).mockResolvedValue(result)
        vi.mocked(apiClient.getNotes).mockResolvedValue([])
        vi.mocked(apiClient.getFolders).mockResolvedValue([])
        vi.mocked(apiClient.getTags).mockResolvedValue([])

        const restoreResult = await useNotesStore.getState().bulkRestoreNotes(['note-1', 'note-2'])

        expect(apiClient.bulkRestoreNotes).toHaveBeenCalledWith(['note-1', 'note-2'])
        expect(restoreResult).toEqual(result)
      })
    })

    describe('bulkPermanentlyDeleteNotes', () => {
      it('should bulk permanently delete notes', async () => {
        const result = { successful: 2, failed: 0, errors: [] }
        vi.mocked(apiClient.bulkPermanentlyDeleteNotes).mockResolvedValue(result)
        vi.mocked(apiClient.getNotes).mockResolvedValue([])
        vi.mocked(apiClient.getFolders).mockResolvedValue([])
        vi.mocked(apiClient.getTags).mockResolvedValue([])

        const deleteResult = await useNotesStore
          .getState()
          .bulkPermanentlyDeleteNotes(['note-1', 'note-2'])

        expect(apiClient.bulkPermanentlyDeleteNotes).toHaveBeenCalledWith(['note-1', 'note-2'])
        expect(deleteResult).toEqual(result)
      })
    })

    describe('moveNotesToFolder', () => {
      beforeEach(() => {
        const note1 = { ...mockNote, id: 'note-1', folderId: null }
        const note2 = { ...mockNote, id: 'note-2', folderId: null }
        useNotesStore.setState({ notes: [note1, note2] })
      })

      it('should move notes to a folder', async () => {
        vi.mocked(apiClient.moveNotesToFolder).mockResolvedValue(undefined)

        await useNotesStore.getState().moveNotesToFolder(['note-1', 'note-2'], 'folder-1')

        expect(apiClient.moveNotesToFolder).toHaveBeenCalledWith(['note-1', 'note-2'], 'folder-1')
        expect(useNotesStore.getState().notes[0].folderId).toBe('folder-1')
        expect(useNotesStore.getState().notes[1].folderId).toBe('folder-1')
      })
    })

    describe('addTagsToNotes', () => {
      beforeEach(() => {
        const note1 = { ...mockNote, id: 'note-1', tags: ['existing'] }
        const note2 = { ...mockNote, id: 'note-2', tags: [] }
        useNotesStore.setState({ notes: [note1, note2] })
      })

      it('should add tags to notes', async () => {
        vi.mocked(apiClient.addTagsToNotes).mockResolvedValue(undefined)

        await useNotesStore.getState().addTagsToNotes(['note-1', 'note-2'], ['new-tag'])

        expect(apiClient.addTagsToNotes).toHaveBeenCalledWith(['note-1', 'note-2'], ['new-tag'])
        expect(useNotesStore.getState().notes[0].tags).toContain('new-tag')
        expect(useNotesStore.getState().notes[1].tags).toContain('new-tag')
      })

      it('should not duplicate existing tags', async () => {
        vi.mocked(apiClient.addTagsToNotes).mockResolvedValue(undefined)

        await useNotesStore.getState().addTagsToNotes(['note-1'], ['existing'])

        const tags = useNotesStore.getState().notes[0].tags
        expect(tags.filter((t) => t === 'existing')).toHaveLength(1)
      })
    })

    describe('removeTagsFromNotes', () => {
      beforeEach(() => {
        const note1 = { ...mockNote, id: 'note-1', tags: ['tag1', 'tag2'] }
        const note2 = { ...mockNote, id: 'note-2', tags: ['tag1'] }
        useNotesStore.setState({ notes: [note1, note2] })
      })

      it('should remove tags from notes', async () => {
        vi.mocked(apiClient.removeTagsFromNotes).mockResolvedValue(undefined)

        await useNotesStore.getState().removeTagsFromNotes(['note-1', 'note-2'], ['tag1'])

        expect(apiClient.removeTagsFromNotes).toHaveBeenCalledWith(['note-1', 'note-2'], ['tag1'])
        expect(useNotesStore.getState().notes[0].tags).not.toContain('tag1')
        expect(useNotesStore.getState().notes[1].tags).not.toContain('tag1')
      })
    })
  })

  describe('updateRetentionPolicy', () => {
    beforeEach(() => {
      useNotesStore.setState({ notes: [mockNote] })
    })

    it('should update note retention policy', async () => {
      vi.mocked(apiClient.updateRetentionPolicy).mockResolvedValue(undefined)

      await useNotesStore.getState().updateRetentionPolicy('note-1', 30)

      expect(apiClient.updateRetentionPolicy).toHaveBeenCalledWith('note-1', 30)
      expect((useNotesStore.getState().notes[0] as any).retentionPolicy).toBe(30)
    })
  })

  describe('Note Links', () => {
    describe('createNoteLink', () => {
      it('should create a note link', async () => {
        const mockLink = { id: 'link-1', sourceNoteId: 'note-1', targetNoteId: 'note-2' }
        vi.mocked(apiClient.createNoteLink).mockResolvedValue(mockLink as any)

        // TODO: createNoteLink not implemented in NotesState
        const result = await apiClient.createNoteLink('note-1', 'note-2', 'Related note')

        expect(apiClient.createNoteLink).toHaveBeenCalledWith('note-1', 'note-2', 'Related note')
        expect(result).toEqual(mockLink)
      })
    })

    describe('getNoteLinks', () => {
      it('should get note links', async () => {
        const links = [{ id: 'link-1' }, { id: 'link-2' }]
        vi.mocked(apiClient.getNoteLinks).mockResolvedValue(links as any)

        // TODO: getNoteLinks not implemented in NotesState
        const result = await apiClient.getNoteLinks('note-1')

        expect(apiClient.getNoteLinks).toHaveBeenCalledWith('note-1')
        expect(result).toEqual(links)
      })
    })

    describe('getNoteBacklinks', () => {
      it('should get note backlinks', async () => {
        const backlinks = [{ id: 'link-1' }, { id: 'link-2' }]
        vi.mocked(apiClient.getNoteBacklinks).mockResolvedValue(backlinks as any)

        // TODO: getNoteBacklinks not implemented in NotesState
        const result = await apiClient.getNoteBacklinks('note-1')

        expect(apiClient.getNoteBacklinks).toHaveBeenCalledWith('note-1')
        expect(result).toEqual(backlinks)
      })
    })

    describe('deleteNoteLink', () => {
      it('should delete a note link', async () => {
        vi.mocked(apiClient.deleteNoteLink).mockResolvedValue(undefined)

        // TODO: deleteNoteLink not implemented in NotesState
        await apiClient.deleteNoteLink('note-1', 'link-1')

        expect(apiClient.deleteNoteLink).toHaveBeenCalledWith('note-1', 'link-1')
      })
    })
  })
})
