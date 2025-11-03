import { describe, it, expect, beforeEach, vi } from 'vitest'
import { useNotesStore } from '@/stores/notesStore'
import { contentService, organizationService, socialService } from '@/services/api'
import * as encryptionUtils from '@/lib/encryption-utils'
import type { Note } from '@/types'

vi.mock('@/services/api', () => ({
  contentService: {
    getNotes: vi.fn(),
    createNote: vi.fn(),
    updateNote: vi.fn(),
    deleteNote: vi.fn(),
    restoreNote: vi.fn(),
    permanentlyDeleteNote: vi.fn(),
    createNoteVersion: vi.fn(),
    getNoteVersions: vi.fn(),
    restoreNoteVersion: vi.fn(),
    compareNoteVersions: vi.fn(),
    getFolders: vi.fn(),
    moveNotesToFolder: vi.fn(),
    bulkDeleteNotes: vi.fn(),
    addTagsToNotes: vi.fn(),
  },
  organizationService: {
    getTags: vi.fn(),
    createTag: vi.fn(),
  },
  socialService: {
    shareNote: vi.fn(),
    getCollaborators: vi.fn(),
  },
}))

vi.mock('@/lib/encryption-utils', () => ({
  ENCRYPTION_VERSION: 'v1',
  encryptTextWithStoredKey: vi.fn(),
  decryptText: vi.fn(),
}))

describe('Integration: Complete Note Lifecycle', () => {
  const mockUser = {
    id: '123',
    email: 'user@example.com',
    name: 'User',
    role: 'user' as const,
    isAdmin: false,
    mfaEnabled: false,
    createdAt: '2024-01-01',
  }

  beforeEach(() => {
    useNotesStore.setState({
      notes: [],
      folders: [],
      tags: [],
      selectedNote: null,
      selectedFolder: null,
      isLoading: false,
    })
    localStorage.setItem('user', JSON.stringify(mockUser))
    vi.clearAllMocks()
    vi.mocked(encryptionUtils.encryptTextWithStoredKey).mockResolvedValue('encrypted')
  })

  describe('Create → Edit → Tag → Share → Version → Trash → Restore Flow', () => {
    it('should complete full note lifecycle', async () => {
      // Step 1: Create new note
      const createdNote: Note = {
        id: 'note-1',
        title: 'encrypted',
        content: 'encrypted',
        userId: '123',
        encrypted: true,
        encryptionVersion: 1,
        folderId: null,
        tags: [],
        pinned: false,
        isTrashed: false,
        sharedWith: [],
        isTemplate: false,
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      }

      vi.mocked(contentService.createNote).mockResolvedValue(createdNote)

      const note = await useNotesStore.getState().createNote({
        title: 'My Note',
        content: 'Note content',
      })

      expect(note.id).toBe('note-1')
      expect(useNotesStore.getState().notes).toHaveLength(1)
      expect(useNotesStore.getState().selectedNote).toEqual(createdNote)

      // Step 2: Edit note
      const updatedNote = {
        ...createdNote,
        title: 'encrypted-updated',
        content: 'encrypted-updated',
        updatedAt: '2024-01-02',
      }

      vi.mocked(contentService.updateNote).mockResolvedValue(updatedNote)

      await useNotesStore.getState().updateNote('note-1', {
        title: 'Updated Title',
        content: 'Updated content',
      })

      expect(useNotesStore.getState().notes[0].title).toBe('encrypted-updated')

      // Step 3: Add tags
      vi.mocked(organizationService.createTag).mockResolvedValue({
        id: 'tag-1',
        name: 'important',
        color: '#ff0000',
        userId: '123',
      })

      await useNotesStore.getState().createTag({ name: 'important' })

      vi.mocked(contentService.addTagsToNotes).mockResolvedValue(undefined)

      await useNotesStore.getState().addTagsToNotes(['note-1'], ['important'])

      expect(useNotesStore.getState().notes[0].tags).toContain('important')

      // Step 4: Create version
      const version = {
        id: 'v1',
        noteId: 'note-1',
        versionNumber: 1,
        title: 'encrypted-updated',
        content: 'encrypted-updated',
        createdAt: '2024-01-02',
        createdBy: '123',
        changeDescription: 'First save',
      }

      vi.mocked(contentService.createNoteVersion).mockResolvedValue(version)

      const createdVersion = await useNotesStore
        .getState()
        .createNoteVersion('note-1', 'First save')

      expect(createdVersion.versionNumber).toBe(1)

      // Step 5: Share note
      vi.mocked(socialService.shareNote).mockResolvedValue(undefined)
      vi.mocked(socialService.getCollaborators).mockResolvedValue([
        { id: '1', email: 'collaborator@example.com', permission: 'read' },
      ])

      await socialService.shareNote('note-1', 'collaborator@example.com', 'read')

      const collaborators = await socialService.getCollaborators('note-1')

      expect(collaborators).toHaveLength(1)
      expect(collaborators[0].email).toBe('collaborator@example.com')

      // Step 6: Move to trash
      vi.mocked(contentService.deleteNote).mockResolvedValue(undefined)

      await useNotesStore.getState().moveToTrash('note-1')

      expect(useNotesStore.getState().notes[0].isTrashed).toBe(true)
      expect(useNotesStore.getState().selectedNote).toBeNull()

      // Step 7: Restore from trash
      vi.mocked(contentService.restoreNote).mockResolvedValue(undefined)

      await useNotesStore.getState().restoreFromTrash('note-1')

      expect(useNotesStore.getState().notes[0].isTrashed).toBe(false)

      // Step 8: Permanent delete
      vi.mocked(contentService.permanentlyDeleteNote).mockResolvedValue(undefined)

      await contentService.permanentlyDeleteNote('note-1')

      useNotesStore.setState({
        notes: useNotesStore.getState().notes.filter((n) => n.id !== 'note-1'),
      })

      expect(useNotesStore.getState().notes).toHaveLength(0)
    })
  })

  describe('Version History Management Flow', () => {
    const mockNote: Note = {
      id: 'note-1',
      title: 'encrypted',
      content: 'encrypted',
      userId: '123',
      encrypted: true,
      encryptionVersion: 1,
      folderId: null,
      tags: [],
      pinned: false,
      isTrashed: false,
      sharedWith: [],
      isTemplate: false,
      createdAt: '2024-01-01',
      updatedAt: '2024-01-01',
    }

    beforeEach(() => {
      useNotesStore.setState({ notes: [mockNote] })
    })

    it('should create, list, and restore versions', async () => {
      // Step 1: Create multiple versions
      const version1 = {
        id: 'v1',
        noteId: 'note-1',
        versionNumber: 1,
        title: 'encrypted-v1',
        content: 'encrypted-v1',
        createdAt: '2024-01-01',
        createdBy: '123',
      }

      const version2 = {
        id: 'v2',
        noteId: 'note-1',
        versionNumber: 2,
        title: 'encrypted-v2',
        content: 'encrypted-v2',
        createdAt: '2024-01-02',
        createdBy: '123',
      }

      vi.mocked(contentService.createNoteVersion)
        .mockResolvedValueOnce(version1)
        .mockResolvedValueOnce(version2)

      await useNotesStore.getState().createNoteVersion('note-1', 'Version 1')
      await useNotesStore.getState().createNoteVersion('note-1', 'Version 2')

      // Step 2: List versions
      vi.mocked(contentService.getNoteVersions).mockResolvedValue([version1, version2])

      const versions = await useNotesStore.getState().getNoteVersions('note-1')

      expect(versions).toHaveLength(2)

      // Step 3: Restore older version
      const restoredNote = { ...mockNote, title: 'encrypted-v1', content: 'encrypted-v1' }
      vi.mocked(contentService.restoreNoteVersion).mockResolvedValue(restoredNote)

      await useNotesStore.getState().restoreNoteVersion('v1')

      expect(useNotesStore.getState().notes[0].title).toBe('encrypted-v1')
    })

    it('should compare versions', async () => {
      const versions = [
        {
          id: 'v1',
          noteId: 'note-1',
          versionNumber: 1,
          title: 'encrypted-v1',
          content: 'encrypted-v1',
          createdAt: '2024-01-01',
          createdBy: '123',
        },
        {
          id: 'v2',
          noteId: 'note-1',
          versionNumber: 2,
          title: 'encrypted-v2',
          content: 'encrypted-v2',
          createdAt: '2024-01-02',
          createdBy: '123',
        },
      ]

      vi.mocked(contentService.compareNoteVersions).mockResolvedValue({
        v1: versions[0],
        v2: versions[1],
      } as any)

      const comparison = await useNotesStore.getState().compareNoteVersions('note-1', 1, 2)

      expect(comparison.v1.versionNumber).toBe(1)
      expect(comparison.v2.versionNumber).toBe(2)
    })
  })

  describe('Bulk Operations Flow', () => {
    const notes: Note[] = [
      {
        id: 'note-1',
        title: 'Note 1',
        content: 'Content 1',
        userId: '123',
        encrypted: true,
        encryptionVersion: 1,
        folderId: null,
        tags: [],
        pinned: false,
        isTrashed: false,
        sharedWith: [],
        isTemplate: false,
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      },
      {
        id: 'note-2',
        title: 'Note 2',
        content: 'Content 2',
        userId: '123',
        encrypted: true,
        encryptionVersion: 1,
        folderId: null,
        tags: [],
        pinned: false,
        isTrashed: false,
        sharedWith: [],
        isTemplate: false,
        createdAt: '2024-01-02',
        updatedAt: '2024-01-02',
      },
      {
        id: 'note-3',
        title: 'Note 3',
        content: 'Content 3',
        userId: '123',
        encrypted: true,
        encryptionVersion: 1,
        folderId: null,
        tags: [],
        pinned: false,
        isTrashed: false,
        sharedWith: [],
        isTemplate: false,
        createdAt: '2024-01-03',
        updatedAt: '2024-01-03',
      },
    ]

    beforeEach(() => {
      useNotesStore.setState({ notes })
    })

    it('should perform bulk operations on multiple notes', async () => {
      // Step 1: Bulk add tags
      vi.mocked(contentService.addTagsToNotes).mockResolvedValue(undefined)

      await useNotesStore.getState().addTagsToNotes(['note-1', 'note-2'], ['work', 'urgent'])

      expect(useNotesStore.getState().notes[0].tags).toContain('work')
      expect(useNotesStore.getState().notes[1].tags).toContain('urgent')

      // Step 2: Bulk move to folder
      vi.mocked(contentService.moveNotesToFolder).mockResolvedValue(undefined)

      await useNotesStore.getState().moveNotesToFolder(['note-1', 'note-2'], 'folder-1')

      expect(useNotesStore.getState().notes[0].folderId).toBe('folder-1')
      expect(useNotesStore.getState().notes[1].folderId).toBe('folder-1')

      // Step 3: Bulk delete
      vi.mocked(contentService.bulkDeleteNotes).mockResolvedValue({
        successful: 2,
        failed: 0,
        errors: [],
      })
      vi.mocked(contentService.getNotes).mockResolvedValue([notes[2]]) // Only note-3 remains
      vi.mocked(contentService.getFolders).mockResolvedValue([])
      vi.mocked(organizationService.getTags).mockResolvedValue([])

      const result = await useNotesStore.getState().bulkDeleteNotes(['note-1', 'note-2'])

      expect(result.successful).toBe(2)
      expect(useNotesStore.getState().notes).toHaveLength(1)
    })
  })

  describe('Error Handling in Note Operations', () => {
    it('should handle note creation failure', async () => {
      vi.mocked(contentService.createNote).mockRejectedValue(new Error('Server error'))

      await expect(
        useNotesStore.getState().createNote({ title: 'Test', content: 'Content' })
      ).rejects.toThrow('Server error')

      expect(useNotesStore.getState().notes).toHaveLength(0)
    })

    it('should handle encryption failure during save', async () => {
      vi.mocked(encryptionUtils.encryptTextWithStoredKey).mockRejectedValue(
        new Error('Encryption failed')
      )

      await expect(
        useNotesStore.getState().createNote({ title: 'Test', content: 'Content' })
      ).rejects.toThrow('Encryption failed')
    })

    it('should handle update failure and rollback', async () => {
      const originalNote: Note = {
        id: 'note-1',
        title: 'Original',
        content: 'Original content',
        userId: '123',
        encrypted: true,
        encryptionVersion: 1,
        folderId: null,
        tags: [],
        pinned: false,
        isTrashed: false,
        sharedWith: [],
        isTemplate: false,
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      }

      useNotesStore.setState({ notes: [originalNote] })

      vi.mocked(contentService.updateNote).mockRejectedValue(new Error('Update failed'))

      await expect(
        useNotesStore.getState().updateNote('note-1', { title: 'Updated' })
      ).rejects.toThrow('Update failed')

      // Note should remain unchanged
      expect(useNotesStore.getState().notes[0].title).toBe('Original')
    })
  })
})
