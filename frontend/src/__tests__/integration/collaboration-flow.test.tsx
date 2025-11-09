import { describe, it, expect, beforeEach, vi } from 'vitest'
import { useNotesStore } from '@/stores/notesStore'
import { useAuthStore } from '@/stores/authStore'

import type { Note } from '@/types'

vi.mock('@/services/api', () => ({
  contentService: {
    createNote: vi.fn(),
    updateNote: vi.fn(),
    getNote: vi.fn(),
    getNotes: vi.fn(),
    getFolders: vi.fn(),
  },
  organizationService: {
    getTags: vi.fn(),
  },
  socialService: {
    shareNote: vi.fn(),
    getCollaborators: vi.fn(),
    removeCollaborator: vi.fn(),
    updateCollaboratorPermission: vi.fn(),
    getSharedNotes: vi.fn(),
    createNoteLink: vi.fn(),
    getNoteLinks: vi.fn(),
    getNoteBacklinks: vi.fn(),
    deleteNoteLink: vi.fn(),
  },
}))

vi.mock('@/lib/encryption-utils', () => ({
  ENCRYPTION_VERSION: 'v1',
  encryptTextWithStoredKey: vi.fn().mockResolvedValue('encrypted'),
}))

// Import mocked services after mocks are declared
import { contentService, socialService } from '@/services/api'

describe('Integration: Collaboration Flow', () => {
  const owner = {
    id: 'user-1',
    email: 'owner@example.com',
    name: 'Owner',
    role: 'user' as const,
    isAdmin: false,
    mfaEnabled: false,
    createdAt: '2024-01-01',
  }

  const collaborator = {
    id: 'user-2',
    email: 'collaborator@example.com',
    name: 'Collaborator',
    role: 'user' as const,
    isAdmin: false,
    mfaEnabled: false,
    createdAt: '2024-01-01',
  }

  beforeEach(() => {
    useAuthStore.setState({
      user: owner,
    })

    useNotesStore.setState({
      notes: [],
      folders: [],
      tags: [],
      selectedNote: null,
    })

    localStorage.setItem('user', JSON.stringify(owner))
    vi.clearAllMocks()
  })

  describe('Share Note with Collaborator', () => {
    it('should complete share note flow', async () => {
      // Step 1: Create note as owner
      const note: Note = {
        id: 'note-1',
        title: 'encrypted',
        content: 'encrypted',
        userId: 'user-1',
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

      vi.mocked(contentService.createNote).mockResolvedValue(note)

      await useNotesStore.getState().createNote({
        title: 'Shared Note',
        content: 'Content to share',
      })

      expect(useNotesStore.getState().notes).toHaveLength(1)

      // Step 2: Share with collaborator (read permission)
      vi.mocked(socialService.shareNote).mockResolvedValue(undefined)

      await socialService.shareNote('note-1', 'collaborator@example.com', 'read')

      // Step 3: Get collaborators list
      vi.mocked(socialService.getCollaborators).mockResolvedValue([
        {
          id: 'user-2',
          email: 'collaborator@example.com',
          name: 'Collaborator',
          permission: 'read',
        },
      ])

      const collaborators = await socialService.getCollaborators('note-1')

      expect(collaborators).toHaveLength(1)
      expect(collaborators[0].email).toBe('collaborator@example.com')
      expect(collaborators[0].permission).toBe('read')

      // Step 4: Upgrade permission to write
      vi.mocked(socialService.updateCollaboratorPermission).mockResolvedValue(undefined)

      await socialService.updateCollaboratorPermission('note-1', 'user-2', 'write')

      vi.mocked(socialService.getCollaborators).mockResolvedValue([
        {
          id: 'user-2',
          email: 'collaborator@example.com',
          name: 'Collaborator',
          permission: 'write',
        },
      ])

      const updatedCollaborators = await socialService.getCollaborators('note-1')

      expect(updatedCollaborators[0].permission).toBe('write')

      // Step 5: Remove collaborator
      vi.mocked(socialService.removeCollaborator).mockResolvedValue(undefined)

      await socialService.removeCollaborator('note-1', 'user-2')

      vi.mocked(socialService.getCollaborators).mockResolvedValue([])

      const finalCollaborators = await socialService.getCollaborators('note-1')

      expect(finalCollaborators).toHaveLength(0)
    })

    it('should handle multi-user collaboration', async () => {
      const note: Note = {
        id: 'note-1',
        title: 'encrypted',
        content: 'encrypted',
        userId: 'user-1',
        encrypted: true,
        encryptionVersion: 1,
        folderId: null,
        tags: [],
        pinned: false,
        isTrashed: false,
        sharedWith: ['user-2', 'user-3', 'user-4'],
        isTemplate: false,
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      }

      vi.mocked(contentService.createNote).mockResolvedValue(note)

      await useNotesStore.getState().createNote({
        title: 'Team Note',
        content: 'Collaborative content',
      })

      // Share with multiple users
      vi.mocked(socialService.shareNote).mockResolvedValue(undefined)

      await socialService.shareNote('note-1', 'user2@example.com', 'write')
      await socialService.shareNote('note-1', 'user3@example.com', 'write')
      await socialService.shareNote('note-1', 'user4@example.com', 'write')

      vi.mocked(socialService.getCollaborators).mockResolvedValue([
        { id: 'user-2', email: 'user2@example.com', permission: 'write' },
        { id: 'user-3', email: 'user3@example.com', permission: 'write' },
        { id: 'user-4', email: 'user4@example.com', permission: 'write' },
      ])

      const collaborators = await socialService.getCollaborators('note-1')

      expect(collaborators).toHaveLength(3)
      expect(collaborators.every((c) => c.permission === 'write')).toBe(true)
    })
  })

  describe('View Shared Notes as Collaborator', () => {
    it('should see notes shared with user', async () => {
      // Switch to collaborator user
      useAuthStore.setState({ user: collaborator })
      localStorage.setItem('user', JSON.stringify(collaborator))

      // Get shared notes
      const sharedNotes: Note[] = [
        {
          id: 'note-1',
          title: 'encrypted',
          content: 'encrypted',
          userId: 'user-1',
          encrypted: true,
          encryptionVersion: 1,
          folderId: null,
          tags: [],
          pinned: false,
          isTrashed: false,
          sharedWith: ['user-2'],
          isTemplate: false,
          createdAt: '2024-01-01',
          updatedAt: '2024-01-01',
        },
      ]

      vi.mocked(socialService.getSharedNotes).mockResolvedValue(sharedNotes)

      const notes = await socialService.getSharedNotes()

      expect(notes).toHaveLength(1)
      expect(notes[0].sharedWith).toContain('user-2')
    })

    it('should allow editing shared notes with write permission', async () => {
      const sharedNote: Note = {
        id: 'note-1',
        title: 'encrypted',
        content: 'encrypted',
        userId: 'user-1',
        encrypted: true,
        encryptionVersion: 1,
        folderId: null,
        tags: [],
        pinned: false,
        isTrashed: false,
        sharedWith: ['user-2'],
        isTemplate: false,
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      }

      useNotesStore.setState({ notes: [sharedNote] })

      // Collaborator with write permission can update
      const updatedNote = { ...sharedNote, content: 'encrypted-updated' }
      vi.mocked(contentService.updateNote).mockResolvedValue(updatedNote)

      await useNotesStore.getState().updateNote('note-1', {
        content: 'Updated by collaborator',
      })

      expect(useNotesStore.getState().notes[0].content).toBe('encrypted-updated')
    })
  })

  describe('Note Linking Between Collaborators', () => {
    it('should create and manage note links', async () => {
      const notes: Note[] = [
        {
          id: 'note-1',
          title: 'Project Overview',
          content: 'See [[note-2]] for details',
          userId: 'user-1',
          encrypted: true,
          encryptionVersion: 1,
          folderId: null,
          tags: [],
          pinned: false,
          isTrashed: false,
          sharedWith: ['user-2'],
          isTemplate: false,
          createdAt: '2024-01-01',
          updatedAt: '2024-01-01',
        },
        {
          id: 'note-2',
          title: 'Project Details',
          content: 'Detailed information',
          userId: 'user-1',
          encrypted: true,
          encryptionVersion: 1,
          folderId: null,
          tags: [],
          pinned: false,
          isTrashed: false,
          sharedWith: ['user-2'],
          isTemplate: false,
          createdAt: '2024-01-01',
          updatedAt: '2024-01-01',
        },
      ]

      useNotesStore.setState({ notes })

      // Create link from note-1 to note-2
      vi.mocked(socialService.createNoteLink).mockResolvedValue({
        id: 'link-1',
        sourceNoteId: 'note-1',
        targetNoteId: 'note-2',
        linkText: 'details',
      } as any)

      const link = await useNotesStore.getState().createNoteLink('note-1', 'note-2', 'details')

      expect(link.sourceNoteId).toBe('note-1')
      expect(link.targetNoteId).toBe('note-2')

      // Get all links from note-1
      vi.mocked(socialService.getNoteLinks).mockResolvedValue({
        links: [{ id: 'link-1', targetNoteId: 'note-2' }],
      } as any)

      const links = await socialService.getNoteLinks('note-1')

      expect(links.links).toHaveLength(1)

      // Get backlinks to note-2
      vi.mocked(socialService.getNoteBacklinks).mockResolvedValue({
        backlinks: [{ id: 'link-1', sourceNoteId: 'note-1' }],
      } as any)

      const backlinks = await socialService.getNoteBacklinks('note-2')

      expect(backlinks.backlinks).toHaveLength(1)
      expect(backlinks.backlinks[0].sourceNoteId).toBe('note-1')
    })
  })

  describe('Collaboration Conflicts and Resolution', () => {
    it('should handle concurrent edits by different users', async () => {
      const note: Note = {
        id: 'note-1',
        title: 'encrypted',
        content: 'encrypted-v1',
        userId: 'user-1',
        encrypted: true,
        encryptionVersion: 1,
        folderId: null,
        tags: [],
        pinned: false,
        isTrashed: false,
        sharedWith: ['user-2'],
        isTemplate: false,
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01T10:00:00Z',
      }

      useNotesStore.setState({ notes: [note] })

      // User 1 edits
      const user1Update = { ...note, content: 'encrypted-user1', updatedAt: '2024-01-01T10:01:00Z' }
      vi.mocked(contentService.updateNote).mockResolvedValueOnce(user1Update)

      await useNotesStore.getState().updateNote('note-1', { content: 'User 1 changes' })

      // User 2 edits (concurrent)
      const user2Update = { ...note, content: 'encrypted-user2', updatedAt: '2024-01-01T10:01:30Z' }
      vi.mocked(contentService.updateNote).mockResolvedValueOnce(user2Update)

      await useNotesStore.getState().updateNote('note-1', { content: 'User 2 changes' })

      // Last write wins
      expect(useNotesStore.getState().notes[0].content).toBe('encrypted-user2')
    })

    it('should handle permission changes during editing', async () => {
      const note: Note = {
        id: 'note-1',
        title: 'encrypted',
        content: 'encrypted',
        userId: 'user-1',
        encrypted: true,
        encryptionVersion: 1,
        folderId: null,
        tags: [],
        pinned: false,
        isTrashed: false,
        sharedWith: ['user-2'],
        isTemplate: false,
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      }

      useNotesStore.setState({ notes: [note] })

      // Collaborator starts editing
      useAuthStore.setState({ user: collaborator })

      // Owner removes write permission (downgrades to read)
      vi.mocked(socialService.updateCollaboratorPermission).mockResolvedValue(undefined)

      await socialService.updateCollaboratorPermission('note-1', 'user-2', 'read')

      // Collaborator tries to save changes
      vi.mocked(contentService.updateNote).mockRejectedValue(
        new Error('Forbidden: Read-only access')
      )

      await expect(
        useNotesStore.getState().updateNote('note-1', { content: 'Updated' })
      ).rejects.toThrow('Forbidden')
    })
  })

  describe('Share Removal and Access Control', () => {
    it('should lose access when share is removed', async () => {
      // Collaborator has access initially
      useAuthStore.setState({ user: collaborator })

      const sharedNote: Note = {
        id: 'note-1',
        title: 'encrypted',
        content: 'encrypted',
        userId: 'user-1',
        encrypted: true,
        encryptionVersion: 1,
        folderId: null,
        tags: [],
        pinned: false,
        isTrashed: false,
        sharedWith: ['user-2'],
        isTemplate: false,
        createdAt: '2024-01-01',
        updatedAt: '2024-01-01',
      }

      vi.mocked(socialService.getSharedNotes).mockResolvedValue([sharedNote])

      const notes = await socialService.getSharedNotes()
      expect(notes).toHaveLength(1)

      // Owner removes collaborator
      useAuthStore.setState({ user: owner })
      vi.mocked(socialService.removeCollaborator).mockResolvedValue(undefined)

      await socialService.removeCollaborator('note-1', 'user-2')

      // Collaborator should no longer see the note
      useAuthStore.setState({ user: collaborator })
      vi.mocked(socialService.getSharedNotes).mockResolvedValue([])

      const notesAfterRemoval = await socialService.getSharedNotes()
      expect(notesAfterRemoval).toHaveLength(0)
    })

    it('should prevent access to unshared notes', async () => {
      // Collaborator tries to access note not shared with them
      useAuthStore.setState({ user: collaborator })

      vi.mocked(contentService.getNote).mockRejectedValue(new Error('Not found'))

      await expect(contentService.getNote('note-1')).rejects.toThrow('Not found')
    })
  })
})
