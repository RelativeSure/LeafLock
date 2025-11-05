import { describe, it, expect, beforeEach, vi } from 'vitest'

vi.mock('@/lib/config', () => ({
  config: {
    apiUrl: 'http://localhost:8080/api/v1',
  },
}))

const setupContentService = async () => {
  const module = await import('../contentService')
  const requestSpy = vi.spyOn(module.contentService as any, 'request')
  return { contentService: module.contentService, requestSpy }
}

describe('contentService', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('notes', () => {
    it('normalizes note payloads from API', async () => {
      const rawNote = {
        id: 'note-1',
        title_encrypted: 'encrypted-title',
        content_encrypted: 'encrypted-content',
        folder_id: 'folder-1',
        tags: ['work'],
        created_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-01-02T00:00:00Z',
        user_id: 'user-123',
        shared_with: ['user-2'],
        is_template: false,
        trashed_at: null,
        pinned: true,
        encryption_version: 2,
      }

      const { contentService, requestSpy } = await setupContentService()
      requestSpy.mockResolvedValue({ notes: [rawNote] })

      const result = await contentService.getNotes()

      expect(requestSpy).toHaveBeenCalledWith('/notes')
      expect(result).toEqual([
        {
          id: 'note-1',
          title: 'encrypted-title',
          content: 'encrypted-content',
          folderId: 'folder-1',
          tags: ['work'],
          encrypted: true,
          createdAt: '2024-01-01T00:00:00Z',
          updatedAt: '2024-01-02T00:00:00Z',
          userId: 'user-123',
          sharedWith: ['user-2'],
          isTemplate: false,
          isTrashed: false,
          trashedAt: undefined,
          pinned: true,
          encryptionVersion: 2,
        },
      ])
    })

    it('creates a note with encrypted payload properties', async () => {
      const { contentService, requestSpy } = await setupContentService()
      requestSpy.mockResolvedValue({
        note: {
          id: 'note-1',
          title_encrypted: 'encrypted-title',
          content_encrypted: 'encrypted-content',
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
          user_id: 'user-123',
        },
      })

      await contentService.createNote({
        title: 'encrypted-title',
        content: 'encrypted-content',
        folderId: 'folder-1',
        tags: [],
        pinned: false,
        encryptionVersion: 1,
      })

      expect(requestSpy).toHaveBeenCalledWith(
        '/notes',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            title_encrypted: 'encrypted-title',
            content_encrypted: 'encrypted-content',
            folderId: 'folder-1',
            tags: [],
            pinned: false,
            encryption_version: 1,
          }),
        })
      )
    })
  })

  describe('templates', () => {
    it('transforms template response fields', async () => {
      const apiTemplate = {
        id: 'tpl-1',
        name: 'Meeting Notes',
        description: 'Template description',
        content: 'Template',
        tags: ['work'],
        icon: '📝',
        is_public: true,
        user_id: 'user-1',
        created_at: '2024-01-01T00:00:00.000Z',
        updated_at: '2024-01-02T00:00:00.000Z',
        usage_count: 3,
      }

      const { contentService, requestSpy } = await setupContentService()
      requestSpy.mockResolvedValue({ templates: [apiTemplate] })

      const templates = await contentService.getTemplates()

      expect(requestSpy).toHaveBeenCalledWith('/templates')
      expect(templates).toEqual([
        {
          id: 'tpl-1',
          name: 'Meeting Notes',
          description: 'Template description',
          content: 'Template',
          tags: ['work'],
          icon: '📝',
          isPublic: true,
          userId: 'user-1',
          createdAt: '2024-01-01T00:00:00.000Z',
          updatedAt: '2024-01-02T00:00:00.000Z',
          usageCount: 3,
        },
      ])
    })
  })

  describe('trash operations', () => {
    it('gets trashed notes', async () => {
      const { contentService, requestSpy } = await setupContentService()
      requestSpy.mockResolvedValue({
        notes: [
          {
            id: 'note-1',
            title_encrypted: 'trashed',
            content_encrypted: 'content',
            trashed_at: '2024-01-01T00:00:00Z',
          },
        ],
      })

      const result = await contentService.getTrash()

      expect(requestSpy).toHaveBeenCalledWith('/notes/trash')
      expect(result).toHaveLength(1)
      expect(result[0].isTrashed).toBe(true)
    })

    it('restores a note from trash', async () => {
      const { contentService, requestSpy } = await setupContentService()
      requestSpy.mockResolvedValue({})

      await contentService.restoreNote('note-1')

      expect(requestSpy).toHaveBeenCalledWith(
        '/notes/note-1/restore',
        expect.objectContaining({ method: 'POST' })
      )
    })

    it('permanently deletes a note', async () => {
      const { contentService, requestSpy } = await setupContentService()
      requestSpy.mockResolvedValue({})

      await contentService.permanentlyDeleteNote('note-1')

      expect(requestSpy).toHaveBeenCalledWith(
        '/notes/note-1/permanent',
        expect.objectContaining({ method: 'DELETE' })
      )
    })
  })

  describe('search', () => {
    it('searches notes with query', async () => {
      const { contentService, requestSpy } = await setupContentService()
      requestSpy.mockResolvedValue({
        notes: [{ id: 'note-1', title_encrypted: 'result', content_encrypted: 'test' }],
      })

      const result = await contentService.searchNotes('test query')

      expect(requestSpy).toHaveBeenCalledWith('/notes/search?q=test%20query')
      expect(result).toHaveLength(1)
    })
  })

  describe('folders', () => {
    it('gets all folders', async () => {
      const { contentService, requestSpy } = await setupContentService()
      requestSpy.mockResolvedValue({
        folders: [{ id: 'folder-1', name: 'Work', parent_id: null }],
      })

      const result = await contentService.getFolders()

      expect(requestSpy).toHaveBeenCalledWith('/folders')
      expect(result).toEqual([{ id: 'folder-1', name: 'Work', parent_id: null }])
    })

    it('creates a folder', async () => {
      const { contentService, requestSpy } = await setupContentService()
      requestSpy.mockResolvedValue({
        folder: { id: 'folder-1', name: 'New Folder' },
      })

      await contentService.createFolder({ name: 'New Folder' })

      expect(requestSpy).toHaveBeenCalledWith(
        '/folders',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ name: 'New Folder' }),
        })
      )
    })

    it('updates a folder', async () => {
      const { contentService, requestSpy } = await setupContentService()
      requestSpy.mockResolvedValue({
        folder: { id: 'folder-1', name: 'Updated' },
      })

      await contentService.updateFolder('folder-1', { name: 'Updated' })

      expect(requestSpy).toHaveBeenCalledWith(
        '/folders/folder-1',
        expect.objectContaining({
          method: 'PUT',
          body: JSON.stringify({ name: 'Updated' }),
        })
      )
    })

    it('deletes a folder', async () => {
      const { contentService, requestSpy } = await setupContentService()
      requestSpy.mockResolvedValue({})

      await contentService.deleteFolder('folder-1')

      expect(requestSpy).toHaveBeenCalledWith(
        '/folders/folder-1',
        expect.objectContaining({ method: 'DELETE' })
      )
    })

    it('moves note to folder', async () => {
      const { contentService, requestSpy } = await setupContentService()
      requestSpy.mockResolvedValue({})

      await contentService.moveNoteToFolder('note-1', 'folder-1')

      expect(requestSpy).toHaveBeenCalledWith(
        '/notes/note-1/folder',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ folder_id: 'folder-1' }),
        })
      )
    })
  })

  describe('templates', () => {
    it('transforms template response fields', async () => {
      const apiTemplate = {
        id: 'tpl-1',
        name: 'Meeting Notes',
        description: 'Template description',
        content: 'Template',
        tags: ['work'],
        icon: '📝',
        is_public: true,
        user_id: 'user-1',
        created_at: '2024-01-01T00:00:00.000Z',
        updated_at: '2024-01-02T00:00:00.000Z',
        usage_count: 3,
      }

      const { contentService, requestSpy } = await setupContentService()
      requestSpy.mockResolvedValue({ templates: [apiTemplate] })

      const templates = await contentService.getTemplates()

      expect(requestSpy).toHaveBeenCalledWith('/templates')
      expect(templates).toEqual([
        {
          id: 'tpl-1',
          name: 'Meeting Notes',
          description: 'Template description',
          content: 'Template',
          tags: ['work'],
          icon: '📝',
          isPublic: true,
          userId: 'user-1',
          createdAt: '2024-01-01T00:00:00.000Z',
          updatedAt: '2024-01-02T00:00:00.000Z',
          usageCount: 3,
        },
      ])
    })

    it('gets a single template', async () => {
      const { contentService, requestSpy } = await setupContentService()
      requestSpy.mockResolvedValue({
        template: { id: 'tpl-1', name: 'Template', content: 'Body' },
      })

      await contentService.getTemplate('tpl-1')

      expect(requestSpy).toHaveBeenCalledWith('/templates/tpl-1')
    })

    it('creates a template', async () => {
      const { contentService, requestSpy } = await setupContentService()
      requestSpy.mockResolvedValue({
        template: { id: 'tpl-1', name: 'New' },
      })

      await contentService.createTemplate({ name: 'New', content: 'Body' })

      expect(requestSpy).toHaveBeenCalledWith(
        '/templates',
        expect.objectContaining({ method: 'POST' })
      )
    })

    it('updates a template', async () => {
      const { contentService, requestSpy } = await setupContentService()
      requestSpy.mockResolvedValue({
        template: { id: 'tpl-1', name: 'Updated' },
      })

      await contentService.updateTemplate('tpl-1', { name: 'Updated' })

      expect(requestSpy).toHaveBeenCalledWith(
        '/templates/tpl-1',
        expect.objectContaining({ method: 'PUT' })
      )
    })

    it('deletes a template', async () => {
      const { contentService, requestSpy } = await setupContentService()
      requestSpy.mockResolvedValue({})

      await contentService.deleteTemplate('tpl-1')

      expect(requestSpy).toHaveBeenCalledWith(
        '/templates/tpl-1',
        expect.objectContaining({ method: 'DELETE' })
      )
    })

    it('uses a template to create a note', async () => {
      const { contentService, requestSpy } = await setupContentService()
      requestSpy.mockResolvedValue({
        note: { id: 'note-1', title_encrypted: 'From template' },
      })

      await contentService.useTemplate('tpl-1')

      expect(requestSpy).toHaveBeenCalledWith(
        '/templates/tpl-1/use',
        expect.objectContaining({ method: 'POST' })
      )
    })
  })

  describe('note versions', () => {
    it('creates a note version', async () => {
      const { contentService, requestSpy } = await setupContentService()
      requestSpy.mockResolvedValue({ version: { id: 'v-1' } })

      await contentService.createNoteVersion({
        noteId: 'note-1',
        title: 'title',
        content: 'content',
      })

      expect(requestSpy).toHaveBeenCalledWith(
        '/notes/versions',
        expect.objectContaining({ method: 'POST' })
      )
    })

    it('gets note versions', async () => {
      const { contentService, requestSpy } = await setupContentService()
      requestSpy.mockResolvedValue([{ id: 'v-1', note_id: 'note-1' }])

      const result = await contentService.getNoteVersions('note-1')

      expect(requestSpy).toHaveBeenCalledWith('/notes/note-1/versions')
      expect(result).toHaveLength(1)
    })

    it('restores a note version', async () => {
      const { contentService, requestSpy } = await setupContentService()
      requestSpy.mockResolvedValue({
        note: { id: 'note-1', title_encrypted: 'restored' },
      })

      await contentService.restoreNoteVersion('v-1')

      expect(requestSpy).toHaveBeenCalledWith(
        '/notes/versions/v-1/restore',
        expect.objectContaining({ method: 'POST' })
      )
    })

    it('deletes a note version', async () => {
      const { contentService, requestSpy } = await setupContentService()
      requestSpy.mockResolvedValue({})

      await contentService.deleteNoteVersion('v-1')

      expect(requestSpy).toHaveBeenCalledWith(
        '/notes/versions/v-1',
        expect.objectContaining({ method: 'DELETE' })
      )
    })

    it('compares note versions', async () => {
      const { contentService, requestSpy } = await setupContentService()
      requestSpy.mockResolvedValue({
        diff: 'differences',
        v1: { id: 'v-1' },
        v2: { id: 'v-2' },
      })

      await contentService.compareNoteVersions('note-1', 1, 2)

      expect(requestSpy).toHaveBeenCalledWith('/notes/note-1/versions/compare?v1=1&v2=2')
    })
  })

  describe('retention policy', () => {
    it('updates retention policy for a note', async () => {
      const { contentService, requestSpy } = await setupContentService()
      requestSpy.mockResolvedValue({})

      await contentService.updateRetentionPolicy('note-1', 30)

      expect(requestSpy).toHaveBeenCalledWith(
        '/notes/note-1/retention',
        expect.objectContaining({
          method: 'PUT',
          body: JSON.stringify({ retention_policy: 30 }),
        })
      )
    })
  })

  describe('bulk operations', () => {
    it('issues bulk delete request with note ids', async () => {
      const { contentService, requestSpy } = await setupContentService()
      requestSpy.mockResolvedValue({ successful: 2, failed: 0, errors: [] })

      const result = await contentService.bulkDeleteNotes(['note-1', 'note-2'])

      expect(requestSpy).toHaveBeenCalledWith(
        '/notes/bulk/delete',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ note_ids: ['note-1', 'note-2'] }),
        })
      )
      expect(result.successful).toBe(2)
    })

    it('bulk restores notes', async () => {
      const { contentService, requestSpy } = await setupContentService()
      requestSpy.mockResolvedValue({ successful: 2, failed: 0 })

      await contentService.bulkRestoreNotes(['note-1', 'note-2'])

      expect(requestSpy).toHaveBeenCalledWith(
        '/notes/bulk/restore',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ note_ids: ['note-1', 'note-2'] }),
        })
      )
    })

    it('bulk permanently deletes notes', async () => {
      const { contentService, requestSpy } = await setupContentService()
      requestSpy.mockResolvedValue({ successful: 2, failed: 0 })

      await contentService.bulkPermanentlyDeleteNotes(['note-1', 'note-2'])

      expect(requestSpy).toHaveBeenCalledWith(
        '/notes/bulk/permanent-delete',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ note_ids: ['note-1', 'note-2'] }),
        })
      )
    })

    it('moves multiple notes to folder', async () => {
      const { contentService, requestSpy } = await setupContentService()
      requestSpy.mockResolvedValue({})

      await contentService.moveNotesToFolder(['note-1', 'note-2'], 'folder-1')

      expect(requestSpy).toHaveBeenCalledWith(
        '/notes/bulk/move',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            note_ids: ['note-1', 'note-2'],
            folder_id: 'folder-1',
          }),
        })
      )
    })
  })
})
