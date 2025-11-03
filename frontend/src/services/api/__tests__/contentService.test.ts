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
  })
})
