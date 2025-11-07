import { describe, it, expect, beforeEach, vi } from 'vitest'

vi.mock('@/lib/config', () => ({
  config: {
    apiUrl: 'http://localhost:8080/api/v1',
  },
}))

const setupOrganizationService = async () => {
  const module = await import('../organizationService')
  const requestSpy = vi.spyOn(module.organizationService as any, 'request')
  return { organizationService: module.organizationService, requestSpy }
}

describe('organizationService', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('tags', () => {
    it('loads tags', async () => {
      const mockTags = [
        { id: 'tag-1', name: 'work', color: 'blue', userId: '123' },
        { id: 'tag-2', name: 'personal', color: 'green', userId: '123' },
      ]

      const { organizationService, requestSpy } = await setupOrganizationService()
      requestSpy.mockResolvedValue({ tags: mockTags })

      const tags = await organizationService.getTags()

      expect(requestSpy).toHaveBeenCalledWith('/tags')
      expect(tags).toEqual(mockTags)
    })

    it('creates a tag', async () => {
      const tag = { id: 'tag-1', name: 'urgent', color: 'red', userId: '123' }
      const { organizationService, requestSpy } = await setupOrganizationService()
      requestSpy.mockResolvedValue(tag)

      const result = await organizationService.createTag({ name: 'urgent', color: 'red' })

      expect(requestSpy).toHaveBeenCalledWith(
        '/tags',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ name: 'urgent', color: 'red' }),
        })
      )
      expect(result).toEqual(tag)
    })

    it('assigns a tag to a note', async () => {
      const { organizationService, requestSpy } = await setupOrganizationService()
      requestSpy.mockResolvedValue({})

      await organizationService.assignTagToNote('note-1', 'tag-1')

      expect(requestSpy).toHaveBeenCalledWith(
        '/notes/note-1/tags',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ tag_id: 'tag-1' }),
        })
      )
    })

    it('removes a tag from a note', async () => {
      const { organizationService, requestSpy } = await setupOrganizationService()
      requestSpy.mockResolvedValue({})

      await organizationService.removeTagFromNote('note-2', 'tag-9')

      expect(requestSpy).toHaveBeenCalledWith(
        '/notes/note-2/tags/tag-9',
        expect.objectContaining({
          method: 'DELETE',
        })
      )
    })

    it('deletes a tag', async () => {
      const { organizationService, requestSpy } = await setupOrganizationService()
      requestSpy.mockResolvedValue({})

      await organizationService.deleteTag('tag-42')

      expect(requestSpy).toHaveBeenCalledWith(
        '/tags/tag-42',
        expect.objectContaining({
          method: 'DELETE',
        })
      )
    })

    it('fetches notes for a tag', async () => {
      const notes = [
        { id: 'note-1', title: 'A', content: 'x' },
        { id: 'note-2', title: 'B', content: 'y' },
      ]
      const { organizationService, requestSpy } = await setupOrganizationService()
      requestSpy.mockResolvedValue(notes)

      const result = await organizationService.getNotesByTag('tag-7')

      expect(requestSpy).toHaveBeenCalledWith('/tags/tag-7/notes')
      expect(result).toEqual(notes)
    })
  })

  describe('settings', () => {
    it('loads user settings', async () => {
      const settings = {
        theme: 'dark',
        autoSave: true,
        autoSaveInterval: 30,
        defaultView: 'list',
        notificationsEnabled: true,
        emailNotifications: false,
        encryptionEnabled: true,
        language: 'en',
        defaultNoteBehavior: 'last-seen',
        profilePicture: { type: 'gravatar' },
      }

      const { organizationService, requestSpy } = await setupOrganizationService()
      requestSpy.mockResolvedValue(settings)

      const result = await organizationService.getSettings()

      expect(requestSpy).toHaveBeenCalledWith('/settings')
      expect(result).toEqual(settings)
    })

    it('updates user settings', async () => {
      const change = { theme: 'light' as const }
      const { organizationService, requestSpy } = await setupOrganizationService()
      requestSpy.mockResolvedValue(change)

      const result = await organizationService.updateSettings(change)

      expect(requestSpy).toHaveBeenCalledWith(
        '/settings',
        expect.objectContaining({
          method: 'PUT',
          body: JSON.stringify(change),
        })
      )
      expect(result).toEqual(change)
    })
  })

  describe('health', () => {
    it('performs a health check', async () => {
      const { organizationService, requestSpy } = await setupOrganizationService()
      requestSpy.mockResolvedValue({ status: 'ok' })

      const result = await organizationService.healthCheck()

      expect(requestSpy).toHaveBeenCalledWith('/health')
      expect(result).toEqual({ status: 'ok' })
    })
  })
})
