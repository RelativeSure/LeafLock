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
