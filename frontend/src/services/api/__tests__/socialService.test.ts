import { describe, it, expect, beforeEach, vi } from 'vitest'

vi.mock('@/lib/config', () => ({
  config: {
    apiUrl: 'http://localhost:8080/api/v1',
  },
}))

const setupSocialService = async () => {
  const module = await import('../socialService')
  const requestSpy = vi.spyOn(module.socialService as any, 'request')
  return { socialService: module.socialService, requestSpy }
}

describe('socialService', () => {
  beforeEach(() => {
    localStorage.clear()
    localStorage.setItem('token', 'test-token')
    vi.clearAllMocks()
  })

  describe('collaboration', () => {
    it('retrieves collaborators for a note', async () => {
      const collaborators = [{ id: '1', email: 'user1@example.com', permission: 'read' }]

      const { socialService, requestSpy } = await setupSocialService()
      requestSpy.mockResolvedValue(collaborators)

      const result = await socialService.getCollaborators('note-1')

      expect(requestSpy).toHaveBeenCalledWith('/notes/note-1/collaborators')
      expect(result).toEqual(collaborators)
    })

    it('shares a note with provided user email and permission', async () => {
      const { socialService, requestSpy } = await setupSocialService()
      requestSpy.mockResolvedValue({})

      await socialService.shareNote('note-1', 'user@example.com', 'write')

      expect(requestSpy).toHaveBeenCalledWith(
        '/notes/note-1/share',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ user_email: 'user@example.com', permission: 'write' }),
        })
      )
    })
  })

  describe('note links', () => {
    it('creates a note link', async () => {
      const { socialService, requestSpy } = await setupSocialService()
      requestSpy.mockResolvedValue({ id: 'link-1' })

      const link = await socialService.createNoteLink('note-1', 'note-2', 'Related note')

      expect(requestSpy).toHaveBeenCalledWith(
        '/notes/note-1/links',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ target_note_id: 'note-2', link_text: 'Related note' }),
        })
      )
      expect(link).toEqual({ id: 'link-1' })
    })
  })

  describe('share links', () => {
    it('creates a share link for a note', async () => {
      const { socialService, requestSpy } = await setupSocialService()
      requestSpy.mockResolvedValue({ token: 'share-token' })

      const link = await socialService.createShareLink('note-1', { expiresAt: '2025-01-01' })

      expect(requestSpy).toHaveBeenCalledWith(
        '/notes/note-1/share-links',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ expiresAt: '2025-01-01' }),
        })
      )
      expect(link).toEqual({ token: 'share-token' })
    })

    it('revokes a share link', async () => {
      const { socialService, requestSpy } = await setupSocialService()
      requestSpy.mockResolvedValue({})

      await socialService.revokeShareLink('share-token')

      expect(requestSpy).toHaveBeenCalledWith(
        '/share-links/share-token',
        expect.objectContaining({ method: 'DELETE' })
      )
    })
  })
})
