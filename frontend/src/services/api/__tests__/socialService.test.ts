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

    it('shares a note with default read permission', async () => {
      const { socialService, requestSpy } = await setupSocialService()
      requestSpy.mockResolvedValue({})

      await socialService.shareNote('note-1', 'user@example.com')

      expect(requestSpy).toHaveBeenCalledWith(
        '/notes/note-1/share',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ user_email: 'user@example.com', permission: 'read' }),
        })
      )
    })

    it('removes a collaborator from a note', async () => {
      const { socialService, requestSpy } = await setupSocialService()
      requestSpy.mockResolvedValue({})

      await socialService.removeCollaborator('note-1', 'user-123')

      expect(requestSpy).toHaveBeenCalledWith(
        '/notes/note-1/collaborators/user-123',
        expect.objectContaining({
          method: 'DELETE',
        })
      )
    })

    it('updates collaborator permission', async () => {
      const { socialService, requestSpy } = await setupSocialService()
      requestSpy.mockResolvedValue({})

      await socialService.updateCollaboratorPermission('note-1', 'user-123', 'write')

      expect(requestSpy).toHaveBeenCalledWith(
        '/notes/note-1/collaborators/user-123',
        expect.objectContaining({
          method: 'PUT',
          body: JSON.stringify({ permission: 'write' }),
        })
      )
    })

    it('retrieves shared notes', async () => {
      const sharedNotes = [
        { id: 'note-1', title: 'Shared Note 1' },
        { id: 'note-2', title: 'Shared Note 2' },
      ]

      const { socialService, requestSpy } = await setupSocialService()
      requestSpy.mockResolvedValue(sharedNotes)

      const result = await socialService.getSharedNotes()

      expect(requestSpy).toHaveBeenCalledWith('/collaborations')
      expect(result).toEqual(sharedNotes)
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

    it('creates a note link without link text', async () => {
      const { socialService, requestSpy } = await setupSocialService()
      requestSpy.mockResolvedValue({ id: 'link-1' })

      const link = await socialService.createNoteLink('note-1', 'note-2')

      expect(requestSpy).toHaveBeenCalledWith(
        '/notes/note-1/links',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ target_note_id: 'note-2', link_text: undefined }),
        })
      )
      expect(link).toEqual({ id: 'link-1' })
    })

    it('retrieves note links', async () => {
      const links = { links: [{ id: 'link-1', target_note_id: 'note-2' }] }

      const { socialService, requestSpy } = await setupSocialService()
      requestSpy.mockResolvedValue(links)

      const result = await socialService.getNoteLinks('note-1')

      expect(requestSpy).toHaveBeenCalledWith('/notes/note-1/links')
      expect(result).toEqual(links)
    })

    it('retrieves note backlinks', async () => {
      const backlinks = { backlinks: [{ id: 'link-1', source_note_id: 'note-2' }] }

      const { socialService, requestSpy } = await setupSocialService()
      requestSpy.mockResolvedValue(backlinks)

      const result = await socialService.getNoteBacklinks('note-1')

      expect(requestSpy).toHaveBeenCalledWith('/notes/note-1/backlinks')
      expect(result).toEqual(backlinks)
    })

    it('deletes a note link', async () => {
      const { socialService, requestSpy } = await setupSocialService()
      requestSpy.mockResolvedValue({})

      await socialService.deleteNoteLink('note-1', 'link-123')

      expect(requestSpy).toHaveBeenCalledWith(
        '/notes/note-1/links/link-123',
        expect.objectContaining({
          method: 'DELETE',
        })
      )
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

    it('retrieves share links for a note', async () => {
      const shareLinks = [
        { token: 'token-1', expiresAt: '2025-01-01' },
        { token: 'token-2', expiresAt: '2025-02-01' },
      ]

      const { socialService, requestSpy } = await setupSocialService()
      requestSpy.mockResolvedValue(shareLinks)

      const result = await socialService.getNoteShareLinks('note-1')

      expect(requestSpy).toHaveBeenCalledWith('/notes/note-1/share-links')
      expect(result).toEqual(shareLinks)
    })

    it('retrieves all share links', async () => {
      const allShareLinks = [
        { token: 'token-1', noteId: 'note-1' },
        { token: 'token-2', noteId: 'note-2' },
      ]

      const { socialService, requestSpy } = await setupSocialService()
      requestSpy.mockResolvedValue(allShareLinks)

      const result = await socialService.getAllShareLinks()

      expect(requestSpy).toHaveBeenCalledWith('/share-links')
      expect(result).toEqual(allShareLinks)
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

    it('updates a share link', async () => {
      const { socialService, requestSpy } = await setupSocialService()
      requestSpy.mockResolvedValue({ token: 'share-token', expiresAt: '2025-12-31' })

      const result = await socialService.updateShareLink('share-token', { expiresAt: '2025-12-31' })

      expect(requestSpy).toHaveBeenCalledWith(
        '/share-links/share-token',
        expect.objectContaining({
          method: 'PUT',
          body: JSON.stringify({ expiresAt: '2025-12-31' }),
        })
      )
      expect(result).toEqual({ token: 'share-token', expiresAt: '2025-12-31' })
    })
  })
})
