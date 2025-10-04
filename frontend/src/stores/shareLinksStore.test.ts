import { describe, it, expect, beforeEach, vi } from 'vitest'
import { useShareLinksStore } from './shareLinksStore'

// Mock fetch
global.fetch = vi.fn()

// Mock localStorage
const localStorageMock = {
  getItem: vi.fn(() => 'mock-token'),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
}
global.localStorage = localStorageMock as any

// Mock clipboard API
Object.assign(navigator, {
  clipboard: {
    writeText: vi.fn(() => Promise.resolve()),
  },
})

describe('ShareLinksStore', () => {
  beforeEach(() => {
    // Reset store state
    useShareLinksStore.setState({
      shareLinks: [],
      currentNoteLinks: [],
      isLoading: false,
      error: null,
    })

    // Clear all mocks
    vi.clearAllMocks()
  })

  describe('createShareLink', () => {
    it('should create a share link successfully', async () => {
      const mockResponse = {
        id: 'link-123',
        token: 'test-token-abc',
        note_id: 'note-456',
        permission: 'read',
        share_url: 'https://example.com/share/test-token-abc',
        use_count: 0,
        is_active: true,
        has_password: false,
        created_at: new Date().toISOString(),
      }

      ;(global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      })

      // Mock fetchNoteShareLinks
      ;(global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ share_links: [mockResponse] }),
      })

      const store = useShareLinksStore.getState()
      const result = await store.createShareLink('note-456', {
        permission: 'read',
      })

      expect(result).toEqual(mockResponse)
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/notes/note-456/share-links'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
            'Authorization': 'Bearer mock-token',
          }),
        })
      )
    })

    it('should create a password-protected share link', async () => {
      const mockResponse = {
        id: 'link-123',
        token: 'test-token-protected',
        note_id: 'note-456',
        permission: 'write',
        share_url: 'https://example.com/share/test-token-protected',
        has_password: true,
        use_count: 0,
        is_active: true,
        created_at: new Date().toISOString(),
      }

      ;(global.fetch as any)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => mockResponse,
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ share_links: [mockResponse] }),
        })

      const store = useShareLinksStore.getState()
      const result = await store.createShareLink('note-456', {
        permission: 'write',
        password: 'secure-password',
      })

      expect(result.has_password).toBe(true)
      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          body: expect.stringContaining('"password":"secure-password"'),
        })
      )
    })

    it('should handle errors when creating share link', async () => {
      ;(global.fetch as any).mockResolvedValueOnce({
        ok: false,
        json: async () => ({ error: 'Failed to create link' }),
      })

      const store = useShareLinksStore.getState()

      await expect(
        store.createShareLink('note-456', { permission: 'read' })
      ).rejects.toThrow('Failed to create link')

      const state = useShareLinksStore.getState()
      expect(state.error).toBe('Failed to create link')
    })
  })

  describe('fetchNoteShareLinks', () => {
    it('should fetch share links for a note', async () => {
      const mockLinks = [
        {
          id: 'link-1',
          token: 'token-1',
          note_id: 'note-123',
          permission: 'read',
          use_count: 5,
          is_active: true,
          has_password: false,
          share_url: 'https://example.com/share/token-1',
          created_at: new Date().toISOString(),
        },
        {
          id: 'link-2',
          token: 'token-2',
          note_id: 'note-123',
          permission: 'write',
          use_count: 2,
          is_active: true,
          has_password: true,
          share_url: 'https://example.com/share/token-2',
          created_at: new Date().toISOString(),
        },
      ]

      ;(global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ share_links: mockLinks }),
      })

      const store = useShareLinksStore.getState()
      await store.fetchNoteShareLinks('note-123')

      const state = useShareLinksStore.getState()
      expect(state.currentNoteLinks).toEqual(mockLinks)
      expect(state.isLoading).toBe(false)
    })

    it('should handle empty share links', async () => {
      ;(global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ share_links: [] }),
      })

      const store = useShareLinksStore.getState()
      await store.fetchNoteShareLinks('note-123')

      const state = useShareLinksStore.getState()
      expect(state.currentNoteLinks).toEqual([])
    })
  })

  describe('fetchAllUserLinks', () => {
    it('should fetch all user share links', async () => {
      const mockLinks = [
        {
          id: 'link-1',
          token: 'token-1',
          note_id: 'note-123',
          note_title: 'My Note',
          permission: 'read',
          use_count: 5,
          is_active: true,
          has_password: false,
          share_url: 'https://example.com/share/token-1',
          created_at: new Date().toISOString(),
        },
      ]

      ;(global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ share_links: mockLinks }),
      })

      const store = useShareLinksStore.getState()
      await store.fetchAllUserLinks()

      const state = useShareLinksStore.getState()
      expect(state.shareLinks).toEqual(mockLinks)
      expect(state.isLoading).toBe(false)
    })
  })

  describe('revokeShareLink', () => {
    it('should revoke a share link', async () => {
      const initialLinks = [
        {
          id: 'link-1',
          token: 'token-to-revoke',
          note_id: 'note-123',
          permission: 'read',
          use_count: 0,
          is_active: true,
          has_password: false,
          share_url: 'https://example.com/share/token-to-revoke',
          created_at: new Date().toISOString(),
        },
        {
          id: 'link-2',
          token: 'token-keep',
          note_id: 'note-123',
          permission: 'write',
          use_count: 0,
          is_active: true,
          has_password: false,
          share_url: 'https://example.com/share/token-keep',
          created_at: new Date().toISOString(),
        },
      ]

      useShareLinksStore.setState({
        shareLinks: initialLinks,
        currentNoteLinks: initialLinks,
      })

      ;(global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ message: 'Link revoked' }),
      })

      const store = useShareLinksStore.getState()
      await store.revokeShareLink('token-to-revoke')

      const state = useShareLinksStore.getState()
      expect(state.shareLinks).toHaveLength(1)
      expect(state.shareLinks[0].token).toBe('token-keep')
      expect(state.currentNoteLinks).toHaveLength(1)
    })

    it('should handle revoke errors', async () => {
      ;(global.fetch as any).mockResolvedValueOnce({
        ok: false,
        json: async () => ({ error: 'Link not found' }),
      })

      const store = useShareLinksStore.getState()

      await expect(store.revokeShareLink('invalid-token')).rejects.toThrow(
        'Link not found'
      )
    })
  })

  describe('updateShareLink', () => {
    it('should update a share link', async () => {
      ;(global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ message: 'Link updated' }),
      })

      const store = useShareLinksStore.getState()
      await store.updateShareLink('test-token', {
        permission: 'write',
        expires_in: '7d',
      })

      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/share-links/test-token'),
        expect.objectContaining({
          method: 'PUT',
          body: expect.stringContaining('"permission":"write"'),
        })
      )
    })
  })

  describe('copyLinkToClipboard', () => {
    it('should copy link to clipboard', async () => {
      const store = useShareLinksStore.getState()
      const testUrl = 'https://example.com/share/test-token'

      await store.copyLinkToClipboard(testUrl)

      expect(navigator.clipboard.writeText).toHaveBeenCalledWith(testUrl)
    })

    it('should handle clipboard errors', async () => {
      ;(navigator.clipboard.writeText as any).mockRejectedValueOnce(
        new Error('Clipboard error')
      )

      const store = useShareLinksStore.getState()

      await expect(
        store.copyLinkToClipboard('https://example.com/share/test')
      ).rejects.toThrow('Failed to copy link to clipboard')
    })
  })

  describe('getSharedNote', () => {
    it('should get a shared note without password', async () => {
      const mockNote = {
        id: 'note-123',
        title_encrypted: new Uint8Array([1, 2, 3]),
        content_encrypted: new Uint8Array([4, 5, 6]),
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        permission: 'read',
        shared_by: 'user@example.com',
        is_shared_access: true,
      }

      ;(global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockNote,
      })

      const store = useShareLinksStore.getState()
      const result = await store.getSharedNote('test-token')

      expect(result).toMatchObject({
        id: 'note-123',
        permission: 'read',
        shared_by: 'user@example.com',
      })
    })

    it('should get a shared note with password', async () => {
      const mockNote = {
        id: 'note-123',
        title_encrypted: new Uint8Array([1, 2, 3]),
        content_encrypted: new Uint8Array([4, 5, 6]),
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        permission: 'read',
        shared_by: 'user@example.com',
        is_shared_access: true,
      }

      ;(global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockNote,
      })

      const store = useShareLinksStore.getState()
      const result = await store.getSharedNote('test-token', 'password123')

      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'X-Share-Password': 'password123',
          }),
        })
      )
      expect(result).toBeDefined()
    })

    it('should handle shared note access errors', async () => {
      ;(global.fetch as any).mockResolvedValueOnce({
        ok: false,
        json: async () => ({ error: 'Link expired' }),
      })

      const store = useShareLinksStore.getState()

      await expect(store.getSharedNote('expired-token')).rejects.toThrow(
        'Link expired'
      )
    })
  })

  describe('loading and error states', () => {
    it('should set loading state during operations', async () => {
      ;(global.fetch as any).mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            setTimeout(
              () =>
                resolve({
                  ok: true,
                  json: async () => ({ share_links: [] }),
                }),
              100
            )
          })
      )

      const store = useShareLinksStore.getState()
      const promise = store.fetchNoteShareLinks('note-123')

      // Check loading state
      let state = useShareLinksStore.getState()
      expect(state.isLoading).toBe(true)

      await promise

      // Check loading state after completion
      state = useShareLinksStore.getState()
      expect(state.isLoading).toBe(false)
    })

    it('should clear error on successful operation', async () => {
      // Set initial error state
      useShareLinksStore.setState({ error: 'Previous error' })

      ;(global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ share_links: [] }),
      })

      const store = useShareLinksStore.getState()
      await store.fetchNoteShareLinks('note-123')

      const state = useShareLinksStore.getState()
      expect(state.error).toBe(null)
    })
  })

  describe('authentication', () => {
    it('should throw error when no auth token', async () => {
      localStorageMock.getItem.mockReturnValueOnce(null)

      const store = useShareLinksStore.getState()

      await expect(
        store.createShareLink('note-123', { permission: 'read' })
      ).rejects.toThrow('No authentication token')
    })

    it('should include auth token in all requests', async () => {
      ;(global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ share_links: [] }),
      })

      const store = useShareLinksStore.getState()
      await store.fetchNoteShareLinks('note-123')

      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: 'Bearer mock-token',
          }),
        })
      )
    })
  })
})
