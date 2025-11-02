import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import * as navigationUtils from '@/lib/navigation'

vi.mock('@/lib/config', () => ({
  config: {
    apiUrl: 'http://localhost:8080/api/v1',
  },
}))

vi.mock('@/lib/navigation', () => ({
  clearAuthStorage: vi.fn(),
  safeRedirectToLogin: vi.fn(),
  isOnAuthRoute: vi.fn(),
}))

global.fetch = vi.fn()

describe('secureApi - Edge Cases and Error Paths', () => {
  const apiBaseUrl = 'http://localhost:8080/api/v1'

  beforeEach(() => {
    localStorage.clear()
    vi.clearAllMocks()
    vi.mocked(global.fetch).mockReset()
    vi.spyOn(console, 'error').mockImplementation(vi.fn())
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('Network Errors', () => {
    it('should handle network timeout', async () => {
      vi.mocked(global.fetch).mockRejectedValue(new Error('Network timeout'))

      const { apiClient } = await import('../secureApi')

      await expect(apiClient.getNotes()).rejects.toThrow('Network timeout')
    })

    it('should handle connection refused', async () => {
      vi.mocked(global.fetch).mockRejectedValue(new Error('Connection refused'))

      const { apiClient } = await import('../secureApi')

      await expect(apiClient.getNotes()).rejects.toThrow('Connection refused')
    })

    it('should handle DNS failure', async () => {
      vi.mocked(global.fetch).mockRejectedValue(new Error('getaddrinfo ENOTFOUND'))

      const { apiClient } = await import('../secureApi')

      await expect(apiClient.getNotes()).rejects.toThrow()
    })
  })

  describe('HTTP Status Code Handling', () => {
    it('should handle 401 Unauthorized and clear auth', async () => {
      localStorage.setItem('token', 'invalid-token')

      vi.mocked(global.fetch).mockResolvedValue({
        ok: false,
        status: 401,
        json: async () => ({ message: 'Unauthorized' }),
      } as Response)

      const { apiClient } = await import('../secureApi')

      await expect(apiClient.getNotes()).rejects.toThrow()
      expect(navigationUtils.clearAuthStorage).toHaveBeenCalled()
    })

    it('should handle 403 Forbidden', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: false,
        status: 403,
        json: async () => ({ message: 'Forbidden' }),
      } as Response)

      const { apiClient } = await import('../secureApi')

      await expect(apiClient.getNotes()).rejects.toThrow('Forbidden')
    })

    it('should handle 404 Not Found', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: false,
        status: 404,
        json: async () => ({ message: 'Not found' }),
      } as Response)

      const { apiClient } = await import('../secureApi')

      await expect(apiClient.getNote('nonexistent')).rejects.toThrow()
    })

    it('should handle 429 Rate Limit', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: false,
        status: 429,
        json: async () => ({ message: 'Too many requests' }),
      } as Response)

      const { apiClient } = await import('../secureApi')

      await expect(apiClient.getNotes()).rejects.toThrow()
    })

    it('should handle 500 Internal Server Error', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: false,
        status: 500,
        json: async () => ({ message: 'Internal server error' }),
      } as Response)

      const { apiClient } = await import('../secureApi')

      await expect(apiClient.getNotes()).rejects.toThrow()
    })

    it('should handle 503 Service Unavailable', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: false,
        status: 503,
        json: async () => ({ message: 'Service unavailable' }),
      } as Response)

      const { apiClient } = await import('../secureApi')

      await expect(apiClient.getNotes()).rejects.toThrow()
    })
  })

  describe('Malformed Response Handling', () => {
    it('should handle non-JSON response', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => {
          throw new Error('Unexpected token in JSON')
        },
      } as Response)

      const { apiClient } = await import('../secureApi')

      await expect(apiClient.getNotes()).rejects.toThrow()
    })

    it('should handle empty response', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => null,
      } as Response)

      const { apiClient } = await import('../secureApi')

      const result = await apiClient.getNotes()
      expect(result).toBeNull()
    })

    it('should handle missing fields in response', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          // Missing required fields
        }),
      } as Response)

      const { apiClient } = await import('../secureApi')

      const result = await apiClient.login('user@example.com', 'password')
      expect(result).toBeDefined()
    })

    it('should handle unexpected data types', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => 'not an object',
      } as Response)

      const { apiClient } = await import('../secureApi')

      const result = await apiClient.getNotes()
      expect(result).toBe('not an object')
    })
  })

  describe('Request Header Handling', () => {
    it('should include authorization header when token exists', async () => {
      localStorage.setItem('token', 'test-token')

      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ([]),
      } as Response)

      const { apiClient } = await import('../secureApi')

      await apiClient.getNotes()

      expect(global.fetch).toHaveBeenCalledWith(
        `${apiBaseUrl}/notes`,
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: 'Bearer test-token',
          }),
        })
      )
    })

    it('should not include authorization header when no token', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ token: 'new-token', user: {} }),
      } as Response)

      const { apiClient } = await import('../secureApi')

      await apiClient.login('user@example.com', 'password')

      expect(global.fetch).toHaveBeenCalledWith(
        `${apiBaseUrl}/auth/login`,
        expect.objectContaining({
          headers: expect.not.objectContaining({
            Authorization: expect.anything(),
          }),
        })
      )
    })

    it('should refresh token from localStorage before each request', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ([]),
      } as Response)

      const { apiClient } = await import('../secureApi')

      // First request without token
      await apiClient.getNotes()

      // Set token
      localStorage.setItem('token', 'new-token')

      // Second request should use new token
      await apiClient.getNotes()

      expect(global.fetch).toHaveBeenLastCalledWith(
        `${apiBaseUrl}/notes`,
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: 'Bearer new-token',
          }),
        })
      )
    })
  })

  describe('Concurrent Requests', () => {
    it('should handle multiple simultaneous requests', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ([]),
      } as Response)

      const { apiClient } = await import('../secureApi')

      await Promise.all([
        apiClient.getNotes(),
        apiClient.getFolders(),
        apiClient.getTags(),
      ])

      expect(global.fetch).toHaveBeenCalledTimes(3)
    })

    it('should handle race conditions in token refresh', async () => {
      localStorage.setItem('token', 'token-1')

      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ([]),
      } as Response)

      const { apiClient } = await import('../secureApi')

      const requests = [
        apiClient.getNotes(),
        new Promise(resolve => setTimeout(() => {
          localStorage.setItem('token', 'token-2')
          resolve(apiClient.getFolders())
        }, 10)),
      ]

      await Promise.all(requests)

      expect(global.fetch).toHaveBeenCalled()
    })
  })

  describe('Special Characters and Encoding', () => {
    it('should handle special characters in request body', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 201,
        json: async () => ({ id: 'note-1' }),
      } as Response)

      const { apiClient } = await import('../secureApi')

      await apiClient.createNote({
        title: 'Test <script>alert("xss")</script>',
        content: 'Content with émojis 🎉 and ümlaut',
      } as any)

      expect(global.fetch).toHaveBeenCalled()
    })

    it('should handle unicode in note content', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ id: 'note-1' }),
      } as Response)

      const { apiClient } = await import('../secureApi')

      await apiClient.createNote({
        title: '中文标题',
        content: 'Содержание на русском',
      } as any)

      expect(global.fetch).toHaveBeenCalled()
    })

    it('should handle very long strings', async () => {
      const longString = 'a'.repeat(100000)

      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ id: 'note-1' }),
      } as Response)

      const { apiClient } = await import('../secureApi')

      await apiClient.createNote({
        title: 'Title',
        content: longString,
      } as any)

      expect(global.fetch).toHaveBeenCalled()
    })
  })

  describe('Retry and Recovery', () => {
    it('should not auto-retry on failure', async () => {
      vi.mocked(global.fetch).mockRejectedValue(new Error('Network error'))

      const { apiClient } = await import('../secureApi')

      await expect(apiClient.getNotes()).rejects.toThrow('Network error')

      expect(global.fetch).toHaveBeenCalledTimes(1) // No automatic retry
    })

    it('should allow manual retry after failure', async () => {
      vi.mocked(global.fetch)
        .mockRejectedValueOnce(new Error('Network error'))
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ([]),
        } as Response)

      const { apiClient } = await import('../secureApi')

      await expect(apiClient.getNotes()).rejects.toThrow('Network error')
      await expect(apiClient.getNotes()).resolves.toEqual([])
    })
  })

  describe('Edge Case Parameters', () => {
    it('should handle null/undefined parameters', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ id: 'note-1' }),
      } as Response)

      const { apiClient } = await import('../secureApi')

      await apiClient.updateNote('note-1', {
        title: undefined,
        content: null,
      } as any)

      expect(global.fetch).toHaveBeenCalled()
    })

    it('should handle empty arrays', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({}),
      } as Response)

      const { apiClient } = await import('../secureApi')

      await apiClient.bulkDeleteNotes([])

      expect(global.fetch).toHaveBeenCalled()
    })

    it('should handle empty strings', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ token: 'token', user: {} }),
      } as Response)

      const { apiClient } = await import('../secureApi')

      await apiClient.login('', '')

      expect(global.fetch).toHaveBeenCalled()
    })
  })
})
