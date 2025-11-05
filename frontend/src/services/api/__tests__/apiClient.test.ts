import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
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

const jsonHeaders = { 'content-type': 'application/json' }

const buildResponse = (status: number, body: any, ok: boolean = status >= 200 && status < 300) => ({
  ok,
  status,
  headers: new Headers(jsonHeaders),
  json: async () => body,
})

describe('ApiClient', () => {
  const apiBaseUrl = 'http://localhost:8080/api/v1'
  let fetchMock: ReturnType<typeof vi.fn>
  let client: any

  beforeEach(async () => {
    localStorage.clear()
    vi.clearAllMocks()

    fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)

    const { ApiClient } = await import('../apiClient')
    class TestClient extends ApiClient {
      async getNotes() {
        return this.request('/notes')
      }
    }
    client = new TestClient()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  describe('authorization handling', () => {
    it('includes Authorization header when token exists', async () => {
      localStorage.setItem('token', 'token-123')
      fetchMock.mockResolvedValue(buildResponse(200, []))

      await client.getNotes()

      expect(fetchMock).toHaveBeenCalledWith(
        `${apiBaseUrl}/notes`,
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: 'Bearer token-123',
          }),
        })
      )
    })

    it('refreshes token from localStorage before each request', async () => {
      localStorage.setItem('token', 'initial-token')
      fetchMock.mockResolvedValue(buildResponse(200, []))

      await client.getNotes()

      localStorage.setItem('token', 'updated-token')
      fetchMock.mockClear()
      fetchMock.mockResolvedValue(buildResponse(200, []))

      await client.getNotes()

      expect(fetchMock).toHaveBeenCalledWith(
        `${apiBaseUrl}/notes`,
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: 'Bearer updated-token',
          }),
        })
      )
    })
  })

  describe('error handling', () => {
    it('propagates network errors', async () => {
      fetchMock.mockRejectedValue(new Error('Network timeout'))

      await expect(client.getNotes()).rejects.toThrow('Network timeout')
    })

    it('clears auth storage on 401', async () => {
      localStorage.setItem('token', 'token-123')
      localStorage.setItem('user', JSON.stringify({ id: 'user-1' }))
      fetchMock.mockResolvedValue(buildResponse(401, { message: 'Unauthorized' }, false))
      vi.mocked(navigationUtils.isOnAuthRoute).mockReturnValue(false)

      await expect(client.getNotes()).rejects.toThrow('Unauthorized')
      expect(navigationUtils.clearAuthStorage).toHaveBeenCalled()
    })

    it('does not redirect when already on auth route', async () => {
      fetchMock.mockResolvedValue(buildResponse(401, { message: 'Unauthorized' }, false))
      vi.mocked(navigationUtils.isOnAuthRoute).mockReturnValue(true)

      await expect(client.getNotes()).rejects.toThrow('Unauthorized')
      expect(navigationUtils.safeRedirectToLogin).not.toHaveBeenCalled()
    })

    it('propagates backend error messages', async () => {
      fetchMock.mockResolvedValue(buildResponse(404, { message: 'Not found' }, false))

      await expect(client.getNotes()).rejects.toThrow('Not found')
    })

    it('falls back to status code when error message missing', async () => {
      fetchMock.mockResolvedValue(buildResponse(400, {}, false))

      await expect(client.getNotes()).rejects.toThrow('HTTP 400')
    })
  })

  describe('response handling', () => {
    it('returns null for 204 responses', async () => {
      fetchMock.mockResolvedValue({
        ok: true,
        status: 204,
        headers: new Headers(jsonHeaders),
        json: async () => {
          throw new Error('no content')
        },
      })

      const result = await client.getNotes()
      expect(result).toBeNull()
    })

    it('handles non-JSON responses gracefully', async () => {
      fetchMock.mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers({ 'content-type': 'text/plain' }),
        text: async () => 'plain text',
      })

      const result = await client.getNotes()
      expect(result).toBeNull()
    })

    it('returns null when response data is null', async () => {
      fetchMock.mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers(jsonHeaders),
        json: async () => null,
      })

      const result = await client.getNotes()
      expect(result).toBeNull()
    })
  })

  describe('header handling', () => {
    it('merges array headers correctly', async () => {
      const { ApiClient } = await import('../apiClient')
      class TestClient extends ApiClient {
        async testRequest() {
          return this.request('/test', {
            headers: [
              ['X-Custom-Header', 'value1'],
              ['X-Another-Header', 'value2'],
            ] as any,
          })
        }
      }
      const testClient = new TestClient()
      fetchMock.mockResolvedValue(buildResponse(200, { success: true }))

      await testClient.testRequest()

      expect(fetchMock).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'X-Custom-Header': 'value1',
            'X-Another-Header': 'value2',
          }),
        })
      )
    })

    it('merges Headers object correctly', async () => {
      const { ApiClient } = await import('../apiClient')
      class TestClient extends ApiClient {
        async testRequest() {
          const headers = new Headers()
          headers.append('X-Custom-Header', 'value1')
          headers.append('X-Another-Header', 'value2')
          return this.request('/test', { headers })
        }
      }
      const testClient = new TestClient()
      fetchMock.mockResolvedValue(buildResponse(200, { success: true }))

      await testClient.testRequest()

      expect(fetchMock).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'x-custom-header': 'value1',
            'x-another-header': 'value2',
          }),
        })
      )
    })
  })
})
