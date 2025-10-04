import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { getStoredAuthToken, persistAuthToken, clearStoredAuthToken } from './utils/auth'

// Mock fetch globally
global.fetch = vi.fn()

// Mock localStorage
const localStorageMock = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
}
global.localStorage = localStorageMock

// Mock crypto service
const mockCryptoService = {
  encryptData: vi.fn(),
  decryptData: vi.fn(),
}
global.cryptoService = mockCryptoService

// Create a simplified SecureAPI class for testing
class SecureAPI {
  constructor(baseURL = '/api/v1') {
    this.baseURL = baseURL
    this.token = getStoredAuthToken()
    this.onUnauthorized = null
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers,
    }

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`
    }

    const response = await fetch(url, {
      ...options,
      headers,
      credentials: 'include',
      mode: 'cors',
    })

    if (!response.ok) {
      let errorMessage = `HTTP ${response.status}`
      try {
        const errorData = await response.json()
        errorMessage = errorData.error || errorData.message || errorMessage
      } catch (parseError) {
        // Ignore parse errors
      }

      if (response.status === 401) {
        this.handleUnauthorized()
      }
      throw new Error(errorMessage)
    }

    return await response.json()
  }

  handleUnauthorized() {
    this.clearToken()
    localStorage.removeItem('user_salt')

    if (this.onUnauthorized) {
      this.onUnauthorized()
    }
  }

  setUnauthorizedCallback(callback) {
    this.onUnauthorized = callback
  }

  setToken(token) {
    this.token = token
    persistAuthToken(token)
  }

  clearToken() {
    this.token = null
    clearStoredAuthToken()
  }

  async register(email, password) {
    const response = await this.request('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    })

    if (response.token) {
      this.setToken(response.token)
    }

    return response
  }

  async login(email, password, mfaCode) {
    const response = await this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password, mfa_code: mfaCode }),
    })

    if (response.token) {
      this.setToken(response.token)
    }

    return response
  }

  async createNote(title, content) {
    const encryptedTitle = await global.cryptoService.encryptData(title)
    const encryptedContent = await global.cryptoService.encryptData(JSON.stringify(content))

    return this.request('/notes', {
      method: 'POST',
      body: JSON.stringify({
        title_encrypted: encryptedTitle,
        content_encrypted: encryptedContent,
      }),
    })
  }

  async getNotes() {
    const response = await this.request('/notes')
    const notes = response.notes || response || []

    const decryptedNotes = await Promise.all(
      notes.map(async (note) => {
        try {
          const title = await global.cryptoService.decryptData(note.title_encrypted)
          const content = JSON.parse(await global.cryptoService.decryptData(note.content_encrypted))
          return { ...note, title, content }
        } catch (err) {
          return null
        }
      })
    )

    return decryptedNotes.filter((note) => note !== null)
  }

  async updateNote(noteId, title, content) {
    const encryptedTitle = await global.cryptoService.encryptData(title)
    const encryptedContent = await global.cryptoService.encryptData(JSON.stringify(content))

    return this.request(`/notes/${noteId}`, {
      method: 'PUT',
      body: JSON.stringify({
        title_encrypted: encryptedTitle,
        content_encrypted: encryptedContent,
      }),
    })
  }

  async deleteNote(noteId) {
    return this.request(`/notes/${noteId}`, {
      method: 'DELETE',
    })
  }

  async getTrash() {
    const response = await this.request('/notes/trash')
    const trashedNotes = response.notes || response || []

    const decryptedNotes = await Promise.all(
      trashedNotes.map(async (note) => {
        try {
          const title = await global.cryptoService.decryptData(note.title_encrypted)
          const content = JSON.parse(await global.cryptoService.decryptData(note.content_encrypted))
          return { ...note, title, content }
        } catch (err) {
          return null
        }
      })
    )

    return decryptedNotes.filter((note) => note !== null)
  }

  async restoreNote(noteId) {
    return this.request(`/notes/${noteId}/restore`, {
      method: 'POST',
    })
  }

  async permanentlyDeleteNote(noteId) {
    return this.request(`/notes/${noteId}/permanent`, {
      method: 'DELETE',
    })
  }
}

describe('SecureAPI', () => {
  let api

  beforeEach(() => {
    vi.clearAllMocks()
    localStorageMock.getItem.mockImplementation(() => null)
    api = new SecureAPI()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('Constructor', () => {
    it('should initialize with default baseURL', () => {
      expect(api.baseURL).toBe('/api/v1')
    })

    it('should initialize with custom baseURL', () => {
      const customAPI = new SecureAPI('/custom/api')
      expect(customAPI.baseURL).toBe('/custom/api')
    })

    it('should load token from localStorage', () => {
      localStorageMock.getItem.mockReturnValue('test-token')
      const tokenAPI = new SecureAPI()
      expect(tokenAPI.token).toBe('test-token')
      expect(localStorageMock.getItem).toHaveBeenCalledWith('secure_token')
    })

    it('should migrate legacy auth_token storage', () => {
      localStorageMock.getItem.mockImplementation((key) =>
        key === 'auth_token' ? 'legacy-token' : null
      )

      const tokenAPI = new SecureAPI()

      expect(tokenAPI.token).toBe('legacy-token')
      expect(localStorageMock.setItem).toHaveBeenCalledWith('secure_token', 'legacy-token')
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('auth_token')
    })
  })

  describe('Token Management', () => {
    it('should set token and save to localStorage', () => {
      const token = 'new-test-token'
      api.setToken(token)

      expect(api.token).toBe(token)
      expect(localStorageMock.setItem).toHaveBeenCalledWith('secure_token', token)
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('auth_token')
    })

    it('should clear token and remove from localStorage', () => {
      api.token = 'test-token'
      api.clearToken()

      expect(api.token).toBeNull()
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('secure_token')
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('auth_token')
    })
  })

  describe('Request Method', () => {
    it('should make successful request', async () => {
      const mockResponse = { message: 'success' }
      fetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      })

      const result = await api.request('/test')

      expect(fetch).toHaveBeenCalledWith('/api/v1/test', {
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        mode: 'cors',
      })
      expect(result).toEqual(mockResponse)
    })

    it('should include Authorization header when token exists', async () => {
      api.setToken('test-token')
      fetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({}),
      })

      await api.request('/test')

      expect(fetch).toHaveBeenCalledWith('/api/v1/test', {
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer test-token',
        },
        credentials: 'include',
        mode: 'cors',
      })
    })

    it('should handle HTTP errors', async () => {
      fetch.mockResolvedValue({
        ok: false,
        status: 400,
        json: () => Promise.resolve({ error: 'Bad Request' }),
      })

      await expect(api.request('/test')).rejects.toThrow('Bad Request')
    })

    it('should handle 401 unauthorized', async () => {
      const unauthorizedCallback = vi.fn()
      api.setUnauthorizedCallback(unauthorizedCallback)
      api.setToken('test-token')

      fetch.mockResolvedValue({
        ok: false,
        status: 401,
        json: () => Promise.resolve({ error: 'Unauthorized' }),
      })

      await expect(api.request('/test')).rejects.toThrow('Unauthorized')
      expect(api.token).toBeNull()
      expect(unauthorizedCallback).toHaveBeenCalled()
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('secure_token')
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('auth_token')
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('user_salt')
    })
  })

  describe('Authentication', () => {
    it('should register user successfully', async () => {
      const mockResponse = { token: 'new-token', user_id: '123' }
      fetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      })

      const result = await api.register('test@example.com', 'password123')

      expect(fetch).toHaveBeenCalledWith('/api/v1/auth/register', {
        method: 'POST',
        body: JSON.stringify({ email: 'test@example.com', password: 'password123' }),
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        mode: 'cors',
      })
      expect(result).toEqual(mockResponse)
      expect(api.token).toBe('new-token')
    })

    it('should login user successfully', async () => {
      const mockResponse = { token: 'login-token', user_id: '123' }
      fetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      })

      const result = await api.login('test@example.com', 'password123', '123456')

      expect(fetch).toHaveBeenCalledWith('/api/v1/auth/login', {
        method: 'POST',
        body: JSON.stringify({
          email: 'test@example.com',
          password: 'password123',
          mfa_code: '123456',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        mode: 'cors',
      })
      expect(result).toEqual(mockResponse)
      expect(api.token).toBe('login-token')
    })
  })

  describe('Notes Management', () => {
    beforeEach(() => {
      api.setToken('test-token')
      mockCryptoService.encryptData.mockResolvedValue('encrypted-data')
      mockCryptoService.decryptData.mockImplementation((data) =>
        Promise.resolve(data.replace('encrypted-', ''))
      )
    })

    it('should create note with encryption', async () => {
      const mockResponse = { id: 'note-123', message: 'Created' }
      fetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      })

      const result = await api.createNote('Test Title', 'Test Content')

      expect(mockCryptoService.encryptData).toHaveBeenCalledWith('Test Title')
      expect(mockCryptoService.encryptData).toHaveBeenCalledWith('"Test Content"')
      expect(fetch).toHaveBeenCalledWith('/api/v1/notes', {
        method: 'POST',
        body: JSON.stringify({
          title_encrypted: 'encrypted-data',
          content_encrypted: 'encrypted-data',
        }),
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer test-token',
        },
        credentials: 'include',
        mode: 'cors',
      })
      expect(result).toEqual(mockResponse)
    })

    it('should get and decrypt notes', async () => {
      const mockResponse = {
        notes: [
          {
            id: 'note-1',
            title_encrypted: 'encrypted-title1',
            content_encrypted: 'encrypted-"content1"',
          },
          {
            id: 'note-2',
            title_encrypted: 'encrypted-title2',
            content_encrypted: 'encrypted-"content2"',
          },
        ],
      }
      fetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      })

      const result = await api.getNotes()

      expect(fetch).toHaveBeenCalledWith('/api/v1/notes', expect.any(Object))
      expect(mockCryptoService.decryptData).toHaveBeenCalledTimes(4) // 2 titles + 2 contents
      expect(result).toHaveLength(2)
      expect(result[0]).toEqual({
        id: 'note-1',
        title_encrypted: 'encrypted-title1',
        content_encrypted: 'encrypted-"content1"',
        title: 'title1',
        content: 'content1',
      })
    })

    it('should filter out notes with decryption errors', async () => {
      const mockResponse = {
        notes: [
          {
            id: 'note-1',
            title_encrypted: 'encrypted-title1',
            content_encrypted: 'encrypted-"content1"',
          },
          {
            id: 'note-2',
            title_encrypted: 'invalid-encrypted',
            content_encrypted: 'invalid-encrypted',
          },
        ],
      }
      fetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      })

      // Mock decryption to fail for second note
      mockCryptoService.decryptData
        .mockResolvedValueOnce('title1')
        .mockResolvedValueOnce('"content1"')
        .mockRejectedValueOnce(new Error('Decryption failed'))

      const result = await api.getNotes()

      expect(result).toHaveLength(1)
      expect(result[0].id).toBe('note-1')
    })

    it('should update note with encryption', async () => {
      const mockResponse = { message: 'Updated' }
      fetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      })

      const result = await api.updateNote('note-123', 'Updated Title', 'Updated Content')

      expect(mockCryptoService.encryptData).toHaveBeenCalledWith('Updated Title')
      expect(mockCryptoService.encryptData).toHaveBeenCalledWith('"Updated Content"')
      expect(fetch).toHaveBeenCalledWith('/api/v1/notes/note-123', {
        method: 'PUT',
        body: JSON.stringify({
          title_encrypted: 'encrypted-data',
          content_encrypted: 'encrypted-data',
        }),
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer test-token',
        },
        credentials: 'include',
        mode: 'cors',
      })
      expect(result).toEqual(mockResponse)
    })

    it('should delete note', async () => {
      const mockResponse = { message: 'Deleted' }
      fetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      })

      const result = await api.deleteNote('note-123')

      expect(fetch).toHaveBeenCalledWith('/api/v1/notes/note-123', {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer test-token',
        },
        credentials: 'include',
        mode: 'cors',
      })
      expect(result).toEqual(mockResponse)
    })
  })

  describe('Trash Management', () => {
    beforeEach(() => {
      api.setToken('test-token')
      mockCryptoService.decryptData.mockImplementation((data) =>
        Promise.resolve(data.replace('encrypted-', ''))
      )
    })

    it('should get trash with decryption', async () => {
      const mockResponse = {
        notes: [
          {
            id: 'trash-1',
            title_encrypted: 'encrypted-deleted-title',
            content_encrypted: 'encrypted-"deleted-content"',
            deleted_at: '2023-01-01T00:00:00Z',
          },
        ],
      }
      fetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      })

      const result = await api.getTrash()

      expect(fetch).toHaveBeenCalledWith('/api/v1/notes/trash', expect.any(Object))
      expect(result).toHaveLength(1)
      expect(result[0]).toEqual({
        id: 'trash-1',
        title_encrypted: 'encrypted-deleted-title',
        content_encrypted: 'encrypted-"deleted-content"',
        deleted_at: '2023-01-01T00:00:00Z',
        title: 'deleted-title',
        content: 'deleted-content',
      })
    })

    it('should restore note from trash', async () => {
      const mockResponse = { message: 'Restored' }
      fetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      })

      const result = await api.restoreNote('note-123')

      expect(fetch).toHaveBeenCalledWith('/api/v1/notes/note-123/restore', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer test-token',
        },
        credentials: 'include',
        mode: 'cors',
      })
      expect(result).toEqual(mockResponse)
    })

    it('should permanently delete note from trash', async () => {
      const mockResponse = { message: 'Permanently deleted' }
      fetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      })

      const result = await api.permanentlyDeleteNote('note-123')

      expect(fetch).toHaveBeenCalledWith('/api/v1/notes/note-123/permanent', {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer test-token',
        },
        credentials: 'include',
        mode: 'cors',
      })
      expect(result).toEqual(mockResponse)
    })
  })
})
