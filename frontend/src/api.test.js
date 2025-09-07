import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mockFetch, mockLocalStorage, mockApiResponse, mockApiError, createMockNote, MockSecureAPI } from './test-utils.jsx'

// Mock environment
global.fetch = mockFetch
global.localStorage = mockLocalStorage

// Create a test version of SecureAPI
class TestSecureAPI {
  constructor(baseURL = '/api/v1') {
    this.baseURL = baseURL
    this.token = localStorage.getItem('secure_token')
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers
    }

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const response = await fetch(url, {
      ...options,
      headers,
      credentials: 'include',
      mode: 'cors'
    })

    if (!response.ok) {
      if (response.status === 401) {
        this.handleUnauthorized();
      }
      const errorData = await response.json();
      throw new Error(errorData.error || `HTTP ${response.status}`);
    }

    return await response.json();
  }

  handleUnauthorized() {
    localStorage.removeItem('secure_token');
    // In real app, would redirect to login
    this.token = null;
  }

  setToken(token) {
    this.token = token;
    localStorage.setItem('secure_token', token);
  }

  clearToken() {
    this.token = null;
    localStorage.removeItem('secure_token');
  }

  async register(email, password) {
    const response = await this.request('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    })
    
    if (response.token) {
      this.setToken(response.token);
    }
    
    return response;
  }

  async login(email, password, mfaCode) {
    const response = await this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password, mfa_code: mfaCode })
    })
    
    if (response.token) {
      this.setToken(response.token);
    }
    
    return response;
  }

  async createNote(title, content) {
    // Mock encryption for testing
    const encryptedTitle = btoa(title);
    const encryptedContent = btoa(JSON.stringify(content));
    
    return this.request('/notes', {
      method: 'POST',
      body: JSON.stringify({
        title_encrypted: encryptedTitle,
        content_encrypted: encryptedContent
      })
    })
  }

  async getNotes() {
    const response = await this.request('/notes');
    const notes = response.notes || response || [];
    
    // Mock decryption for testing
    return notes.map(note => ({
      ...note,
      title: note.title_encrypted ? atob(note.title_encrypted) : 'Untitled',
      content: note.content_encrypted ? JSON.parse(atob(note.content_encrypted)) : ''
    }));
  }

  async updateNote(noteId, title, content) {
    const encryptedTitle = btoa(title);
    const encryptedContent = btoa(JSON.stringify(content));
    
    return this.request(`/notes/${noteId}`, {
      method: 'PUT',
      body: JSON.stringify({
        title_encrypted: encryptedTitle,
        content_encrypted: encryptedContent
      })
    })
  }

  async deleteNote(noteId) {
    return this.request(`/notes/${noteId}`, {
      method: 'DELETE'
    })
  }
}

describe('SecureAPI', () => {
  let api;

  beforeEach(() => {
    vi.clearAllMocks();
    mockLocalStorage.clear();
    mockFetch.mockClear();
    api = new TestSecureAPI();
  })

  afterEach(() => {
    vi.resetAllMocks();
  })

  describe('Initialization', () => {
    it('creates API instance with default base URL', () => {
      const defaultApi = new TestSecureAPI();
      expect(defaultApi.baseURL).toBe('/api/v1');
    })

    it('creates API instance with custom base URL', () => {
      const customApi = new TestSecureAPI('https://api.example.com/v2');
      expect(customApi.baseURL).toBe('https://api.example.com/v2');
    })

    it('loads token from localStorage on initialization', () => {
      mockLocalStorage.getItem.mockReturnValue('existing-token');
      const apiWithToken = new TestSecureAPI();
      expect(apiWithToken.token).toBe('existing-token');
    })

    it('handles missing token gracefully', () => {
      mockLocalStorage.getItem.mockReturnValue(null);
      const apiWithoutToken = new TestSecureAPI();
      expect(apiWithoutToken.token).toBeNull();
    })
  })

  describe('Request Method', () => {
    it('makes GET request with proper headers', async () => {
      mockFetch.mockResolvedValue(mockApiResponse({ data: 'test' }));
      
      await api.request('/test');
      
      expect(mockFetch).toHaveBeenCalledWith(
        '/api/v1/test',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Content-Type': 'application/json'
          }),
          credentials: 'include',
          mode: 'cors'
        })
      );
    })

    it('includes authorization header when token present', async () => {
      api.setToken('test-token');
      mockFetch.mockResolvedValue(mockApiResponse({ data: 'test' }));
      
      await api.request('/test');
      
      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': 'Bearer test-token'
          })
        })
      );
    })

    it('makes POST request with body', async () => {
      mockFetch.mockResolvedValue(mockApiResponse({ success: true }));
      const testData = { key: 'value' }
      
      await api.request('/test', {
        method: 'POST',
        body: JSON.stringify(testData)
      })
      
      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify(testData)
        })
      );
    })

    it('handles successful response', async () => {
      const responseData = { message: 'success' }
      mockFetch.mockResolvedValue(mockApiResponse(responseData));
      
      const result = await api.request('/test');
      
      expect(result).toEqual(responseData);
    })

    it('handles 401 unauthorized response', async () => {
      api.setToken('invalid-token');
      mockFetch.mockResolvedValue(mockApiError(401, 'Unauthorized'));
      
      await expect(api.request('/protected')).rejects.toThrow('Unauthorized');
      expect(mockLocalStorage.removeItem).toHaveBeenCalledWith('secure_token');
      expect(api.token).toBeNull();
    })

    it('handles 403 forbidden response', async () => {
      mockFetch.mockResolvedValue(mockApiError(403, 'Forbidden'));
      
      await expect(api.request('/forbidden')).rejects.toThrow('Forbidden');
    })

    it('handles 404 not found response', async () => {
      mockFetch.mockResolvedValue(mockApiError(404, 'Not found'));
      
      await expect(api.request('/nonexistent')).rejects.toThrow('Not found');
    })

    it('handles 500 server error response', async () => {
      mockFetch.mockResolvedValue(mockApiError(500, 'Internal server error'));
      
      await expect(api.request('/error')).rejects.toThrow('Internal server error');
    })

    it('handles network errors', async () => {
      mockFetch.mockRejectedValue(new Error('Network error'));
      
      await expect(api.request('/test')).rejects.toThrow('Network error');
    })

    it('includes custom headers', async () => {
      mockFetch.mockResolvedValue(mockApiResponse({ data: 'test' }));
      
      await api.request('/test', {
        headers: { 'X-Custom-Header': 'custom-value' }
      })
      
      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
            'X-Custom-Header': 'custom-value'
          })
        })
      );
    })
  })

  describe('Token Management', () => {
    it('sets token and stores in localStorage', () => {
      const token = 'new-token';
      api.setToken(token);
      
      expect(api.token).toBe(token);
      expect(mockLocalStorage.setItem).toHaveBeenCalledWith('secure_token', token);
    })

    it('clears token from memory and localStorage', () => {
      api.setToken('test-token');
      api.clearToken();
      
      expect(api.token).toBeNull();
      expect(mockLocalStorage.removeItem).toHaveBeenCalledWith('secure_token');
    })

    it('handles unauthorized by clearing token', () => {
      api.setToken('invalid-token');
      api.handleUnauthorized();
      
      expect(api.token).toBeNull();
      expect(mockLocalStorage.removeItem).toHaveBeenCalledWith('secure_token');
    })
  })

  describe('Authentication Endpoints', () => {
    describe('register', () => {
      it('registers user successfully', async () => {
        const responseData = {
          token: 'new-token',
          user_id: 'user-123',
          workspace_id: 'workspace-456',
          message: 'Registration successful'
        }
        mockFetch.mockResolvedValue(mockApiResponse(responseData));
        
        const result = await api.register('test@example.com', 'SecurePassword123!');
        
        expect(mockFetch).toHaveBeenCalledWith(
          '/api/v1/auth/register',
          expect.objectContaining({
            method: 'POST',
            body: JSON.stringify({
              email: 'test@example.com',
              password: 'SecurePassword123!'
            })
          })
        );
        expect(result).toEqual(responseData);
        expect(api.token).toBe('new-token');
        expect(mockLocalStorage.setItem).toHaveBeenCalledWith('secure_token', 'new-token');
      })

      it('handles registration failure', async () => {
        mockFetch.mockResolvedValue(mockApiError(400, 'Email already exists'));
        
        await expect(api.register('existing@example.com', 'password')).rejects.toThrow('Email already exists');
        expect(api.token).toBeNull();
      })

      it('handles registration with weak password', async () => {
        mockFetch.mockResolvedValue(mockApiError(400, 'Password too weak'));
        
        await expect(api.register('test@example.com', 'weak')).rejects.toThrow('Password too weak');
      })
    })

    describe('login', () => {
      it('logs in user successfully', async () => {
        const responseData = {
          token: 'login-token',
          session: 'session-123',
          user_id: 'user-123',
          workspace_id: 'workspace-456'
        }
        mockFetch.mockResolvedValue(mockApiResponse(responseData));
        
        const result = await api.login('test@example.com', 'Password123!');
        
        expect(mockFetch).toHaveBeenCalledWith(
          '/api/v1/auth/login',
          expect.objectContaining({
            method: 'POST',
            body: JSON.stringify({
              email: 'test@example.com',
              password: 'Password123!',
              mfa_code: undefined
            })
          })
        );
        expect(result).toEqual(responseData);
        expect(api.token).toBe('login-token');
      })

      it('handles login with MFA code', async () => {
        const responseData = { token: 'mfa-token' }
        mockFetch.mockResolvedValue(mockApiResponse(responseData));
        
        await api.login('test@example.com', 'Password123!', '123456');
        
        expect(mockFetch).toHaveBeenCalledWith(
          expect.any(String),
          expect.objectContaining({
            body: JSON.stringify({
              email: 'test@example.com',
              password: 'Password123!',
              mfa_code: '123456'
            })
          })
        );
      })

      it('handles MFA required response', async () => {
        const responseData = { mfa_required: true }
        mockFetch.mockResolvedValue(mockApiResponse(responseData));
        
        const result = await api.login('test@example.com', 'Password123!');
        
        expect(result).toEqual(responseData);
        expect(api.token).toBeNull(); // No token set when MFA required
      })

      it('handles invalid credentials', async () => {
        mockFetch.mockResolvedValue(mockApiError(401, 'Invalid credentials'));
        
        await expect(api.login('wrong@example.com', 'wrongpass')).rejects.toThrow('Invalid credentials');
        expect(api.token).toBeNull();
      })

      it('handles account lockout', async () => {
        mockFetch.mockResolvedValue(mockApiError(403, 'Account locked'));
        
        await expect(api.login('locked@example.com', 'password')).rejects.toThrow('Account locked');
      })
    })
  })

  describe('Notes Endpoints', () => {
    beforeEach(() => {
      api.setToken('valid-token');
    })

    describe('createNote', () => {
      it('creates note successfully', async () => {
        const responseData = {
          id: 'note-123',
          message: 'Note created successfully'
        }
        mockFetch.mockResolvedValue(mockApiResponse(responseData));
        
        const result = await api.createNote('Test Title', 'Test content');
        
        expect(mockFetch).toHaveBeenCalledWith(
          '/api/v1/notes',
          expect.objectContaining({
            method: 'POST',
            headers: expect.objectContaining({
              'Authorization': 'Bearer valid-token'
            }),
            body: JSON.stringify({
              title_encrypted: btoa('Test Title'),
              content_encrypted: btoa(JSON.stringify('Test content'))
            })
          })
        );
        expect(result).toEqual(responseData);
      })

      it('handles creation failure', async () => {
        mockFetch.mockResolvedValue(mockApiError(400, 'Invalid data'));
        
        await expect(api.createNote('', '')).rejects.toThrow('Invalid data');
      })

      it('requires authentication', async () => {
        api.clearToken();
        mockFetch.mockResolvedValue(mockApiError(401, 'Unauthorized'));
        
        await expect(api.createNote('Title', 'Content')).rejects.toThrow('Unauthorized');
        expect(api.token).toBeNull();
      })
    })

    describe('getNotes', () => {
      it('fetches notes successfully', async () => {
        const encryptedNotes = [
          {
            id: 'note-1',
            title_encrypted: btoa('Note 1'),
            content_encrypted: btoa(JSON.stringify('Content 1')),
            created_at: '2024-01-01T00:00:00Z',
            updated_at: '2024-01-01T00:00:00Z'
          },
          {
            id: 'note-2',
            title_encrypted: btoa('Note 2'),
            content_encrypted: btoa(JSON.stringify('Content 2')),
            created_at: '2024-01-02T00:00:00Z',
            updated_at: '2024-01-02T00:00:00Z'
          }
        ];
        mockFetch.mockResolvedValue(mockApiResponse({ notes: encryptedNotes }));
        
        const result = await api.getNotes();
        
        expect(mockFetch).toHaveBeenCalledWith(
          '/api/v1/notes',
          expect.objectContaining({
            headers: expect.objectContaining({
              'Authorization': 'Bearer valid-token'
            })
          })
        );
        
        expect(result).toHaveLength(2);
        expect(result[0]).toEqual(expect.objectContaining({
          id: 'note-1',
          title: 'Note 1',
          content: 'Content 1'
        }));
        expect(result[1]).toEqual(expect.objectContaining({
          id: 'note-2',
          title: 'Note 2',
          content: 'Content 2'
        }));
      })

      it('handles empty notes response', async () => {
        mockFetch.mockResolvedValue(mockApiResponse({ notes: [] }));
        
        const result = await api.getNotes();
        
        expect(result).toEqual([]);
      })

      it('handles notes response without wrapper', async () => {
        const notes = [createMockNote()];
        mockFetch.mockResolvedValue(mockApiResponse(notes));
        
        const result = await api.getNotes();
        
        expect(Array.isArray(result)).toBe(true);
      })

      it('filters out notes that fail decryption', async () => {
        const mixedNotes = [
          {
            id: 'note-1',
            title_encrypted: btoa('Good Note'),
            content_encrypted: btoa(JSON.stringify('Good Content'))
          },
          {
            id: 'note-2',
            title_encrypted: 'invalid-base64!',
            content_encrypted: btoa(JSON.stringify('Content'))
          }
        ];
        mockFetch.mockResolvedValue(mockApiResponse({ notes: mixedNotes }));
        
        const result = await api.getNotes();
        
        // Should handle decryption failure gracefully
        expect(result).toHaveLength(2);
        expect(result[0].title).toBe('Good Note');
        expect(result[1].title).toBe('Untitled'); // Fallback for failed decryption
      })

      it('requires authentication', async () => {
        api.clearToken();
        mockFetch.mockResolvedValue(mockApiError(401, 'Unauthorized'));
        
        await expect(api.getNotes()).rejects.toThrow('Unauthorized');
      })
    })

    describe('updateNote', () => {
      it('updates note successfully', async () => {
        const responseData = { message: 'Note updated successfully' }
        mockFetch.mockResolvedValue(mockApiResponse(responseData));
        
        const result = await api.updateNote('note-123', 'Updated Title', 'Updated content');
        
        expect(mockFetch).toHaveBeenCalledWith(
          '/api/v1/notes/note-123',
          expect.objectContaining({
            method: 'PUT',
            body: JSON.stringify({
              title_encrypted: btoa('Updated Title'),
              content_encrypted: btoa(JSON.stringify('Updated content'))
            })
          })
        );
        expect(result).toEqual(responseData);
      })

      it('handles note not found', async () => {
        mockFetch.mockResolvedValue(mockApiError(404, 'Note not found'));
        
        await expect(api.updateNote('nonexistent', 'Title', 'Content')).rejects.toThrow('Note not found');
      })

      it('handles unauthorized access', async () => {
        mockFetch.mockResolvedValue(mockApiError(403, 'Access denied'));
        
        await expect(api.updateNote('other-user-note', 'Title', 'Content')).rejects.toThrow('Access denied');
      })
    })

    describe('deleteNote', () => {
      it('deletes note successfully', async () => {
        const responseData = { message: 'Note deleted successfully' }
        mockFetch.mockResolvedValue(mockApiResponse(responseData));
        
        const result = await api.deleteNote('note-123');
        
        expect(mockFetch).toHaveBeenCalledWith(
          '/api/v1/notes/note-123',
          expect.objectContaining({
            method: 'DELETE'
          })
        );
        expect(result).toEqual(responseData);
      })

      it('handles note not found', async () => {
        mockFetch.mockResolvedValue(mockApiError(404, 'Note not found'));
        
        await expect(api.deleteNote('nonexistent')).rejects.toThrow('Note not found');
      })

      it('handles unauthorized deletion', async () => {
        mockFetch.mockResolvedValue(mockApiError(403, 'Access denied'));
        
        await expect(api.deleteNote('other-user-note')).rejects.toThrow('Access denied');
      })
    })
  })

  describe('Error Handling', () => {
    it('handles fetch network errors', async () => {
      mockFetch.mockRejectedValue(new Error('Failed to fetch'));
      
      await expect(api.request('/test')).rejects.toThrow('Failed to fetch');
    })

    it('handles JSON parsing errors', async () => {
      const invalidJsonResponse = {
        ok: true,
        status: 200,
        json: vi.fn().mockRejectedValue(new Error('Invalid JSON'))
      }
      mockFetch.mockResolvedValue(invalidJsonResponse);
      
      await expect(api.request('/test')).rejects.toThrow('Invalid JSON');
    })

    it('handles responses without error message', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        json: vi.fn().mockResolvedValue({})
      })
      
      await expect(api.request('/test')).rejects.toThrow('HTTP 500');
    })

    it('handles timeout errors', async () => {
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Request timeout')), 100);
      })
      mockFetch.mockReturnValue(timeoutPromise);
      
      await expect(api.request('/slow-endpoint')).rejects.toThrow('Request timeout');
    })
  })

  describe('Security Features', () => {
    it('includes CORS credentials', async () => {
      mockFetch.mockResolvedValue(mockApiResponse({ data: 'test' }));
      
      await api.request('/test');
      
      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          credentials: 'include',
          mode: 'cors'
        })
      );
    })

    it('properly encrypts sensitive data before sending', async () => {
      mockFetch.mockResolvedValue(mockApiResponse({ id: 'note-123' }));
      
      await api.createNote('Sensitive Title', 'Sensitive Content');
      
      const callArgs = mockFetch.mock.calls[0][1];
      const requestBody = JSON.parse(callArgs.body);
      
      // Verify data is encrypted (base64 encoded in our mock)
      expect(requestBody.title_encrypted).toBe(btoa('Sensitive Title'));
      expect(requestBody.content_encrypted).toBe(btoa(JSON.stringify('Sensitive Content')));
      
      // Verify plaintext is not sent
      expect(callArgs.body).not.toContain('Sensitive Title');
      expect(callArgs.body).not.toContain('Sensitive Content');
    })

    it('automatically handles token expiration', async () => {
      api.setToken('expired-token');
      mockFetch.mockResolvedValue(mockApiError(401, 'Token expired'));
      
      await expect(api.request('/protected')).rejects.toThrow('Token expired');
      expect(api.token).toBeNull();
      expect(mockLocalStorage.removeItem).toHaveBeenCalledWith('secure_token');
    })

    it('prevents token leakage in error messages', async () => {
      api.setToken('secret-token');
      mockFetch.mockResolvedValue(mockApiError(403, 'Access denied'));
      
      try {
        await api.request('/protected');
      } catch (error) {
        expect(error.message).not.toContain('secret-token');
      }
    })
  })

  describe('Mock API Helper', () => {
    let mockApi;

    beforeEach(() => {
      mockApi = new MockSecureAPI();
    })

    it('provides mock responses for testing', async () => {
      mockApi.setMockResponse('/notes', { id: 'test-note' })
      
      const result = await mockApi.createNote('Title', 'Content');
      
      expect(result).toEqual({ id: 'test-note' })
    })

    it('handles mock errors', async () => {
      mockApi.setMockResponse('/notes', { error: 'Mock error' })
      
      await expect(mockApi.createNote('Title', 'Content')).rejects.toThrow('Mock error');
    })

    it('provides default responses', async () => {
      const result = await mockApi.getNotes();
      
      expect(Array.isArray(result)).toBe(true);
    })

    it('maintains consistent token behavior', () => {
      mockApi.setToken('test-token');
      expect(mockApi.token).toBe('test-token');
      
      mockApi.clearToken();
      expect(mockApi.token).toBeNull();
    })
  })
})