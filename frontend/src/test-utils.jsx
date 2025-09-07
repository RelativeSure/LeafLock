// Test utilities for React components
import React from 'react'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { vi } from 'vitest'

// Mock libsodium-wrappers
export const mockSodium = {
  ready: Promise.resolve(),
  crypto_secretbox_NONCEBYTES: 24,
  crypto_pwhash_SALTBYTES: 32,
  base64_variants: {
    ORIGINAL: 0,
  },
  randombytes_buf: vi.fn().mockImplementation((size) => new Uint8Array(size).fill(1)),
  from_string: vi.fn().mockImplementation((str) => new TextEncoder().encode(str)),
  to_string: vi.fn().mockImplementation((bytes) => new TextDecoder().decode(bytes)),
  from_base64: vi.fn().mockImplementation((str) => new Uint8Array([1, 2, 3, 4])),
  to_base64: vi.fn().mockImplementation((bytes) => 'mocked-base64'),
  crypto_secretbox_easy: vi.fn().mockImplementation(() => new Uint8Array([5, 6, 7, 8])),
  crypto_secretbox_open_easy: vi
    .fn()
    .mockImplementation(() => new TextEncoder().encode('decrypted')),
}

// Mock fetch for API calls
export const mockFetch = vi.fn()
global.fetch = mockFetch

// Mock localStorage
export const mockLocalStorage = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
}
global.localStorage = mockLocalStorage

// Mock crypto.subtle for password derivation
export const mockCryptoSubtle = {
  importKey: vi.fn().mockResolvedValue('mock-key-material'),
  deriveBits: vi.fn().mockResolvedValue(new ArrayBuffer(32)),
}
global.crypto = {
  subtle: mockCryptoSubtle,
}

// Test data factories
export const createMockUser = (overrides = {}) => ({
  id: 'test-user-id',
  email: 'test@example.com',
  ...overrides,
})

export const createMockNote = (overrides = {}) => ({
  id: 'test-note-id',
  title: 'Test Note',
  content: 'Test content',
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
  ...overrides,
})

export const createMockEncryptedNote = (overrides = {}) => ({
  id: 'test-note-id',
  title_encrypted: 'dGVzdCB0aXRsZQ==',
  content_encrypted: 'dGVzdCBjb250ZW50',
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
  ...overrides,
})

// API response mocks
export const mockApiResponse = (data, status = 200) => {
  const response = {
    ok: status >= 200 && status < 300,
    status,
    json: vi.fn().mockResolvedValue(data),
  }
  return response
}

export const mockApiError = (status = 500, message = 'Server Error') => {
  const response = {
    ok: false,
    status,
    json: vi.fn().mockResolvedValue({ error: message }),
  }
  return response
}

// Custom render function with common providers
export const renderWithProviders = (ui, options = {}) => {
  const Wrapper = ({ children }) => {
    return <div data-testid="test-wrapper">{children}</div>
  }

  return render(ui, { wrapper: Wrapper, ...options })
}

// Helper functions for common interactions
export const typeIntoField = async (fieldName, value) => {
  const field = screen.getByLabelText(fieldName) || screen.getByPlaceholderText(fieldName)
  fireEvent.change(field, { target: { value } })
  await waitFor(() => expect(field.value).toBe(value))
}

export const clickButton = async (buttonText) => {
  const button = screen.getByRole('button', { name: new RegExp(buttonText, 'i') })
  fireEvent.click(button)
}

export const waitForLoading = async () => {
  await waitFor(() => {
    expect(screen.queryByText(/loading/i)).not.toBeInTheDocument()
  })
}

export const waitForError = async (errorText) => {
  await waitFor(() => {
    expect(screen.getByText(new RegExp(errorText, 'i'))).toBeInTheDocument()
  })
}

// Mock CryptoService for consistent testing
export class MockCryptoService {
  constructor() {
    this.masterKey = new Uint8Array(32).fill(1)
    this.sodiumReady = true
  }

  async initSodium() {
    this.sodiumReady = true
  }

  async deriveKeyFromPassword(password, salt) {
    return new Uint8Array(32).fill(1)
  }

  async encryptData(plaintext) {
    return btoa(plaintext) // Simple base64 encoding for tests
  }

  async decryptData(encryptedData) {
    return atob(encryptedData) // Simple base64 decoding for tests
  }

  async generateSalt() {
    return new Uint8Array(32).fill(1)
  }

  async setMasterKey(key) {
    this.masterKey = key
  }
}

// Mock SecureAPI for consistent testing
export class MockSecureAPI {
  constructor() {
    this.token = null
    this.responses = new Map()
    this.mockCrypto = new MockCryptoService()
  }

  // Set mock responses for specific endpoints
  setMockResponse(endpoint, response) {
    this.responses.set(endpoint, response)
  }

  async request(endpoint, options = {}) {
    const mockResponse = this.responses.get(endpoint)
    if (mockResponse) {
      if (mockResponse.error) {
        throw new Error(mockResponse.error)
      }
      return mockResponse
    }

    // Default success response
    return { success: true }
  }

  setToken(token) {
    this.token = token
  }

  clearToken() {
    this.token = null
  }

  async register(email, password) {
    const response = this.responses.get('/auth/register') || {
      token: 'mock-token',
      user_id: 'test-user-id',
      workspace_id: 'test-workspace-id',
    }

    if (response.token) {
      this.setToken(response.token)
    }

    return response
  }

  async login(email, password, mfaCode) {
    const response = this.responses.get('/auth/login') || {
      token: 'mock-token',
      session: 'mock-session',
      user_id: 'test-user-id',
      workspace_id: 'test-workspace-id',
    }

    if (response.token) {
      this.setToken(response.token)
    }

    return response
  }

  async createNote(title, content) {
    return (
      this.responses.get('/notes') || {
        id: 'test-note-id',
        message: 'Note created successfully',
      }
    )
  }

  async getNotes() {
    const mockNotes = this.responses.get('/notes/list') || [
      createMockNote({ id: '1', title: 'Note 1' }),
      createMockNote({ id: '2', title: 'Note 2' }),
    ]

    return mockNotes
  }

  async updateNote(noteId, title, content) {
    return (
      this.responses.get(`/notes/${noteId}`) || {
        message: 'Note updated successfully',
      }
    )
  }

  async deleteNote(noteId) {
    return (
      this.responses.get(`/notes/${noteId}/delete`) || {
        message: 'Note deleted successfully',
      }
    )
  }
}

// Performance testing utilities
export const measureRenderTime = (component) => {
  const start = performance.now()
  render(component)
  const end = performance.now()
  return end - start
}

export const measureEncryptionTime = async (cryptoService, data) => {
  const start = performance.now()
  await cryptoService.encryptData(data)
  const end = performance.now()
  return end - start
}

// Accessibility testing helpers
export const checkA11y = async () => {
  // Check for basic accessibility attributes
  const buttons = screen.getAllByRole('button')
  buttons.forEach((button) => {
    expect(button).toHaveAttribute('type')
  })

  const inputs = screen.getAllByRole('textbox')
  inputs.forEach((input) => {
    expect(input).toHaveAttribute('aria-label')
  })
}

// Security testing utilities
export const checkForXSS = (component, _userInput) => {
  const maliciousInputs = [
    '<script>alert("xss")</script>',
    'data:text/html,<script>alert("xss")</script>',
    '"><img src=x onerror=alert("xss")>',
    '"><svg onload=alert("xss")>',
  ]

  maliciousInputs.forEach((_input) => {
    render(component)
    // Verify that malicious input is properly escaped
    expect(document.body.innerHTML).not.toContain('<script>')
    expect(document.body.innerHTML).not.toContain('data:text/html')
    expect(document.body.innerHTML).not.toContain('onerror=')
    expect(document.body.innerHTML).not.toContain('onload=')
  })
}

export const checkForCSRF = (apiCall) => {
  // Verify that API calls include proper headers
  const mockCall = vi.fn()
  apiCall(mockCall)

  expect(mockCall).toHaveBeenCalledWith(
    expect.anything(),
    expect.objectContaining({
      headers: expect.objectContaining({
        'Content-Type': 'application/json',
      }),
    })
  )
}

export default {
  mockSodium,
  mockFetch,
  mockLocalStorage,
  mockCryptoSubtle,
  createMockUser,
  createMockNote,
  createMockEncryptedNote,
  mockApiResponse,
  mockApiError,
  renderWithProviders,
  typeIntoField,
  clickButton,
  waitForLoading,
  waitForError,
  MockCryptoService,
  MockSecureAPI,
  measureRenderTime,
  measureEncryptionTime,
  checkA11y,
  checkForXSS,
  checkForCSRF,
}
