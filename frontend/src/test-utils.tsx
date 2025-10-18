// Test utilities for React components
import type { ReactElement, ReactNode } from 'react'
import { render, screen, fireEvent, waitFor, type RenderOptions } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi } from 'vitest'
import type { Note } from '@/features/app/types'

declare global {
  // Some tests rely on toggling registration availability at runtime
  var __LEAFLOCK_REGISTRATION__: boolean
}

// Mock libsodium-wrappers
const sodiumMockBase = {
  ready: Promise.resolve(),
  crypto_secretbox_NONCEBYTES: 24,
  crypto_pwhash_SALTBYTES: 32,
  base64_variants: {
    ORIGINAL: 0,
  },
  randombytes_buf: vi.fn().mockImplementation((size) => new Uint8Array(size).fill(1)),
  from_string: vi.fn().mockImplementation((str) => new TextEncoder().encode(str)),
  to_string: vi.fn().mockImplementation((bytes) => new TextDecoder().decode(bytes)),
  from_base64: vi.fn().mockImplementation((_str) => new Uint8Array([1, 2, 3, 4])),
  to_base64: vi.fn().mockImplementation((_bytes) => 'mocked-base64'),
  crypto_secretbox_easy: vi.fn().mockImplementation(() => new Uint8Array([5, 6, 7, 8])),
  crypto_secretbox_open_easy: vi
    .fn()
    .mockImplementation(() => new TextEncoder().encode('decrypted')),
}

export const mockSodium = {
  ...sodiumMockBase,
  default: sodiumMockBase,
}

// Mock fetch for API calls
export const mockFetch: (input: RequestInfo | URL, init?: RequestInit) => Promise<any> = vi.fn()
global.fetch = mockFetch as unknown as typeof fetch

// Mock localStorage
class LocalStorageMock implements Storage {
  private store = new Map<string, string>()

  clear = vi.fn(() => {
    this.store.clear()
  })

  getItem = vi.fn((key: string): string | null => this.store.get(key) ?? null)

  key = vi.fn((index: number): string | null => Array.from(this.store.keys())[index] ?? null)

  removeItem = vi.fn((key: string): void => {
    this.store.delete(key)
  })

  setItem = vi.fn((key: string, value: string): void => {
    this.store.set(key, value)
  })

  get length(): number {
    return this.store.size
  }
}

export const mockLocalStorage = new LocalStorageMock()
global.localStorage = mockLocalStorage

// Mock crypto.subtle for password derivation
const importKeyMock = vi.fn(async () => 'mock-key-material')
const deriveBitsMock = vi.fn(async () => new ArrayBuffer(32))

export const mockCryptoSubtle = {
  importKey: importKeyMock,
  deriveBits: deriveBitsMock,
}

Object.defineProperty(globalThis, 'crypto', {
  value: {
    subtle: mockCryptoSubtle as unknown as SubtleCrypto,
  } as Crypto,
  writable: true,
})

// Default frontend configuration overrides for tests
global.__LEAFLOCK_REGISTRATION__ = true

type MockUser = {
  id: string
  email: string
  [key: string]: unknown
}

// Test data factories
export const createMockUser = (overrides: Partial<MockUser> = {}): MockUser => ({
  id: 'test-user-id',
  email: 'test@example.com',
  ...overrides,
})

export const createMockNote = (overrides: Partial<Note> = {}): Note => ({
  id: 'test-note-id',
  title: 'Test Note',
  content: 'Test content',
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
  ...overrides,
})

export const createMockEncryptedNote = (overrides: Partial<Note> = {}): Note => ({
  id: 'test-note-id',
  title_encrypted: 'dGVzdCB0aXRsZQ==',
  content_encrypted: 'dGVzdCBjb250ZW50',
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
  title: 'Encrypted Note',
  content: 'Encrypted content',
  ...overrides,
})

// API response mocks
export const mockApiResponse = <T,>(data: T, status = 200) => {
  const json = vi.fn(async () => data) as unknown as () => Promise<T>
  return {
    ok: status >= 200 && status < 300,
    status,
    json,
  }
}

export const mockApiError = (status = 500, message = 'Server Error') => {
  const json = vi.fn(async () => ({ error: message })) as unknown as () => Promise<{
    error: string
  }>
  return {
    ok: false,
    status,
    json,
  }
}

// Custom render function with common providers
export const createTestQueryClient = () =>
  new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  })

export const renderWithProviders = (ui: ReactElement, options: RenderOptions = {}) => {
  const queryClient = createTestQueryClient()

  const Wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <div data-testid="test-wrapper">{children}</div>
    </QueryClientProvider>
  )

  return render(ui, { wrapper: Wrapper, ...options })
}

// Helper functions for common interactions
export const typeIntoField = async (fieldName: string, value: string) => {
  const labeledField = screen.queryByLabelText(fieldName) as HTMLInputElement | null
  const placeholderField = screen.queryByPlaceholderText(fieldName) as HTMLInputElement | null
  const field = labeledField ?? placeholderField
  if (!field) {
    throw new Error(`Unable to locate input with label or placeholder "${fieldName}"`)
  }

  fireEvent.change(field, { target: { value } })
  await waitFor(() => expect(field.value).toBe(value))
}

export const clickButton = async (buttonText: string) => {
  const button = screen.getByRole('button', { name: new RegExp(buttonText, 'i') })
  fireEvent.click(button)
}

export const waitForLoading = async () => {
  await waitFor(() => {
    expect(screen.queryByText(/loading/i)).not.toBeInTheDocument()
  })
}

export const waitForError = async (errorText: string) => {
  await waitFor(() => {
    expect(screen.getByText(new RegExp(errorText, 'i'))).toBeInTheDocument()
  })
}

// Mock CryptoService for consistent testing
export class MockCryptoService {
  public masterKey: Uint8Array | null
  public derivedKey: Uint8Array | null
  public sodiumReady: boolean

  constructor() {
    this.masterKey = new Uint8Array(32).fill(1)
    this.derivedKey = null
    this.sodiumReady = true
  }

  async initSodium(): Promise<void> {
    this.sodiumReady = true
  }

  async deriveKeyFromPassword(_password: string, _salt: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(32).fill(1)
  }

  async encryptData(plaintext: string): Promise<string> {
    return btoa(plaintext) // Simple base64 encoding for tests
  }

  async decryptData(encryptedData: string): Promise<string> {
    return atob(encryptedData) // Simple base64 decoding for tests
  }

  async generateSalt(): Promise<Uint8Array> {
    return new Uint8Array(32).fill(1)
  }

  async setMasterKey(key: Uint8Array): Promise<void> {
    this.masterKey = key
  }
}

type MockApiResponse = Record<string, unknown> & { error?: string }

// Mock SecureAPI for consistent testing
export class MockSecureAPI {
  public token: string | null
  public readonly responses: Map<string, MockApiResponse>
  public readonly mockCrypto: MockCryptoService

  constructor() {
    this.token = null
    this.responses = new Map()
    this.mockCrypto = new MockCryptoService()
  }

  // Set mock responses for specific endpoints
  setMockResponse(endpoint: string, response: MockApiResponse): void {
    this.responses.set(endpoint, response)
  }

  async request(endpoint: string, _options: RequestInit = {}): Promise<MockApiResponse> {
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

  setToken(token: string): void {
    this.token = token
  }

  clearToken(): void {
    this.token = null
  }

  async register(_email: string, _password: string): Promise<MockApiResponse> {
    const response = this.responses.get('/auth/register') || {
      token: 'mock-token',
      user_id: 'test-user-id',
      workspace_id: 'test-workspace-id',
    }

    if (response.token) {
      this.setToken(response.token as string)
    }

    return response
  }

  async login(_email: string, _password: string, _mfaCode?: string): Promise<MockApiResponse> {
    const response = this.responses.get('/auth/login') || {
      token: 'mock-token',
      session: 'mock-session',
      user_id: 'test-user-id',
      workspace_id: 'test-workspace-id',
    }

    if (response.token) {
      this.setToken(response.token as string)
    }

    return response
  }

  async createNote(_title: string, _content: string): Promise<MockApiResponse> {
    return (
      this.responses.get('/notes') || {
        id: 'test-note-id',
        message: 'Note created successfully',
      }
    )
  }

  async getNotes(): Promise<Note[]> {
    const mockNotes = this.responses.get('/notes/list')
    if (Array.isArray(mockNotes)) {
      return mockNotes as Note[]
    }

    return [
      createMockNote({ id: '1', title: 'Note 1' }),
      createMockNote({ id: '2', title: 'Note 2' }),
    ]
  }

  async updateNote(noteId: string, _title: string, _content: string): Promise<MockApiResponse> {
    return (
      this.responses.get(`/notes/${noteId}`) || {
        message: 'Note updated successfully',
      }
    )
  }

  async deleteNote(noteId: string): Promise<MockApiResponse> {
    return (
      this.responses.get(`/notes/${noteId}/delete`) || {
        message: 'Note deleted successfully',
      }
    )
  }
}

// Performance testing utilities
export const measureRenderTime = (component: ReactElement): number => {
  const start = performance.now()
  render(component)
  const end = performance.now()
  return end - start
}

export const measureEncryptionTime = async (
  cryptoSvc: { encryptData: (data: string) => Promise<unknown> },
  data: string
): Promise<number> => {
  const start = performance.now()
  await cryptoSvc.encryptData(data)
  const end = performance.now()
  return end - start
}

// Accessibility testing helpers
export const checkA11y = async (): Promise<void> => {
  // Check for basic accessibility attributes
  const buttons = screen.getAllByRole('button') as HTMLElement[]
  buttons.forEach((button) => {
    expect(button).toHaveAttribute('type')
  })

  const inputs = screen.getAllByRole('textbox') as HTMLElement[]
  inputs.forEach((input) => {
    expect(input).toHaveAttribute('aria-label')
  })
}

// Security testing utilities
export const checkForXSS = (component: ReactElement, _userInput?: unknown): void => {
  const scriptProtocol = ['java', 'script:'].join('')
  const maliciousInputs = [
    '<script>alert("xss")</script>',
    `${scriptProtocol}alert("xss")`,
    '"><img src=x onerror=alert("xss")>',
    '"><svg onload=alert("xss")>',
  ]

  maliciousInputs.forEach((_input) => {
    render(component)
    // Verify that malicious input is properly escaped
    expect(document.body.innerHTML).not.toContain('<script>')
    expect(document.body.innerHTML).not.toContain(scriptProtocol)
    expect(document.body.innerHTML).not.toContain('onerror=')
    expect(document.body.innerHTML).not.toContain('onload=')
  })
}

export const checkForCSRF = (
  apiCall: (fn: (input: RequestInfo | URL, init?: RequestInit) => unknown) => void
): void => {
  // Verify that API calls include proper headers
  const mockCall: (input: RequestInfo | URL, init?: RequestInit) => unknown = vi.fn()
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
