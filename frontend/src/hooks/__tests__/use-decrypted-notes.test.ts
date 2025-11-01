import { describe, it, expect, beforeEach, vi } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { useDecryptedNotes } from '../use-decrypted-notes'
import type { Note } from '@/types'

// Helper to create valid Note objects for testing
const createTestNote = (overrides: Partial<Note> = {}): Note => ({
  id: '1',
  title: 'test-title',
  content: 'test-content',
  folderId: null,
  tags: [],
  encrypted: true,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
  userId: 'user-1',
  sharedWith: [],
  isTemplate: false,
  isTrashed: false,
  ...overrides,
})

// Mock encryption context
const mockDecryptText = vi.fn()
const mockIsUnlocked = vi.fn(() => true)

vi.mock('@/lib/encryption-context', () => ({
  useEncryption: () => ({
    isUnlocked: mockIsUnlocked(),
    decryptText: mockDecryptText,
  }),
}))

describe('useDecryptedNotes', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockIsUnlocked.mockReturnValue(true)
    mockDecryptText.mockImplementation(async (text: string) => `decrypted:${text}`)
  })

  it('should return empty cache when encryption is not unlocked', async () => {
    mockIsUnlocked.mockReturnValue(false)

    const notes: Note[] = [createTestNote({ title: 'encrypted-title', content: 'encrypted-content' })]

    const { result } = renderHook(() => useDecryptedNotes(notes))

    await waitFor(() => {
      expect(result.current.isUnlocked).toBe(false)
      expect(result.current.isDecrypting).toBe(false)
      expect(result.current.decryptedNotes).toEqual({})
    })
  })

  it('should decrypt notes when encryption is unlocked', async () => {
    const notes: Note[] = [createTestNote({ title: 'encrypted-title-1', content: 'encrypted-content-1' })]

    mockDecryptText.mockResolvedValueOnce('decrypted-title-1')
    mockDecryptText.mockResolvedValueOnce('decrypted-content-1')

    const { result } = renderHook(() => useDecryptedNotes(notes))

    await waitFor(() => {
      expect(result.current.isDecrypting).toBe(false)
    })

    expect(mockDecryptText).toHaveBeenCalledTimes(2)
    expect(result.current.decryptedNotes['1']).toEqual({
      title: 'decrypted-title-1',
      content: 'decrypted-content-1',
      timestamp: expect.any(Number),
    })
  })

  it('should handle empty title and content', async () => {
    const notes: Note[] = [createTestNote({ title: '', content: '' })]

    mockDecryptText.mockResolvedValue('')

    const { result } = renderHook(() => useDecryptedNotes(notes))

    await waitFor(() => {
      expect(result.current.isDecrypting).toBe(false)
    })

    expect(result.current.decryptedNotes['1']).toEqual({
      title: '',
      content: '',
      timestamp: expect.any(Number),
    })
  })

  it('should cache notes based on updatedAt timestamp', async () => {
    const updatedAt = new Date().toISOString()
    const notes: Note[] = [createTestNote({ title: 'encrypted-title', content: 'encrypted-content', updatedAt })]

    mockDecryptText.mockResolvedValueOnce('decrypted-title')
    mockDecryptText.mockResolvedValueOnce('decrypted-content')

    const { result, rerender } = renderHook(({ notes }) => useDecryptedNotes(notes), {
      initialProps: { notes },
    })

    await waitFor(() => {
      expect(result.current.isDecrypting).toBe(false)
    })

    const firstCallCount = mockDecryptText.mock.calls.length

    // Re-render with same notes (same updatedAt)
    rerender({ notes })

    await waitFor(() => {
      expect(result.current.isDecrypting).toBe(false)
    })

    // Should not decrypt again (cached)
    expect(mockDecryptText.mock.calls.length).toBe(firstCallCount)
  })

  it('should re-decrypt when updatedAt changes', async () => {
    const updatedAt1 = new Date().toISOString()
    const notes1: Note[] = [createTestNote({ title: 'encrypted-title', content: 'encrypted-content', updatedAt: updatedAt1 })]

    mockDecryptText.mockResolvedValueOnce('decrypted-title-1')
    mockDecryptText.mockResolvedValueOnce('decrypted-content-1')

    const { result, rerender } = renderHook(({ notes }) => useDecryptedNotes(notes), {
      initialProps: { notes: notes1 },
    })

    await waitFor(() => {
      expect(result.current.isDecrypting).toBe(false)
    })

    const updatedAt2 = new Date(Date.now() + 1000).toISOString()
    const notes2: Note[] = [createTestNote({ title: 'encrypted-title', content: 'encrypted-content', updatedAt: updatedAt2 })]

    mockDecryptText.mockResolvedValueOnce('decrypted-title-2')
    mockDecryptText.mockResolvedValueOnce('decrypted-content-2')

    rerender({ notes: notes2 })

    await waitFor(() => {
      expect(result.current.isDecrypting).toBe(false)
    })

    // Should decrypt again for new timestamp
    expect(result.current.decryptedNotes['1']).toEqual({
      title: 'decrypted-title-2',
      content: 'decrypted-content-2',
      timestamp: expect.any(Number),
    })
  })

  it('should handle decryption errors gracefully', async () => {
    const notes: Note[] = [createTestNote({ title: 'encrypted-title', content: 'encrypted-content' })]

    mockDecryptText.mockRejectedValueOnce(new Error('Decryption failed'))

    const { result } = renderHook(() => useDecryptedNotes(notes))

    await waitFor(() => {
      expect(result.current.isDecrypting).toBe(false)
    })

    // Should fallback to original values on error
    expect(result.current.decryptedNotes['1']).toEqual({
      title: 'encrypted-title',
      content: 'encrypted-content',
      timestamp: expect.any(Number),
    })
  })

  it('should handle invalid updatedAt dates', async () => {
    const notes: Note[] = [createTestNote({ title: 'encrypted-title', content: 'encrypted-content', updatedAt: 'invalid-date' })]

    mockDecryptText.mockResolvedValueOnce('decrypted-title')
    mockDecryptText.mockResolvedValueOnce('decrypted-content')

    const { result } = renderHook(() => useDecryptedNotes(notes))

    await waitFor(() => {
      expect(result.current.isDecrypting).toBe(false)
    })

    expect(result.current.decryptedNotes['1'].timestamp).toBe(0)
  })

  it('should decrypt multiple notes', async () => {
    const notes: Note[] = [
      createTestNote({ id: '1', title: 'encrypted-title-1', content: 'encrypted-content-1' }),
      createTestNote({ id: '2', title: 'encrypted-title-2', content: 'encrypted-content-2' }),
    ]

    mockDecryptText
      .mockResolvedValueOnce('decrypted-title-1')
      .mockResolvedValueOnce('decrypted-content-1')
      .mockResolvedValueOnce('decrypted-title-2')
      .mockResolvedValueOnce('decrypted-content-2')

    const { result } = renderHook(() => useDecryptedNotes(notes))

    await waitFor(() => {
      expect(result.current.isDecrypting).toBe(false)
    })

    expect(Object.keys(result.current.decryptedNotes)).toHaveLength(2)
    expect(result.current.decryptedNotes['1'].title).toBe('decrypted-title-1')
    expect(result.current.decryptedNotes['2'].title).toBe('decrypted-title-2')
  })

  it('should set isDecrypting to true during decryption', async () => {
    const notes: Note[] = [createTestNote({ title: 'encrypted-title', content: 'encrypted-content' })]

    let resolveDecrypt: () => void
    const decryptPromise = new Promise<string>((resolve) => {
      resolveDecrypt = () => resolve('decrypted')
    })

    mockDecryptText.mockReturnValue(decryptPromise)

    const { result } = renderHook(() => useDecryptedNotes(notes))

    // Should be decrypting initially
    expect(result.current.isDecrypting).toBe(true)

    resolveDecrypt!()

    await waitFor(() => {
      expect(result.current.isDecrypting).toBe(false)
    })
  })
})
