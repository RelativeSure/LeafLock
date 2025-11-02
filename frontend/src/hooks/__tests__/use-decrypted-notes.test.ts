import { describe, it, expect, beforeEach, vi } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { useDecryptedNotes } from '../use-decrypted-notes'
import { useEncryption } from '@/lib/encryption-context'
import type { Note } from '@/types'

vi.mock('@/lib/encryption-context', () => ({
  useEncryption: vi.fn(),
}))

describe('useDecryptedNotes', () => {
  const mockNote: Note = {
    id: 'note-1',
    title: 'encrypted-title',
    content: 'encrypted-content',
    userId: '123',
    encrypted: true,
    encryptionVersion: 1,
    folderId: null,
    tags: [],
    pinned: false,
    isTrashed: false,
    sharedWith: [],
    isTemplate: false,
    createdAt: '2024-01-01',
    updatedAt: '2024-01-01',
  }

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('should return empty array for empty input', async () => {
    vi.mocked(useEncryption).mockReturnValue({
      isUnlocked: true,
      encryptionVersion: 1,
      encryptText: vi.fn(),
      decryptText: vi.fn(),
      setEncryptionKey: vi.fn(),
      clearEncryptionKey: vi.fn(),
    })

    const { result } = renderHook(() => useDecryptedNotes([]))

    await waitFor(() => {
      expect(result.current).toEqual([])
    })
  })

  it('should decrypt notes', async () => {
    const mockDecryptText = vi.fn()
      .mockResolvedValueOnce('Decrypted Title')
      .mockResolvedValueOnce('Decrypted Content')

    vi.mocked(useEncryption).mockReturnValue({
      isUnlocked: true,
      encryptionVersion: 1,
      encryptText: vi.fn(),
      decryptText: mockDecryptText,
      setEncryptionKey: vi.fn(),
      clearEncryptionKey: vi.fn(),
    })

    const { result } = renderHook(() => useDecryptedNotes([mockNote]))

    await waitFor(() => {
      expect(result.current.length).toBe(1)
      expect(result.current[0].title).toBe('Decrypted Title')
      expect(result.current[0].content).toBe('Decrypted Content')
    })
  })

  it('should return encrypted notes when not unlocked', () => {
    vi.mocked(useEncryption).mockReturnValue({
      isUnlocked: false,
      encryptionVersion: 1,
      encryptText: vi.fn(),
      decryptText: vi.fn(),
      setEncryptionKey: vi.fn(),
      clearEncryptionKey: vi.fn(),
    })

    const { result } = renderHook(() => useDecryptedNotes([mockNote]))

    expect(result.current[0].title).toBe('encrypted-title')
  })

  it('should handle multiple notes', async () => {
    const notes: Note[] = [
      { ...mockNote, id: 'note-1', title: 'enc-1', content: 'enc-content-1' },
      { ...mockNote, id: 'note-2', title: 'enc-2', content: 'enc-content-2' },
    ]

    const mockDecryptText = vi.fn()
      .mockResolvedValueOnce('Dec-1')
      .mockResolvedValueOnce('Dec-Content-1')
      .mockResolvedValueOnce('Dec-2')
      .mockResolvedValueOnce('Dec-Content-2')

    vi.mocked(useEncryption).mockReturnValue({
      isUnlocked: true,
      encryptionVersion: 1,
      encryptText: vi.fn(),
      decryptText: mockDecryptText,
      setEncryptionKey: vi.fn(),
      clearEncryptionKey: vi.fn(),
    })

    const { result } = renderHook(() => useDecryptedNotes(notes))

    await waitFor(() => {
      expect(result.current.length).toBe(2)
    })
  })

  it('should handle decryption errors gracefully', async () => {
    const mockDecryptText = vi.fn()
      .mockRejectedValueOnce(new Error('Decryption failed'))
      .mockRejectedValueOnce(new Error('Decryption failed'))

    vi.mocked(useEncryption).mockReturnValue({
      isUnlocked: true,
      encryptionVersion: 1,
      encryptText: vi.fn(),
      decryptText: mockDecryptText,
      setEncryptionKey: vi.fn(),
      clearEncryptionKey: vi.fn(),
    })

    const { result } = renderHook(() => useDecryptedNotes([mockNote]))

    await waitFor(() => {
      expect(result.current.length).toBe(1)
      expect(result.current[0].title).toContain('[Decryption Error]')
    })
  })
})
