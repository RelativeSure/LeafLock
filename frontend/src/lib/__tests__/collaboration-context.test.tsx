import { describe, it, expect, beforeEach, vi } from 'vitest'
import { renderHook } from '@testing-library/react'
import { useCollaboration } from '../collaboration-context'

describe('CollaborationContext', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('should return collaboration functions', () => {
    const { result } = renderHook(() => useCollaboration())

    expect(result.current.getSessionUsers).toBeDefined()
    expect(result.current.joinSession).toBeDefined()
    expect(result.current.leaveSession).toBeDefined()
    expect(result.current.shareNote).toBeDefined()
    expect(result.current.unshareNote).toBeDefined()
    expect(result.current.getSharedUsers).toBeDefined()
  })

  it('should return empty users array', () => {
    const { result } = renderHook(() => useCollaboration())

    expect(result.current.getSessionUsers('note-1')).toEqual([])
    expect(result.current.getSharedUsers('note-1')).toEqual([])
  })

  it('should handle joinSession without errors', () => {
    const { result } = renderHook(() => useCollaboration())

    expect(() => {
      result.current.joinSession('note-1')
    }).not.toThrow()
  })

  it('should handle leaveSession without errors', () => {
    const { result } = renderHook(() => useCollaboration())

    expect(() => {
      result.current.leaveSession('note-1')
    }).not.toThrow()
  })

  it('should resolve shareNote promise', async () => {
    const { result } = renderHook(() => useCollaboration())

    await expect(result.current.shareNote('note-1', 'user@example.com')).resolves.toBeUndefined()
  })

  it('should resolve unshareNote promise', async () => {
    const { result } = renderHook(() => useCollaboration())

    await expect(result.current.unshareNote('note-1', 'user-1')).resolves.toBeUndefined()
  })
})
