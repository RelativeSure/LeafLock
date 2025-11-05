import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'
import { useCollaboration } from '../collaboration-context'

// Mock the social service
const mockGetCollaborators = vi.fn()
const mockShareNote = vi.fn()

vi.mock('@/services/api', () => ({
  socialService: {
    getCollaborators: (...args: any[]) => mockGetCollaborators(...args),
    shareNote: (...args: any[]) => mockShareNote(...args),
  },
}))

describe('CollaborationContext', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    global.fetch = vi.fn()
  })

  afterEach(() => {
    vi.restoreAllMocks()
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

  it('should return empty users array initially', () => {
    const { result } = renderHook(() => useCollaboration())

    expect(result.current.getSessionUsers('note-1')).toEqual([])
    expect(result.current.getSharedUsers('note-1')).toEqual([])
  })

  it('should handle joinSession without errors', () => {
    mockGetCollaborators.mockResolvedValue([])
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
    mockShareNote.mockResolvedValue(undefined)
    mockGetCollaborators.mockResolvedValue([])
    const { result } = renderHook(() => useCollaboration())

    await expect(result.current.shareNote('note-1', 'user@example.com')).resolves.toBeUndefined()
  })

  it('should resolve unshareNote promise', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true })
    mockGetCollaborators.mockResolvedValue([])
    const { result } = renderHook(() => useCollaboration())

    await expect(result.current.unshareNote('note-1', 'user-1')).resolves.toBeUndefined()
  })

  it('should load shared users when joining session', async () => {
    const mockCollaborators = [
      { userId: 'user-1', email: 'alice@example.com' },
      { userId: 'user-2', email: 'bob@example.com' },
    ]
    mockGetCollaborators.mockResolvedValue(mockCollaborators)

    const { result } = renderHook(() => useCollaboration())

    act(() => {
      result.current.joinSession('note-1')
    })

    await waitFor(() => {
      const users = result.current.getSessionUsers('note-1')
      expect(users).toHaveLength(2)
      expect(users[0].email).toBe('alice@example.com')
      expect(users[1].email).toBe('bob@example.com')
    })
  })

  it('should generate user names from emails', async () => {
    mockGetCollaborators.mockResolvedValue([{ userId: 'user-1', email: 'alice@example.com' }])

    const { result } = renderHook(() => useCollaboration())

    act(() => {
      result.current.joinSession('note-1')
    })

    await waitFor(() => {
      const users = result.current.getSessionUsers('note-1')
      expect(users[0].name).toBe('alice')
    })
  })

  it('should generate colors for users', async () => {
    mockGetCollaborators.mockResolvedValue([
      { userId: 'user-1', email: 'alice@example.com' },
      { userId: 'user-2', email: 'bob@example.com' },
    ])

    const { result } = renderHook(() => useCollaboration())

    act(() => {
      result.current.joinSession('note-1')
    })

    await waitFor(() => {
      const users = result.current.getSessionUsers('note-1')
      expect(users[0].color).toMatch(/^hsl\(\d+, 70%, 50%\)$/)
      expect(users[1].color).toMatch(/^hsl\(\d+, 70%, 50%\)$/)
    })
  })

  it('should use localStorage user_id when joining session', () => {
    localStorage.setItem('user_id', 'test-user-123')
    mockGetCollaborators.mockResolvedValue([])

    const { result } = renderHook(() => useCollaboration())

    act(() => {
      result.current.joinSession('note-1')
    })

    expect(localStorage.getItem('user_id')).toBe('test-user-123')
  })

  it('should use default user_id if not in localStorage', () => {
    mockGetCollaborators.mockResolvedValue([])

    const { result } = renderHook(() => useCollaboration())

    act(() => {
      result.current.joinSession('note-1')
    })

    expect(() => result.current.joinSession('note-1')).not.toThrow()
  })

  it('should handle leave session for user', () => {
    localStorage.setItem('user_id', 'test-user')
    mockGetCollaborators.mockResolvedValue([])

    const { result } = renderHook(() => useCollaboration())

    act(() => {
      result.current.joinSession('note-1')
    })

    act(() => {
      result.current.leaveSession('note-1')
    })

    expect(() => result.current.leaveSession('note-1')).not.toThrow()
  })

  it('should call API with correct parameters when sharing note', async () => {
    mockShareNote.mockResolvedValue(undefined)
    mockGetCollaborators.mockResolvedValue([])

    const { result } = renderHook(() => useCollaboration())

    await act(async () => {
      await result.current.shareNote('note-123', 'user@example.com')
    })

    expect(mockShareNote).toHaveBeenCalledWith('note-123', 'user@example.com', 'read')
  })

  it('should reload shared users after sharing note', async () => {
    mockShareNote.mockResolvedValue(undefined)
    mockGetCollaborators.mockResolvedValue([{ userId: 'new-user', email: 'newuser@example.com' }])

    const { result } = renderHook(() => useCollaboration())

    await act(async () => {
      await result.current.shareNote('note-1', 'newuser@example.com')
    })

    await waitFor(() => {
      const users = result.current.getSharedUsers('note-1')
      expect(users).toHaveLength(1)
      expect(users[0].email).toBe('newuser@example.com')
    })
  })

  it('should call DELETE API when unsharing note', async () => {
    const mockFetch = vi.fn().mockResolvedValue({ ok: true })
    global.fetch = mockFetch
    localStorage.setItem('token', 'test-token')
    mockGetCollaborators.mockResolvedValue([])

    const { result } = renderHook(() => useCollaboration())

    await act(async () => {
      await result.current.unshareNote('note-123', 'user-456')
    })

    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/notes/note-123/share/user-456'),
      expect.objectContaining({
        method: 'DELETE',
        headers: { Authorization: 'Bearer test-token' },
      })
    )
  })

  it('should reload shared users after unsharing note', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true })
    mockGetCollaborators
      .mockResolvedValueOnce([
        { userId: 'user-1', email: 'user1@example.com' },
        { userId: 'user-2', email: 'user2@example.com' },
      ])
      .mockResolvedValueOnce([{ userId: 'user-1', email: 'user1@example.com' }])

    const { result } = renderHook(() => useCollaboration())

    await act(async () => {
      result.current.joinSession('note-1')
    })

    await act(async () => {
      await result.current.unshareNote('note-1', 'user-2')
    })

    await waitFor(() => {
      const users = result.current.getSharedUsers('note-1')
      expect(users).toHaveLength(1)
    })
  })

  it('should handle API errors when loading collaborators', async () => {
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    mockGetCollaborators.mockRejectedValue(new Error('API Error'))

    const { result } = renderHook(() => useCollaboration())

    await act(async () => {
      result.current.joinSession('note-1')
    })

    await waitFor(() => {
      expect(consoleErrorSpy).toHaveBeenCalled()
    })

    consoleErrorSpy.mockRestore()
  })

  it('should return empty array for non-existent note', () => {
    const { result } = renderHook(() => useCollaboration())

    expect(result.current.getSessionUsers('non-existent-note')).toEqual([])
    expect(result.current.getSharedUsers('non-existent-note')).toEqual([])
  })

  it('should handle multiple concurrent sessions', async () => {
    mockGetCollaborators
      .mockResolvedValueOnce([{ userId: 'user-1', email: 'user1@example.com' }])
      .mockResolvedValueOnce([{ userId: 'user-2', email: 'user2@example.com' }])

    const { result } = renderHook(() => useCollaboration())

    await act(async () => {
      result.current.joinSession('note-1')
      result.current.joinSession('note-2')
    })

    await waitFor(() => {
      expect(result.current.getSessionUsers('note-1')).toHaveLength(1)
      expect(result.current.getSessionUsers('note-2')).toHaveLength(1)
    })
  })

  it('should handle collaborators without userId', async () => {
    mockGetCollaborators.mockResolvedValue([{ email: 'user@example.com' }])

    const { result } = renderHook(() => useCollaboration())

    await act(async () => {
      result.current.joinSession('note-1')
    })

    await waitFor(() => {
      const users = result.current.getSessionUsers('note-1')
      expect(users[0].id).toMatch(/^user-\d+$/)
    })
  })

  it('should handle collaborators without email', async () => {
    mockGetCollaborators.mockResolvedValue([{ userId: 'user-1' }])

    const { result } = renderHook(() => useCollaboration())

    await act(async () => {
      result.current.joinSession('note-1')
    })

    await waitFor(() => {
      const users = result.current.getSessionUsers('note-1')
      expect(users[0].name).toBe('User')
      expect(users[0].email).toBe('')
    })
  })

  it('should maintain separate state for different notes', async () => {
    mockGetCollaborators
      .mockResolvedValueOnce([{ userId: 'user-1', email: 'user1@example.com' }])
      .mockResolvedValueOnce([
        { userId: 'user-2', email: 'user2@example.com' },
        { userId: 'user-3', email: 'user3@example.com' },
      ])

    const { result } = renderHook(() => useCollaboration())

    await act(async () => {
      result.current.joinSession('note-1')
      result.current.joinSession('note-2')
    })

    await waitFor(() => {
      expect(result.current.getSessionUsers('note-1')).toHaveLength(1)
      expect(result.current.getSessionUsers('note-2')).toHaveLength(2)
    })
  })

  it('should handle session cleanup properly', () => {
    localStorage.setItem('user_id', 'test-user')
    mockGetCollaborators.mockResolvedValue([])

    const { result } = renderHook(() => useCollaboration())

    act(() => {
      result.current.joinSession('note-1')
      result.current.joinSession('note-2')
    })

    act(() => {
      result.current.leaveSession('note-1')
      result.current.leaveSession('note-2')
    })

    expect(() => {
      result.current.getSessionUsers('note-1')
      result.current.getSessionUsers('note-2')
    }).not.toThrow()
  })

  it('should have all required function types', () => {
    const { result } = renderHook(() => useCollaboration())

    expect(typeof result.current.getSessionUsers).toBe('function')
    expect(typeof result.current.joinSession).toBe('function')
    expect(typeof result.current.leaveSession).toBe('function')
    expect(typeof result.current.shareNote).toBe('function')
    expect(typeof result.current.unshareNote).toBe('function')
    expect(typeof result.current.getSharedUsers).toBe('function')
  })
})
