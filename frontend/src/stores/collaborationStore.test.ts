import { describe, it, expect, beforeEach, vi } from 'vitest'
import { useCollaborationStore } from './collaborationStore'

// Mock socket.io-client
vi.mock('socket.io-client', () => ({
  io: vi.fn(() => ({
    on: vi.fn(),
    emit: vi.fn(),
    disconnect: vi.fn(),
  })),
}))

// Mock fetch
global.fetch = vi.fn()

describe('CollaborationStore', () => {
  beforeEach(() => {
    // Reset store state
    const store = useCollaborationStore.getState()
    store.disconnect()
    vi.clearAllMocks()
  })

  it('should initialize with default state', () => {
    const store = useCollaborationStore.getState()

    expect(store.socket).toBeNull()
    expect(store.isConnected).toBe(false)
    expect(store.currentNoteId).toBeNull()
    expect(store.currentUserId).toBeNull()
    expect(store.collaborators).toEqual([])
    expect(store.presenceUsers).toEqual([])
    expect(store.pendingEdits).toEqual([])
    expect(store.isProcessingEdit).toBe(false)
  })

  it('should handle successful note sharing', async () => {
    const store = useCollaborationStore.getState()

    // Mock successful fetch response
    const mockFetch = vi.mocked(fetch)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ message: 'Note shared successfully' }),
    } as Response)

    // Mock localStorage
    Storage.prototype.getItem = vi.fn(() => 'mock-token')

    // Mock fetchCollaborators
    store.fetchCollaborators = vi.fn().mockResolvedValue(undefined)

    await store.shareNote('note-123', 'user@example.com', 'write')

    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:8080/api/v1/notes/note-123/share',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer mock-token',
        },
        body: JSON.stringify({
          user_email: 'user@example.com',
          permission: 'write',
        }),
      }
    )

    expect(store.fetchCollaborators).toHaveBeenCalledWith('note-123')
  })

  it('should handle failed note sharing', async () => {
    const store = useCollaborationStore.getState()

    // Mock failed fetch response
    const mockFetch = vi.mocked(fetch)
    mockFetch.mockResolvedValueOnce({
      ok: false,
      json: async () => ({ error: 'User not found' }),
    } as Response)

    // Mock localStorage
    Storage.prototype.getItem = vi.fn(() => 'mock-token')

    await expect(store.shareNote('note-123', 'invalid@example.com', 'write'))
      .rejects.toThrow('User not found')
  })

  it('should handle successful collaborator removal', async () => {
    const store = useCollaborationStore.getState()

    // Mock successful fetch response
    const mockFetch = vi.mocked(fetch)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ message: 'Collaborator removed' }),
    } as Response)

    // Mock localStorage
    Storage.prototype.getItem = vi.fn(() => 'mock-token')

    // Mock fetchCollaborators
    store.fetchCollaborators = vi.fn().mockResolvedValue(undefined)

    await store.removeCollaborator('note-123', 'user-456')

    expect(mockFetch).toHaveBeenCalledWith(
      'http://localhost:8080/api/v1/notes/note-123/collaborators/user-456',
      {
        method: 'DELETE',
        headers: {
          'Authorization': 'Bearer mock-token',
        },
      }
    )

    expect(store.fetchCollaborators).toHaveBeenCalledWith('note-123')
  })

  it('should handle fetching collaborators', async () => {
    const store = useCollaborationStore.getState()

    const mockCollaborators = [
      {
        id: 'collab-1',
        note_id: 'note-123',
        user_id: 'user-456',
        user_email: 'user@example.com',
        permission: 'write',
        created_at: '2025-01-01T00:00:00Z',
      },
    ]

    // Mock successful fetch response
    const mockFetch = vi.mocked(fetch)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ collaborators: mockCollaborators }),
    } as Response)

    // Mock localStorage
    Storage.prototype.getItem = vi.fn(() => 'mock-token')

    await store.fetchCollaborators('note-123')

    expect(store.collaborators).toEqual(mockCollaborators)
  })

  it('should handle fetching shared notes', async () => {
    const store = useCollaborationStore.getState()

    const mockSharedNotes = [
      {
        id: 'note-456',
        title: 'Shared Note',
        content: 'This is shared',
        permission: 'read',
        owner_email: 'owner@example.com',
        is_shared: true,
      },
    ]

    // Mock successful fetch response
    const mockFetch = vi.mocked(fetch)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ notes: mockSharedNotes }),
    } as Response)

    // Mock localStorage
    Storage.prototype.getItem = vi.fn(() => 'mock-token')

    const result = await store.fetchSharedNotes()

    expect(result).toEqual(mockSharedNotes)
  })

  it('should handle presence updates', () => {
    const store = useCollaborationStore.getState()

    const newPresence = {
      user_id: 'user-123',
      user_email: 'user@example.com',
      status: 'online' as const,
    }

    store.handlePresenceUpdate(newPresence)

    expect(store.presenceUsers).toContainEqual(newPresence)
  })

  it('should update existing user presence', () => {
    const store = useCollaborationStore.getState()

    // Add initial presence
    const initialPresence = {
      user_id: 'user-123',
      user_email: 'user@example.com',
      status: 'online' as const,
    }
    store.handlePresenceUpdate(initialPresence)

    // Update presence
    const updatedPresence = {
      user_id: 'user-123',
      user_email: 'user@example.com',
      status: 'typing' as const,
    }
    store.handlePresenceUpdate(updatedPresence)

    expect(store.presenceUsers).toHaveLength(1)
    expect(store.presenceUsers[0].status).toBe('typing')
  })

  it('should handle incoming edits', () => {
    const store = useCollaborationStore.getState()
    store.currentUserId = 'current-user'

    const edit = {
      operation: 'insert' as const,
      position: 10,
      content: 'hello',
      timestamp: Date.now(),
      user_id: 'other-user',
    }

    store.handleIncomingEdit(edit)

    expect(store.isProcessingEdit).toBe(true)
  })

  it('should ignore own edits', () => {
    const store = useCollaborationStore.getState()
    store.currentUserId = 'current-user'

    const edit = {
      operation: 'insert' as const,
      position: 10,
      content: 'hello',
      timestamp: Date.now(),
      user_id: 'current-user',
    }

    store.handleIncomingEdit(edit)

    expect(store.isProcessingEdit).toBe(false)
  })
})