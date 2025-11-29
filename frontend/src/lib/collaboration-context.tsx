import { useState, useCallback } from 'react'
import { socialService } from '@/services/api'

interface User {
  id: string
  name: string
  email: string
  color: string
}

// Active collaboration sessions tracked in memory
const activeSessions = new Map<string, Set<string>>()

export function useCollaboration() {
  const [sharedUsers, setSharedUsers] = useState<Record<string, User[]>>({})

  const loadSharedUsers = useCallback(async (noteId: string) => {
    try {
      const collaborators = await socialService.getCollaborators(noteId)
      const users = collaborators.map((c: any, index: number) => ({
        id: c.userId || `user-${index}`,
        name: c.email?.split('@')[0] || 'User',
        email: c.email || '',
        color: `hsl(${(index * 137) % 360}, 70%, 50%)`, // Generate color from index
      }))
      setSharedUsers((prev) => ({ ...prev, [noteId]: users }))
    } catch (error) {
      console.error('Failed to load collaborators:', error)
    }
  }, [])

  const joinSession = useCallback(
    (noteId: string) => {
      if (!activeSessions.has(noteId)) {
        activeSessions.set(noteId, new Set())
      }
      const userId = localStorage.getItem('user_id') || 'current-user'
      activeSessions.get(noteId)?.add(userId)

      loadSharedUsers(noteId)
    },
    [loadSharedUsers]
  )

  const leaveSession = useCallback((noteId: string) => {
    // Track that current user left this session
    const userId = localStorage.getItem('user_id') || 'current-user'
    activeSessions.get(noteId)?.delete(userId)
    if (activeSessions.get(noteId)?.size === 0) {
      activeSessions.delete(noteId)
    }
  }, [])

  const getSessionUsers = (noteId: string): User[] => {
    return sharedUsers[noteId] || []
  }

  const shareNote = useCallback(
    async (noteId: string, email: string) => {
      await socialService.shareNote(noteId, email, 'read')
      await loadSharedUsers(noteId)
    },
    [loadSharedUsers]
  )

  const unshareNote = useCallback(
    async (noteId: string, userId: string) => {
      // Use socialService to remove collaborator instead of direct fetch with JWT
      await socialService.removeCollaborator(noteId, userId)
      await loadSharedUsers(noteId)
    },
    [loadSharedUsers]
  )

  const getSharedUsers = (noteId: string): User[] => {
    return sharedUsers[noteId] || []
  }

  return {
    getSessionUsers,
    joinSession,
    leaveSession,
    shareNote,
    unshareNote,
    getSharedUsers,
  }
}
