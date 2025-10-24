"use client"

import { createContext, useContext, useState, useEffect, type ReactNode } from "react"
import type { CollaborationSession } from "./types"
import { useAuth } from "./auth-context"

interface CollaborationContextType {
  activeSessions: Map<string, CollaborationSession>
  joinSession: (noteId: string) => void
  leaveSession: (noteId: string) => void
  updateCursor: (noteId: string, cursor: { line: number; ch: number }) => void
  getSessionUsers: (noteId: string) => CollaborationSession["users"]
  shareNote: (noteId: string, userEmail: string) => Promise<void>
  unshareNote: (noteId: string, userId: string) => void
  getSharedUsers: (noteId: string) => Array<{ id: string; email: string; name: string }>
}

const CollaborationContext = createContext<CollaborationContextType | undefined>(undefined)

export function CollaborationProvider({ children }: { children: ReactNode }) {
  const { user } = useAuth()
  const [activeSessions, setActiveSessions] = useState<Map<string, CollaborationSession>>(new Map())
  const [sharedNotes, setSharedNotes] = useState<Map<string, string[]>>(new Map())

  // Load shared notes from localStorage
  useEffect(() => {
    if (user) {
      const stored = localStorage.getItem(`shared_notes_${user.id}`)
      if (stored) {
        const data = JSON.parse(stored)
        setSharedNotes(new Map(Object.entries(data)))
      }
    }
  }, [user])

  // Save shared notes to localStorage
  useEffect(() => {
    if (user && sharedNotes.size > 0) {
      const data = Object.fromEntries(sharedNotes)
      localStorage.setItem(`shared_notes_${user.id}`, JSON.stringify(data))
    }
  }, [sharedNotes, user])

  const joinSession = (noteId: string) => {
    if (!user) return

    setActiveSessions((prev) => {
      const newSessions = new Map(prev)
      const session = newSessions.get(noteId)

      const userColors = ["#3b82f6", "#8b5cf6", "#10b981", "#f59e0b", "#ef4444", "#ec4899"]
      const randomColor = userColors[Math.floor(Math.random() * userColors.length)]

      if (session) {
        // Add user to existing session if not already there
        if (!session.users.find((u) => u.id === user.id)) {
          session.users.push({
            id: user.id,
            name: user.name,
            color: randomColor,
          })
        }
      } else {
        // Create new session
        newSessions.set(noteId, {
          noteId,
          users: [
            {
              id: user.id,
              name: user.name,
              color: randomColor,
            },
          ],
        })
      }

      return newSessions
    })
  }

  const leaveSession = (noteId: string) => {
    if (!user) return

    setActiveSessions((prev) => {
      const newSessions = new Map(prev)
      const session = newSessions.get(noteId)

      if (session) {
        session.users = session.users.filter((u) => u.id !== user.id)
        if (session.users.length === 0) {
          newSessions.delete(noteId)
        }
      }

      return newSessions
    })
  }

  const updateCursor = (noteId: string, cursor: { line: number; ch: number }) => {
    if (!user) return

    setActiveSessions((prev) => {
      const newSessions = new Map(prev)
      const session = newSessions.get(noteId)

      if (session) {
        const userIndex = session.users.findIndex((u) => u.id === user.id)
        if (userIndex !== -1) {
          session.users[userIndex].cursor = cursor
        }
      }

      return newSessions
    })
  }

  const getSessionUsers = (noteId: string) => {
    const session = activeSessions.get(noteId)
    return session?.users || []
  }

  const shareNote = async (noteId: string, userEmail: string) => {
    // In production, this would validate the user exists
    // For demo, we'll simulate sharing
    const users = JSON.parse(localStorage.getItem("users") || "[]")
    const targetUser = users.find((u: any) => u.email === userEmail)

    if (!targetUser) {
      throw new Error("User not found")
    }

    setSharedNotes((prev) => {
      const newShared = new Map(prev)
      const currentShared = newShared.get(noteId) || []
      if (!currentShared.includes(targetUser.id)) {
        newShared.set(noteId, [...currentShared, targetUser.id])
      }
      return newShared
    })
  }

  const unshareNote = (noteId: string, userId: string) => {
    setSharedNotes((prev) => {
      const newShared = new Map(prev)
      const currentShared = newShared.get(noteId) || []
      newShared.set(
        noteId,
        currentShared.filter((id) => id !== userId),
      )
      return newShared
    })
  }

  const getSharedUsers = (noteId: string) => {
    const userIds = sharedNotes.get(noteId) || []
    const users = JSON.parse(localStorage.getItem("users") || "[]")

    return userIds
      .map((id) => {
        const user = users.find((u: any) => u.id === id)
        return user ? { id: user.id, email: user.email, name: user.name } : null
      })
      .filter(Boolean) as Array<{ id: string; email: string; name: string }>
  }

  return (
    <CollaborationContext.Provider
      value={{
        activeSessions,
        joinSession,
        leaveSession,
        updateCursor,
        getSessionUsers,
        shareNote,
        unshareNote,
        getSharedUsers,
      }}
    >
      {children}
    </CollaborationContext.Provider>
  )
}

export function useCollaboration() {
  const context = useContext(CollaborationContext)
  if (context === undefined) {
    throw new Error("useCollaboration must be used within a CollaborationProvider")
  }
  return context
}
