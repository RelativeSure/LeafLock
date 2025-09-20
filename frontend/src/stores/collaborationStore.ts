import { create } from 'zustand'

export interface Collaborator {
  id: string
  note_id: string
  user_id: string
  user_email: string
  permission: 'read' | 'write' | 'admin'
  created_at: string
}

export interface PresenceUser {
  user_id: string
  user_email: string
  status: 'online' | 'offline' | 'typing'
  cursor_position?: number
  last_seen?: string
}

export interface EditMessage {
  operation: 'insert' | 'delete' | 'replace'
  position: number
  content: string
  timestamp: number
  user_id: string
}

export interface CursorMessage {
  user_id: string
  position: number
  length: number
}

interface CollaborationState {
  // Connection state
  socket: WebSocket | null
  isConnected: boolean
  currentNoteId: string | null
  currentUserId: string | null

  // Collaboration data
  collaborators: Collaborator[]
  presenceUsers: PresenceUser[]

  // Real-time editing
  pendingEdits: EditMessage[]
  isProcessingEdit: boolean

  // Actions
  connect: (noteId: string, userId: string, token: string) => void
  disconnect: () => void
  shareNote: (noteId: string, userEmail: string, permission: 'read' | 'write' | 'admin') => Promise<void>
  removeCollaborator: (noteId: string, userId: string) => Promise<void>
  fetchCollaborators: (noteId: string) => Promise<void>
  fetchSharedNotes: () => Promise<void>

  // Real-time editing actions
  sendEdit: (edit: Omit<EditMessage, 'timestamp' | 'user_id'>) => void
  sendCursor: (position: number, length: number) => void
  sendPresence: (status: 'typing' | 'idle') => void

  // Event handlers
  handleIncomingEdit: (edit: EditMessage) => void
  handleIncomingCursor: (cursor: CursorMessage) => void
  handlePresenceUpdate: (presence: PresenceUser) => void
}

const API_BASE_URL = (import.meta as any).env.VITE_API_URL || 'http://localhost:8080'
const WS_BASE_URL = (import.meta as any).env.VITE_WS_URL || 'ws://localhost:8080'

export const useCollaborationStore = create<CollaborationState>((set, get) => ({
  // Initial state
  socket: null,
  isConnected: false,
  currentNoteId: null,
  currentUserId: null,
  collaborators: [],
  presenceUsers: [],
  pendingEdits: [],
  isProcessingEdit: false,

  // Connection management
  connect: (noteId: string, userId: string, token: string) => {
    const { socket: existingSocket } = get()

    // Disconnect existing socket if any
    if (existingSocket) {
      existingSocket.close()
    }

    // Create WebSocket URL with query parameters
    const wsUrl = `${WS_BASE_URL}/ws/notes?note_id=${noteId}&user_id=${userId}&token=${token}`

    // Create new WebSocket connection
    const socket = new WebSocket(wsUrl)

    socket.onopen = () => {
      console.log('Connected to collaboration server')
      set({ isConnected: true })
    }

    socket.onclose = () => {
      console.log('Disconnected from collaboration server')
      set({ isConnected: false })
    }

    socket.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data)

        switch (message.type) {
          case 'edit':
            get().handleIncomingEdit(message.content)
            break
          case 'cursor':
            get().handleIncomingCursor(message.content)
            break
          case 'presence':
            get().handlePresenceUpdate(message.content)
            break
          default:
            console.log('Unknown message type:', message.type)
        }
      } catch (error) {
        console.error('Error parsing WebSocket message:', error)
      }
    }

    socket.onerror = (error) => {
      console.error('WebSocket error:', error)
    }

    set({
      socket,
      currentNoteId: noteId,
      currentUserId: userId,
    })
  },

  disconnect: () => {
    const { socket } = get()
    if (socket) {
      socket.close()
    }
    set({
      socket: null,
      isConnected: false,
      currentNoteId: null,
      currentUserId: null,
      presenceUsers: [],
      pendingEdits: [],
    })
  },

  // API calls
  shareNote: async (noteId: string, userEmail: string, permission: 'read' | 'write' | 'admin') => {
    const token = localStorage.getItem('token')
    if (!token) throw new Error('No authentication token')

    const response = await fetch(`${API_BASE_URL}/api/v1/notes/${noteId}/share`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({
        user_email: userEmail,
        permission,
      }),
    })

    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.error || 'Failed to share note')
    }

    // Refresh collaborators list
    await get().fetchCollaborators(noteId)
  },

  removeCollaborator: async (noteId: string, userId: string) => {
    const token = localStorage.getItem('token')
    if (!token) throw new Error('No authentication token')

    const response = await fetch(`${API_BASE_URL}/api/v1/notes/${noteId}/collaborators/${userId}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    })

    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.error || 'Failed to remove collaborator')
    }

    // Refresh collaborators list
    await get().fetchCollaborators(noteId)
  },

  fetchCollaborators: async (noteId: string) => {
    const token = localStorage.getItem('token')
    if (!token) throw new Error('No authentication token')

    const response = await fetch(`${API_BASE_URL}/api/v1/notes/${noteId}/collaborators`, {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    })

    if (response.ok) {
      const data = await response.json()
      set({ collaborators: data.collaborators || [] })
    }
  },

  fetchSharedNotes: async () => {
    const token = localStorage.getItem('token')
    if (!token) throw new Error('No authentication token')

    const response = await fetch(`${API_BASE_URL}/api/v1/notes/shared`, {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    })

    if (response.ok) {
      const data = await response.json()
      return data.notes || []
    }
    return []
  },

  // Real-time editing
  sendEdit: (edit: Omit<EditMessage, 'timestamp' | 'user_id'>) => {
    const { socket, currentUserId } = get()
    if (!socket || !currentUserId || socket.readyState !== WebSocket.OPEN) return

    const fullEdit: EditMessage = {
      ...edit,
      timestamp: Date.now(),
      user_id: currentUserId,
    }

    const message = {
      type: 'edit',
      content: fullEdit,
    }

    socket.send(JSON.stringify(message))

    // Add to pending edits for optimistic updates
    set(state => ({
      pendingEdits: [...state.pendingEdits, fullEdit],
    }))
  },

  sendCursor: (position: number, length: number) => {
    const { socket, currentUserId } = get()
    if (!socket || !currentUserId || socket.readyState !== WebSocket.OPEN) return

    const message = {
      type: 'cursor',
      content: {
        user_id: currentUserId,
        position,
        length,
      },
    }

    socket.send(JSON.stringify(message))
  },

  sendPresence: (status: 'typing' | 'idle') => {
    const { socket, currentUserId } = get()
    if (!socket || !currentUserId || socket.readyState !== WebSocket.OPEN) return

    const message = {
      type: 'presence',
      content: {
        user_id: currentUserId,
        status,
      },
    }

    socket.send(JSON.stringify(message))
  },

  // Event handlers
  handleIncomingEdit: (edit: EditMessage) => {
    const { currentUserId } = get()

    // Don't process our own edits
    if (edit.user_id === currentUserId) return

    set(() => ({
      isProcessingEdit: true,
    }))

    // Apply the edit to the document
    // This would integrate with your editor component
    console.log('Received edit:', edit)

    setTimeout(() => {
      set({ isProcessingEdit: false })
    }, 100)
  },

  handleIncomingCursor: (cursor: CursorMessage) => {
    const { currentUserId } = get()

    // Don't process our own cursor updates
    if (cursor.user_id === currentUserId) return

    console.log('Received cursor update:', cursor)
    // Update cursor position in the editor
  },

  handlePresenceUpdate: (presence: PresenceUser) => {
    const { currentUserId } = get()

    // Don't process our own presence updates
    if (presence.user_id === currentUserId) return

    set(state => {
      const existingUserIndex = state.presenceUsers.findIndex(
        user => user.user_id === presence.user_id
      )

      let newPresenceUsers
      if (existingUserIndex >= 0) {
        // Update existing user
        newPresenceUsers = [...state.presenceUsers]
        newPresenceUsers[existingUserIndex] = presence
      } else {
        // Add new user
        newPresenceUsers = [...state.presenceUsers, presence]
      }

      // Remove offline users after a delay
      if (presence.status === 'offline') {
        setTimeout(() => {
          set(state => ({
            presenceUsers: state.presenceUsers.filter(
              user => user.user_id !== presence.user_id
            ),
          }))
        }, 5000)
      }

      return { presenceUsers: newPresenceUsers }
    })
  },
}))