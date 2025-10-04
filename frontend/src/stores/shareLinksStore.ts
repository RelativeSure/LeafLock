import { create } from 'zustand'
import { resolveApiBaseUrl } from '@/utils/network'

export interface ShareLink {
  id: string
  token: string
  note_id: string
  note_title?: string
  permission: 'read' | 'write'
  expires_at?: string
  max_uses?: number
  use_count: number
  is_active: boolean
  has_password: boolean
  created_at: string
  last_accessed_at?: string
  share_url: string
}

export interface CreateShareLinkRequest {
  permission: 'read' | 'write'
  expires_in?: string // "1h", "24h", "7d", "30d", or null for never
  max_uses?: number
  password?: string
}

export interface SharedNoteData {
  id: string
  title_encrypted: Uint8Array
  content_encrypted: Uint8Array
  created_at: string
  updated_at: string
  permission: 'read' | 'write'
  shared_by: string
  is_shared_access: boolean
}

interface ShareLinksState {
  shareLinks: ShareLink[]
  currentNoteLinks: ShareLink[]
  isLoading: boolean
  error: string | null

  // Actions
  createShareLink: (noteId: string, config: CreateShareLinkRequest) => Promise<ShareLink>
  fetchNoteShareLinks: (noteId: string) => Promise<void>
  fetchAllUserLinks: () => Promise<void>
  revokeShareLink: (token: string) => Promise<void>
  updateShareLink: (token: string, updates: Partial<CreateShareLinkRequest>) => Promise<void>
  copyLinkToClipboard: (url: string) => Promise<void>

  // Public share link access
  getSharedNote: (token: string, password?: string) => Promise<SharedNoteData>
}

const API_BASE_URL = resolveApiBaseUrl()

export const useShareLinksStore = create<ShareLinksState>((set, get) => ({
  shareLinks: [],
  currentNoteLinks: [],
  isLoading: false,
  error: null,

  createShareLink: async (noteId: string, config: CreateShareLinkRequest) => {
    set({ isLoading: true, error: null })
    const token = localStorage.getItem('token')
    if (!token) throw new Error('No authentication token')

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/notes/${noteId}/share-links`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify(config),
      })

      if (!response.ok) {
        const error = await response.json()
        throw new Error(error.error || 'Failed to create share link')
      }

      const shareLink = await response.json()

      // Refresh the current note's links
      await get().fetchNoteShareLinks(noteId)

      set({ isLoading: false })
      return shareLink
    } catch (error) {
      set({
        isLoading: false,
        error: error instanceof Error ? error.message : 'Failed to create share link'
      })
      throw error
    }
  },

  fetchNoteShareLinks: async (noteId: string) => {
    set({ isLoading: true, error: null })
    const token = localStorage.getItem('token')
    if (!token) throw new Error('No authentication token')

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/notes/${noteId}/share-links`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      })

      if (!response.ok) {
        throw new Error('Failed to fetch share links')
      }

      const data = await response.json()
      set({
        currentNoteLinks: data.share_links || [],
        isLoading: false
      })
    } catch (error) {
      set({
        isLoading: false,
        error: error instanceof Error ? error.message : 'Failed to fetch share links'
      })
      throw error
    }
  },

  fetchAllUserLinks: async () => {
    set({ isLoading: true, error: null })
    const token = localStorage.getItem('token')
    if (!token) throw new Error('No authentication token')

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/share-links`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      })

      if (!response.ok) {
        throw new Error('Failed to fetch share links')
      }

      const data = await response.json()
      set({
        shareLinks: data.share_links || [],
        isLoading: false
      })
    } catch (error) {
      set({
        isLoading: false,
        error: error instanceof Error ? error.message : 'Failed to fetch share links'
      })
      throw error
    }
  },

  revokeShareLink: async (token: string) => {
    set({ isLoading: true, error: null })
    const authToken = localStorage.getItem('token')
    if (!authToken) throw new Error('No authentication token')

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/share-links/${token}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${authToken}`,
        },
      })

      if (!response.ok) {
        const error = await response.json()
        throw new Error(error.error || 'Failed to revoke share link')
      }

      // Remove from local state
      set(state => ({
        shareLinks: state.shareLinks.filter(link => link.token !== token),
        currentNoteLinks: state.currentNoteLinks.filter(link => link.token !== token),
        isLoading: false
      }))
    } catch (error) {
      set({
        isLoading: false,
        error: error instanceof Error ? error.message : 'Failed to revoke share link'
      })
      throw error
    }
  },

  updateShareLink: async (token: string, updates: Partial<CreateShareLinkRequest>) => {
    set({ isLoading: true, error: null })
    const authToken = localStorage.getItem('token')
    if (!authToken) throw new Error('No authentication token')

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/share-links/${token}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`,
        },
        body: JSON.stringify(updates),
      })

      if (!response.ok) {
        const error = await response.json()
        throw new Error(error.error || 'Failed to update share link')
      }

      set({ isLoading: false })
    } catch (error) {
      set({
        isLoading: false,
        error: error instanceof Error ? error.message : 'Failed to update share link'
      })
      throw error
    }
  },

  copyLinkToClipboard: async (url: string) => {
    try {
      await navigator.clipboard.writeText(url)
    } catch (error) {
      throw new Error('Failed to copy link to clipboard')
    }
  },

  getSharedNote: async (token: string, password?: string) => {
    set({ isLoading: true, error: null })

    try {
      const headers: HeadersInit = {
        'Content-Type': 'application/json',
      }

      if (password) {
        headers['X-Share-Password'] = password
      }

      const response = await fetch(`${API_BASE_URL}/api/v1/share/${token}`, {
        method: 'GET',
        headers,
      })

      if (!response.ok) {
        const error = await response.json()
        throw new Error(error.error || 'Failed to access shared note')
      }

      const data = await response.json()

      // Convert base64 encrypted data to Uint8Array if needed
      const sharedNote: SharedNoteData = {
        ...data,
        title_encrypted: typeof data.title_encrypted === 'string'
          ? new Uint8Array(Buffer.from(data.title_encrypted, 'base64'))
          : data.title_encrypted,
        content_encrypted: typeof data.content_encrypted === 'string'
          ? new Uint8Array(Buffer.from(data.content_encrypted, 'base64'))
          : data.content_encrypted,
      }

      set({ isLoading: false })
      return sharedNote
    } catch (error) {
      set({
        isLoading: false,
        error: error instanceof Error ? error.message : 'Failed to access shared note'
      })
      throw error
    }
  },
}))
