import { resolveApiBaseUrl } from '@/utils/network'
import { getStoredAuthToken } from '@/utils/auth'

/**
 * Tags service for managing note tags
 */

export interface Tag {
  id: string
  name: string
  color: string
  created_at: string
  updated_at: string
}

export interface CreateTagRequest {
  name: string
  color?: string
}

export interface AssignTagRequest {
  tag_id: string
}

export interface TagsResponse {
  tags: Tag[]
}

export interface NotesResponse {
  notes: Array<{
    id: string
    title: string
    content: string
    created_at: string
    updated_at: string
  }>
}

class TagsService {
  private baseUrl: string

  constructor() {
    this.baseUrl = resolveApiBaseUrl()
  }

  private getAuthHeaders(): Record<string, string> {
    const token = getStoredAuthToken()
    const csrfToken = localStorage.getItem('csrf_token')

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    }

    if (token) {
      headers['Authorization'] = `Bearer ${token}`
    }

    if (csrfToken) {
      headers['X-CSRF-Token'] = csrfToken
    }

    return headers
  }

  /**
   * Get all tags for the current user
   */
  async getTags(): Promise<Tag[]> {
    const response = await fetch(`${this.baseUrl}/tags`, {
      method: 'GET',
      headers: this.getAuthHeaders(),
    })

    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.error || 'Failed to fetch tags')
    }

    const data: TagsResponse = await response.json()
    return data.tags
  }

  /**
   * Create a new tag
   */
  async createTag(tag: CreateTagRequest): Promise<Tag> {
    const response = await fetch(`${this.baseUrl}/tags`, {
      method: 'POST',
      headers: this.getAuthHeaders(),
      body: JSON.stringify(tag),
    })

    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.error || 'Failed to create tag')
    }

    return response.json()
  }

  /**
   * Delete a tag
   */
  async deleteTag(tagId: string): Promise<void> {
    const response = await fetch(`${this.baseUrl}/tags/${tagId}`, {
      method: 'DELETE',
      headers: this.getAuthHeaders(),
    })

    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.error || 'Failed to delete tag')
    }
  }

  /**
   * Get notes associated with a tag
   */
  async getNotesByTag(tagId: string): Promise<NotesResponse['notes']> {
    const response = await fetch(`${this.baseUrl}/tags/${tagId}/notes`, {
      method: 'GET',
      headers: this.getAuthHeaders(),
    })

    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.error || 'Failed to fetch notes by tag')
    }

    const data: NotesResponse = await response.json()
    return data.notes
  }

  /**
   * Assign a tag to a note
   */
  async assignTagToNote(noteId: string, tagId: string): Promise<void> {
    const response = await fetch(`${this.baseUrl}/notes/${noteId}/tags`, {
      method: 'POST',
      headers: this.getAuthHeaders(),
      body: JSON.stringify({ tag_id: tagId }),
    })

    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.error || 'Failed to assign tag to note')
    }
  }

  /**
   * Remove a tag from a note
   */
  async removeTagFromNote(noteId: string, tagId: string): Promise<void> {
    const response = await fetch(`${this.baseUrl}/notes/${noteId}/tags/${tagId}`, {
      method: 'DELETE',
      headers: this.getAuthHeaders(),
    })

    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.error || 'Failed to remove tag from note')
    }
  }
}

export const tagsService = new TagsService()
