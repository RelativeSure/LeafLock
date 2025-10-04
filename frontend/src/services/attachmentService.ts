import { resolveApiBaseUrl } from '@/utils/network'
import { getStoredAuthToken } from '@/utils/auth'

/**
 * Attachment service for handling file uploads and downloads
 */

export interface Attachment {
  id: string
  note_id: string
  filename: string
  mime_type: string
  size_bytes: number
  created_at: string
  download_url: string
}

interface UploadResponse {
  id: string
  note_id: string
  filename: string
  mime_type: string
  size_bytes: number
  created_at: string
  download_url: string
}

class AttachmentService {
  private baseUrl: string

  constructor() {
    this.baseUrl = resolveApiBaseUrl()
  }

  private getAuthHeaders(): Record<string, string> {
    const token = getStoredAuthToken()
    const csrfToken = localStorage.getItem('csrf_token')

    const headers: Record<string, string> = {}

    if (token) {
      headers['Authorization'] = `Bearer ${token}`
    }

    if (csrfToken) {
      headers['X-CSRF-Token'] = csrfToken
    }

    return headers
  }

  /**
   * Upload a file as an attachment to a note
   */
  async uploadAttachment(noteId: string, file: File): Promise<UploadResponse> {
    const formData = new FormData()
    formData.append('file', file)

    const response = await fetch(`${this.baseUrl}/api/v1/notes/${noteId}/attachments`, {
      method: 'POST',
      headers: this.getAuthHeaders(),
      body: formData,
    })

    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.error || 'Failed to upload attachment')
    }

    return response.json()
  }

  /**
   * Get all attachments for a note
   */
  async getAttachments(noteId: string): Promise<Attachment[]> {
    const response = await fetch(`${this.baseUrl}/api/v1/notes/${noteId}/attachments`, {
      headers: this.getAuthHeaders(),
    })

    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.error || 'Failed to fetch attachments')
    }

    return response.json()
  }

  /**
   * Download an attachment
   */
  async downloadAttachment(noteId: string, attachmentId: string): Promise<Blob> {
    const response = await fetch(`${this.baseUrl}/api/v1/notes/${noteId}/attachments/${attachmentId}`, {
      headers: this.getAuthHeaders(),
    })

    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.error || 'Failed to download attachment')
    }

    return response.blob()
  }

  /**
   * Delete an attachment
   */
  async deleteAttachment(noteId: string, attachmentId: string): Promise<void> {
    const response = await fetch(`${this.baseUrl}/api/v1/notes/${noteId}/attachments/${attachmentId}`, {
      method: 'DELETE',
      headers: this.getAuthHeaders(),
    })

    if (!response.ok) {
      const error = await response.json()
      throw new Error(error.error || 'Failed to delete attachment')
    }
  }

  /**
   * Get the download URL for an attachment (for embedding in editor)
   */
  getAttachmentUrl(noteId: string, attachmentId: string): string {
    const token = getStoredAuthToken()
    const csrfToken = localStorage.getItem('csrf_token')

    const params = new URLSearchParams()
    if (token) params.append('token', token)
    if (csrfToken) params.append('csrf', csrfToken)

    return `${this.baseUrl}/api/v1/notes/${noteId}/attachments/${attachmentId}?${params.toString()}`
  }
}

export const attachmentService = new AttachmentService()
