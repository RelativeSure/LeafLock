import { ApiClient } from './apiClient'
import { Note } from './types'

class SocialService extends ApiClient {
  // Collaboration methods
  async shareNote(
    noteId: string,
    userEmail: string,
    permission: 'read' | 'write' | 'admin' = 'read'
  ): Promise<void> {
    await this.request(`/notes/${noteId}/share`, {
      method: 'POST',
      body: JSON.stringify({ user_email: userEmail, permission }),
    })
  }

  async getCollaborators(noteId: string): Promise<any[]> {
    return this.request<any[]>(`/notes/${noteId}/collaborators`)
  }

  async removeCollaborator(noteId: string, userId: string): Promise<void> {
    await this.request(`/notes/${noteId}/collaborators/${userId}`, {
      method: 'DELETE',
    })
  }

  async updateCollaboratorPermission(
    noteId: string,
    userId: string,
    permission: string
  ): Promise<void> {
    await this.request(`/notes/${noteId}/collaborators/${userId}`, {
      method: 'PUT',
      body: JSON.stringify({ permission }),
    })
  }

  async getSharedNotes(): Promise<Note[]> {
    return this.request<Note[]>('/collaborations')
  }

  // Note links methods
  async createNoteLink(
    sourceNoteId: string,
    targetNoteId: string,
    linkText?: string
  ): Promise<any> {
    return this.request(`/notes/${sourceNoteId}/links`, {
      method: 'POST',
      body: JSON.stringify({ target_note_id: targetNoteId, link_text: linkText }),
    })
  }

  async getNoteLinks(noteId: string): Promise<{ links: any[] }> {
    return this.request(`/notes/${noteId}/links`)
  }

  async getNoteBacklinks(noteId: string): Promise<{ backlinks: any[] }> {
    return this.request(`/notes/${noteId}/backlinks`)
  }

  async deleteNoteLink(noteId: string, linkId: string): Promise<void> {
    await this.request(`/notes/${noteId}/links/${linkId}`, {
      method: 'DELETE',
    })
  }

  // Share links methods
  async createShareLink(noteId: string, options: any): Promise<any> {
    return this.request(`/notes/${noteId}/share-links`, {
      method: 'POST',
      body: JSON.stringify(options),
    })
  }

  async getNoteShareLinks(noteId: string): Promise<any[]> {
    return this.request<any[]>(`/notes/${noteId}/share-links`)
  }

  async getAllShareLinks(): Promise<any[]> {
    return this.request<any[]>('/share-links')
  }

  async revokeShareLink(token: string): Promise<void> {
    await this.request(`/share-links/${token}`, {
      method: 'DELETE',
    })
  }

  async updateShareLink(token: string, options: any): Promise<any> {
    return this.request(`/share-links/${token}`, {
      method: 'PUT',
      body: JSON.stringify(options),
    })
  }

  // Pin/Lock methods
  async togglePin(noteId: string, isPinned: boolean, pinnedOrder?: number): Promise<any> {
    return this.request(`/notes/${noteId}/pin`, {
      method: 'POST',
      body: JSON.stringify({
        is_pinned: isPinned,
        pinned_order: pinnedOrder,
      }),
    })
  }

  async toggleLock(noteId: string, isLocked: boolean): Promise<any> {
    return this.request(`/notes/${noteId}/lock`, {
      method: 'POST',
      body: JSON.stringify({
        is_locked: isLocked,
      }),
    })
  }
}

export const socialService = new SocialService()
