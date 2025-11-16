import { ApiClient } from './apiClient'
import { Note, Folder, Template, NoteVersion, normalizeNoteResponse } from './types'

class ContentService extends ApiClient {
  // Notes methods
  async getNotes(): Promise<Note[]> {
    const response = await this.request<{ notes: any[] }>('/notes')
    const notes = response?.notes
    if (!Array.isArray(notes)) {
      return []
    }
    return notes.map(normalizeNoteResponse)
  }

  async getNote(id: string): Promise<Note> {
    const response = await this.request<any>(`/notes/${id}`)
    if (response && typeof response === 'object' && 'note' in response) {
      return normalizeNoteResponse(response.note)
    }
    return normalizeNoteResponse(response)
  }

  async createNote(note: Partial<Note>): Promise<Note> {
    // Send encrypted data as expected by backend
    const noteData = {
      title_encrypted: note.title || '',
      content_encrypted: note.content || '',
      folderId: note.folderId,
      tags: note.tags || [],
      pinned: note.pinned,
      encryption_version: note.encryptionVersion,
    }

    const response = await this.request<any>('/notes', {
      method: 'POST',
      body: JSON.stringify(noteData),
    })

    if (response && typeof response === 'object' && 'note' in response) {
      return normalizeNoteResponse(response.note)
    }

    return normalizeNoteResponse(response)
  }

  async updateNote(id: string, note: Partial<Note>): Promise<Note> {
    // Send encrypted data as expected by backend
    const noteData = {
      title_encrypted: note.title || '',
      content_encrypted: note.content || '',
      folderId: note.folderId,
      tags: note.tags,
      pinned: note.pinned,
      encryption_version: note.encryptionVersion,
    }

    const response = await this.request<any>(`/notes/${id}`, {
      method: 'PUT',
      body: JSON.stringify(noteData),
    })

    if (response && typeof response === 'object' && 'note' in response) {
      return normalizeNoteResponse(response.note)
    }

    return normalizeNoteResponse(response)
  }

  async deleteNote(id: string): Promise<void> {
    await this.request(`/notes/${id}`, {
      method: 'DELETE',
    })
  }

  async getTrash(): Promise<Note[]> {
    const response = await this.request<{ notes: any[] }>('/notes/trash')
    return (response.notes || []).map(normalizeNoteResponse)
  }

  async restoreNote(id: string): Promise<void> {
    await this.request(`/notes/${id}/restore`, {
      method: 'POST',
    })
  }

  async permanentlyDeleteNote(id: string): Promise<void> {
    await this.request(`/notes/${id}/permanent`, {
      method: 'DELETE',
    })
  }

  async searchNotes(query: string): Promise<Note[]> {
    const response = await this.request<{ notes: any[] }>(
      `/notes/search?q=${encodeURIComponent(query)}`
    )
    return (response.notes || []).map(normalizeNoteResponse)
  }

  // Folders methods
  async getFolders(): Promise<Folder[]> {
    const response = await this.request<{ folders: Folder[] }>('/folders')
    return response.folders || []
  }

  async getFolderTree(): Promise<Folder[]> {
    const response = await this.request<{ folders: Folder[] }>('/folders/tree')
    return response.folders || []
  }

  async createFolder(folder: Partial<Folder>): Promise<Folder> {
    return this.request<Folder>('/folders', {
      method: 'POST',
      body: JSON.stringify(folder),
    })
  }

  async updateFolder(id: string, folder: Partial<Folder>): Promise<Folder> {
    return this.request<Folder>(`/folders/${id}`, {
      method: 'PUT',
      body: JSON.stringify(folder),
    })
  }

  async deleteFolder(id: string): Promise<void> {
    await this.request(`/folders/${id}`, {
      method: 'DELETE',
    })
  }

  async moveFolderToParent(folderId: string, parentId: string | null): Promise<void> {
    await this.request(`/folders/${folderId}/move`, {
      method: 'POST',
      body: JSON.stringify({ parent_id: parentId }),
    })
  }

  async moveNoteToFolder(noteId: string, folderId: string): Promise<void> {
    await this.request(`/notes/${noteId}/folder`, {
      method: 'POST',
      body: JSON.stringify({ folder_id: folderId }),
    })
  }

  // Templates methods
  async getTemplates(): Promise<Template[]> {
    const response = await this.request<{ templates: any[] }>('/templates')
    const templates = Array.isArray(response.templates) ? response.templates : []
    return templates.map((template) => this.transformTemplateResponse(template))
  }

  async getTemplate(id: string): Promise<Template> {
    const response = await this.request<any>(`/templates/${id}`)
    return this.transformTemplateResponse(response)
  }

  async createTemplate(template: Partial<Template>): Promise<Template> {
    const payload = this.buildTemplatePayload(template)
    const response = await this.request<any>('/templates', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
    return this.transformTemplateResponse(response)
  }

  async updateTemplate(id: string, template: Partial<Template>): Promise<Template> {
    const payload = this.buildTemplatePayload(template)
    const response = await this.request<any>(`/templates/${id}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    })
    return this.transformTemplateResponse(response)
  }

  async deleteTemplate(id: string): Promise<void> {
    await this.request(`/templates/${id}`, {
      method: 'DELETE',
    })
  }

  async useTemplate(id: string): Promise<Note> {
    const response = await this.request<any>(`/templates/${id}/use`, {
      method: 'POST',
      body: JSON.stringify({}), // Backend expects request body
    })

    if (response && typeof response === 'object' && 'note' in response) {
      return normalizeNoteResponse(response.note)
    }

    return normalizeNoteResponse(response)
  }

  private buildTemplatePayload(template: Partial<Template>) {
    return {
      name: template.name ?? '',
      description: template.description ?? '',
      content: template.content ?? '',
      tags: template.tags ?? [],
      icon: template.icon ?? '',
      is_public: template.isPublic ?? false,
    }
  }

  private transformTemplateResponse(data: any): Template {
    if (!data) {
      throw new Error('Invalid template payload received from API')
    }

    const tags = Array.isArray(data.tags) ? data.tags : []
    const createdAtRaw = data.created_at ?? data.createdAt
    const updatedAtRaw = data.updated_at ?? data.updatedAt
    const userIdRaw = data.user_id ?? data.userId ?? null
    const usageCountRaw = data.usage_count ?? data.usageCount

    return {
      id: data.id,
      name: data.name ?? '',
      description: data.description ?? '',
      content: data.content ?? undefined,
      tags,
      icon: data.icon ?? null,
      isPublic: data.is_public ?? data.isPublic ?? false,
      userId: userIdRaw ?? null,
      createdAt: this.normalizeIsoString(createdAtRaw),
      updatedAt: updatedAtRaw ? this.normalizeIsoString(updatedAtRaw) : undefined,
      usageCount: typeof usageCountRaw === 'number' ? usageCountRaw : 0,
    }
  }

  private normalizeIsoString(value: any): string {
    if (!value) {
      return new Date().toISOString()
    }

    if (typeof value === 'string') {
      const parsed = new Date(value)
      if (!Number.isNaN(parsed.getTime())) {
        return parsed.toISOString()
      }
      return value
    }

    if (value instanceof Date) {
      return value.toISOString()
    }

    const parsed = new Date(value)
    if (!Number.isNaN(parsed.getTime())) {
      return parsed.toISOString()
    }

    return new Date().toISOString()
  }

  // Version methods
  async createNoteVersion(data: {
    noteId: string
    title: string
    content: string
    changeDescription?: string
  }): Promise<NoteVersion> {
    return this.request<NoteVersion>('/notes/versions', {
      method: 'POST',
      body: JSON.stringify(data),
    })
  }

  async getNoteVersions(noteId: string): Promise<NoteVersion[]> {
    return this.request<NoteVersion[]>(`/notes/${noteId}/versions`)
  }

  async restoreNoteVersion(versionId: string): Promise<Note> {
    return this.request<Note>(`/notes/versions/${versionId}/restore`, {
      method: 'POST',
    })
  }

  async deleteNoteVersion(versionId: string): Promise<void> {
    await this.request<void>(`/notes/versions/${versionId}`, {
      method: 'DELETE',
    })
  }

  async compareNoteVersions(
    noteId: string,
    v1: number,
    v2: number
  ): Promise<{ v1: NoteVersion; v2: NoteVersion }> {
    return this.request<{ v1: NoteVersion; v2: NoteVersion }>(
      `/notes/${noteId}/versions/compare?v1=${v1}&v2=${v2}`
    )
  }

  async updateRetentionPolicy(noteId: string, policy: number): Promise<void> {
    await this.request<void>(`/notes/${noteId}/retention`, {
      method: 'PUT',
      body: JSON.stringify({ retention_policy: policy }),
    })
  }

  // Bulk operations
  async bulkDeleteNotes(
    noteIds: string[]
  ): Promise<{ successful: number; failed: number; errors: string[] }> {
    return this.request<{ successful: number; failed: number; errors: string[] }>(
      '/notes/bulk/delete',
      {
        method: 'POST',
        body: JSON.stringify({ note_ids: noteIds }),
      }
    )
  }

  async bulkRestoreNotes(
    noteIds: string[]
  ): Promise<{ successful: number; failed: number; errors: string[] }> {
    return this.request<{ successful: number; failed: number; errors: string[] }>(
      '/notes/bulk/restore',
      {
        method: 'POST',
        body: JSON.stringify({ note_ids: noteIds }),
      }
    )
  }

  async bulkPermanentlyDeleteNotes(
    noteIds: string[]
  ): Promise<{ successful: number; failed: number; errors: string[] }> {
    return this.request<{ successful: number; failed: number; errors: string[] }>(
      '/notes/bulk/permanent-delete',
      {
        method: 'POST',
        body: JSON.stringify({ note_ids: noteIds }),
      }
    )
  }

  async moveNotesToFolder(noteIds: string[], folderId: string): Promise<void> {
    await this.request<void>('/notes/bulk/move', {
      method: 'POST',
      body: JSON.stringify({ note_ids: noteIds, folder_id: folderId }),
    })
  }

  async addTagsToNotes(noteIds: string[], tagNames: string[]): Promise<void> {
    await this.request<void>('/notes/bulk/tags/add', {
      method: 'POST',
      body: JSON.stringify({ noteIds, tagNames }),
    })
  }

  async removeTagsFromNotes(noteIds: string[], tagNames: string[]): Promise<void> {
    await this.request<void>('/notes/bulk/tags/remove', {
      method: 'POST',
      body: JSON.stringify({ noteIds, tagNames }),
    })
  }
}

export const contentService = new ContentService()
