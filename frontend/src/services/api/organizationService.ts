import { ApiClient } from './apiClient'
import { Tag, UserSettings, Note } from './types'

class OrganizationService extends ApiClient {
  // Tags methods
  async getTags(): Promise<Tag[]> {
    const response = await this.request<{ tags: Tag[] }>('/tags')
    return response.tags || []
  }

  async createTag(tag: Partial<Tag>): Promise<Tag> {
    return this.request<Tag>('/tags', {
      method: 'POST',
      body: JSON.stringify(tag),
    })
  }

  async deleteTag(id: string): Promise<void> {
    await this.request(`/tags/${id}`, {
      method: 'DELETE',
    })
  }

  async assignTagToNote(noteId: string, tagId: string): Promise<void> {
    await this.request(`/notes/${noteId}/tags`, {
      method: 'POST',
      body: JSON.stringify({ tag_id: tagId }),
    })
  }

  async removeTagFromNote(noteId: string, tagId: string): Promise<void> {
    await this.request(`/notes/${noteId}/tags/${tagId}`, {
      method: 'DELETE',
    })
  }

  async getNotesByTag(tagId: string): Promise<Note[]> {
    return this.request<Note[]>(`/tags/${tagId}/notes`)
  }

  // Settings methods
  async getSettings(): Promise<UserSettings> {
    return this.request<UserSettings>('/settings')
  }

  async updateSettings(settings: Partial<UserSettings>): Promise<UserSettings> {
    return this.request<UserSettings>('/settings', {
      method: 'PUT',
      body: JSON.stringify(settings),
    })
  }

  // Health check
  async healthCheck(): Promise<any> {
    return this.request('/health')
  }
}

export const organizationService = new OrganizationService()
