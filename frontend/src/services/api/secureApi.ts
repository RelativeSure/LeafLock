const API_BASE_URL =
  import.meta.env.VITE_API_URL ||
  (typeof window !== 'undefined'
    ? window.location.origin + '/api/v1'
    : 'http://localhost:8080/api/v1')

interface LoginResponse {
  token: string
  user: {
    id: string
    email: string
    name: string
    mfaEnabled: boolean
    createdAt: string
  }
  requiresMFA?: boolean
}

interface RegisterResponse {
  token: string
  user: {
    id: string
    email: string
    name: string
    mfaEnabled: boolean
    createdAt: string
  }
}

interface MFAStatusResponse {
  enabled: boolean
  backupCodes?: string[]
}

interface Note {
  id: string
  title: string
  content: string
  folderId: string | null
  tags: string[]
  encrypted: boolean
  createdAt: string
  updatedAt: string
  userId: string
  sharedWith: string[]
  isTemplate: boolean
  isTrashed: boolean
  trashedAt?: string
  pinned?: boolean
}

interface Folder {
  id: string
  name: string
  color: string
  userId: string
  parentId: string | null
  createdAt: string
}

interface Template {
  id: string
  name: string
  content: string
  tags: string[]
  isPublic: boolean
  userId: string
  createdAt: string
  usageCount: number
}

interface Tag {
  id: string
  name: string
  color: string
  userId: string
}

interface UserSettings {
  theme: 'light' | 'dark' | 'system'
  autoSave: boolean
  autoSaveInterval: number
  defaultView: 'list' | 'grid'
  notificationsEnabled: boolean
  emailNotifications: boolean
  encryptionEnabled: boolean
  language: string
}

class ApiClient {
  private baseURL: string
  private token: string | null = null

  constructor(baseURL: string = API_BASE_URL) {
    this.baseURL = baseURL
    this.token = typeof window !== 'undefined' ? localStorage.getItem('token') : null
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.baseURL}${endpoint}`
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    }

    // Merge headers safely
    if (options.headers) {
      if (Array.isArray(options.headers)) {
        options.headers.forEach(([key, value]) => {
          headers[key] = value
        })
      } else if (options.headers instanceof Headers) {
        options.headers.forEach((value, key) => {
          headers[key] = value
        })
      } else {
        Object.assign(headers, options.headers)
      }
    }

    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`
    }

    const response = await fetch(url, {
      ...options,
      headers,
    })

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      throw new Error(errorData.message || errorData.error || `HTTP ${response.status}`)
    }

    // Handle empty responses (204 No Content)
    if (response.status === 204 || response.headers.get('content-length') === '0') {
      return {} as T
    }

    // Check if response has JSON content type
    const contentType = response.headers.get('content-type')
    if (!contentType || !contentType.includes('application/json')) {
      return {} as T
    }

    return response.json()
  }

  // Authentication methods
  async login(email: string, password: string): Promise<LoginResponse> {
    const response = await this.request<LoginResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    })

    if (response.token) {
      this.token = response.token
      if (typeof window !== 'undefined') {
        localStorage.setItem('token', response.token)
        localStorage.setItem('user', JSON.stringify(response.user))
      }
    }

    return response
  }

  async register(email: string, password: string, name: string): Promise<RegisterResponse> {
    const response = await this.request<RegisterResponse>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, name }),
    })

    if (response.token) {
      this.token = response.token
      if (typeof window !== 'undefined') {
        localStorage.setItem('token', response.token)
        localStorage.setItem('user', JSON.stringify(response.user))
      }
    }

    return response
  }

  async verifyMFA(code: string): Promise<LoginResponse> {
    const response = await this.request<LoginResponse>('/auth/mfa/verify', {
      method: 'POST',
      body: JSON.stringify({ code }),
    })

    if (response.token) {
      this.token = response.token
      if (typeof window !== 'undefined') {
        localStorage.setItem('token', response.token)
        localStorage.setItem('user', JSON.stringify(response.user))
      }
    }

    return response
  }

  async logout(): Promise<void> {
    this.token = null
    if (typeof window !== 'undefined') {
      localStorage.removeItem('token')
      localStorage.removeItem('user')
    }
  }

  async getMFAStatus(): Promise<MFAStatusResponse> {
    return this.request<MFAStatusResponse>('/auth/mfa/status')
  }

  async beginMFASetup(): Promise<{ secret: string; qrCode: string }> {
    return this.request<{ secret: string; qrCode: string }>('/auth/mfa/begin', {
      method: 'POST',
    })
  }

  async enableMFA(code: string): Promise<void> {
    await this.request('/auth/mfa/enable', {
      method: 'POST',
      body: JSON.stringify({ code }),
    })
  }

  async disableMFA(): Promise<void> {
    await this.request('/auth/mfa/disable', {
      method: 'POST',
    })
  }

  async getBackupCodes(): Promise<string[]> {
    const response = await this.request<{ backupCodes: string[] }>('/auth/mfa/backup-codes')
    return response.backupCodes
  }

  async regenerateBackupCodes(): Promise<string[]> {
    const response = await this.request<{ backupCodes: string[] }>(
      '/auth/mfa/backup-codes/regenerate',
      {
        method: 'POST',
      }
    )
    return response.backupCodes
  }

  // Notes methods
  async getNotes(): Promise<Note[]> {
    return this.request<Note[]>('/notes')
  }

  async getNote(id: string): Promise<Note> {
    return this.request<Note>(`/notes/${id}`)
  }

  async createNote(note: Partial<Note>): Promise<Note> {
    // Encrypt title and content before sending to backend
    const titleEncrypted = note.title ? btoa(unescape(encodeURIComponent(note.title))) : ''
    const contentEncrypted = note.content ? btoa(unescape(encodeURIComponent(note.content))) : ''

    const encryptedNote = {
      title_encrypted: titleEncrypted,
      content_encrypted: contentEncrypted,
      folderId: note.folderId,
      tags: note.tags,
      encrypted: note.encrypted,
      userId: note.userId,
    }

    return this.request<Note>('/notes', {
      method: 'POST',
      body: JSON.stringify(encryptedNote),
    })
  }

  async updateNote(id: string, note: Partial<Note>): Promise<Note> {
    // Encrypt title and content before sending to backend
    const encryptedNote: any = { ...note }

    if (note.title) {
      encryptedNote.title_encrypted = btoa(unescape(encodeURIComponent(note.title)))
      delete encryptedNote.title
    }

    if (note.content) {
      encryptedNote.content_encrypted = btoa(unescape(encodeURIComponent(note.content)))
      delete encryptedNote.content
    }

    return this.request<Note>(`/notes/${id}`, {
      method: 'PUT',
      body: JSON.stringify(encryptedNote),
    })
  }

  async deleteNote(id: string): Promise<void> {
    await this.request(`/notes/${id}`, {
      method: 'DELETE',
    })
  }

  async getTrash(): Promise<Note[]> {
    return this.request<Note[]>('/notes/trash')
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

  async getNoteVersions(id: string): Promise<any[]> {
    return this.request<any[]>(`/notes/${id}/versions`)
  }

  async restoreNoteVersion(id: string, version: string): Promise<void> {
    await this.request(`/notes/${id}/versions/${version}`, {
      method: 'POST',
    })
  }

  // Tags methods
  async getTags(): Promise<Tag[]> {
    return this.request<Tag[]>('/tags')
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
      body: JSON.stringify({ tagId }),
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

  // Folders methods
  async getFolders(): Promise<Folder[]> {
    return this.request<Folder[]>('/folders')
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

  async moveNoteToFolder(noteId: string, folderId: string): Promise<void> {
    await this.request(`/notes/${noteId}/folder`, {
      method: 'POST',
      body: JSON.stringify({ folderId }),
    })
  }

  // Templates methods
  async getTemplates(): Promise<Template[]> {
    return this.request<Template[]>('/templates')
  }

  async getTemplate(id: string): Promise<Template> {
    return this.request<Template>(`/templates/${id}`)
  }

  async createTemplate(template: Partial<Template>): Promise<Template> {
    // Encrypt template content before sending to backend
    const encryptedTemplate: any = { ...template }

    if (template.content) {
      encryptedTemplate.content_encrypted = btoa(unescape(encodeURIComponent(template.content)))
      delete encryptedTemplate.content
    }

    if (template.name) {
      encryptedTemplate.name_encrypted = btoa(unescape(encodeURIComponent(template.name)))
      delete encryptedTemplate.name
    }

    return this.request<Template>('/templates', {
      method: 'POST',
      body: JSON.stringify(encryptedTemplate),
    })
  }

  async updateTemplate(id: string, template: Partial<Template>): Promise<Template> {
    return this.request<Template>(`/templates/${id}`, {
      method: 'PUT',
      body: JSON.stringify(template),
    })
  }

  async deleteTemplate(id: string): Promise<void> {
    await this.request(`/templates/${id}`, {
      method: 'DELETE',
    })
  }

  async useTemplate(id: string): Promise<Note> {
    return this.request<Note>(`/templates/${id}/use`, {
      method: 'POST',
    })
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

  // Search methods
  async searchNotes(query: string): Promise<Note[]> {
    return this.request<Note[]>('/search', {
      method: 'POST',
      body: JSON.stringify({ query }),
    })
  }

  // Collaboration methods
  async shareNote(noteId: string, userIds: string[]): Promise<void> {
    await this.request(`/notes/${noteId}/share`, {
      method: 'POST',
      body: JSON.stringify({ userIds }),
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

  async getSharedNotes(): Promise<Note[]> {
    return this.request<Note[]>('/collaborations')
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

  // Health check
  async healthCheck(): Promise<any> {
    return this.request('/health')
  }

  // Check if registration is enabled
  async isRegistrationEnabled(): Promise<boolean> {
    const response = await this.request<{ enabled: boolean }>('/auth/registration')
    return response.enabled
  }

  async createFolder(folder: Partial<Folder>): Promise<Folder> {
    return this.request<Folder>('/folders', {
      method: 'POST',
      body: JSON.stringify(folder),
    })
  }
}

export const apiClient = new ApiClient()
export type { Note, Folder, Template, Tag, UserSettings, LoginResponse, RegisterResponse }
