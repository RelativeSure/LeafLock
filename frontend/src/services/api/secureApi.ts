import { config } from '@/lib/config'
import { clearAuthStorage, safeRedirectToLogin, isOnAuthRoute } from '@/lib/navigation'

const API_BASE_URL = config.apiUrl

const DEFAULT_NOTE_FIELDS = {
  folderId: null,
  tags: [] as string[],
  sharedWith: [] as string[],
  isTemplate: false,
  isTrashed: false,
  pinned: false,
}

function normalizeNoteResponse(note: any): Note {
  if (!note) {
    throw new Error('Invalid note payload received from API')
  }

  const createdAt = note.created_at || note.createdAt || new Date().toISOString()
  const updatedAt = note.updated_at || note.updatedAt || createdAt
  const deletedAt = note.deleted_at || note.trashed_at || null
  const tags = Array.isArray(note.tags) ? [...note.tags] : [...DEFAULT_NOTE_FIELDS.tags]
  const sharedWith = Array.isArray(note.shared_with)
    ? [...note.shared_with]
    : Array.isArray(note.sharedWith)
      ? [...note.sharedWith]
      : [...DEFAULT_NOTE_FIELDS.sharedWith]
  const pinned = typeof note.pinned === 'boolean' ? note.pinned : DEFAULT_NOTE_FIELDS.pinned
  const userId = note.user_id || note.userId || ''

  return {
    id: note.id,
    title: note.title_encrypted ?? note.title ?? '',
    content: note.content_encrypted ?? note.content ?? '',
    folderId: note.folder_id ?? note.folderId ?? DEFAULT_NOTE_FIELDS.folderId,
    tags,
    encrypted: true,
    createdAt,
    updatedAt,
    userId,
    sharedWith,
    isTemplate: note.is_template ?? note.isTemplate ?? DEFAULT_NOTE_FIELDS.isTemplate,
    isTrashed: deletedAt != null,
    trashedAt: deletedAt ?? undefined,
    pinned,
    encryptionVersion: note.encryption_version ?? note.encryptionVersion,
  }
}

interface LoginResponse {
  token: string
  user: {
    id: string
    email: string
    name: string
    role: 'admin' | 'user'
    mfaEnabled: boolean
    createdAt: string
  }
  requiresMFA?: boolean
  encryptionSalt?: string
  encryptionVersion?: number
}

interface RegisterResponse {
  token: string
  user: {
    id: string
    email: string
    name: string
    role: 'admin' | 'user'
    mfaEnabled: boolean
    createdAt: string
  }
  encryptionSalt?: string
  encryptionVersion?: number
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
  encryptionVersion?: number
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
  content?: string
  description?: string
  tags: string[]
  icon?: string | null
  isPublic: boolean
  userId?: string | null
  createdAt: string
  updatedAt?: string
  usageCount: number
}

interface Tag {
  id: string
  name: string
  color: string
  userId: string
}

interface NoteVersion {
  id: string
  noteId: string
  title: string
  content: string
  createdAt: string
  createdBy: string
  changeDescription?: string
  versionNumber: number
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
  defaultNoteBehavior: 'last-seen' | 'new-note'
  profilePicture: {
    type: 'gravatar' | 'initials' | 'custom'
    customUrl?: string
  }
}

class ApiClient {
  private baseURL: string
  private token: string | null = null

  constructor(baseURL: string = API_BASE_URL) {
    this.baseURL = baseURL
    this.token = typeof window !== 'undefined' ? localStorage.getItem('token') : null
  }

  private refreshToken(): void {
    if (typeof window !== 'undefined') {
      this.token = localStorage.getItem('token')
    }
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

    // Always refresh token from localStorage before making requests to ensure it's current
    // This handles cases where token was set in another tab/window or after page reload
    this.refreshToken()

    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`
    }

    const response = await fetch(url, {
      ...options,
      headers,
    })

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))

      // Handle 401 Unauthorized - token expired
      if (response.status === 401) {
        console.warn('401 Unauthorized - clearing expired session')
        clearAuthStorage()
        if (typeof window !== 'undefined' && !isOnAuthRoute()) {
          // Small timeout to allow UI to settle before navigation
          setTimeout(() => safeRedirectToLogin(), 50)
        }
      }

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
    const response = await this.request<any>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    })

    if (response.token) {
      this.token = response.token

      // Transform backend response to frontend format
      const transformedResponse: LoginResponse = {
        token: response.token,
        user: {
          id: response.user_id || '',
          email: email, // Store the email we used for login
          name: '', // We'll get the name from other endpoints or registration
          role: response.is_admin ? 'admin' : 'user',
          mfaEnabled: response.mfa_required || false,
          createdAt: new Date().toISOString(),
        },
        requiresMFA: response.mfa_required,
        encryptionSalt: response.encryption_salt,
        encryptionVersion: response.encryption_version,
      }

      if (typeof window !== 'undefined') {
        localStorage.setItem('token', response.token)
        localStorage.setItem('user', JSON.stringify(transformedResponse.user))
        // Ensure token is synced immediately
        this.token = response.token
      }

      return transformedResponse
    }

    return response
  }

  async register(email: string, password: string, name: string): Promise<RegisterResponse> {
    const response = await this.request<any>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, name }),
    })

    if (response.token) {
      this.token = response.token

      // Transform backend response to frontend format
      const transformedResponse: RegisterResponse = {
        token: response.token,
        user: {
          id: response.user_id || '',
          email: email,
          name: name,
          role: response.is_admin ? 'admin' : 'user',
          mfaEnabled: false,
          createdAt: new Date().toISOString(),
        },
        encryptionSalt: response.encryption_salt,
        encryptionVersion: response.encryption_version,
      }

      if (typeof window !== 'undefined') {
        localStorage.setItem('token', response.token)
        localStorage.setItem('user', JSON.stringify(transformedResponse.user))
        // Ensure token is synced immediately after localStorage write
        this.token = response.token
      }

      return transformedResponse
    }

    return response
  }

  async verifyMFA(code: string): Promise<LoginResponse> {
    const response = await this.request<any>('/auth/mfa/verify', {
      method: 'POST',
      body: JSON.stringify({ code }),
    })

    if (response.token) {
      this.token = response.token

      // Get the stored user data to preserve email and name
      let storedUser: any = {}
      if (typeof window !== 'undefined') {
        const userStr = localStorage.getItem('user')
        if (userStr) {
          storedUser = JSON.parse(userStr)
        }
      }

      // Transform backend response to frontend format
      const transformedResponse: LoginResponse = {
        token: response.token,
        user: {
          id: response.user_id || storedUser.id || '',
          email: storedUser.email || '',
          name: storedUser.name || '',
          role: response.is_admin ? 'admin' : 'user',
          mfaEnabled: true,
          createdAt: storedUser.createdAt || new Date().toISOString(),
        },
        requiresMFA: false,
        encryptionSalt: response.encryption_salt,
        encryptionVersion: response.encryption_version,
      }

      if (typeof window !== 'undefined') {
        localStorage.setItem('token', response.token)
        localStorage.setItem('user', JSON.stringify(transformedResponse.user))
        // Ensure token is synced immediately after localStorage write
        this.token = response.token
      }

      return transformedResponse
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
    const response = await this.request<{ notes: any[] }>('/notes')
    return (response.notes || []).map(normalizeNoteResponse)
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
    // Backend expects base64-encoded strings
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
    const response = await this.request<{ folders: Folder[] }>('/folders')
    return response.folders || []
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
    return this.request<Note>(`/templates/${id}/use`, {
      method: 'POST',
    })
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
      body: JSON.stringify({ noteIds, folderId }),
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
