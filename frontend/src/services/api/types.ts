import { config } from '@/lib/config'

export const API_BASE_URL = config.apiUrl

export const DEFAULT_NOTE_FIELDS = {
  folderId: null,
  tags: [] as string[],
  sharedWith: [] as string[],
  isTemplate: false,
  isTrashed: false,
  pinned: false,
}

export interface LoginResponse {
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
  mfaSession?: string
  encryptionSalt?: string
  encryptionVersion?: number
}

export interface RegisterResponse {
  message: string
}

export interface MFAStatusResponse {
  enabled: boolean
  backupCodes?: string[]
}

export interface Note {
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

export interface Folder {
  id: string
  name: string
  color: string
  userId: string
  parentId: string | null
  createdAt: string
}

export interface Template {
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

export interface Tag {
  id: string
  name: string
  color: string
  userId: string
}

export interface NoteVersion {
  id: string
  noteId: string
  title: string
  content: string
  createdAt: string
  createdBy: string
  changeDescription?: string
  versionNumber: number
}

export interface UserSettings {
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

export function normalizeNoteResponse(note: any): Note {
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
