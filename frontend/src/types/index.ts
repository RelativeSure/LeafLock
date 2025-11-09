export interface User {
  id: string
  email: string
  name: string
  role: 'admin' | 'user'
  isAdmin: boolean
  mfaEnabled: boolean
  mfaSecret?: string
  createdAt: string
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
  position: number
  depth: number
  path: string
  children?: Folder[]
  createdAt: string
  updatedAt: string
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

export interface CollaborationSession {
  noteId: string
  users: {
    id: string
    name: string
    color: string
    cursor?: { line: number; ch: number }
  }[]
}

export interface UserActivityLog {
  id: string
  userId: string
  userName: string
  userEmail: string
  action: 'login' | 'logout' | 'mfa_enabled' | 'mfa_disabled' | 'mfa_verified'
  timestamp: string
  ipAddress?: string
  userAgent?: string
  mfaUsed: boolean
}
