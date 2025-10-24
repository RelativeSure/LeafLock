export interface User {
  id: string
  email: string
  name: string
  mfaEnabled: boolean
  mfaSecret?: string
  createdAt: string
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
  content: string
  tags: string[]
  isPublic: boolean
  userId: string
  createdAt: string
  usageCount: number
}

export interface Tag {
  id: string
  name: string
  color: string
  userId: string
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

export interface UserSettings {
  theme: 'light' | 'dark' | 'system'
  autoSave: boolean
  autoSaveInterval: number
  defaultView: 'list' | 'grid'
  notificationsEnabled: boolean
  emailNotifications: boolean
  encryptionEnabled: boolean
  language: string
}
