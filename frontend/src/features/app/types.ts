export interface Note {
  id: string
  title: string
  content: string
  created_at: string
  updated_at: string
  title_encrypted?: string
  content_encrypted?: string
}

export type ViewType =
  | 'login'
  | 'notes'
  | 'editor'
  | 'unlock'
  | 'forgot'
  | 'reset'
  | 'admin'
  | 'settings'
  | 'tags'
  | 'folders'
  | 'templates'

export type EncryptionStatus = 'locked' | 'unlocked'
