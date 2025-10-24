export interface AuthResponse {
  token: string
  user_id: string
  mfa_required?: boolean
  session?: string
}

export interface Note {
  id: string
  title: string
  content: string
  created_at: string
  updated_at: string
  title_encrypted?: string
  content_encrypted?: string
}

export type EncryptionStatus = 'locked' | 'unlocked'
