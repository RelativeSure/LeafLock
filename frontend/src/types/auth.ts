export interface AuthResponse {
  token: string
  user_id: string
  mfa_required?: boolean
  session?: string
}
