import {
  adminListUsersResponseSchema,
  adminActionResponseSchema,
  adminUserRolesResponseSchema,
  mfaSetupSchema,
  mfaStatusSchema,
  type AdminListUsersResponse,
  type AdminActionResponse,
  type AdminUserRolesResponse,
  type MfaSetup,
  type MfaStatus,
} from '@/lib/schemas'
import type { AuthResponse } from '@/types/auth'
import { getStoredAuthToken, persistAuthToken, clearStoredAuthToken } from '@/utils/auth'
import type { ThemeType } from '@/ThemeContext'
import type { Note } from '@/features/app/types'
import { cryptoService, type CryptoService } from './cryptoService'
import type { UseTemplateRequest, UseTemplateResponse } from './templatesService'

export class SecureAPI {
  private token: string | null
  private onUnauthorized: (() => void) | null = null

  constructor(
    private readonly crypto: CryptoService,
    private readonly baseURL: string = '/api/v1'
  ) {
    this.token = getStoredAuthToken()
  }

  private async request(endpoint: string, options: RequestInit = {}): Promise<any> {
    const url = `${this.baseURL}${endpoint}`
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...((options.headers as Record<string, string>) || {}),
    }

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`
    }
    // Include CSRF token when available (server sets cookie `csrf_token`)
    const csrfToken = localStorage.getItem('csrf_token')
    if (csrfToken && !headers['X-CSRF-Token']) {
      headers['X-CSRF-Token'] = csrfToken
    }

    console.log('🔗 API Request:', {
      url,
      method: options.method || 'GET',
      headers: Object.keys(headers),
    })

    try {
      const response = await fetch(url, {
        ...options,
        headers,
        credentials: 'include',
        mode: 'cors',
      })

      console.log('📡 API Response:', {
        status: response.status,
        statusText: response.statusText,
        url,
      })

      if (!response.ok) {
        let errorMessage = `HTTP ${response.status}`
        try {
          const errorData = await response.json()
          errorMessage = errorData.error || errorData.message || errorMessage
          console.error('❌ API Error Response:', errorData)
        } catch (parseError) {
          console.error('❌ Could not parse error response:', parseError)
        }

        if (response.status === 401) {
          console.log('🚨 401 Unauthorized - triggering logout')
          this.handleUnauthorized()
        }
        const error = new Error(errorMessage) as Error & { status?: number }
        error.name = 'APIError'
        error.status = response.status
        throw error
      }

      const data = await response.json()
      console.log('✅ API Success:', { endpoint, data: Object.keys(data) })
      return data
    } catch (error) {
      console.error('💥 API request failed:', { url, error: (error as Error).message })
      throw error
    }
  }

  handleUnauthorized(): void {
    console.log('🔒 Handling unauthorized access')
    this.clearToken()
    localStorage.removeItem('user_salt')

    if (this.onUnauthorized) {
      this.onUnauthorized()
    }
  }

  setUnauthorizedCallback(callback: () => void): void {
    this.onUnauthorized = callback
  }

  setToken(token: string): void {
    this.token = token
    persistAuthToken(token)
    try {
      const payload = JSON.parse(atob(token.split('.')[1] || ''))
      if (payload && typeof payload.user_id === 'string') {
        localStorage.setItem('current_user_id', payload.user_id)
      }
    } catch {
      // ignore malformed tokens
    }
  }

  clearToken(): void {
    this.token = null
    clearStoredAuthToken()
  }

  async validateToken(): Promise<boolean> {
    if (!this.token) {
      console.log('❌ No token to validate')
      return false
    }

    try {
      console.log('🔍 Validating token...')
      const timeoutPromise = new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Token validation timeout')), 5000)
      )

      await Promise.race([this.request('/health'), timeoutPromise])

      console.log('✅ Token is valid')
      return true
    } catch (error) {
      console.log('❌ Token validation failed:', (error as Error).message)
      return false
    }
  }

  async login(email: string, password: string, mfaCode?: string): Promise<AuthResponse> {
    console.log('🔍 Frontend Login Debug Info:')
    console.log('   - Email:', email)
    console.log('   - Password length:', password.length)
    if (password.length > 0) {
      console.log('   - Password first char:', password[0])
      console.log('   - Password last char:', password[password.length - 1])
      console.log('   - Password contains [:', password.includes('['))
      console.log('   - Password contains ]:', password.includes(']'))
    }

    const requestBody = { email, password, mfa_code: mfaCode }
    const serializedBody = JSON.stringify(requestBody)
    console.log('   - JSON body length:', serializedBody.length)
    console.log('   - JSON body preview:', serializedBody.substring(0, 100) + '...')

    const response = await this.request('/auth/login', {
      method: 'POST',
      body: serializedBody,
    })

    if (response.token) {
      this.setToken(response.token)
    }
    if (response.user_id) {
      try {
        localStorage.setItem('current_user_id', response.user_id)
      } catch {
        // ignore storage failures
      }
    }

    return response
  }

  async register(email: string, password: string): Promise<AuthResponse> {
    const response = await this.request('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    })

    if (response.token) {
      this.setToken(response.token)
    }
    if (response.user_id) {
      try {
        localStorage.setItem('current_user_id', response.user_id)
      } catch {
        // ignore storage failures
      }
    }

    return response
  }

  async logout(): Promise<void> {
    this.clearToken()
    localStorage.removeItem('user_salt')
    localStorage.removeItem('current_user_id')
  }

  async getRegistrationStatus(): Promise<{ enabled: boolean }> {
    return this.request('/auth/registration')
  }

  async requestPasswordReset(email: string): Promise<{ message: string }> {
    return this.request('/auth/password/reset-request', {
      method: 'POST',
      body: JSON.stringify({ email }),
    })
  }

  async verifyResetToken(token: string): Promise<{ valid: boolean }> {
    return this.request(`/auth/password/reset-verify?token=${encodeURIComponent(token)}`)
  }

  async confirmPasswordReset(token: string, newPassword: string): Promise<{ message: string }> {
    return this.request('/auth/password/reset-confirm', {
      method: 'POST',
      body: JSON.stringify({ token, new_password: newPassword }),
    })
  }

  async getMfaStatus(): Promise<MfaStatus> {
    const raw = await this.request('/auth/mfa/status')
    const parsed = mfaStatusSchema.safeParse(raw)
    if (!parsed.success) {
      console.error('❌ MFA status validation failed', parsed.error)
      throw new Error('Invalid response when loading MFA status')
    }
    return parsed.data
  }

  async startMfaSetup(): Promise<MfaSetup> {
    const raw = await this.request('/auth/mfa/setup', { method: 'POST' })
    const parsed = mfaSetupSchema.safeParse(raw)
    if (!parsed.success) {
      console.error('❌ MFA setup response validation failed', parsed.error)
      throw new Error('Invalid response when generating MFA secret')
    }
    return parsed.data
  }

  async enableMfa(code: string): Promise<MfaStatus> {
    const raw = await this.request('/auth/mfa/enable', {
      method: 'POST',
      body: JSON.stringify({ code }),
    })
    const parsed = mfaStatusSchema.safeParse(raw)
    if (!parsed.success) {
      console.error('❌ MFA enable response validation failed', parsed.error)
      throw new Error('Invalid response when enabling MFA')
    }
    return parsed.data
  }

  async disableMfa(code: string): Promise<MfaStatus> {
    const raw = await this.request('/auth/mfa/disable', {
      method: 'POST',
      body: JSON.stringify({ code }),
    })
    const parsed = mfaStatusSchema.safeParse(raw)
    if (!parsed.success) {
      console.error('❌ MFA disable response validation failed', parsed.error)
      throw new Error('Invalid response when disabling MFA')
    }
    return parsed.data
  }

  async getBackupCodes(): Promise<{ total: number; remaining: number }> {
    return this.request('/auth/mfa/backup-codes')
  }

  async regenerateBackupCodes(password: string): Promise<{ codes: string[] }> {
    return this.request('/auth/mfa/backup-codes/regenerate', {
      method: 'POST',
      body: JSON.stringify({ password }),
    })
  }

  async deleteAccount(password: string): Promise<{ success: boolean; message: string }> {
    return this.request('/account', {
      method: 'DELETE',
      body: JSON.stringify({ password }),
    })
  }

  async exportAccountData(): Promise<any> {
    return this.request('/account/export')
  }

  async createNote(title: string, content: string): Promise<any> {
    const encryptedTitle = await this.crypto.encryptData(title)
    const encryptedContent = await this.crypto.encryptData(JSON.stringify(content))

    return this.request('/notes', {
      method: 'POST',
      body: JSON.stringify({
        title_encrypted: encryptedTitle,
        content_encrypted: encryptedContent,
      }),
    })
  }

  async useTemplate(
    templateId: string,
    options: UseTemplateRequest = {}
  ): Promise<UseTemplateResponse> {
    return this.request(`/templates/${templateId}/use`, {
      method: 'POST',
      body: JSON.stringify(options),
    })
  }

  async getNotes(): Promise<Note[]> {
    const response = await this.request('/notes')
    const notes = response.notes || response || []

    const decryptedNotes = await Promise.all(
      notes.map(async (note: any) => {
        try {
          const title = await this.crypto.decryptData(note.title_encrypted)
          const content = JSON.parse(await this.crypto.decryptData(note.content_encrypted))
          return { ...note, title, content }
        } catch (err) {
          console.error('Failed to decrypt note:', note.id)
          return null
        }
      })
    )

    return decryptedNotes.filter((note): note is Note => note !== null)
  }

  async updateNote(noteId: string, title: string, content: string): Promise<any> {
    const encryptedTitle = await this.crypto.encryptData(title)
    const encryptedContent = await this.crypto.encryptData(JSON.stringify(content))

    return this.request(`/notes/${noteId}`, {
      method: 'PUT',
      body: JSON.stringify({
        title_encrypted: encryptedTitle,
        content_encrypted: encryptedContent,
      }),
    })
  }

  async deleteNote(noteId: string): Promise<any> {
    return this.request(`/notes/${noteId}`, {
      method: 'DELETE',
    })
  }

  async getTrash(): Promise<Note[]> {
    const response = await this.request('/notes/trash')
    const trashedNotes = response.notes || response || []

    const decryptedNotes = await Promise.all(
      trashedNotes.map(async (note: any) => {
        try {
          const title = await this.crypto.decryptData(note.title_encrypted)
          const content = JSON.parse(await this.crypto.decryptData(note.content_encrypted))
          return { ...note, title, content }
        } catch (err) {
          console.error('Failed to decrypt trashed note:', note.id)
          return null
        }
      })
    )

    return decryptedNotes.filter((note): note is Note => note !== null)
  }

  async restoreNote(noteId: string): Promise<any> {
    return this.request(`/notes/${noteId}/restore`, {
      method: 'POST',
    })
  }

  async permanentlyDeleteNote(noteId: string): Promise<any> {
    return this.request(`/notes/${noteId}/permanent`, {
      method: 'DELETE',
    })
  }

  async getAnnouncements(): Promise<{ announcements: any[] }> {
    const raw = await this.request('/announcements')
    if (!raw || typeof raw !== 'object') {
      throw new Error('Invalid response when fetching announcements')
    }
    return raw as { announcements: any[] }
  }

  async getUserSettings(): Promise<{ theme: ThemeType }> {
    return await this.request('/settings')
  }

  async updateUserSettings(theme: ThemeType): Promise<void> {
    await this.request('/settings', {
      method: 'PUT',
      body: JSON.stringify({ theme }),
    })
  }

  async adminHealth(): Promise<boolean> {
    try {
      const r = await this.request('/admin/health')
      return r && r.status === 'ok'
    } catch (error) {
      const status = (error as { status?: number } | undefined)?.status
      if (status === 404 || status === 403) {
        console.debug('Admin health endpoint unavailable for current user.')
        return false
      }
      console.warn('Admin health check failed:', error)
      return false
    }
  }

  async adminSetAdmin(userId: string, admin: boolean): Promise<AdminActionResponse> {
    const raw = await this.request(`/admin/users/${userId}/admin`, {
      method: 'PUT',
      body: JSON.stringify({ admin }),
    })
    const parsed = adminActionResponseSchema.safeParse(raw)
    if (!parsed.success) {
      console.error('❌ Admin setAdmin response validation failed', parsed.error)
      throw new Error('Invalid response when updating admin status')
    }
    return parsed.data
  }

  async adminGetUserRoles(userId: string): Promise<AdminUserRolesResponse> {
    const raw = await this.request(`/admin/users/${userId}/roles`)
    const parsed = adminUserRolesResponseSchema.safeParse(raw)
    if (!parsed.success) {
      console.error('❌ Admin roles response validation failed', parsed.error)
      throw new Error('Invalid response when loading user roles')
    }
    return parsed.data
  }

  async adminListUsers(
    params?: Record<string, string | number | boolean>
  ): Promise<AdminListUsersResponse> {
    const query = new URLSearchParams()
    if (params) {
      for (const [k, v] of Object.entries(params)) {
        if (v === undefined || v === null || v === '') continue
        query.set(k, String(v))
      }
    }
    const qs = query.toString()
    const raw = await this.request(`/admin/users${qs ? `?${qs}` : ''}`)
    const parsed = adminListUsersResponseSchema.safeParse(raw)
    if (!parsed.success) {
      console.error('❌ Admin users response validation failed', parsed.error)
      throw new Error('Invalid response when loading users')
    }
    return parsed.data
  }

  async adminExportUsersCsv(params?: Record<string, string | number | boolean>): Promise<Blob> {
    const query = new URLSearchParams()
    if (params) {
      for (const [k, v] of Object.entries(params)) {
        if (v === undefined || v === null || v === '') continue
        query.set(k, String(v))
      }
    }

    const response = await fetch(
      `${this.baseURL}/admin/users/export${query.toString() ? `?${query}` : ''}`,
      {
        method: 'GET',
        headers: {
          Authorization: this.token ? `Bearer ${this.token}` : '',
        },
      }
    )

    if (!response.ok) {
      throw new Error('Failed to export users CSV')
    }

    return await response.blob()
  }
}

export const secureApi = new SecureAPI(cryptoService)
