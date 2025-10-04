import React, { useState, useEffect, useCallback, useMemo, useRef, Suspense, lazy } from 'react'
import sodium from 'libsodium-wrappers'
import { Shield, Settings, Hash, Folder, FileText, Plus } from 'lucide-react'
import {
  adminListUsersResponseSchema,
  adminActionResponseSchema,
  adminUserRolesResponseSchema,
  mfaSetupSchema,
  mfaStatusSchema,
  registrationStatusSchema,
  type AdminListUsersResponse,
  type AdminActionResponse,
  type AdminUserRolesResponse,
  type MfaSetup,
  type MfaStatus,
  type RegistrationStatus,
} from '@/lib/schemas'

// shadcn/ui components
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { ButtonGroup, ButtonGroupSeparator } from '@/components/ui/button-group'
import { LoadingOverlay } from '@/features/common/LoadingOverlay'
import { ErrorNotice } from '@/features/common/ErrorNotice'
import { OnboardingOverlay } from '@/features/onboarding/OnboardingOverlay'
import { LoginView } from '@/features/auth/LoginView'
import { UnlockView } from '@/features/auth/UnlockView'
import type { AuthResponse } from '@/types/auth'
import { Spinner } from '@/components/ui/spinner'
import { Toaster } from '@/components/ui/sonner'
import Footer from '@/components/Footer'
import AnnouncementBanner, { Announcement } from '@/components/AnnouncementBanner'
import { getStoredAuthToken, persistAuthToken, clearStoredAuthToken } from '@/utils/auth'

// Lazy loaded components for code splitting
const AdminPage = lazy(() => import('./AdminPage'))
const SettingsPage = lazy(() => import('@/components/settings/SettingsPage').then(module => ({ default: module.SettingsPage })))
const ImportExportDialog = lazy(() => import('@/components/ImportExportDialog').then(module => ({ default: module.ImportExportDialog })))
const RichTextEditor = lazy(() => import('@/components/RichTextEditor').then(module => ({ default: module.RichTextEditor })))
const SearchBar = lazy(() => import('@/components/SearchBar'))
const SearchResults = lazy(() => import('@/components/SearchResults'))
const TagsManager = lazy(() => import('@/components/TagsManager'))
const TagSelector = lazy(() => import('@/components/TagSelector'))
const FoldersManager = lazy(() => import('@/components/FoldersManager'))
const TemplatesManager = lazy(() => import('@/components/TemplatesManager'))
import { SearchResult } from '@/services/searchService'
import { Template } from '@/services/templatesService'
import { ThemeProvider, useTheme, type ThemeType } from '@/ThemeContext'

// Loading component for lazy loaded components
const ComponentLoader: React.FC = () => (
  <div className="flex items-center justify-center p-4">
    <Skeleton className="h-6 w-6 rounded-full" />
  </div>
)

// Types
interface Note {
  id: string
  title: string
  content: string
  created_at: string
  updated_at: string
  title_encrypted?: string
  content_encrypted?: string
}


type ViewType = 'login' | 'notes' | 'editor' | 'unlock' | 'admin' | 'settings' | 'tags' | 'folders' | 'templates'
type EncryptionStatus = 'locked' | 'unlocked'
// Debounce function type
interface DebounceFunction {
  (...args: any[]): void
  cancel: () => void
}

// Secure Crypto Service for E2E Encryption
class CryptoService {
  public masterKey: Uint8Array | null = null
  public derivedKey: Uint8Array | null = null
  public sodiumReady: boolean = false

  constructor() {
    this.initSodium()
  }

  async initSodium(): Promise<void> {
    if (!this.sodiumReady) {
      try {
        console.log('🧪 Initializing sodium library...')
        await sodium.ready

        // Verify all required functions are available
        const requiredFunctions = [
          'crypto_secretbox_easy',
          'crypto_secretbox_open_easy',
          'crypto_secretbox_NONCEBYTES',
          'from_string',
          'to_string',
          'to_base64',
          'from_base64',
          'base64_variants',
        ]

        for (const func of requiredFunctions) {
          if (typeof (sodium as any)[func] === 'undefined') {
            throw new Error(`Sodium function ${func} is not available`)
          }
        }

        this.sodiumReady = true
        console.log('🧪 Sodium library initialized successfully with all functions')
      } catch (err) {
        console.error('💥 Failed to initialize sodium:', err)
        this.sodiumReady = false
        throw err
      }
    }
  }

  async deriveKeyFromPassword(password: string, salt: Uint8Array): Promise<Uint8Array> {
    const encoder = new TextEncoder()
    const passwordBytes = encoder.encode(password)

    // Use PBKDF2 with high iterations for key derivation
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      passwordBytes,
      'PBKDF2',
      false,
      ['deriveBits']
    )

    const derivedBits = await window.crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: salt as BufferSource,
        iterations: 600000, // High iteration count for security
        hash: 'SHA-256',
      },
      keyMaterial,
      256
    )

    return new Uint8Array(derivedBits)
  }

  async encryptData(plaintext: string): Promise<string> {
    await this.initSodium()
    if (!this.masterKey) throw new Error('No encryption key set')

    // Ensure sodium is fully ready before using its functions
    if (
      !this.sodiumReady ||
      typeof (sodium as any).crypto_secretbox_easy !== 'function' ||
      typeof (sodium as any).crypto_secretbox_NONCEBYTES !== 'number' ||
      typeof (sodium as any).from_string !== 'function'
    ) {
      console.warn('Sodium not ready, waiting and re-initializing...')
      await sodium.ready
      this.sodiumReady = true

      // Double check after waiting
      if (typeof (sodium as any).crypto_secretbox_easy !== 'function') {
        throw new Error('Sodium encryption functions not available')
      }
    }

    // Use Web Crypto API for nonce generation to avoid sodium timing issues
    const nonce = new Uint8Array((sodium as any).crypto_secretbox_NONCEBYTES)
    crypto.getRandomValues(nonce)

    const messageBytes = (sodium as any).from_string(plaintext)
    const ciphertext = (sodium as any).crypto_secretbox_easy(messageBytes, nonce, this.masterKey)

    // Combine nonce and ciphertext
    const combined = new Uint8Array(nonce.length + ciphertext.length)
    combined.set(nonce)
    combined.set(ciphertext, nonce.length)

    return (sodium as any).to_base64(combined, (sodium as any).base64_variants.ORIGINAL)
  }

  async decryptData(encryptedData: string): Promise<string> {
    await this.initSodium()
    if (!this.masterKey) throw new Error('No decryption key set')

    // Ensure sodium is fully ready before using its functions
    if (!this.sodiumReady || typeof (sodium as any).crypto_secretbox_open_easy !== 'function') {
      console.warn('Sodium not ready for decryption, waiting...')
      await sodium.ready
      this.sodiumReady = true
    }

    const combined = (sodium as any).from_base64(
      encryptedData,
      (sodium as any).base64_variants.ORIGINAL
    )
    const nonce = combined.slice(0, (sodium as any).crypto_secretbox_NONCEBYTES)
    const ciphertext = combined.slice((sodium as any).crypto_secretbox_NONCEBYTES)

    const decrypted = (sodium as any).crypto_secretbox_open_easy(ciphertext, nonce, this.masterKey)
    return (sodium as any).to_string(decrypted)
  }

  async generateSalt(): Promise<Uint8Array> {
    await this.initSodium()
    // Use standard Web Crypto API for salt generation to avoid sodium timing issues
    const saltBytes = new Uint8Array(32) // 32 bytes for salt
    crypto.getRandomValues(saltBytes)
    console.log('🧂 Generated salt using Web Crypto API')
    return saltBytes
  }

  async setMasterKey(key: Uint8Array): Promise<void> {
    this.masterKey = key
  }

  isSodiumReady(): boolean {
    return (
      this.sodiumReady &&
      typeof (sodium as any).crypto_secretbox_easy === 'function' &&
      typeof (sodium as any).crypto_secretbox_NONCEBYTES === 'number'
    )
  }
}

const cryptoService = new CryptoService()

// Secure API Service with encryption
class SecureAPI {
  private baseURL: string
  private token: string | null
  private onUnauthorized: (() => void) | null = null

  constructor(baseURL: string = '/api/v1') {
    this.baseURL = baseURL
    this.token = getStoredAuthToken()
  }

  async request(endpoint: string, options: RequestInit = {}): Promise<any> {
    const url = `${this.baseURL}${endpoint}`
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...((options.headers as Record<string, string>) || {}),
    }

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`
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
        // Try to get error message from response body
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
        throw new Error(errorMessage)
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

    // Call the callback to update React state
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
    // Derive and store current_user_id from JWT if possible
    try {
      const payload = JSON.parse(atob(token.split('.')[1] || ''))
      if (payload && typeof payload.user_id === 'string') {
        localStorage.setItem('current_user_id', payload.user_id)
      }
    } catch (err) {
      // ignore malformed tokens; current_user_id will simply remain unset
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
      // Use a lightweight endpoint to check token validity with timeout
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
    // Enhanced debug logging for special character password issues
    console.log('🔍 Frontend Login Debug Info:')
    console.log('   - Email:', email)
    console.log('   - Password length:', password.length)
    if (password.length > 0) {
      console.log('   - Password first char:', password[0])
      console.log('   - Password last char:', password[password.length - 1])
      console.log('   - Password contains [:', password.includes('['))
      console.log('   - Password contains ]:', password.includes(']'))
    }

    // Test JSON serialization
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
      } catch (err) {
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
      } catch (err) {
        // ignore storage failures
      }
    }

    return response
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

  async getRegistrationStatus(): Promise<{ enabled: boolean }> {
    return this.request('/auth/registration')
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
    // Encrypt note content before sending
    const encryptedTitle = await cryptoService.encryptData(title)
    const encryptedContent = await cryptoService.encryptData(JSON.stringify(content))

    return this.request('/notes', {
      method: 'POST',
      body: JSON.stringify({
        title_encrypted: encryptedTitle,
        content_encrypted: encryptedContent,
      }),
    })
  }
  // Admin helpers
  async adminHealth(): Promise<boolean> {
    const r = await this.request('/admin/health')
    return r && r.status === 'ok'
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
    const qs = query.toString()
    const url = `${this.baseURL}/admin/users.csv${qs ? `?${qs}` : ''}`
    const response = await fetch(url, {
      headers: { ...(this.token ? { Authorization: `Bearer ${this.token}` } : {}) },
      credentials: 'include',
      mode: 'cors',
    })
    if (!response.ok) throw new Error(`Export failed: ${response.status}`)
    return await response.blob()
  }
  async adminAssignRole(userId: string, role: string): Promise<AdminActionResponse> {
    const raw = await this.request(`/admin/users/${userId}/roles`, {
      method: 'POST',
      body: JSON.stringify({ role }),
    })
    const parsed = adminActionResponseSchema.safeParse(raw)
    if (!parsed.success) {
      console.error('❌ Admin assignRole response validation failed', parsed.error)
      throw new Error('Invalid response when assigning role')
    }
    return parsed.data
  }
  async adminRemoveRole(userId: string, role: string): Promise<AdminActionResponse> {
    const raw = await this.request(`/admin/users/${userId}/roles/${role}`, { method: 'DELETE' })
    const parsed = adminActionResponseSchema.safeParse(raw)
    if (!parsed.success) {
      console.error('❌ Admin removeRole response validation failed', parsed.error)
      throw new Error('Invalid response when removing role')
    }
    return parsed.data
  }
  async adminBulkRole(
    action: 'assign' | 'remove',
    role: string,
    filters: Record<string, any>
  ): Promise<AdminActionResponse> {
    const raw = await this.request('/admin/users/roles/bulk', {
      method: 'POST',
      body: JSON.stringify({ action, role, ...filters }),
    })
    const parsed = adminActionResponseSchema.safeParse(raw)
    if (!parsed.success) {
      console.error('❌ Admin bulk role response validation failed', parsed.error)
      throw new Error('Invalid response for bulk role operation')
    }
    return parsed.data
  }
  async adminBulkAdmin(action: 'grant' | 'revoke', filters: Record<string, any>): Promise<AdminActionResponse> {
    const raw = await this.request('/admin/users/admin/bulk', {
      method: 'POST',
      body: JSON.stringify({ action, ...filters }),
    })
    const parsed = adminActionResponseSchema.safeParse(raw)
    if (!parsed.success) {
      console.error('❌ Admin bulk admin response validation failed', parsed.error)
      throw new Error('Invalid response for bulk admin operation')
    }
    return parsed.data
  }
  async adminGetRegistration(): Promise<RegistrationStatus> {
    const raw = await this.request('/admin/settings/registration')
    const parsed = registrationStatusSchema.safeParse(raw)
    if (!parsed.success) {
      console.error('❌ Registration status validation failed', parsed.error)
      throw new Error('Invalid response when loading registration status')
    }
    return parsed.data
  }
  async adminSetRegistration(enabled: boolean): Promise<RegistrationStatus> {
    const raw = await this.request('/admin/settings/registration', {
      method: 'PUT',
      body: JSON.stringify({ enabled }),
    })
    const parsed = registrationStatusSchema.safeParse(raw)
    if (!parsed.success) {
      console.error('❌ Registration update validation failed', parsed.error)
      throw new Error('Invalid response when updating registration status')
    }
    return parsed.data
  }

  // Announcement API methods
  async adminGetAnnouncements(): Promise<{ announcements: any[] }> {
    const raw = await this.request('/admin/announcements')
    if (!raw || typeof raw !== 'object') {
      throw new Error('Invalid response when fetching announcements')
    }
    return raw as { announcements: any[] }
  }

  async adminCreateAnnouncement(data: any): Promise<{ id: string; message: string }> {
    const raw = await this.request('/admin/announcements', {
      method: 'POST',
      body: JSON.stringify(data),
    })
    if (!raw || typeof raw !== 'object') {
      throw new Error('Invalid response when creating announcement')
    }
    return raw as { id: string; message: string }
  }

  async adminUpdateAnnouncement(id: string, data: any): Promise<{ message: string }> {
    const raw = await this.request(`/admin/announcements/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    })
    if (!raw || typeof raw !== 'object') {
      throw new Error('Invalid response when updating announcement')
    }
    return raw as { message: string }
  }

  async adminDeleteAnnouncement(id: string): Promise<{ message: string }> {
    const raw = await this.request(`/admin/announcements/${id}`, {
      method: 'DELETE',
    })
    if (!raw || typeof raw !== 'object') {
      throw new Error('Invalid response when deleting announcement')
    }
    return raw as { message: string }
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
      body: JSON.stringify({ theme })
    })
  }

  async getNotes(): Promise<Note[]> {
    const response = await this.request('/notes')
    const notes = response.notes || response || []

    // Decrypt notes
    const decryptedNotes = await Promise.all(
      notes.map(async (note: any) => {
        try {
          const title = await cryptoService.decryptData(note.title_encrypted)
          const content = JSON.parse(await cryptoService.decryptData(note.content_encrypted))
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
    // Encrypt note content before sending
    const encryptedTitle = await cryptoService.encryptData(title)
    const encryptedContent = await cryptoService.encryptData(JSON.stringify(content))

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

    // Decrypt trashed notes
    const decryptedNotes = await Promise.all(
      trashedNotes.map(async (note: any) => {
        try {
          const title = await cryptoService.decryptData(note.title_encrypted)
          const content = JSON.parse(await cryptoService.decryptData(note.content_encrypted))
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
}

const api = new SecureAPI()

// Loading Skeleton Components using Shadcn
const NoteSkeleton: React.FC = () => (
  <div className="p-4 border-b space-y-3">
    <Skeleton className="h-4 w-3/4" />
    <Skeleton className="h-3 w-full" />
    <Skeleton className="h-3 w-2/3" />
    <Skeleton className="h-3 w-1/4" />
  </div>
)

const NoteListSkeleton: React.FC = () => (
  <div>
    {[...Array(5)].map((_, i) => (
      <NoteSkeleton key={i} />
    ))}
  </div>
)


// Utility function for debouncing with cancel support
function debounce(func: (...args: any[]) => void, wait: number): DebounceFunction {
  let timeout: NodeJS.Timeout
  function executedFunction(...args: any[]) {
    const later = () => {
      clearTimeout(timeout)
      func(...args)
    }
    clearTimeout(timeout)
    timeout = setTimeout(later, wait)
  }

  // Add cancel method
  executedFunction.cancel = () => {
    clearTimeout(timeout)
  }

  return executedFunction
}

// Theme Toggle Component
const ThemeToggle: React.FC = () => {
  const { theme, setTheme } = useTheme()
  const [isOpen, setIsOpen] = useState(false)

  const themeOptions = [
    {
      value: 'system' as ThemeType,
      label: 'System',
      icon: (
        <svg
          className="w-4 h-4"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"
          />
        </svg>
      ),
    },
    {
      value: 'light' as ThemeType,
      label: 'Light',
      icon: (
        <svg
          className="w-4 h-4"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"
          />
        </svg>
      ),
    },
    {
      value: 'blue' as ThemeType,
      label: 'Blue',
      icon: (
        <svg
          className="w-4 h-4"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M7 21a4 4 0 01-4-4V5a2 2 0 012-2h4a2 2 0 012 2v12a4 4 0 01-4 4zm0 0h12a2 2 0 002-2v-4a2 2 0 00-2-2h-2.343M11 7.343l1.657-1.657a2 2 0 012.828 0l2.829 2.829a2 2 0 010 2.828l-8.486 8.485M7 17h.01"
          />
        </svg>
      ),
    },
    {
      value: 'dark' as ThemeType,
      label: 'Dark',
      icon: (
        <svg
          className="w-4 h-4"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"
          />
        </svg>
      ),
    },
  ]

  const currentOption = themeOptions.find((option) => option.value === theme)

  return (
    <div className="relative">
      <Button
        onClick={() => setIsOpen(!isOpen)}
        variant="ghost"
        size="sm"
        className="flex items-center px-3 py-1 text-sm"
        aria-label="Theme selector"
        title="Change theme"
      >
        {currentOption?.icon}
        <span className="ml-1">{currentOption?.label}</span>
        <svg
          className="w-3 h-3 ml-1"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </Button>

      {isOpen && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setIsOpen(false)} />
          <div className="absolute right-0 top-full mt-1 w-32 bg-popover border border-border rounded-lg shadow-lg z-20">
            {themeOptions.map((option) => (
              <Button
                key={option.value}
                onClick={() => {
                  setTheme(option.value)
                  setIsOpen(false)
                }}
                variant="ghost"
                className={`w-full flex items-center justify-start px-3 py-2 text-sm first:rounded-t-lg last:rounded-b-lg h-auto ${
                  theme === option.value ? 'text-primary bg-accent' : 'text-popover-foreground'
                }`}
              >
                {option.icon}
                <span className="ml-2">{option.label}</span>
              </Button>
            ))}
          </div>
        </>
      )}
    </div>
  )
}

// Main App Component
function LeafLockApp() {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [currentView, setCurrentView] = useState<ViewType>('login')
  const [notes, setNotes] = useState<Note[]>([])
  const [trashedNotes, setTrashedNotes] = useState<Note[]>([])
  const [selectedNote, setSelectedNote] = useState<Note | null>(null)
  const [encryptionStatus, setEncryptionStatus] = useState<EncryptionStatus>('locked')
  const [viewingTrash, setViewingTrash] = useState(false)
  const [loading, setLoading] = useState(false)
  const [initializing, setInitializing] = useState(true)
  const [, setError] = useState<string | null>(null)
  const [notesError, setNotesError] = useState<string | null>(null)
  const [showOnboarding, setShowOnboarding] = useState(false)
  const [onboardingStep, setOnboardingStep] = useState(0)
  const [isAdmin, setIsAdmin] = useState(false)
  const [announcements, setAnnouncements] = useState<Announcement[]>([])
  const [_announcementsLoading, setAnnouncementsLoading] = useState(false)
  const [_showTemplatesManager, _setShowTemplatesManager] = useState(false)
  const [showTemplateSelector, setShowTemplateSelector] = useState(false)

  console.log(
    '🔄 LeafLockApp render - initializing:',
    initializing,
    'isAuthenticated:',
    isAuthenticated,
    'currentView:',
    currentView
  )

  // Centralized logout function
  const handleLogout = useCallback(() => {
    console.log('🚪 Performing complete logout...')

    // Clear all auth-related state
    api.clearToken()
    cryptoService.masterKey = null
    localStorage.removeItem('user_salt')

    // Reset React state
    setIsAuthenticated(false)
    setCurrentView('login')
    setEncryptionStatus('locked')
    setNotes([])
    setSelectedNote(null)
    setError(null)
    setNotesError(null)
    setIsAdmin(false)

    console.log('✅ Complete logout finished')
  }, [])


  const loadNotes = async () => {
    try {
      setLoading(true)
      setNotesError(null)
      console.log('📝 Loading notes...')
      const fetchedNotes = await api.getNotes()
      setNotes(fetchedNotes)
      console.log(`✅ Loaded ${fetchedNotes.length} notes`)
    } catch (err) {
      console.error('💥 Failed to load notes:', err)

      // Check if it's an authentication error
      if (
        (err as Error).message.includes('401') ||
        (err as Error).message.includes('Unauthorized')
      ) {
        console.log('🚨 Authentication error while loading notes - logging out')
        handleLogout()
        return // Don't set error message, just logout
      }

      setNotesError((err as Error).message || 'Failed to load notes')
    } finally {
      setLoading(false)
    }
  }

  const loadTrash = async () => {
    try {
      setLoading(true)
      setNotesError(null)
      console.log('🗑️ Loading trash...')
      const fetchedTrash = await api.getTrash()
      setTrashedNotes(fetchedTrash)
      console.log(`✅ Loaded ${fetchedTrash.length} trashed notes`)
    } catch (err) {
      console.error('💥 Failed to load trash:', err)

      // Check if it's an authentication error
      if (
        (err as Error).message.includes('401') ||
        (err as Error).message.includes('Unauthorized')
      ) {
        console.log('🚨 Authentication error while loading trash - logging out')
        handleLogout()
        return
      }

      setNotesError((err as Error).message || 'Failed to load trash')
    } finally {
      setLoading(false)
    }
  }

  const handleUnlockWithPassword = useCallback(
    async (password: string) => {
      const trimmed = password.trim()
      if (!trimmed) {
        throw new Error('Password is required')
      }

      const storedSalt = localStorage.getItem('user_salt')
      if (!storedSalt) {
        throw new Error('No stored salt found - please log in again')
      }

      try {
        const salt = new Uint8Array(Array.from(atob(storedSalt), (c) => c.charCodeAt(0)))
        const key = await cryptoService.deriveKeyFromPassword(trimmed, salt)
        await cryptoService.setMasterKey(key)

        setCurrentView('notes')
        setEncryptionStatus('unlocked')
        await loadNotes()
      } catch (error) {
        console.error('💥 Failed to unlock with provided password:', error)
        throw (error instanceof Error ? error : new Error('Failed to unlock notes'))
      }
    },
    [loadNotes]
  )

  const handleRestoreNote = async (noteId: string) => {
    try {
      console.log('♻️ Restoring note:', noteId)
      await api.restoreNote(noteId)
      console.log('✅ Note restored successfully')

      // Reload both lists to reflect changes
      await Promise.all([loadNotes(), loadTrash()])

      // Clear selected note if it was the restored one
      if (selectedNote && selectedNote.id === noteId) {
        setSelectedNote(null)
      }
    } catch (err) {
      console.error('💥 Failed to restore note:', err)
      setNotesError((err as Error).message || 'Failed to restore note')
    }
  }

  const handlePermanentDelete = async (noteId: string) => {
    try {
      console.log('🗑️ Permanently deleting note:', noteId)
      await api.permanentlyDeleteNote(noteId)
      console.log('✅ Note permanently deleted')

      // Reload trash to reflect changes
      await loadTrash()

      // Clear selected note if it was the deleted one
      if (selectedNote && selectedNote.id === noteId) {
        setSelectedNote(null)
      }
    } catch (err) {
      console.error('💥 Failed to permanently delete note:', err)
      setNotesError((err as Error).message || 'Failed to permanently delete note')
    }
  }

  const handleTemplateSelect = useCallback(
    async (template: Template) => {
      try {
        const response = await api.request('/templates/' + template.id + '/use', {
          method: 'POST',
          body: JSON.stringify({
            title: `${template.name} - ${new Date().toLocaleDateString()}`,
          }),
        })

        console.log('✅ Note created from template:', response)

        setShowTemplateSelector(false)
        await loadNotes()

        const newNote = notes.find((note) => note.id === response.id)
        if (newNote) {
          setSelectedNote(newNote)
          setCurrentView('editor')
        }
      } catch (err) {
        console.error('Failed to create note from template:', err)
        setError(err instanceof Error ? err.message : 'Failed to create note from template')
      }
    },
    [api, loadNotes, notes]
  )

  useEffect(() => {
    const initializeApp = async () => {
      try {
        console.log('🚀 Starting app initialization...')
        const token = getStoredAuthToken()
        if (token && !localStorage.getItem('current_user_id')) {
          try {
            const payload = JSON.parse(atob(token.split('.')[1] || ''))
            if (payload && typeof payload.user_id === 'string') {
              localStorage.setItem('current_user_id', payload.user_id)
            }
          } catch (err) {
            // ignore payload parsing failures; setup continues without cached id
          }
        }
        if (token) {
          console.log('🔐 Found stored token, validating...')

          let isValid = false
          try {
            console.log('🔍 Validating token with 3-second timeout...')
            const timeoutPromise = new Promise<boolean>((_, reject) =>
              setTimeout(() => reject(new Error('Validation timeout')), 3000)
            )
            isValid = await Promise.race([api.validateToken(), timeoutPromise])
          } catch (err) {
            console.warn('⚠️ Token validation failed:', err)
            isValid = false
          }

          if (isValid) {
            console.log('✅ Token valid, checking encryption key...')
            try {
              const adminOk = await api.adminHealth()
              setIsAdmin(!!adminOk)
            } catch {
              setIsAdmin(false)
            }

            if (!cryptoService.masterKey) {
              console.log('🔐 No master key - user needs to re-enter password')
              setIsAuthenticated(true)
              setCurrentView('unlock')
              setEncryptionStatus('locked')
            } else {
              console.log('🔑 Master key found, initializing app...')
              setIsAuthenticated(true)
              setCurrentView('notes')
              setEncryptionStatus('unlocked')
              loadNotes().catch((err) => {
                console.error('Failed to load notes during init:', err)
              })
              const hasSeenOnboarding = localStorage.getItem('hasSeenOnboarding')
              if (!hasSeenOnboarding) {
                setShowOnboarding(true)
              }
            }
          } else {
            console.log('❌ Token invalid, clearing and redirecting to login')
            api.clearToken()
            localStorage.removeItem('user_salt')
            cryptoService.masterKey = null
            setIsAuthenticated(false)
            setCurrentView('login')
            setEncryptionStatus('locked')
          }
        } else {
          console.log('ℹ️ No stored token found - showing login')
          setIsAuthenticated(false)
          setCurrentView('login')
          setEncryptionStatus('locked')
        }
      } catch (err) {
        console.error('💥 Failed to initialize app:', err)
        setError('Failed to initialize application')
        setIsAuthenticated(false)
        setCurrentView('login')
        setEncryptionStatus('locked')
      } finally {
        console.log('🏁 App initialization complete, setting initializing = false')
        setInitializing(false)
        console.log('✅ setInitializing(false) called')
      }
    }

    void initializeApp()
  }, [])

  const handleOnboardingNext = () => {
    setOnboardingStep((prev) => prev + 1)
  }

  const handleOnboardingPrev = () => {
    setOnboardingStep((prev) => Math.max(0, prev - 1))
  }

  const handleOnboardingSkip = () => {
    localStorage.setItem('hasSeenOnboarding', 'true')
    setShowOnboarding(false)
    setOnboardingStep(0)
  }

  const handleOnboardingComplete = () => {
    localStorage.setItem('hasSeenOnboarding', 'true')
    setShowOnboarding(false)
    setOnboardingStep(0)
  }

  // Notes Editor Component
  const NotesEditor: React.FC = () => {
    const [title, setTitle] = useState(selectedNote?.title || '')
    const [content, setContent] = useState(selectedNote?.content || '')
    const [saving, setSaving] = useState(false)
    const [lastSaved, setLastSaved] = useState<Date | null>(null)
    const [saveError, setSaveError] = useState<string | null>(null)

    // Use refs to access current values inside debounced function
    const titleRef = useRef(title)
    const contentRef = useRef(content)
    const selectedNoteRef = useRef(selectedNote)
    const debouncedAutosaveRef = useRef<DebounceFunction | null>(null)

    // Keep refs in sync with state
    useEffect(() => {
      titleRef.current = title
      contentRef.current = content
      selectedNoteRef.current = selectedNote
    }, [title, content, selectedNote])

    // Initialize content when selectedNote changes
    useEffect(() => {
      if (selectedNote) {
        setTitle(selectedNote.title || '')
        setContent(selectedNote.content || '')
        setLastSaved(selectedNote.updated_at ? new Date(selectedNote.updated_at) : null)
      } else {
        setTitle('')
        setContent('')
        setLastSaved(null)
      }
    }, [selectedNote])

    const handleSave = useCallback(async () => {
      // Prevent concurrent saves
      if (saving) {
        console.log('💾 Save already in progress, skipping duplicate')
        return
      }

      setSaving(true)
      setSaveError(null)

      // Cancel any pending debounced saves when manual save occurs
      if (debouncedAutosaveRef.current) {
        debouncedAutosaveRef.current.cancel()
        console.log('🚫 Cancelled pending autosave due to manual save')
      }

      try {
        // Check if encryption is ready before attempting to save
        if (!cryptoService.isSodiumReady()) {
          console.warn('⚠️ Sodium not ready, skipping autosave')
          setSaveError('Encryption not ready - please try manual save')
          return
        }

        // Use current values from refs
        const currentTitle = titleRef.current
        const currentContent = contentRef.current
        const currentSelectedNote = selectedNoteRef.current

        if (currentSelectedNote && currentSelectedNote.id) {
          // Update existing note (only if ID exists and is not empty)
          await api.updateNote(currentSelectedNote.id, currentTitle, currentContent)
          console.log('✅ Updated existing note:', currentSelectedNote.id)

          // Update the selectedNote state with new content
          setSelectedNote({
            ...currentSelectedNote,
            title: currentTitle,
            content: currentContent,
            updated_at: new Date().toISOString(),
          })

          // Update the note in the notes list
          setNotes((prevNotes) =>
            prevNotes.map((note) =>
              note.id === currentSelectedNote.id
                ? {
                    ...note,
                    title: currentTitle,
                    content: currentContent,
                    updated_at: new Date().toISOString(),
                  }
                : note
            )
          )
        } else {
          // Create new note and capture the response
          const response = await api.createNote(currentTitle, currentContent)
          console.log('✅ Created new note with ID:', response.id)

          // Create complete note object
          const newNote: Note = {
            id: response.id,
            title: currentTitle || 'Untitled',
            content: currentContent,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          }

          // Set the newly created note as selected
          setSelectedNote(newNote)

          // Add to notes list without full reload to prevent aggressive refresh
          setNotes((prevNotes) => [newNote, ...prevNotes])
        }
        setLastSaved(new Date())
      } catch (err) {
        console.error('Failed to save note:', err)
        setSaveError((err as Error).message || 'Failed to save note')
      } finally {
        setSaving(false)
      }
    }, [])

    // Create a stable debounced function using useMemo to prevent recreation
    const debouncedSave = useMemo(() => {
      const debouncedFunc = debounce(async () => {
        // Check current values from refs and ensure content actually changed
        const currentNote = selectedNoteRef.current
        const currentTitle = titleRef.current
        const currentContent = contentRef.current

        // Only save if content has actually changed from the loaded note
        if (
          currentNote &&
          (currentTitle !== currentNote.title || currentContent !== currentNote.content)
        ) {
          try {
            await handleSave()
            console.log('✅ Autosave completed')
          } catch (err) {
            console.error('💥 Autosave failed:', err)
            setSaveError((err as Error).message || 'Autosave failed')
          }
        }
      }, 3000) // Increased delay to 3 seconds for better UX

      // Store reference for cancellation
      debouncedAutosaveRef.current = debouncedFunc
      return debouncedFunc
    }, [handleSave])

    // Only trigger autosave when content actually changes AND not during initial load
    useEffect(() => {
      // Don't autosave if we just loaded the note or if content is empty
      if (
        (title || content) &&
        selectedNote &&
        (title !== selectedNote.title || content !== selectedNote.content)
      ) {
        debouncedSave()
      }
    }, [title, content, debouncedSave, selectedNote])

    return (
      <div className="flex-1 flex flex-col" role="main" aria-label="Note editor">
        <header className="bg-card border-b border-border px-6 py-4">
          <label htmlFor="note-title" className="sr-only">
            Note title
          </label>
          <input
            id="note-title"
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Note title..."
            className="w-full bg-transparent text-xl font-semibold text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 rounded px-2 py-1 -mx-2"
          />
          <div
            className="flex items-center justify-between mt-1 text-sm text-muted-foreground"
            aria-live="polite"
          >
            <div className="flex items-center">
              {saving && (
                <span className="flex items-center">
                  <Spinner className="mr-2 h-4 w-4" aria-hidden="true" />
                  <span>Saving...</span>
                  <span className="sr-only">Your note is being saved</span>
                </span>
              )}
              {!saving && lastSaved && <span>Last saved {lastSaved.toLocaleTimeString()}</span>}
              {!saving && !lastSaved && (title || content) && (
                <span className="text-yellow-500">Unsaved changes</span>
              )}
            </div>

            <ButtonGroup>
              {/* Manual Save Button */}
              <Button
                data-save-action
                onClick={handleSave}
                disabled={saving || (!title && !content)}
                variant="default"
                size="sm"
                title="Save note manually (Ctrl+S)"
              >
                <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3-3m0 0l-3 3m3-3v12"
                  />
                </svg>
                Save
              </Button>

              <ButtonGroupSeparator />

              {/* Tags Selector */}
              {selectedNote && selectedNote.id && (
                <>
                  <Suspense fallback={<div className="h-8 w-20 bg-muted rounded animate-pulse"></div>}>
                    <TagSelector
                      noteId={selectedNote.id}
                      size="sm"
                    />
                  </Suspense>
                  <ButtonGroupSeparator />
                </>
              )}

              {/* Encryption Status Badge */}
              <Badge variant="secondary" className="text-xs">
                🔒 E2E
              </Badge>
            </ButtonGroup>
          </div>
        </header>

        {saveError && (
          <div className="px-6 py-2">
            <ErrorNotice
              error={saveError}
              onRetry={handleSave}
              onDismiss={() => setSaveError(null)}
              className="mb-4"
            />
          </div>
        )}

        <div className="flex-1 p-6">
          <Suspense fallback={<ComponentLoader />}>
            <RichTextEditor
              content={content}
              onChange={setContent}
              noteId={selectedNote?.id}
            placeholder="Start writing your secure note... You can use rich text formatting or Markdown!"
            className="h-full"
            defaultMode="wysiwyg"
            showModeToggle={true}
            />
          </Suspense>
          <p id="editor-help" className="sr-only">
            This note is automatically encrypted and saved as you type. Supports rich text and Markdown formatting.
          </p>
        </div>
      </div>
    )
  }

  // Notes List Component
  const NotesList: React.FC = () => {
    const [searchQuery, setSearchQuery] = useState('')
    const [searchResults, setSearchResults] = useState<SearchResult[]>([])
    const [isSearchMode, setIsSearchMode] = useState(false)

    const currentNotes = viewingTrash ? trashedNotes : notes
    const filteredNotes = currentNotes.filter(
      (note) =>
        note.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        note.content.toLowerCase().includes(searchQuery.toLowerCase())
    )

    const handleSearchResults = (results: SearchResult[], query: string) => {
      setSearchResults(results)
      setIsSearchMode(!!query.trim())
    }

    const handleSearchClear = () => {
      setSearchResults([])
      setIsSearchMode(false)
      setSearchQuery('')
    }

    const handleSelectSearchResult = (noteId: string) => {
      const note = notes.find(n => n.id === noteId)
      if (note) {
        setSelectedNote(note)
        if (window.innerWidth < 768) {
          setCurrentView('editor')
        }
      }
    }

    return (
      <nav
        className="w-full md:w-80 bg-card md:border-r border-border flex flex-col h-full"
        role="navigation"
        aria-label={viewingTrash ? 'Trash list' : 'Notes list'}
      >
        <div className="p-4 border-b border-border">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-lg font-semibold text-foreground">
              {viewingTrash ? 'Trash' : 'Notes'}
            </h2>
            {viewingTrash && (
              <Badge variant="secondary" className="text-xs">
                {trashedNotes.length} items
              </Badge>
            )}
          </div>

          {!viewingTrash ? (
            <Suspense fallback={<ComponentLoader />}>
              <SearchBar
                onSearchResults={handleSearchResults}
                onClear={handleSearchClear}
                placeholder="Search notes..."
                className="w-full"
              />
            </Suspense>
          ) : (
            <div className="relative">
              <label htmlFor="search-notes" className="sr-only">
                Search trash
              </label>
              <svg
                className="absolute left-3 top-2.5 w-5 h-5 text-muted-foreground"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
                aria-hidden="true"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
                />
              </svg>
              <Input
                id="search-notes"
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search trash..."
                className="w-full pl-10"
                aria-describedby="search-help"
              />
              <p id="search-help" className="sr-only">
                Search through your trashed notes
              </p>
            </div>
          )}
        </div>

        <div className="flex-1 overflow-y-auto" role="list" aria-label="Notes">
          {notesError ? (
            <div className="p-4">
              <ErrorNotice
                error={notesError}
                onRetry={() => loadNotes()}
                onDismiss={() => setNotesError(null)}
              />
            </div>
          ) : loading ? (
            <NoteListSkeleton />
          ) : !viewingTrash && isSearchMode ? (
            <div className="p-4">
              <Suspense fallback={<ComponentLoader />}>
                <SearchResults
                  results={searchResults}
                  query={searchResults.length > 0 ? 'search' : ''}
                  onSelectNote={handleSelectSearchResult}
                  className=""
                />
              </Suspense>
            </div>
          ) : filteredNotes.length > 0 ? (
            filteredNotes.map((note) => (
              <div
                key={note.id}
                className={`border-b border-border ${
                  selectedNote?.id === note.id ? 'bg-accent' : ''
                }`}
              >
                <div className="flex">
                  <button
                    data-note-button
                    onClick={() => {
                      if (!viewingTrash) {
                        setSelectedNote(note)
                        // On mobile, switch to editor view when selecting a note
                        if (window.innerWidth < 768) {
                          setCurrentView('editor')
                        }
                      }
                    }}
                    className={`flex-1 text-left p-4 md:p-4 py-6 md:py-4 cursor-pointer hover:bg-accent active:bg-accent transition focus:outline-none focus:bg-accent focus:ring-2 focus:ring-ring ${
                      viewingTrash ? 'cursor-default' : ''
                    }`}
                    role="listitem"
                    aria-pressed={selectedNote?.id === note.id}
                    aria-describedby={`note-${note.id}-date`}
                    disabled={viewingTrash}
                  >
                    <h3 className="font-medium text-foreground mb-1">{note.title || 'Untitled'}</h3>
                    <p className="text-sm text-muted-foreground line-clamp-2">
                      {note.content || 'No content'}
                    </p>
                    <p id={`note-${note.id}-date`} className="text-xs text-muted-foreground mt-2">
                      {viewingTrash ? 'Deleted' : 'Modified'}{' '}
                      {new Date(note.updated_at).toLocaleDateString()}
                    </p>
                  </button>

                  {/* Action buttons */}
                  <div className="flex flex-col justify-center px-2 py-2 space-y-1">
                    {viewingTrash ? (
                      <>
                        {/* Restore button */}
                        <button
                          onClick={() => handleRestoreNote(note.id)}
                          className="p-2 text-green-400 hover:text-green-300 hover:bg-green-900/50 rounded transition focus:outline-none focus:ring-2 focus:ring-green-500/50"
                          title="Restore note"
                          aria-label="Restore note"
                        >
                          <svg
                            className="w-4 h-4"
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                            aria-hidden="true"
                          >
                            <path
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth={2}
                              d="M3 10h10a8 8 0 018 8v2M3 10l6 6m-6-6l6-6"
                            />
                          </svg>
                        </button>

                        {/* Permanent delete button */}
                        <button
                          onClick={() => {
                            if (confirm('Permanently delete this note? This cannot be undone.')) {
                              handlePermanentDelete(note.id)
                            }
                          }}
                          className="p-2 text-red-400 hover:text-red-300 hover:bg-red-900/50 rounded transition focus:outline-none focus:ring-2 focus:ring-red-500/50"
                          title="Delete permanently"
                          aria-label="Delete permanently"
                        >
                          <svg
                            className="w-4 h-4"
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                            aria-hidden="true"
                          >
                            <path
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth={2}
                              d="M6 18L18 6M6 6l12 12"
                            />
                          </svg>
                        </button>
                      </>
                    ) : (
                      /* Delete button for regular notes */
                      <button
                        onClick={() => {
                          if (confirm('Move this note to trash?')) {
                            api
                              .deleteNote(note.id)
                              .then(() => {
                                // Remove from notes list
                                setNotes((prevNotes) => prevNotes.filter((n) => n.id !== note.id))
                                // Clear selection if this note was selected
                                if (selectedNote?.id === note.id) {
                                  setSelectedNote(null)
                                }
                              })
                              .catch((err) => {
                                console.error('Failed to delete note:', err)
                                setNotesError(err.message || 'Failed to delete note')
                              })
                          }
                        }}
                        className="p-2 text-red-400 hover:text-red-300 hover:bg-red-900/50 rounded transition focus:outline-none focus:ring-2 focus:ring-red-500/50"
                        title="Move to trash"
                        aria-label="Move to trash"
                      >
                        <svg
                          className="w-4 h-4"
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                          aria-hidden="true"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={2}
                            d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1-1H7a1 1 0 00-1 1v3M4 7h16"
                          />
                        </svg>
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ))
          ) : (
            <div className="p-4 text-center text-gray-500" role="status" aria-live="polite">
              {viewingTrash
                ? searchQuery
                  ? 'No items found in trash'
                  : 'Trash is empty'
                : searchQuery
                  ? 'No notes found'
                  : 'No notes yet'}
            </div>
          )}
        </div>

        {!viewingTrash && (
          <div className="p-4 border-t border-border space-y-2">
            <Button
              onClick={() => {
                setSelectedNote({
                  id: '',
                  title: '',
                  content: '',
                  created_at: new Date().toISOString(),
                  updated_at: new Date().toISOString(),
                })
                setCurrentView('editor')
              }}
              className="w-full"
              aria-describedby="new-note-help"
            >
              <Plus className="h-4 w-4 mr-2" />
              New Note
            </Button>
            <Button
              onClick={() => setShowTemplateSelector(true)}
              variant="outline"
              className="w-full"
              aria-describedby="template-note-help"
            >
              <FileText className="h-4 w-4 mr-2" />
              New from Template
            </Button>
            <p id="new-note-help" className="sr-only">
              Create a new note
            </p>
            <p id="template-note-help" className="sr-only">
              Create a new note from a template
            </p>
          </div>
        )}
      </nav>
    )
  }

  // Main App Layout
  const AppLayout: React.FC = () => {
    // Filter announcements for logged-in users
    const loggedInAnnouncements = announcements.filter(a =>
      a.visibility === 'all' || a.visibility === 'logged_in'
    )

    return (
      <div className="h-screen flex flex-col bg-background">
        {/* Announcements for logged-in users */}
        {loggedInAnnouncements.length > 0 && (
          <div className="border-b border-border bg-card/50 px-4 py-2">
            <AnnouncementBanner announcements={loggedInAnnouncements} />
          </div>
        )}

        <div className="flex-1 flex flex-col md:flex-row">
          <div className="md:hidden flex items-center justify-between bg-card border-b border-border px-4 py-3">
            <h1 className="text-lg font-semibold text-foreground">LeafLock</h1>
            <Button
              onClick={() => setCurrentView(currentView === 'notes' ? 'editor' : 'notes')}
              variant="ghost"
              size="sm"
              className="p-1"
              aria-label={currentView === 'notes' ? 'Show editor' : 'Show notes list'}
            >
              {currentView === 'notes' ? (
                <svg
                  className="w-5 h-5"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  aria-hidden="true"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M12 4v16m8-8H4"
                  />
                </svg>
              ) : (
                <svg
                  className="w-5 h-5"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  aria-hidden="true"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M4 6h16M4 12h16M4 18h16"
                  />
                </svg>
              )}
            </Button>
          </div>

          <div
            className={`${currentView === 'notes' || selectedNote || currentView === 'editor' ? 'hidden md:block' : 'block'} w-full md:w-80`}
          >
            <NotesList />
          </div>

          <div
            className={`${currentView === 'notes' && !selectedNote ? 'hidden md:flex' : 'flex'} flex-1 flex-col`}
          >
            <header className="hidden md:flex bg-card border-b border-border px-6 py-3 items-center justify-between">
              <div className="flex items-center space-x-4">
                <h1 className="text-lg font-semibold text-foreground">LeafLock</h1>
              </div>

              <div className="flex items-center space-x-4">
                <Suspense fallback={<ComponentLoader />}>
                  <ImportExportDialog
                    noteId={selectedNote?.id}
                    notes={notes}
                    setNotes={setNotes}
                    onImportSuccess={() => loadNotes()}
                  />
                </Suspense>

                <ThemeToggle />

                <button
                  onClick={() => setCurrentView('settings')}
                  className="text-gray-400 hover:text-white transition focus:outline-none focus:ring-2 focus:ring-blue-500/50 rounded p-1"
                  aria-label="Security settings"
                  title="Security settings"
                >
                  <Settings className="w-5 h-5" />
                </button>

                <button
                  onClick={() => setCurrentView('tags')}
                  className="text-gray-400 hover:text-white transition focus:outline-none focus:ring-2 focus:ring-blue-500/50 rounded p-1"
                  aria-label="Manage tags"
                  title="Manage tags"
                >
                  <Hash className="w-5 h-5" />
                </button>

                <button
                  onClick={() => setCurrentView('folders')}
                  className="text-gray-400 hover:text-white transition focus:outline-none focus:ring-2 focus:ring-blue-500/50 rounded p-1"
                  aria-label="Manage folders"
                  title="Manage folders"
                >
                  <Folder className="w-5 h-5" />
                </button>

                <button
                  onClick={() => setCurrentView('templates')}
                  className="text-gray-400 hover:text-white transition focus:outline-none focus:ring-2 focus:ring-blue-500/50 rounded p-1"
                  aria-label="Manage templates"
                  title="Manage templates"
                >
                  <FileText className="w-5 h-5" />
                </button>

                <button
                  onClick={() => {
                    setViewingTrash(!viewingTrash)
                    if (!viewingTrash) {
                      loadTrash()
                    }
                  }}
                  className={`flex items-center px-3 py-1 text-sm rounded transition focus:outline-none focus:ring-2 focus:ring-blue-500/50 ${
                    viewingTrash ? 'bg-red-600 text-white' : 'text-gray-400 hover:text-white'
                  }`}
                  aria-label={viewingTrash ? 'Exit trash view' : 'View trash'}
                  title={viewingTrash ? 'Exit trash view' : 'View trash'}
                >
                  <svg
                    className="w-4 h-4 mr-1"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                    aria-hidden="true"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1-1H7a1 1 0 00-1 1v3M4 7h16"
                    />
                  </svg>
                  {viewingTrash ? 'Exit Trash' : 'Trash'}
                </button>

                {isAdmin && (
                  <button
                    onClick={() => setCurrentView('admin')}
                    className="text-gray-400 hover:text-white transition focus:outline-none focus:ring-2 focus:ring-blue-500/50 rounded p-1"
                    aria-label="Admin panel"
                    title="Admin panel"
                  >
                    <Shield className="w-5 h-5" />
                  </button>
                )}

                <button
                  onClick={handleLogout}
                  className="text-gray-400 hover:text-white transition focus:outline-none focus:ring-2 focus:ring-blue-500/50 rounded p-1"
                  aria-label="Sign out"
                  title="Sign out"
                >
                  <svg
                    className="w-5 h-5"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                    aria-hidden="true"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"
                    />
                  </svg>
                </button>
              </div>
            </header>

            {selectedNote || currentView === 'editor' ? (
              <NotesEditor />
            ) : (
              <main className="flex-1 flex items-center justify-center" role="main">
                <div className="text-center">
                  <svg
                    className="w-16 h-16 mx-auto text-gray-600 mb-4"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                    aria-hidden="true"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={1.5}
                      d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                    />
                  </svg>
                  <p className="text-gray-500">Select a note or create a new one</p>
                  <p className="text-gray-600 text-sm mt-2">
                    Your notes are end-to-end encrypted for maximum privacy
                  </p>
                </div>
              </main>
            )}
          </div>
        </div>
        <Footer />
      </div>
    )
  }

  // Security check: Only force logout if locked in an unexpected view
  useEffect(() => {
    if (
      !initializing &&
      encryptionStatus === 'locked' &&
      isAuthenticated &&
      currentView !== 'unlock'
    ) {
      console.log(
        '🚨 Security check: Locked while authenticated outside unlock view - forcing logout'
      )
      setIsAuthenticated(false)
      setCurrentView('login')
    }
  }, [encryptionStatus, isAuthenticated, initializing, currentView])

  // Load announcements
  const loadAnnouncements = useCallback(async () => {
    try {
      setAnnouncementsLoading(true)
      const response = await api.getAnnouncements()
      setAnnouncements(response.announcements || [])
    } catch (error) {
      console.warn('Failed to load announcements:', error)
      // Don't show error to user for announcements - it's not critical
    } finally {
      setAnnouncementsLoading(false)
    }
  }, [])

  // Load announcements on app start and when authentication changes
  useEffect(() => {
    if (!initializing) {
      loadAnnouncements()
    }
  }, [initializing, isAuthenticated, loadAnnouncements])

  if (initializing) {
    return <LoadingOverlay message="Starting LeafLock" />
  }

    return (
    <>
      {isAuthenticated && encryptionStatus === 'unlocked' && currentView === 'settings' ? (
        <SettingsPage api={api} onBack={() => setCurrentView('notes')} onLogout={handleLogout} />
      ) : isAuthenticated && encryptionStatus === 'unlocked' && currentView === 'tags' ? (
        <div className="h-screen flex items-center justify-center bg-background">
          <Suspense fallback={<ComponentLoader />}>
            <TagsManager onClose={() => setCurrentView('notes')} />
          </Suspense>
        </div>
      ) : isAuthenticated && encryptionStatus === 'unlocked' && currentView === 'folders' ? (
        <div className="h-screen flex items-center justify-center bg-background">
          <Suspense fallback={<ComponentLoader />}>
            <FoldersManager onClose={() => setCurrentView('notes')} />
          </Suspense>
        </div>
      ) : isAuthenticated && encryptionStatus === 'unlocked' && currentView === 'templates' ? (
        <div className="h-screen flex items-center justify-center bg-background">
          <Suspense fallback={<ComponentLoader />}>
            <TemplatesManager onClose={() => setCurrentView('notes')} mode="manage" />
          </Suspense>
        </div>
      ) : isAuthenticated && encryptionStatus === 'unlocked' && isAdmin && currentView === 'admin' ? (
        <Suspense fallback={<ComponentLoader />}>
          <AdminPage api={api} onBack={() => setCurrentView('notes')} />
        </Suspense>
      ) : isAuthenticated && encryptionStatus === 'unlocked' ? (
        <>
          <AppLayout />
        </>
      ) : isAuthenticated && currentView === 'unlock' ? (
        <UnlockView onUnlock={handleUnlockWithPassword} onLogout={handleLogout} />
      ) : (
        <LoginView
          api={api}
          cryptoService={cryptoService}
          announcements={announcements}
          onAuthenticated={async () => {
            // User has a valid token and master key; transition to notes
            setIsAuthenticated(true)
            setCurrentView('notes')
            setEncryptionStatus('unlocked')
            // Determine admin status
            try {
              const adminOk = await api.adminHealth()
              setIsAdmin(!!adminOk)
            } catch {
              setIsAdmin(false)
            }
            try {
              await loadNotes()
            } catch (e) {
              console.error('Failed to load notes after auth:', e)
            }
            const hasSeenOnboarding = localStorage.getItem('hasSeenOnboarding')
            if (!hasSeenOnboarding) setShowOnboarding(true)
          }}
        />
      )}
      {/* Admin panel is now accessible via header icon for admins only */}
      {showOnboarding && isAuthenticated && encryptionStatus === 'unlocked' && (
        <OnboardingOverlay
          step={onboardingStep}
          onNext={handleOnboardingNext}
          onPrev={handleOnboardingPrev}
          onSkip={handleOnboardingSkip}
          onComplete={handleOnboardingComplete}
        />
      )}

      {/* Template Selector Modal */}
      {showTemplateSelector && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-background rounded-lg max-w-6xl w-full max-h-[90vh] overflow-hidden">
            <Suspense fallback={<ComponentLoader />}>
              <TemplatesManager
                onClose={() => setShowTemplateSelector(false)}
                onTemplateSelect={handleTemplateSelect}
                mode="select"
              />
            </Suspense>
          </div>
        </div>
      )}
    </>
  )
}

// Main App component wrapped with ThemeProvider
const App: React.FC = () => {
  return (
    <ThemeProvider>
      <LeafLockApp />
      <Toaster />
    </ThemeProvider>
  )
}

export default App
