import { clearAuthStorage, safeRedirectToLogin, isOnAuthRoute } from '@/lib/navigation'
import { API_BASE_URL } from './types'

export class ApiClient {
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

  protected async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
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
      // BUT: Don't clear session for login/register endpoints (those 401s are expected for wrong credentials)
      const isAuthEndpoint = endpoint.includes('/auth/login') ||
                            endpoint.includes('/auth/register') ||
                            endpoint.includes('/auth/mfa/verify')

      if (response.status === 401 && !isAuthEndpoint) {
        console.warn('401 Unauthorized - clearing expired session')
        clearAuthStorage()
        if (typeof window !== 'undefined' && !isOnAuthRoute()) {
          // Small timeout to allow UI to settle before navigation
          setTimeout(() => safeRedirectToLogin(), 50)
        }
      }

      throw new Error(errorData.message || errorData.error || `HTTP ${response.status}`)
    }

    // Handle empty responses (204 No Content or missing payload)
    if (response.status === 204 || response.headers.get('content-length') === '0') {
      return null as T
    }

    // Check if response has JSON content type
    const contentType = response.headers.get('content-type')
    if (!contentType || !contentType.includes('application/json')) {
      return null as T
    }

    const data = await response.json()

    if (data == null) {
      return null as T
    }

    return data
  }

  protected setToken(token: string): void {
    this.token = token
    if (typeof window !== 'undefined') {
      localStorage.setItem('token', token)
    }
  }

  protected clearToken(): void {
    this.token = null
    if (typeof window !== 'undefined') {
      localStorage.removeItem('token')
      localStorage.removeItem('user')
    }
  }
}
