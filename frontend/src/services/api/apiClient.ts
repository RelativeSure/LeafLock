import { safeRedirectToLogin, isOnAuthRoute } from '@/lib/navigation'
import { API_BASE_URL } from './types'

export class ApiClient {
  private baseURL: string

  constructor(baseURL: string = API_BASE_URL) {
    this.baseURL = baseURL
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



    const response = await fetch(url, {
      ...options,
      headers,
    })

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))

      // Handle 401 Unauthorized - but don't clear session for login/register endpoints
      const isAuthEndpoint =
        endpoint.includes('/auth/login') ||
        endpoint.includes('/auth/register') ||
        endpoint.includes('/auth/mfa/verify')

      if (response.status === 401 && !isAuthEndpoint) {
        console.warn('401 Unauthorized - authentication required')
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



  // Public methods for direct usage
  async get<T>(endpoint: string, options?: RequestInit): Promise<T> {
    return this.request<T>(endpoint, { ...options, method: 'GET' })
  }

  async post<T>(endpoint: string, data?: any, options?: RequestInit): Promise<T> {
    return this.request<T>(endpoint, {
      ...options,
      method: 'POST',
      body: data ? JSON.stringify(data) : undefined,
    })
  }

  async put<T>(endpoint: string, data?: any, options?: RequestInit): Promise<T> {
    return this.request<T>(endpoint, {
      ...options,
      method: 'PUT',
      body: data ? JSON.stringify(data) : undefined,
    })
  }

  async delete<T>(endpoint: string, options?: RequestInit): Promise<T> {
    return this.request<T>(endpoint, { ...options, method: 'DELETE' })
  }
}

// Export a singleton instance
export const apiClient = new ApiClient()
