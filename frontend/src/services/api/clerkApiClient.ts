/**
 * Clerk API Client - Enhanced with Error Handling and Debugging
 *
 * @description
 * Replaces the legacy API client with Clerk session token authentication.
 * Provides compatibility layer for existing API calls while using Clerk tokens.
 *
 * @features
 * - Clerk session token authentication
 * - Enhanced error handling with debugging
 * - Rate limiting protection
 * - Retry logic for transient errors
 * - Comprehensive error logging
 */

import React from 'react'
import { useSession } from '@clerk/clerk-react'

// Enhanced error types for better debugging
export class ClerkApiError extends Error {
  constructor(
    message: string,
    public status?: number,
    public code?: string,
    public debugInfo?: any
  ) {
    super(message)
    this.name = 'ClerkApiError'
  }
}

interface ApiClientConfig {
  maxRetries?: number
  retryDelay?: number
  enableDebug?: boolean
  retryOnAuthFailure?: boolean
}

export class ClerkApiClient {
  private baseURL: string
  private session: ReturnType<typeof useSession> | null = null
  private config: Required<ApiClientConfig>
  private pendingRequests = new Map<string, Promise<any>>()
  private authFailureCount = 0
  private maxAuthFailures = 3

  constructor(baseURL: string, config: ApiClientConfig = {}) {
    this.baseURL = baseURL.replace(/\/$/, '') // Remove trailing slash
    this.config = {
      maxRetries: config.maxRetries ?? 2,
      retryDelay: config.retryDelay ?? 1000,
      enableDebug: config.enableDebug ?? import.meta.env.DEV,
      retryOnAuthFailure: config.retryOnAuthFailure ?? false,
    }
  }

  setSession(session: ReturnType<typeof useSession>) {
    this.session = session
    this.authFailureCount = 0 // Reset failure count on new session
  }

  private debug(...args: any[]) {
    if (this.config.enableDebug) {
      console.log('[ClerkAPI Debug]', ...args)
    }
  }

  private error(...args: any[]) {
    console.error('[ClerkAPI Error]', ...args)
  }

  async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const requestKey = `${endpoint}-${Date.now()}-${Math.random()}`
    
    // Check for duplicate requests
    if (this.pendingRequests.has(endpoint)) {
      this.debug(`Duplicate request detected: ${endpoint}, returning cached promise`)
      return this.pendingRequests.get(endpoint)!
    }

    const requestPromise = this.executeRequest<T>(endpoint, options)
      .finally(() => {
        this.pendingRequests.delete(endpoint)
      })

    this.pendingRequests.set(endpoint, requestPromise)
    return requestPromise
  }

  private async executeRequest<T>(endpoint: string, options: RequestInit, attempt = 1): Promise<T> {
    const url = `${this.baseURL}${endpoint}`
    
    this.debug(`Making ${options.method || 'GET'} request to: ${url} (attempt ${attempt})`)

    let token: string | null = null

    // Get Clerk session token
    try {
      if (
        this.session &&
        'session' in this.session &&
        this.session.session &&
        'getToken' in this.session.session
      ) {
        token = await this.session.session.getToken()
        this.debug(`Token acquired: ${token ? `${token.substring(0, 20)}...` : 'null'}`)
      }
    } catch (error) {
      this.error('Failed to get Clerk session token:', error)
      
      // If we're having trouble getting tokens, let Clerk handle it
      if (attempt > 1) {
        throw new ClerkApiError(
          'Authentication failed. Please sign in again.',
          401,
          'AUTH_FAILED',
          { originalError: error }
        )
      }
      
      // Retry once for token acquisition
      await this.sleep(this.config.retryDelay)
      return this.executeRequest<T>(endpoint, options, attempt + 1)
    }

    // Prepare headers
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...((options.headers as Record<string, string>) || {}),
    }

    // Add authorization header if we have a token
    if (token) {
      headers.Authorization = `Bearer ${token}`
    } else if (!this.isAuthRoute(endpoint)) {
      this.debug('No token available for non-auth route')
    }

    const config: RequestInit = {
      ...options,
      headers,
      credentials: 'include',
    }

    try {
      const response = await fetch(url, config)

      this.debug(`Response status: ${response.status} for ${url}`)

      if (!response.ok) {
        return this.handleErrorResponse<T>(response, endpoint, options, attempt)
      }

      // Reset auth failure count on success
      this.authFailureCount = 0

      // Parse response
      const contentType = response.headers.get('content-type')
      if (contentType && contentType.includes('application/json')) {
        return await response.json()
      } else {
        return (await response.text()) as T
      }
    } catch (error) {
      if (error instanceof ClerkApiError) {
        throw error
      }
      
      this.error('Network error:', error)
      
      // Retry for network errors
      if (attempt <= this.config.maxRetries && this.isRetryableError(error)) {
        this.debug(`Retrying after network error (attempt ${attempt + 1})`)
        await this.sleep(this.config.retryDelay * attempt)
        return this.executeRequest<T>(endpoint, options, attempt + 1)
      }
      
      throw new ClerkApiError('Network error occurred', undefined, 'NETWORK_ERROR', { originalError: error })
    }
  }

  private async handleErrorResponse<T>(
    response: Response,
    endpoint: string,
    options: RequestInit,
    attempt: number
  ): Promise<T> {
    const errorData = await response.text()
    let errorMessage = `HTTP ${response.status}: ${response.statusText}`
    let parsedError: any = null

    try {
      parsedError = JSON.parse(errorData)
      errorMessage = parsedError.message || parsedError.error || errorMessage
    } catch {
      errorMessage = errorData || errorMessage
    }

    this.debug(`Error response: ${errorMessage}`, parsedError)

    // Handle authentication failures
    if (response.status === 401 || response.status === 403) {
      this.authFailureCount++
      
      // Check if we're in a redirect loop
      if (this.authFailureCount >= this.maxAuthFailures) {
        this.error('Max auth failures reached, preventing redirect loop')
        throw new ClerkApiError(
          'Authentication failed multiple times. Please sign in again.',
          401,
          'AUTH_LOOP_DETECTED',
          { endpoint, attempts: this.authFailureCount }
        )
      }

      // Don't automatically redirect - let the component handle it
      throw new ClerkApiError(
        errorMessage,
        response.status,
        parsedError?.code || 'AUTH_FAILED',
        { 
          endpoint, 
          debugInfo: parsedError?.debug,
          tokenLength: this.session ? 'present' : 'missing',
          attempts: this.authFailureCount
        }
      )
    }

    // Retry for 5xx errors
    if (response.status >= 500 && attempt <= this.config.maxRetries) {
      this.debug(`Retrying after server error ${response.status} (attempt ${attempt + 1})`)
      await this.sleep(this.config.retryDelay * attempt)
      return this.executeRequest<T>(endpoint, options, attempt + 1)
    }

    throw new ClerkApiError(errorMessage, response.status, parsedError?.code, parsedError)
  }

  private isAuthRoute(endpoint: string): boolean {
    return endpoint.includes('/auth/') || endpoint.includes('/login') || endpoint.includes('/register')
  }

  private isRetryableError(error: any): boolean {
    const errorMessage = error?.message || ''
    const networkErrors = [
      'Failed to fetch',
      'NetworkError',
      'ECONNREFUSED',
      'ETIMEDOUT',
      'ENOTFOUND',
    ]
    
    return networkErrors.some(err => errorMessage.includes(err))
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms))
  }

  // Public debug method to check auth status
  getAuthStatus() {
    return {
      hasSession: !!(this.session && 'session' in this.session && this.session.session),
      authFailureCount: this.authFailureCount,
      maxAuthFailures: this.maxAuthFailures,
      baseURL: this.baseURL,
    }
  }

  // Convenience methods
  async get<T>(endpoint: string): Promise<T> {
    return this.request<T>(endpoint, { method: 'GET' })
  }

  async post<T>(endpoint: string, data?: any): Promise<T> {
    return this.request<T>(endpoint, {
      method: 'POST',
      body: data ? JSON.stringify(data) : undefined,
    })
  }

  async put<T>(endpoint: string, data?: any): Promise<T> {
    return this.request<T>(endpoint, {
      method: 'PUT',
      body: data ? JSON.stringify(data) : undefined,
    })
  }

  async delete<T>(endpoint: string): Promise<T> {
    return this.request<T>(endpoint, { method: 'DELETE' })
  }

  // Batch request method for multiple endpoints
  async batch<T>(requests: Array<{endpoint: string, options?: RequestInit}>): Promise<T[]> {
    return Promise.all(
      requests.map(req => this.request<T>(req.endpoint, req.options))
    )
  }
}

// Enhanced error boundary for auth errors
export function isAuthLoopError(error: any): boolean {
  return error instanceof ClerkApiError && 
         (error.code === 'AUTH_LOOP_DETECTED' || 
          (error.status === 401 && error.message?.includes('multiple times')))
}

export function shouldRedirectToLogin(error: any): boolean {
  if (!error) return false
  
  // Don't redirect for auth loop errors
  if (isAuthLoopError(error)) {
    return false
  }
  
  // Only redirect for auth errors with specific codes
  const authErrorCodes = ['AUTH_FAILED', 'SESSION_EXPIRED']
  return error instanceof ClerkApiError && 
         error.status === 401 && 
         authErrorCodes.includes(error.code || '')
}

// Create singleton instance with enhanced configuration
export const clerkApiClient = new ClerkApiClient(
  import.meta.env.VITE_API_URL || '',
  {
    enableDebug: import.meta.env.DEV,
    maxRetries: 2,
    retryOnAuthFailure: false,
  }
)

// Hook to initialize the API client with Clerk session
export const useClerkApiClient = () => {
  const session = useSession()

  React.useEffect(() => {
    clerkApiClient.setSession(session)
  }, [session])

  return clerkApiClient
}

// Hook to check if we're potentially in an auth loop
export const useAuthLoopDetector = () => {
  const [authErrorCount, setAuthErrorCount] = React.useState(0)
  const [lastAuthError, setLastAuthError] = React.useState<any>(null)

  const recordAuthError = React.useCallback((error: any) => {
    setAuthErrorCount(prev => {
      const newCount = prev + 1
      
      // If we get more than 3 auth errors in a row, we might be in a loop
      if (newCount > 3) {
        console.error('Potential auth loop detected:', {
          error,
          count: newCount,
        })
      }
      
      return newCount
    })
    setLastAuthError(error)
  }, [])

  const resetAuthErrorCount = React.useCallback(() => {
    setAuthErrorCount(0)
    setLastAuthError(null)
  }, [])

  const isPotentiallyInAuthLoop = authErrorCount > 3

  return {
    authErrorCount,
    lastAuthError,
    isPotentiallyInAuthLoop,
    recordAuthError,
    resetAuthErrorCount,
  }
}
