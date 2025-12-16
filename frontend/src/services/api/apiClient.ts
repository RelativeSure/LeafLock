import {
  ClerkApiClient,
  ClerkApiError,
  isAuthLoopError,
  shouldRedirectToLogin,
} from './clerkApiClient'
import { safeRedirectToLogin } from '@/lib/navigation'
import { API_BASE_URL } from './types'

export class ApiClient extends ClerkApiClient {
  constructor(baseURL: string = API_BASE_URL) {
    super(baseURL, {
      enableDebug: import.meta.env.DEV,
      maxRetries: 2,
      retryOnAuthFailure: false,
    })
  }

  // Override request to maintain backward compatibility with error handling
  public async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    try {
      return await super.request<T>(endpoint, options)
    } catch (error) {
      // Handle auth errors with backward-compatible redirect behavior
      if (shouldRedirectToLogin(error) && typeof window !== 'undefined') {
        console.warn('Authentication required - redirecting to login')
        setTimeout(() => safeRedirectToLogin(), 50)
      }

      // Re-throw for backward compatibility
      throw error
    }
  }
}

// Export a singleton instance
export const apiClient = new ApiClient()

// Re-export error types for backward compatibility
export { ClerkApiError, isAuthLoopError, shouldRedirectToLogin }
