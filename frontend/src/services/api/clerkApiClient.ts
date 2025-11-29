/**
 * Clerk API Client
 * 
 * @description
 * Replaces the legacy API client with Clerk session token authentication.
 * Provides compatibility layer for existing API calls while using Clerk tokens.
 * 
 * @features
 * - Clerk session token authentication
 * - Automatic token refresh
 * - Error handling for authentication failures
 * - Compatibility with existing API endpoints
 */

import React from 'react'
import { useSession } from '@clerk/clerk-react'

export class ClerkApiClient {
  private baseURL: string
  private session: ReturnType<typeof useSession> | null = null

  constructor(baseURL: string) {
    this.baseURL = baseURL.replace(/\/$/, '') // Remove trailing slash
  }

  setSession(session: ReturnType<typeof useSession>) {
    this.session = session
  }

  async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.baseURL}${endpoint}`
    
    // Get Clerk session token - handle different session states
    let token: string | null = null
    if (this.session && 'session' in this.session && this.session.session && 'getToken' in this.session.session) {
      try {
        token = await this.session.session.getToken()
      } catch (error) {
        console.warn('Failed to get Clerk session token:', error)
      }
    }
    
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string> || {}),
    }

    // Add authorization header if we have a token
    if (token) {
      headers.Authorization = `Bearer ${token}`
    }

    const config: RequestInit = {
      ...options,
      headers,
      credentials: 'include',
    }

    try {
      const response = await fetch(url, config)

      if (!response.ok) {
        const errorData = await response.text()
        let errorMessage = `HTTP ${response.status}: ${response.statusText}`
        
        try {
          const parsedError = JSON.parse(errorData)
          errorMessage = parsedError.message || parsedError.error || errorMessage
        } catch {
          errorMessage = errorData || errorMessage
        }

        throw new Error(errorMessage)
      }

      const contentType = response.headers.get('content-type')
      if (contentType && contentType.includes('application/json')) {
        return await response.json()
      } else {
        return (await response.text()) as T
      }
    } catch (error) {
      if (error instanceof Error) {
        // Handle specific authentication errors
        if (error.message.includes('401') || error.message.includes('Unauthorized')) {
          console.error('Authentication failed - may need to re-authenticate with Clerk')
          // Clerk will handle the redirect to login automatically
        }
        throw error
      }
      throw new Error('Network error occurred')
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
}

// Create singleton instance
export const clerkApiClient = new ClerkApiClient(import.meta.env.VITE_API_URL || '')

// Hook to initialize the API client with Clerk session
export const useClerkApiClient = () => {
  const session = useSession()
  
  React.useEffect(() => {
    clerkApiClient.setSession(session)
  }, [session])
  
  return clerkApiClient
}