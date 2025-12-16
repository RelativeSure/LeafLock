/**
 * Runtime Configuration Utility
 *
 * @description
 * Provides access to environment variables that can be set at runtime,
 * not just at build time. This is essential for deployment platforms like
 * Railway where environment variables may not be available during the build.
 *
 * @architecture
 * 1. Checks window.__ENV__ for runtime-injected variables (from meta tags)
 * 2. Falls back to import.meta.env for build-time variables
 * 3. Provides type-safe access to configuration values
 *
 * @usage
 * ```typescript
 * import { getRuntimeConfig } from '@/lib/runtime-config'
 *
 * const config = getRuntimeConfig()
 * console.log(config.clerkPublishableKey)
 * ```
 */

declare global {
  interface Window {
    __ENV__?: {
      VITE_CLERK_PUBLISHABLE_KEY?: string
      VITE_API_URL?: string
      [key: string]: string | undefined
    }
  }
}

export interface RuntimeConfig {
  clerkPublishableKey: string | undefined
  apiUrl: string | undefined
  isDevelopment: boolean
  isProduction: boolean
}

/**
 * Get runtime configuration values
 *
 * @description
 * Retrieves configuration values in the following priority order:
 * 1. Runtime-injected values (window.__ENV__)
 * 2. Build-time values (import.meta.env)
 *
 * @returns {RuntimeConfig} Configuration object with all available values
 *
 * @example
 * ```typescript
 * const config = getRuntimeConfig()
 * if (!config.clerkPublishableKey) {
 *   console.error('Clerk key not configured')
 * }
 * ```
 */
export function getRuntimeConfig(): RuntimeConfig {
  // Try runtime-injected values first (from meta tags)
  const runtimeClerkKey =
    typeof window !== 'undefined' ? window.__ENV__?.VITE_CLERK_PUBLISHABLE_KEY : undefined

  const runtimeApiUrl = typeof window !== 'undefined' ? window.__ENV__?.VITE_API_URL : undefined

  // Fall back to build-time values
  const buildTimeClerkKey = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY
  const buildTimeApiUrl = import.meta.env.VITE_API_URL

  const clerkPublishableKey = runtimeClerkKey || buildTimeClerkKey
  const apiUrl = runtimeApiUrl || buildTimeApiUrl

  return {
    clerkPublishableKey,
    apiUrl,
    isDevelopment: import.meta.env.DEV,
    isProduction: import.meta.env.PROD,
  }
}

/**
 * Get Clerk publishable key with validation
 *
 * @description
 * Retrieves the Clerk publishable key and validates it's present.
 * Logs a warning if the key is missing.
 *
 * @returns {string | undefined} Clerk publishable key or undefined
 *
 * @example
 * ```typescript
 * const key = getClerkPublishableKey()
 * if (key) {
 *   // Initialize Clerk
 * }
 * ```
 */
export function getClerkPublishableKey(): string | undefined {
  const config = getRuntimeConfig()

  if (!config.clerkPublishableKey) {
    console.error(
      '🚨 VITE_CLERK_PUBLISHABLE_KEY is not configured!\n' +
        'This should be set either:\n' +
        '1. As a build-time variable in Railway\n' +
        '2. As a runtime variable (injected via meta tags)\n' +
        'Check Railway environment variables and Dockerfile configuration.'
    )
  }

  return config.clerkPublishableKey
}

/**
 * Get API URL with fallback
 *
 * @description
 * Retrieves the API URL from runtime or build-time configuration.
 * Falls back to '/api/v1' if not configured.
 *
 * @returns {string} API URL
 *
 * @example
 * ```typescript
 * const apiUrl = getApiUrl()
 * fetch(`${apiUrl}/health`)
 * ```
 */
export function getApiUrl(): string {
  const config = getRuntimeConfig()
  return config.apiUrl || '/api/v1'
}

/**
 * Wait for runtime configuration to be ready
 *
 * @description
 * Returns a promise that resolves when the runtime configuration
 * has been loaded from meta tags. Useful for ensuring config is
 * available before initializing the app.
 *
 * @param {number} timeout - Maximum time to wait in milliseconds (default: 5000)
 * @returns {Promise<RuntimeConfig>} Promise that resolves with the config
 *
 * @example
 * ```typescript
 * await waitForRuntimeConfig()
 * const config = getRuntimeConfig()
 * ```
 */
export function waitForRuntimeConfig(timeout = 5000): Promise<RuntimeConfig> {
  return new Promise((resolve, reject) => {
    // Check if config is already available
    if (typeof window !== 'undefined' && window.__ENV__) {
      resolve(getRuntimeConfig())
      return
    }

    // Wait for runtime-config-ready event
    const handleReady = () => {
      clearTimeout(timeoutId)
      resolve(getRuntimeConfig())
    }

    const timeoutId = setTimeout(() => {
      window.removeEventListener('runtime-config-ready', handleReady)
      // Resolve anyway with whatever config is available
      resolve(getRuntimeConfig())
    }, timeout)

    if (typeof window !== 'undefined') {
      window.addEventListener('runtime-config-ready', handleReady, { once: true })
    } else {
      clearTimeout(timeoutId)
      reject(new Error('Window is not defined'))
    }
  })
}

/**
 * Debug runtime configuration
 *
 * @description
 * Logs current configuration state to console for debugging.
 * Only logs in development mode.
 *
 * @example
 * ```typescript
 * debugRuntimeConfig()
 * ```
 */
export function debugRuntimeConfig(): void {
  const config = getRuntimeConfig()

  if (config.isDevelopment) {
    console.group('🔧 Runtime Configuration Debug')
    console.log('Clerk Key:', config.clerkPublishableKey ? '✅ Set' : '❌ Missing')
    console.log('API URL:', config.apiUrl || '❌ Not set (will use default)')
    console.log('Environment:', config.isDevelopment ? 'Development' : 'Production')

    if (typeof window !== 'undefined' && window.__ENV__) {
      console.log('Runtime Config:', window.__ENV__)
    } else {
      console.log('Runtime Config: ❌ Not loaded')
    }

    console.log('Build-time Config:', {
      clerkKey: import.meta.env.VITE_CLERK_PUBLISHABLE_KEY ? '✅ Set' : '❌ Missing',
      apiUrl: import.meta.env.VITE_API_URL || '❌ Not set',
    })
    console.groupEnd()
  }
}
