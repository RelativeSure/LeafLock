/**
 * Dynamic configuration utility for Railway deployments
 * Automatically detects service URLs based on environment
 */

export interface Config {
  apiUrl: string
  environment: 'development' | 'production' | 'preview'
  isRailway: boolean
  serviceName?: string
}

/**
 * Detect if running on Railway
 */
function isRailwayEnvironment(): boolean {
  return !!(
    import.meta.env.RAILWAY_ENVIRONMENT ||
    import.meta.env.RAILWAY_PROJECT_ID ||
    import.meta.env.RAILWAY_SERVICE_NAME ||
    // Check for Railway-specific environment variables
    (typeof window !== 'undefined' && window.location.hostname.includes('railway.app'))
  )
}

/**
 * Get Railway service URL from environment variables
 */
function getRailwayServiceUrl(serviceName: string): string | null {
  // Railway service references (recommended approach)
  // These are automatically set when you reference other services
  const envVarName = `${serviceName.toUpperCase()}_URL`
  const serviceUrl = import.meta.env[envVarName as keyof ImportMetaEnv]
  if (serviceUrl) {
    return serviceUrl as string
  }

  // Railway provides these environment variables
  const railwayVarName = `RAILWAY_${serviceName.toUpperCase()}_URL`
  const railwayUrl = import.meta.env[railwayVarName as keyof ImportMetaEnv]
  if (railwayUrl) {
    return railwayUrl as string
  }

  // Fallback: construct from Railway's internal networking
  const railwayInternalHost = import.meta.env.RAILWAY_INTERNAL_HOST
  if (railwayInternalHost) {
    return `https://${railwayInternalHost}`
  }

  return null
}

/**
 * Resolve API URL based on environment and service discovery
 */
function resolveApiUrl(): string {
  // Special case: Railway preview deployments should use same-origin
  // This avoids CORS issues and ensures preview uses its own backend
  if (isRailwayEnvironment() && import.meta.env.RAILWAY_ENVIRONMENT === 'preview') {
    if (typeof window !== 'undefined') {
      console.log('🔧 Railway preview detected: using same-origin API URL')
      return `${window.location.origin}/api/v1`
    }
  }

  // 1. Explicit override (highest priority)
  if (import.meta.env.VITE_API_URL) {
    return import.meta.env.VITE_API_URL
  }

  // 2. Railway service discovery (automatic - no manual config needed!)
  if (isRailwayEnvironment()) {
    // Try Railway's automatic service variables first (most reliable)
    const automaticBackendUrl = (import.meta.env.BACKEND_URL ||
      import.meta.env.API_URL ||
      import.meta.env.SERVER_URL) as string | undefined

    if (automaticBackendUrl) {
      return `${automaticBackendUrl}/api/v1`
    }

    // Try Railway's private/internal networking (preferred for internal communication)
    const railwayInternalHost = import.meta.env.RAILWAY_INTERNAL_HOST
    if (railwayInternalHost) {
      return `https://${railwayInternalHost}/api/v1`
    }

    // Try Railway's private domain pattern
    const railwayPrivateDomain = import.meta.env.RAILWAY_PRIVATE_DOMAIN
    if (railwayPrivateDomain) {
      return `https://${railwayPrivateDomain}/api/v1`
    }

    // Try multiple service name patterns
    const serviceNames = ['backend', 'api', 'server', 'leaflock-backend', 'leaflock-api']

    for (const serviceName of serviceNames) {
      const serviceUrl = getRailwayServiceUrl(serviceName)
      if (serviceUrl) {
        return `${serviceUrl}/api/v1`
      }
    }

    // Try Railway's public domain pattern (fallback)
    const railwayPublicDomain = import.meta.env.RAILWAY_PUBLIC_DOMAIN
    if (railwayPublicDomain) {
      return `https://${railwayPublicDomain}/api/v1`
    }
  }

  // 3. Development proxy target
  if (import.meta.env.VITE_DEV_PROXY_TARGET) {
    return `${import.meta.env.VITE_DEV_PROXY_TARGET as string}/api/v1`
  }

  // 4. Granular dev settings
  if (import.meta.env.VITE_DEV_BACKEND_PROTOCOL) {
    const protocol = import.meta.env.VITE_DEV_BACKEND_PROTOCOL as string
    const host = (import.meta.env.VITE_DEV_BACKEND_HOST as string) || 'localhost'
    const port = (import.meta.env.VITE_DEV_BACKEND_PORT as string) || '8080'
    return `${protocol}://${host}:${port}/api/v1`
  }

  // 5. Browser-based fallback
  if (typeof window !== 'undefined') {
    return `${window.location.origin}/api/v1`
  }

  // 6. Default fallback
  return 'http://localhost:8080/api/v1'
}

/**
 * Get service name from Railway environment
 */
function getServiceName(): string | undefined {
  return (import.meta.env.RAILWAY_SERVICE_NAME || import.meta.env.VITE_SERVICE_NAME) as
    | string
    | undefined
}

/**
 * Determine environment type
 */
function getEnvironment(): 'development' | 'production' | 'preview' {
  if (import.meta.env.MODE === 'development') {
    return 'development'
  }

  if (import.meta.env.RAILWAY_ENVIRONMENT === 'preview') {
    return 'preview'
  }

  return 'production'
}

/**
 * Main configuration object
 */
export const config: Config = {
  apiUrl: resolveApiUrl(),
  environment: getEnvironment(),
  isRailway: isRailwayEnvironment(),
  serviceName: getServiceName(),
}

/**
 * Get configuration with runtime overrides
 */
export function getConfig(overrides?: Partial<Config>): Config {
  return {
    ...config,
    ...overrides,
  }
}

/**
 * Log configuration for debugging
 */
export function logConfig(): void {
  if (import.meta.env.DEV) {
    console.log('LeafLock Configuration:', {
      apiUrl: config.apiUrl,
      environment: config.environment,
      isRailway: config.isRailway,
      serviceName: config.serviceName,
      envVars: {
        VITE_API_URL: import.meta.env.VITE_API_URL,
        RAILWAY_ENVIRONMENT: import.meta.env.RAILWAY_ENVIRONMENT,
        RAILWAY_SERVICE_NAME: import.meta.env.RAILWAY_SERVICE_NAME,
        RAILWAY_INTERNAL_HOST: import.meta.env.RAILWAY_INTERNAL_HOST,
      },
    })
  }
}

export default config
