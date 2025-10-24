/**
 * Dynamic configuration utility for Railway deployments
 * Automatically detects service URLs based on environment
 */

interface Config {
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
    process.env.RAILWAY_ENVIRONMENT ||
    process.env.RAILWAY_PROJECT_ID ||
    process.env.RAILWAY_SERVICE_NAME ||
    // Check for Railway-specific environment variables
    (typeof window !== 'undefined' &&
     window.location.hostname.includes('railway.app'))
  )
}

/**
 * Get Railway service URL from environment variables
 */
function getRailwayServiceUrl(serviceName: string): string | null {
  // Railway service references (recommended approach)
  // These are automatically set when you reference other services
  const serviceUrl = process.env[`${serviceName.toUpperCase()}_URL`]
  if (serviceUrl) {
    return serviceUrl
  }

  // Railway provides these environment variables
  const railwayUrl = process.env[`RAILWAY_${serviceName.toUpperCase()}_URL`]
  if (railwayUrl) {
    return railwayUrl
  }

  // Fallback: construct from Railway's internal networking
  const railwayInternalHost = process.env.RAILWAY_INTERNAL_HOST
  if (railwayInternalHost) {
    return `https://${railwayInternalHost}`
  }

  return null
}

/**
 * Resolve API URL based on environment and service discovery
 */
function resolveApiUrl(): string {
  // 1. Explicit override (highest priority)
  if (process.env.VITE_API_URL) {
    return process.env.VITE_API_URL
  }

  // 2. Railway service discovery (automatic - no manual config needed!)
  if (isRailwayEnvironment()) {
    // Try Railway's automatic service variables first (most reliable)
    const automaticBackendUrl = process.env.BACKEND_URL ||
                               process.env.API_URL ||
                               process.env.SERVER_URL

    if (automaticBackendUrl) {
      return `${automaticBackendUrl}/api/v1`
    }

    // Try Railway's private/internal networking (preferred for internal communication)
    const railwayInternalHost = process.env.RAILWAY_INTERNAL_HOST
    if (railwayInternalHost) {
      return `https://${railwayInternalHost}/api/v1`
    }

    // Try Railway's private domain pattern
    const railwayPrivateDomain = process.env.RAILWAY_PRIVATE_DOMAIN
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
    const railwayPublicDomain = process.env.RAILWAY_PUBLIC_DOMAIN
    if (railwayPublicDomain) {
      return `https://${railwayPublicDomain}/api/v1`
    }
  }

  // 3. Development proxy target
  if (process.env.VITE_DEV_PROXY_TARGET) {
    return `${process.env.VITE_DEV_PROXY_TARGET}/api/v1`
  }

  // 4. Granular dev settings
  if (process.env.VITE_DEV_BACKEND_PROTOCOL) {
    const protocol = process.env.VITE_DEV_BACKEND_PROTOCOL
    const host = process.env.VITE_DEV_BACKEND_HOST || 'localhost'
    const port = process.env.VITE_DEV_BACKEND_PORT || '8080'
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
  return process.env.RAILWAY_SERVICE_NAME ||
         process.env.VITE_SERVICE_NAME
}

/**
 * Determine environment type
 */
function getEnvironment(): 'development' | 'production' | 'preview' {
  if (process.env.NODE_ENV === 'development') {
    return 'development'
  }

  if (process.env.RAILWAY_ENVIRONMENT === 'preview') {
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
  console.log('LeafLock Configuration:', {
    apiUrl: config.apiUrl,
    environment: config.environment,
    isRailway: config.isRailway,
    serviceName: config.serviceName,
    envVars: {
      VITE_API_URL: process.env.VITE_API_URL,
      RAILWAY_ENVIRONMENT: process.env.RAILWAY_ENVIRONMENT,
      RAILWAY_SERVICE_NAME: process.env.RAILWAY_SERVICE_NAME,
      RAILWAY_INTERNAL_HOST: process.env.RAILWAY_INTERNAL_HOST,
    },
  })
}

export default config
