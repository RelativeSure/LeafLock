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
 * Get environment variable from either import.meta.env or process.env
 */
function getEnvVar(key: string): string | undefined {
  // In browser/Vite environment
  if (typeof import.meta !== 'undefined' && import.meta.env) {
    return import.meta.env[key as keyof ImportMetaEnv] as string | undefined
  }
  // In Node.js/test environment
  if (typeof process !== 'undefined' && process.env) {
    return process.env[key]
  }
  return undefined
}

/**
 * Detect if running on Railway
 */
function isRailwayEnvironment(): boolean {
  return !!(
    getEnvVar('RAILWAY_ENVIRONMENT') ||
    getEnvVar('RAILWAY_PROJECT_ID') ||
    getEnvVar('RAILWAY_SERVICE_NAME') ||
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
  const serviceUrl = getEnvVar(envVarName)
  if (serviceUrl) {
    return serviceUrl
  }

  // Railway provides these environment variables
  const railwayVarName = `RAILWAY_${serviceName.toUpperCase()}_URL`
  const railwayUrl = getEnvVar(railwayVarName)
  if (railwayUrl) {
    return railwayUrl
  }

  // Fallback: construct from Railway's internal networking
  const railwayInternalHost = getEnvVar('RAILWAY_INTERNAL_HOST')
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
  // Skip this in test environment to avoid console.log interference
  if (
    isRailwayEnvironment() &&
    getEnvVar('RAILWAY_ENVIRONMENT') === 'preview' &&
    !getEnvVar('VITEST')
  ) {
    if (typeof window !== 'undefined') {
      console.log('🔧 Railway preview detected: using same-origin API URL')
      return `${window.location.origin}/api/v1`
    }
  }

  // 1. Explicit override (highest priority)
  const viteApiUrl = getEnvVar('VITE_API_URL')
  if (viteApiUrl) {
    return viteApiUrl
  }

  // 2. Railway service discovery (automatic - no manual config needed!)
  if (isRailwayEnvironment()) {
    // Try Railway's automatic service variables first (most reliable)
    const automaticBackendUrl =
      getEnvVar('BACKEND_URL') || getEnvVar('API_URL') || getEnvVar('SERVER_URL')

    if (automaticBackendUrl) {
      return `${automaticBackendUrl}/api/v1`
    }

    // Try Railway's private/internal networking (preferred for internal communication)
    const railwayInternalHost = getEnvVar('RAILWAY_INTERNAL_HOST')
    if (railwayInternalHost) {
      return `https://${railwayInternalHost}/api/v1`
    }

    // Try Railway's private domain pattern
    const railwayPrivateDomain = getEnvVar('RAILWAY_PRIVATE_DOMAIN')
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
    const railwayPublicDomain = getEnvVar('RAILWAY_PUBLIC_DOMAIN')
    if (railwayPublicDomain) {
      return `https://${railwayPublicDomain}/api/v1`
    }
  }

  // 3. Development proxy target
  const devProxyTarget = getEnvVar('VITE_DEV_PROXY_TARGET')
  if (devProxyTarget) {
    return `${devProxyTarget}/api/v1`
  }

  // 4. Granular dev settings
  const devBackendProtocol = getEnvVar('VITE_DEV_BACKEND_PROTOCOL')
  if (devBackendProtocol) {
    const protocol = devBackendProtocol
    const host = getEnvVar('VITE_DEV_BACKEND_HOST') || 'localhost'
    const port = getEnvVar('VITE_DEV_BACKEND_PORT') || '8080'
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
  return getEnvVar('RAILWAY_SERVICE_NAME') || getEnvVar('VITE_SERVICE_NAME')
}

/**
 * Determine environment type
 */
function getEnvironment(): 'development' | 'production' | 'preview' {
  if (getEnvVar('NODE_ENV') === 'development') {
    return 'development'
  }

  if (getEnvVar('MODE') === 'development') {
    return 'development'
  }

  if (getEnvVar('RAILWAY_ENVIRONMENT') === 'preview') {
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
  const isDev = getEnvVar('DEV') === 'true' || getEnvVar('NODE_ENV') === 'development'
  // Always log in test environment or when explicitly requested
  const shouldLog = isDev || getEnvVar('VITE_API_URL') || getEnvVar('RAILWAY_ENVIRONMENT')
  if (shouldLog) {
    console.log('LeafLock Configuration:', {
      apiUrl: config.apiUrl,
      environment: config.environment,
      isRailway: config.isRailway,
      serviceName: config.serviceName,
      envVars: {
        VITE_API_URL: getEnvVar('VITE_API_URL'),
        RAILWAY_ENVIRONMENT: getEnvVar('RAILWAY_ENVIRONMENT'),
        RAILWAY_SERVICE_NAME: getEnvVar('RAILWAY_SERVICE_NAME'),
        RAILWAY_INTERNAL_HOST: getEnvVar('RAILWAY_INTERNAL_HOST'),
      },
    })
  }
}

export default config
