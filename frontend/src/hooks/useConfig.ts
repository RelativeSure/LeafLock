import { useMemo } from 'react'
import { config, getConfig, Config } from '@/lib/config'

/**
 * Hook to access configuration in React components
 */
export function useConfig(overrides?: Partial<Config>): Config {
  return useMemo(() => getConfig(overrides), [overrides])
}

/**
 * Hook to get just the API URL
 */
export function useApiUrl(): string {
  return useMemo(() => config.apiUrl, [])
}

/**
 * Hook to check if running on Railway
 */
export function useIsRailway(): boolean {
  return useMemo(() => config.isRailway, [])
}

/**
 * Hook to get environment info
 */
export function useEnvironment(): {
  environment: 'development' | 'production' | 'preview'
  isDevelopment: boolean
  isProduction: boolean
  isPreview: boolean
} {
  return useMemo(() => ({
    environment: config.environment,
    isDevelopment: config.environment === 'development',
    isProduction: config.environment === 'production',
    isPreview: config.environment === 'preview',
  }), [])
}
