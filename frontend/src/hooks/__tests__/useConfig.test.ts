import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { renderHook } from '@testing-library/react'
import { useConfig, useApiUrl, useIsRailway, useEnvironment } from '../useConfig'

// Mock the config module
vi.mock('@/lib/config', () => ({
  config: {
    apiUrl: 'http://localhost:8080/api/v1',
    environment: 'development' as const,
    isRailway: false,
    serviceName: 'frontend',
  },
  getConfig: vi.fn((overrides) => ({
    apiUrl: overrides?.apiUrl || 'http://localhost:8080/api/v1',
    environment: overrides?.environment || ('development' as const),
    isRailway: overrides?.isRailway ?? false,
    serviceName: overrides?.serviceName || 'frontend',
  })),
}))

describe('useConfig', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('useConfig hook', () => {
    it('should return default config without overrides', () => {
      const { result } = renderHook(() => useConfig())

      expect(result.current).toEqual({
        apiUrl: 'http://localhost:8080/api/v1',
        environment: 'development',
        isRailway: false,
        serviceName: 'frontend',
      })
    })

    it('should apply overrides to config', () => {
      const overrides = {
        apiUrl: 'https://api.example.com/api/v1',
        environment: 'production' as const,
      }

      const { result } = renderHook(() => useConfig(overrides))

      expect(result.current.apiUrl).toBe('https://api.example.com/api/v1')
      expect(result.current.environment).toBe('production')
    })

    it('should memoize config based on overrides', () => {
      const overrides = { apiUrl: 'http://test.com/api/v1' }
      const { result, rerender } = renderHook(
        ({ overrides }) => useConfig(overrides),
        {
          initialProps: { overrides },
        }
      )

      const firstResult = result.current

      // Rerender with same overrides object reference
      rerender({ overrides })

      // Should return same object reference (memoized)
      expect(result.current).toBe(firstResult)
    })

    it('should update when overrides change', () => {
      const { result, rerender } = renderHook(
        ({ overrides }) => useConfig(overrides),
        {
          initialProps: { overrides: { apiUrl: 'http://test1.com/api/v1' } },
        }
      )

      const firstResult = result.current

      // Rerender with different overrides
      rerender({ overrides: { apiUrl: 'http://test2.com/api/v1' } })

      // Should return different object
      expect(result.current).not.toBe(firstResult)
      expect(result.current.apiUrl).toBe('http://test2.com/api/v1')
    })

    it('should handle partial overrides', () => {
      const overrides = {
        environment: 'preview' as const,
      }

      const { result } = renderHook(() => useConfig(overrides))

      expect(result.current.environment).toBe('preview')
      expect(result.current.apiUrl).toBe('http://localhost:8080/api/v1')
      expect(result.current.isRailway).toBe(false)
    })

    it('should handle undefined overrides', () => {
      const { result } = renderHook(() => useConfig(undefined))

      expect(result.current).toBeDefined()
      expect(result.current.apiUrl).toBe('http://localhost:8080/api/v1')
    })
  })

  describe('useApiUrl hook', () => {
    it('should return API URL', () => {
      const { result } = renderHook(() => useApiUrl())

      expect(result.current).toBe('http://localhost:8080/api/v1')
    })

    it('should memoize API URL', () => {
      const { result, rerender } = renderHook(() => useApiUrl())

      const firstResult = result.current

      rerender()

      // Should return same value (memoized)
      expect(result.current).toBe(firstResult)
    })

    it('should return string type', () => {
      const { result } = renderHook(() => useApiUrl())

      expect(typeof result.current).toBe('string')
    })
  })

  describe('useIsRailway hook', () => {
    it('should return Railway detection status', () => {
      const { result } = renderHook(() => useIsRailway())

      expect(result.current).toBe(false)
    })

    it('should return boolean type', () => {
      const { result } = renderHook(() => useIsRailway())

      expect(typeof result.current).toBe('boolean')
    })

    it('should memoize Railway status', () => {
      const { result, rerender } = renderHook(() => useIsRailway())

      const firstResult = result.current

      rerender()

      // Should return same value (memoized)
      expect(result.current).toBe(firstResult)
    })
  })

  describe('useEnvironment hook', () => {
    it('should return environment info object', () => {
      const { result } = renderHook(() => useEnvironment())

      expect(result.current).toEqual({
        environment: 'development',
        isDevelopment: true,
        isProduction: false,
        isPreview: false,
      })
    })

    it('should calculate boolean flags correctly for development', () => {
      const { result } = renderHook(() => useEnvironment())

      expect(result.current.environment).toBe('development')
      expect(result.current.isDevelopment).toBe(true)
      expect(result.current.isProduction).toBe(false)
      expect(result.current.isPreview).toBe(false)
    })

    it('should memoize environment object', () => {
      const { result, rerender } = renderHook(() => useEnvironment())

      const firstResult = result.current

      rerender()

      // Should return same object reference (memoized)
      expect(result.current).toBe(firstResult)
    })

    it('should have all required properties', () => {
      const { result } = renderHook(() => useEnvironment())

      expect(result.current).toHaveProperty('environment')
      expect(result.current).toHaveProperty('isDevelopment')
      expect(result.current).toHaveProperty('isProduction')
      expect(result.current).toHaveProperty('isPreview')
    })

    it('should return correct types for all properties', () => {
      const { result } = renderHook(() => useEnvironment())

      expect(typeof result.current.environment).toBe('string')
      expect(typeof result.current.isDevelopment).toBe('boolean')
      expect(typeof result.current.isProduction).toBe('boolean')
      expect(typeof result.current.isPreview).toBe('boolean')
    })

    it('should ensure only one environment flag is true', () => {
      const { result } = renderHook(() => useEnvironment())

      const flags = [
        result.current.isDevelopment,
        result.current.isProduction,
        result.current.isPreview,
      ]

      const trueCount = flags.filter((flag) => flag).length

      expect(trueCount).toBe(1)
    })
  })

  describe('integration scenarios', () => {
    it('should use hooks together in a component', () => {
      const { result: configResult } = renderHook(() => useConfig())
      const { result: apiUrlResult } = renderHook(() => useApiUrl())
      const { result: isRailwayResult } = renderHook(() => useIsRailway())
      const { result: envResult } = renderHook(() => useEnvironment())

      expect(configResult.current.apiUrl).toBe(apiUrlResult.current)
      expect(configResult.current.isRailway).toBe(isRailwayResult.current)
      expect(configResult.current.environment).toBe(envResult.current.environment)
    })

    it('should handle re-renders efficiently with memoization', () => {
      const { result: configResult, rerender: rerenderConfig } = renderHook(() => useConfig())
      const { result: envResult, rerender: rerenderEnv } = renderHook(() => useEnvironment())

      const initialConfig = configResult.current
      const initialEnv = envResult.current

      // Multiple rerenders
      rerenderConfig()
      rerenderEnv()
      rerenderConfig()
      rerenderEnv()

      // Should maintain same references (memoized)
      expect(configResult.current).toBe(initialConfig)
      expect(envResult.current).toBe(initialEnv)
    })
  })
})
