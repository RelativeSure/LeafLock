import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import type { Config } from '../config'

describe('config utility', () => {
  const originalEnv = { ...process.env }
  const originalWindow = global.window

  beforeEach(() => {
    // Clear all env vars
    process.env = { ...originalEnv }
    delete process.env.VITE_API_URL
    delete process.env.RAILWAY_ENVIRONMENT
    delete process.env.RAILWAY_PROJECT_ID
    delete process.env.RAILWAY_SERVICE_NAME
    delete process.env.RAILWAY_INTERNAL_HOST
    delete process.env.RAILWAY_PRIVATE_DOMAIN
    delete process.env.RAILWAY_PUBLIC_DOMAIN
    delete process.env.BACKEND_URL
    delete process.env.API_URL
    delete process.env.SERVER_URL
    delete process.env.VITE_DEV_PROXY_TARGET
    delete process.env.VITE_DEV_BACKEND_PROTOCOL
    delete process.env.VITE_DEV_BACKEND_HOST
    delete process.env.VITE_DEV_BACKEND_PORT
    delete process.env.VITE_SERVICE_NAME
    delete process.env.NODE_ENV

    // Reset window
    delete (global as any).window
    global.window = {
      location: {
        origin: 'http://localhost:3000',
        hostname: 'localhost',
      },
    } as any

    // Clear module cache to re-evaluate config
    vi.resetModules()
  })

  afterEach(() => {
    process.env = originalEnv
    global.window = originalWindow as any
  })

  describe('resolveApiUrl', () => {
    it('should use VITE_API_URL when explicitly set (highest priority)', async () => {
      process.env.VITE_API_URL = 'https://custom-api.example.com/api/v1'
      process.env.RAILWAY_ENVIRONMENT = 'production'
      process.env.RAILWAY_INTERNAL_HOST = 'railway.internal'

      const { config } = await import('../config')

      expect(config.apiUrl).toBe('https://custom-api.example.com/api/v1')
    })

    it('should detect Railway environment from RAILWAY_ENVIRONMENT', async () => {
      process.env.RAILWAY_ENVIRONMENT = 'production'
      process.env.BACKEND_URL = 'https://backend.railway.app'

      const { config } = await import('../config')

      expect(config.isRailway).toBe(true)
      expect(config.apiUrl).toBe('https://backend.railway.app/api/v1')
    })

    it('should detect Railway environment from RAILWAY_PROJECT_ID', async () => {
      process.env.RAILWAY_PROJECT_ID = 'project-123'
      process.env.RAILWAY_INTERNAL_HOST = 'backend.railway.internal'

      const { config } = await import('../config')

      expect(config.isRailway).toBe(true)
      expect(config.apiUrl).toBe('https://backend.railway.internal/api/v1')
    })

    it('should detect Railway environment from RAILWAY_SERVICE_NAME', async () => {
      process.env.RAILWAY_SERVICE_NAME = 'frontend'
      process.env.BACKEND_URL = 'https://api.railway.app'

      const { config } = await import('../config')

      expect(config.isRailway).toBe(true)
      expect(config.serviceName).toBe('frontend')
    })

    it('should detect Railway environment from railway.app hostname', async () => {
      global.window = {
        location: {
          hostname: 'myapp.railway.app',
          origin: 'https://myapp.railway.app',
        },
      } as any

      const { config } = await import('../config')

      expect(config.isRailway).toBe(true)
    })

    it('should use BACKEND_URL on Railway', async () => {
      process.env.RAILWAY_ENVIRONMENT = 'production'
      process.env.BACKEND_URL = 'https://backend.railway.app'

      const { config } = await import('../config')

      expect(config.apiUrl).toBe('https://backend.railway.app/api/v1')
    })

    it('should use API_URL on Railway', async () => {
      process.env.RAILWAY_ENVIRONMENT = 'production'
      process.env.API_URL = 'https://api.railway.app'

      const { config } = await import('../config')

      expect(config.apiUrl).toBe('https://api.railway.app/api/v1')
    })

    it('should use RAILWAY_INTERNAL_HOST on Railway', async () => {
      process.env.RAILWAY_ENVIRONMENT = 'production'
      process.env.RAILWAY_INTERNAL_HOST = 'backend.railway.internal'

      const { config } = await import('../config')

      expect(config.apiUrl).toBe('https://backend.railway.internal/api/v1')
    })

    it('should use RAILWAY_PRIVATE_DOMAIN on Railway', async () => {
      process.env.RAILWAY_ENVIRONMENT = 'production'
      process.env.RAILWAY_PRIVATE_DOMAIN = 'private.railway.app'

      const { config } = await import('../config')

      expect(config.apiUrl).toBe('https://private.railway.app/api/v1')
    })

    it('should try multiple service name patterns on Railway', async () => {
      process.env.RAILWAY_ENVIRONMENT = 'production'
      process.env.BACKEND_URL = 'https://backend-service.railway.app'

      const { config } = await import('../config')

      expect(config.apiUrl).toContain('/api/v1')
    })

    it('should use RAILWAY_PUBLIC_DOMAIN as fallback', async () => {
      process.env.RAILWAY_ENVIRONMENT = 'production'
      process.env.RAILWAY_PUBLIC_DOMAIN = 'public.railway.app'

      const { config } = await import('../config')

      expect(config.apiUrl).toBe('https://public.railway.app/api/v1')
    })

    it('should use VITE_DEV_PROXY_TARGET in development', async () => {
      process.env.VITE_DEV_PROXY_TARGET = 'http://localhost:8080'

      const { config } = await import('../config')

      expect(config.apiUrl).toBe('http://localhost:8080/api/v1')
    })

    it('should use granular dev settings', async () => {
      process.env.VITE_DEV_BACKEND_PROTOCOL = 'https'
      process.env.VITE_DEV_BACKEND_HOST = 'api.dev.local'
      process.env.VITE_DEV_BACKEND_PORT = '9000'

      const { config } = await import('../config')

      expect(config.apiUrl).toBe('https://api.dev.local:9000/api/v1')
    })

    it('should use default host and port when only protocol is set', async () => {
      process.env.VITE_DEV_BACKEND_PROTOCOL = 'http'

      const { config } = await import('../config')

      expect(config.apiUrl).toBe('http://localhost:8080/api/v1')
    })

    it('should use window.location.origin when available', async () => {
      global.window = {
        location: {
          origin: 'https://app.example.com',
          hostname: 'app.example.com',
        },
      } as any

      const { config } = await import('../config')

      expect(config.apiUrl).toBe('https://app.example.com/api/v1')
    })

    it('should fallback to localhost:8080 when nothing is configured', async () => {
      delete (global as any).window

      const { config } = await import('../config')

      expect(config.apiUrl).toBe('http://localhost:8080/api/v1')
    })
  })

  describe('getEnvironment', () => {
    it('should return development when NODE_ENV is development', async () => {
      process.env.NODE_ENV = 'development'

      const { config } = await import('../config')

      expect(config.environment).toBe('development')
    })

    it('should return preview when RAILWAY_ENVIRONMENT is preview', async () => {
      process.env.RAILWAY_ENVIRONMENT = 'preview'

      const { config } = await import('../config')

      expect(config.environment).toBe('preview')
    })

    it('should return production by default', async () => {
      const { config } = await import('../config')

      expect(config.environment).toBe('production')
    })

    it('should prioritize NODE_ENV over RAILWAY_ENVIRONMENT', async () => {
      process.env.NODE_ENV = 'development'
      process.env.RAILWAY_ENVIRONMENT = 'preview'

      const { config } = await import('../config')

      expect(config.environment).toBe('development')
    })
  })

  describe('getServiceName', () => {
    it('should use RAILWAY_SERVICE_NAME when set', async () => {
      process.env.RAILWAY_SERVICE_NAME = 'frontend-service'

      const { config } = await import('../config')

      expect(config.serviceName).toBe('frontend-service')
    })

    it('should use VITE_SERVICE_NAME as fallback', async () => {
      process.env.VITE_SERVICE_NAME = 'vite-frontend'

      const { config } = await import('../config')

      expect(config.serviceName).toBe('vite-frontend')
    })

    it('should prefer RAILWAY_SERVICE_NAME over VITE_SERVICE_NAME', async () => {
      process.env.RAILWAY_SERVICE_NAME = 'railway-frontend'
      process.env.VITE_SERVICE_NAME = 'vite-frontend'

      const { config } = await import('../config')

      expect(config.serviceName).toBe('railway-frontend')
    })

    it('should return undefined when neither is set', async () => {
      const { config } = await import('../config')

      expect(config.serviceName).toBeUndefined()
    })
  })

  describe('getConfig', () => {
    it('should return default config without overrides', async () => {
      process.env.VITE_API_URL = 'https://api.example.com/api/v1'
      const { getConfig } = await import('../config')

      const result = getConfig()

      expect(result.apiUrl).toBe('https://api.example.com/api/v1')
      expect(result.environment).toBe('production')
    })

    it('should apply overrides', async () => {
      const { getConfig } = await import('../config')

      const result = getConfig({
        apiUrl: 'https://override.example.com/api/v1',
        environment: 'development',
      })

      expect(result.apiUrl).toBe('https://override.example.com/api/v1')
      expect(result.environment).toBe('development')
    })

    it('should partially override config', async () => {
      process.env.VITE_API_URL = 'https://api.example.com/api/v1'
      const { getConfig } = await import('../config')

      const result = getConfig({
        environment: 'preview',
      })

      expect(result.apiUrl).toBe('https://api.example.com/api/v1')
      expect(result.environment).toBe('preview')
    })
  })

  describe('logConfig', () => {
    it('should log configuration to console', async () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
      process.env.VITE_API_URL = 'https://api.example.com/api/v1'
      process.env.RAILWAY_SERVICE_NAME = 'test-service'

      const { logConfig } = await import('../config')

      logConfig()

      expect(consoleSpy).toHaveBeenCalledWith(
        'LeafLock Configuration:',
        expect.objectContaining({
          apiUrl: 'https://api.example.com/api/v1',
          serviceName: 'test-service',
          envVars: expect.any(Object),
        })
      )

      consoleSpy.mockRestore()
    })
  })

  describe('Config interface', () => {
    it('should have all required properties', async () => {
      const { config } = await import('../config')

      expect(config).toHaveProperty('apiUrl')
      expect(config).toHaveProperty('environment')
      expect(config).toHaveProperty('isRailway')
      expect(config).toHaveProperty('serviceName')
    })

    it('should have correct types', async () => {
      const { config } = await import('../config')

      expect(typeof config.apiUrl).toBe('string')
      expect(['development', 'production', 'preview']).toContain(config.environment)
      expect(typeof config.isRailway).toBe('boolean')
      expect(typeof config.serviceName === 'string' || config.serviceName === undefined).toBe(true)
    })
  })
})
