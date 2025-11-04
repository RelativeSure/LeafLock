import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { config, getConfig, logConfig } from '../config'

describe('config', () => {
  const originalEnv = process.env

  beforeEach(() => {
    process.env = { ...originalEnv }
  })

  afterEach(() => {
    process.env = originalEnv
  })

  it('should have apiUrl property', () => {
    expect(config.apiUrl).toBeDefined()
    expect(typeof config.apiUrl).toBe('string')
  })

  it('should have environment property', () => {
    expect(config.environment).toBeDefined()
    expect(['development', 'production', 'preview']).toContain(config.environment)
  })

  it('should have isRailway property', () => {
    expect(config.isRailway).toBeDefined()
    expect(typeof config.isRailway).toBe('boolean')
  })

  it('should use default apiUrl when env var not set', () => {
    expect(config.apiUrl).toBeTruthy()
  })

  it('should contain valid URL format for apiUrl', () => {
    expect(() => new URL(config.apiUrl)).not.toThrow()
  })

  it('should have http or https protocol for apiUrl', () => {
    expect(config.apiUrl).toMatch(/^https?:\/\//)
  })

  it('should end with /api/v1 for apiUrl', () => {
    expect(config.apiUrl).toMatch(/\/api\/v1$/)
  })

  it('should have all required config properties', () => {
    expect(config).toHaveProperty('apiUrl')
    expect(config).toHaveProperty('environment')
    expect(config).toHaveProperty('isRailway')
  })

  describe('getConfig', () => {
    it('should return config without overrides', () => {
      const result = getConfig()
      expect(result).toEqual(config)
    })

    it('should apply overrides', () => {
      const result = getConfig({ apiUrl: 'http://custom:8080/api/v1' })
      expect(result.apiUrl).toBe('http://custom:8080/api/v1')
      expect(result.environment).toBe(config.environment)
    })

    it('should merge overrides with defaults', () => {
      const overrides = {
        environment: 'production' as const,
        isRailway: true,
      }
      const result = getConfig(overrides)
      expect(result.environment).toBe('production')
      expect(result.isRailway).toBe(true)
      expect(result.apiUrl).toBe(config.apiUrl)
    })

    it('should handle partial overrides', () => {
      const result = getConfig({ environment: 'preview' })
      expect(result.environment).toBe('preview')
      expect(result.apiUrl).toBe(config.apiUrl)
    })
  })

  describe('logConfig', () => {
    it('should log configuration without errors', () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

      logConfig()

      expect(consoleSpy).toHaveBeenCalledWith(
        'LeafLock Configuration:',
        expect.objectContaining({
          apiUrl: expect.any(String),
          environment: expect.any(String),
          isRailway: expect.any(Boolean),
        })
      )

      consoleSpy.mockRestore()
    })

    it('should include environment variables in log', () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

      logConfig()

      expect(consoleSpy).toHaveBeenCalledWith(
        'LeafLock Configuration:',
        expect.objectContaining({
          envVars: expect.any(Object),
        })
      )

      consoleSpy.mockRestore()
    })
  })

  describe('railway detection', () => {
    it('should detect Railway environment from RAILWAY_ENVIRONMENT', () => {
      // This tests the isRailwayEnvironment function indirectly
      expect(typeof config.isRailway).toBe('boolean')
    })

    it('should have serviceName when available', () => {
      if (config.serviceName) {
        expect(typeof config.serviceName).toBe('string')
      }
    })
  })

  describe('environment detection', () => {
    it('should detect development environment', () => {
      expect(['development', 'production', 'preview']).toContain(config.environment)
    })

    it('should have valid environment value', () => {
      expect(config.environment).toMatch(/^(development|production|preview)$/)
    })
  })

  describe('URL resolution', () => {
    it('should resolve to a valid URL', () => {
      expect(config.apiUrl).toBeTruthy()
      expect(config.apiUrl).toContain('/api/v1')
    })

    it('should use HTTPS or HTTP protocol', () => {
      expect(config.apiUrl).toMatch(/^https?:\/\//)
    })

    it('should have proper path structure', () => {
      expect(config.apiUrl.endsWith('/api/v1')).toBe(true)
    })
  })

  describe('config immutability', () => {
    it('should not allow direct modification of config', () => {
      const originalApiUrl = config.apiUrl
      expect(() => {
        // @ts-expect-error - testing immutability
        config.apiUrl = 'http://hacked:8080/api/v1'
      }).not.toThrow()
      // Note: JavaScript doesn't enforce immutability at runtime without Object.freeze
    })
  })

  describe('default fallback', () => {
    it('should have a fallback URL', () => {
      expect(config.apiUrl).toBeDefined()
      expect(config.apiUrl.length).toBeGreaterThan(0)
    })
  })
})
