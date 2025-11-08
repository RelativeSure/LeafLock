import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'

const baseEnv = { ...process.env }

async function loadConfigModule() {
  vi.resetModules()
  return import('../config')
}

describe('config utilities', () => {
  beforeEach(() => {
    process.env = { ...baseEnv }
  })

  afterEach(() => {
    process.env = { ...baseEnv }
    vi.resetModules()
  })

  test('prefers explicit VITE_API_URL overrides', async () => {
    process.env.VITE_API_URL = 'https://override.leaflock.test'
    const configModule = await loadConfigModule()

    expect(configModule.config.apiUrl).toBe('https://override.leaflock.test')
    expect(configModule.config.isRailway).toBe(false)
  })

  test('infers Railway environment using service URLs', async () => {
    process.env.RAILWAY_ENVIRONMENT = 'production'
    process.env.RAILWAY_BACKEND_URL = 'https://railway-backend.leaflock.test'
    const configModule = await loadConfigModule()

    expect(configModule.config.isRailway).toBe(true)
    expect(configModule.config.apiUrl).toBe('https://railway-backend.leaflock.test/api/v1')
  })

  test('applies environment specific metadata', async () => {
    process.env.NODE_ENV = 'development'
    process.env.RAILWAY_SERVICE_NAME = 'leaflock-api'
    const configModule = await loadConfigModule()

    expect(configModule.config.environment).toBe('development')
    expect(configModule.config.serviceName).toBe('leaflock-api')
    expect(configModule.getConfig().environment).toBe('development')
    expect(configModule.getConfig({ environment: 'preview' }).environment).toBe('preview')
  })

  test('logConfig emits structured diagnostics', async () => {
    process.env.RAILWAY_ENVIRONMENT = 'preview'
    process.env.RAILWAY_SERVICE_NAME = 'leaflock-preview'
    process.env.RAILWAY_INTERNAL_HOST = 'backend.internal'
    process.env.VITE_API_URL = 'https://preview-api.leaflock.test'
    process.env.NODE_ENV = 'production'
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

    const configModule = await loadConfigModule()
    configModule.logConfig()

    expect(consoleSpy).toHaveBeenCalledWith(
      'LeafLock Configuration:',
      expect.objectContaining({
        apiUrl: 'https://preview-api.leaflock.test',
        environment: 'preview',
        isRailway: true,
        serviceName: 'leaflock-preview',
        envVars: expect.objectContaining({
          VITE_API_URL: 'https://preview-api.leaflock.test',
          RAILWAY_ENVIRONMENT: 'preview',
          RAILWAY_SERVICE_NAME: 'leaflock-preview',
          RAILWAY_INTERNAL_HOST: 'backend.internal',
        }),
      })
    )

    consoleSpy.mockRestore()
  })
})
