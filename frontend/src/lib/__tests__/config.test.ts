import { describe, it, expect } from 'vitest'
import { config } from '../config'

describe('config', () => {
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
})
