import { describe, it, expect, beforeEach } from 'vitest'
import { config } from '../config'

describe('config', () => {
  beforeEach(() => {
    // Reset environment variables
    delete import.meta.env.VITE_API_URL
    delete import.meta.env.VITE_WS_URL
  })

  it('should have apiUrl property', () => {
    expect(config.apiUrl).toBeDefined()
    expect(typeof config.apiUrl).toBe('string')
  })

  it('should have wsUrl property', () => {
    expect(config.wsUrl).toBeDefined()
    expect(typeof config.wsUrl).toBe('string')
  })

  it('should use default apiUrl when env var not set', () => {
    expect(config.apiUrl).toBeTruthy()
  })

  it('should use default wsUrl when env var not set', () => {
    expect(config.wsUrl).toBeTruthy()
  })

  it('should contain valid URL format for apiUrl', () => {
    expect(() => new URL(config.apiUrl)).not.toThrow()
  })

  it('should contain valid URL format for wsUrl', () => {
    const wsUrl = config.wsUrl.replace('ws://', 'http://').replace('wss://', 'https://')
    expect(() => new URL(wsUrl)).not.toThrow()
  })

  it('should have http or https protocol for apiUrl', () => {
    expect(config.apiUrl).toMatch(/^https?:\/\//)
  })

  it('should have ws or wss protocol for wsUrl', () => {
    expect(config.wsUrl).toMatch(/^wss?:\/\//)
  })

  it('should export immutable config object', () => {
    const originalApiUrl = config.apiUrl

    expect(() => {
      (config as any).apiUrl = 'http://hacker.com'
    }).toThrow()

    expect(config.apiUrl).toBe(originalApiUrl)
  })
})
