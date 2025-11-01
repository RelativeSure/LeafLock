import { describe, it, expect, beforeEach, vi } from 'vitest'
import { ActivityLogger } from '../activity-logger'

describe('ActivityLogger', () => {
  beforeEach(() => {
    vi.spyOn(console, 'log').mockImplementation(() => {})
  })

  it('should log activity with all parameters', () => {
    ActivityLogger.log('user-123', 'John Doe', 'john@example.com', 'login', true)

    expect(console.log).toHaveBeenCalledWith('Activity:', {
      userId: 'user-123',
      name: 'John Doe',
      email: 'john@example.com',
      action: 'login',
      success: true,
    })
  })

  it('should log failed activity', () => {
    ActivityLogger.log('user-456', 'Jane Doe', 'jane@example.com', 'login', false)

    expect(console.log).toHaveBeenCalledWith('Activity:', {
      userId: 'user-456',
      name: 'Jane Doe',
      email: 'jane@example.com',
      action: 'login',
      success: false,
    })
  })

  it('should return empty array for getLogsByUser', () => {
    const logs = ActivityLogger.getLogsByUser('user-123')
    expect(logs).toEqual([])
  })
})

