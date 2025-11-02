import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { ActivityLogger } from '../activity-logger'

describe('ActivityLogger', () => {
  beforeEach(() => {
    vi.spyOn(console, 'log').mockImplementation(vi.fn())
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('log', () => {
    it('should log activity with all parameters', () => {
      ActivityLogger.log('user-1', 'John Doe', 'john@example.com', 'login', true)

      expect(console.log).toHaveBeenCalledWith('Activity:', {
        userId: 'user-1',
        name: 'John Doe',
        email: 'john@example.com',
        action: 'login',
        success: true,
      })
    })

    it('should log failed activity', () => {
      ActivityLogger.log('user-2', 'Jane Doe', 'jane@example.com', 'delete_note', false)

      expect(console.log).toHaveBeenCalledWith('Activity:', {
        userId: 'user-2',
        name: 'Jane Doe',
        email: 'jane@example.com',
        action: 'delete_note',
        success: false,
      })
    })

    it('should log multiple activities', () => {
      ActivityLogger.log('user-1', 'User 1', 'user1@example.com', 'create_note', true)
      ActivityLogger.log('user-2', 'User 2', 'user2@example.com', 'update_note', true)
      ActivityLogger.log('user-3', 'User 3', 'user3@example.com', 'share_note', false)

      expect(console.log).toHaveBeenCalledTimes(3)
    })

    it('should handle empty strings', () => {
      ActivityLogger.log('', '', '', '', true)

      expect(console.log).toHaveBeenCalledWith('Activity:', {
        userId: '',
        name: '',
        email: '',
        action: '',
        success: true,
      })
    })
  })

  describe('getLogsByUser', () => {
    it('should return empty array for any user', () => {
      const logs = ActivityLogger.getLogsByUser('user-1')

      expect(logs).toEqual([])
    })

    it('should return empty array for empty user ID', () => {
      const logs = ActivityLogger.getLogsByUser('')

      expect(logs).toEqual([])
    })
  })
})
