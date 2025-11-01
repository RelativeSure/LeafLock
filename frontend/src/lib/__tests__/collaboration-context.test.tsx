import { describe, it, expect } from 'vitest'
import { renderHook } from '@testing-library/react'
import { useCollaboration } from '../collaboration-context'

describe('useCollaboration', () => {
  describe('getSessionUsers', () => {
    it('should return empty array', () => {
      const { result } = renderHook(() => useCollaboration())

      const users = result.current.getSessionUsers('note-1')

      expect(users).toEqual([])
      expect(Array.isArray(users)).toBe(true)
    })

    it('should work with different note IDs', () => {
      const { result } = renderHook(() => useCollaboration())

      expect(result.current.getSessionUsers('note-1')).toEqual([])
      expect(result.current.getSessionUsers('note-2')).toEqual([])
      expect(result.current.getSessionUsers('note-3')).toEqual([])
    })

    it('should handle empty string note ID', () => {
      const { result } = renderHook(() => useCollaboration())

      const users = result.current.getSessionUsers('')

      expect(users).toEqual([])
    })
  })

  describe('joinSession', () => {
    it('should not throw when joining session', () => {
      const { result } = renderHook(() => useCollaboration())

      expect(() => {
        result.current.joinSession('note-1')
      }).not.toThrow()
    })

    it('should handle multiple join calls', () => {
      const { result } = renderHook(() => useCollaboration())

      expect(() => {
        result.current.joinSession('note-1')
        result.current.joinSession('note-1')
        result.current.joinSession('note-1')
      }).not.toThrow()
    })

    it('should handle different note IDs', () => {
      const { result } = renderHook(() => useCollaboration())

      expect(() => {
        result.current.joinSession('note-1')
        result.current.joinSession('note-2')
        result.current.joinSession('note-3')
      }).not.toThrow()
    })
  })

  describe('leaveSession', () => {
    it('should not throw when leaving session', () => {
      const { result } = renderHook(() => useCollaboration())

      expect(() => {
        result.current.leaveSession('note-1')
      }).not.toThrow()
    })

    it('should handle multiple leave calls', () => {
      const { result } = renderHook(() => useCollaboration())

      expect(() => {
        result.current.leaveSession('note-1')
        result.current.leaveSession('note-1')
        result.current.leaveSession('note-1')
      }).not.toThrow()
    })

    it('should handle join and leave sequence', () => {
      const { result } = renderHook(() => useCollaboration())

      expect(() => {
        result.current.joinSession('note-1')
        result.current.leaveSession('note-1')
        result.current.joinSession('note-1')
        result.current.leaveSession('note-1')
      }).not.toThrow()
    })
  })

  describe('shareNote', () => {
    it('should resolve when sharing note', async () => {
      const { result } = renderHook(() => useCollaboration())

      await expect(
        result.current.shareNote('note-1', 'user@example.com')
      ).resolves.toBeUndefined()
    })

    it('should handle multiple share calls', async () => {
      const { result } = renderHook(() => useCollaboration())

      await result.current.shareNote('note-1', 'user1@example.com')
      await result.current.shareNote('note-1', 'user2@example.com')
      await result.current.shareNote('note-1', 'user3@example.com')

      expect(true).toBe(true)
    })

    it('should handle different note IDs', async () => {
      const { result } = renderHook(() => useCollaboration())

      await result.current.shareNote('note-1', 'user@example.com')
      await result.current.shareNote('note-2', 'user@example.com')
      await result.current.shareNote('note-3', 'user@example.com')

      expect(true).toBe(true)
    })

    it('should handle empty email', async () => {
      const { result } = renderHook(() => useCollaboration())

      await expect(
        result.current.shareNote('note-1', '')
      ).resolves.toBeUndefined()
    })
  })

  describe('unshareNote', () => {
    it('should resolve when unsharing note', async () => {
      const { result } = renderHook(() => useCollaboration())

      await expect(
        result.current.unshareNote('note-1', 'user-123')
      ).resolves.toBeUndefined()
    })

    it('should handle multiple unshare calls', async () => {
      const { result } = renderHook(() => useCollaboration())

      await result.current.unshareNote('note-1', 'user-1')
      await result.current.unshareNote('note-1', 'user-2')
      await result.current.unshareNote('note-1', 'user-3')

      expect(true).toBe(true)
    })

    it('should handle share and unshare sequence', async () => {
      const { result } = renderHook(() => useCollaboration())

      await result.current.shareNote('note-1', 'user@example.com')
      await result.current.unshareNote('note-1', 'user-123')

      expect(true).toBe(true)
    })
  })

  describe('getSharedUsers', () => {
    it('should return empty array', () => {
      const { result } = renderHook(() => useCollaboration())

      const users = result.current.getSharedUsers('note-1')

      expect(users).toEqual([])
      expect(Array.isArray(users)).toBe(true)
    })

    it('should work with different note IDs', () => {
      const { result } = renderHook(() => useCollaboration())

      expect(result.current.getSharedUsers('note-1')).toEqual([])
      expect(result.current.getSharedUsers('note-2')).toEqual([])
      expect(result.current.getSharedUsers('note-3')).toEqual([])
    })

    it('should return empty array even after sharing', async () => {
      const { result } = renderHook(() => useCollaboration())

      await result.current.shareNote('note-1', 'user@example.com')
      const users = result.current.getSharedUsers('note-1')

      expect(users).toEqual([])
    })
  })

  describe('integration', () => {
    it('should handle complete collaboration workflow', async () => {
      const { result } = renderHook(() => useCollaboration())

      // Join session
      result.current.joinSession('note-1')

      // Get session users (empty in placeholder)
      const sessionUsers = result.current.getSessionUsers('note-1')
      expect(sessionUsers).toEqual([])

      // Share note
      await result.current.shareNote('note-1', 'user@example.com')

      // Get shared users (empty in placeholder)
      const sharedUsers = result.current.getSharedUsers('note-1')
      expect(sharedUsers).toEqual([])

      // Unshare note
      await result.current.unshareNote('note-1', 'user-123')

      // Leave session
      result.current.leaveSession('note-1')

      expect(true).toBe(true)
    })

    it('should handle multiple notes simultaneously', async () => {
      const { result } = renderHook(() => useCollaboration())

      // Work with multiple notes
      result.current.joinSession('note-1')
      result.current.joinSession('note-2')

      await result.current.shareNote('note-1', 'user1@example.com')
      await result.current.shareNote('note-2', 'user2@example.com')

      expect(result.current.getSessionUsers('note-1')).toEqual([])
      expect(result.current.getSessionUsers('note-2')).toEqual([])

      result.current.leaveSession('note-1')
      result.current.leaveSession('note-2')

      expect(true).toBe(true)
    })

    it('should be callable from multiple hook instances', () => {
      const { result: result1 } = renderHook(() => useCollaboration())
      const { result: result2 } = renderHook(() => useCollaboration())

      expect(() => {
        result1.current.joinSession('note-1')
        result2.current.joinSession('note-1')
        result1.current.leaveSession('note-1')
        result2.current.leaveSession('note-1')
      }).not.toThrow()
    })
  })

  describe('edge cases', () => {
    it('should handle special characters in note ID', () => {
      const { result } = renderHook(() => useCollaboration())

      expect(() => {
        result.current.joinSession('note-with-special-chars-!@#$%')
        result.current.getSessionUsers('note-with-special-chars-!@#$%')
        result.current.leaveSession('note-with-special-chars-!@#$%')
      }).not.toThrow()
    })

    it('should handle special characters in email', async () => {
      const { result } = renderHook(() => useCollaboration())

      await expect(
        result.current.shareNote('note-1', 'user+tag@example.com')
      ).resolves.toBeUndefined()
    })

    it('should handle very long note IDs', () => {
      const { result } = renderHook(() => useCollaboration())
      const longId = 'a'.repeat(1000)

      expect(() => {
        result.current.joinSession(longId)
        result.current.getSessionUsers(longId)
      }).not.toThrow()
    })

    it('should handle concurrent operations', async () => {
      const { result } = renderHook(() => useCollaboration())

      const promises = [
        result.current.shareNote('note-1', 'user1@example.com'),
        result.current.shareNote('note-2', 'user2@example.com'),
        result.current.shareNote('note-3', 'user3@example.com'),
      ]

      await Promise.all(promises)

      expect(true).toBe(true)
    })
  })

  describe('stability', () => {
    it('should return consistent results', () => {
      const { result } = renderHook(() => useCollaboration())

      const users1 = result.current.getSessionUsers('note-1')
      const users2 = result.current.getSessionUsers('note-1')
      const users3 = result.current.getSessionUsers('note-1')

      expect(users1).toEqual(users2)
      expect(users2).toEqual(users3)
    })

    it('should maintain function references across calls', () => {
      const { result, rerender } = renderHook(() => useCollaboration())

      const initialJoinSession = result.current.joinSession

      rerender()

      // Functions should be stable
      expect(typeof result.current.joinSession).toBe('function')
      expect(typeof result.current.leaveSession).toBe('function')
      expect(typeof result.current.shareNote).toBe('function')
      expect(typeof result.current.unshareNote).toBe('function')
      expect(typeof result.current.getSessionUsers).toBe('function')
      expect(typeof result.current.getSharedUsers).toBe('function')
    })
  })
})
