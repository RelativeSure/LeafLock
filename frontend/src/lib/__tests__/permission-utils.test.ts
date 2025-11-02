import { describe, it, expect } from 'vitest'
import {
  isAdmin,
  isUser,
  hasPermission,
  requiresAdmin,
  canManageUsers,
  canViewAnalytics,
  canManageAnnouncements,
  canViewSecuritySettings,
  canManageSystemSettings,
} from '../permission-utils'
import type { User } from '@/types'

describe('permission-utils', () => {
  const adminUser: User = {
    id: '1',
    email: 'admin@example.com',
    name: 'Admin User',
    role: 'admin',
    isAdmin: true,
    mfaEnabled: false,
    createdAt: '2024-01-01',
  }

  const regularUser: User = {
    id: '2',
    email: 'user@example.com',
    name: 'Regular User',
    role: 'user',
    isAdmin: false,
    mfaEnabled: false,
    createdAt: '2024-01-01',
  }

  describe('isAdmin', () => {
    it('should return true for admin user', () => {
      expect(isAdmin(adminUser)).toBe(true)
    })

    it('should return false for regular user', () => {
      expect(isAdmin(regularUser)).toBe(false)
    })

    it('should return false for null user', () => {
      expect(isAdmin(null)).toBe(false)
    })
  })

  describe('isUser', () => {
    it('should return true for regular user', () => {
      expect(isUser(regularUser)).toBe(true)
    })

    it('should return false for admin user', () => {
      expect(isUser(adminUser)).toBe(false)
    })

    it('should return false for null user', () => {
      expect(isUser(null)).toBe(false)
    })
  })

  describe('hasPermission', () => {
    it('should return true for admin with admin permission', () => {
      expect(hasPermission(adminUser, 'admin')).toBe(true)
    })

    it('should return true for admin with user permission', () => {
      expect(hasPermission(adminUser, 'user')).toBe(true)
    })

    it('should return false for user with admin permission', () => {
      expect(hasPermission(regularUser, 'admin')).toBe(false)
    })

    it('should return true for user with user permission', () => {
      expect(hasPermission(regularUser, 'user')).toBe(true)
    })

    it('should return false for null user', () => {
      expect(hasPermission(null, 'admin')).toBe(false)
      expect(hasPermission(null, 'user')).toBe(false)
    })
  })

  describe('requiresAdmin', () => {
    it('should return true for admin user', () => {
      expect(requiresAdmin(adminUser)).toBe(true)
    })

    it('should return false for regular user', () => {
      expect(requiresAdmin(regularUser)).toBe(false)
    })

    it('should return false for null user', () => {
      expect(requiresAdmin(null)).toBe(false)
    })
  })

  describe('canManageUsers', () => {
    it('should allow admin to manage users', () => {
      expect(canManageUsers(adminUser)).toBe(true)
    })

    it('should not allow regular user to manage users', () => {
      expect(canManageUsers(regularUser)).toBe(false)
    })

    it('should not allow null user to manage users', () => {
      expect(canManageUsers(null)).toBe(false)
    })
  })

  describe('canViewAnalytics', () => {
    it('should allow admin to view analytics', () => {
      expect(canViewAnalytics(adminUser)).toBe(true)
    })

    it('should not allow regular user to view analytics', () => {
      expect(canViewAnalytics(regularUser)).toBe(false)
    })

    it('should not allow null user to view analytics', () => {
      expect(canViewAnalytics(null)).toBe(false)
    })
  })

  describe('canManageAnnouncements', () => {
    it('should allow admin to manage announcements', () => {
      expect(canManageAnnouncements(adminUser)).toBe(true)
    })

    it('should not allow regular user to manage announcements', () => {
      expect(canManageAnnouncements(regularUser)).toBe(false)
    })

    it('should not allow null user to manage announcements', () => {
      expect(canManageAnnouncements(null)).toBe(false)
    })
  })

  describe('canViewSecuritySettings', () => {
    it('should allow admin to view security settings', () => {
      expect(canViewSecuritySettings(adminUser)).toBe(true)
    })

    it('should not allow regular user to view security settings', () => {
      expect(canViewSecuritySettings(regularUser)).toBe(false)
    })

    it('should not allow null user to view security settings', () => {
      expect(canViewSecuritySettings(null)).toBe(false)
    })
  })

  describe('canManageSystemSettings', () => {
    it('should allow admin to manage system settings', () => {
      expect(canManageSystemSettings(adminUser)).toBe(true)
    })

    it('should not allow regular user to manage system settings', () => {
      expect(canManageSystemSettings(regularUser)).toBe(false)
    })

    it('should not allow null user to manage system settings', () => {
      expect(canManageSystemSettings(null)).toBe(false)
    })
  })

  describe('Edge Cases', () => {
    it('should handle user with undefined role', () => {
      const userWithUndefinedRole = {
        ...regularUser,
        role: undefined,
      } as any

      expect(isAdmin(userWithUndefinedRole)).toBe(false)
      expect(hasPermission(userWithUndefinedRole, 'admin')).toBe(false)
    })

    it('should handle user with invalid role', () => {
      const userWithInvalidRole = {
        ...regularUser,
        role: 'invalid' as any,
      }

      expect(isAdmin(userWithInvalidRole)).toBe(false)
      expect(isUser(userWithInvalidRole)).toBe(false)
      expect(hasPermission(userWithInvalidRole, 'admin')).toBe(false)
    })
  })
})
