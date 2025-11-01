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
    name: 'Admin',
    role: 'admin',
    isAdmin: true,
    mfaEnabled: false,
    createdAt: new Date().toISOString(),
  }

  const regularUser: User = {
    id: '2',
    email: 'user@example.com',
    name: 'User',
    role: 'user',
    isAdmin: false,
    mfaEnabled: false,
    createdAt: new Date().toISOString(),
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

    it('should return true for user with user permission', () => {
      expect(hasPermission(regularUser, 'user')).toBe(true)
    })

    it('should return false for user with admin permission', () => {
      expect(hasPermission(regularUser, 'admin')).toBe(false)
    })

    it('should return false for null user', () => {
      expect(hasPermission(null, 'user')).toBe(false)
      expect(hasPermission(null, 'admin')).toBe(false)
    })
  })

  describe('requiresAdmin', () => {
    it('should return true for admin user', () => {
      expect(requiresAdmin(adminUser)).toBe(true)
    })

    it('should return false for regular user', () => {
      expect(requiresAdmin(regularUser)).toBe(false)
    })
  })

  describe('canManageUsers', () => {
    it('should return true for admin', () => {
      expect(canManageUsers(adminUser)).toBe(true)
    })

    it('should return false for regular user', () => {
      expect(canManageUsers(regularUser)).toBe(false)
    })
  })

  describe('canViewAnalytics', () => {
    it('should return true for admin', () => {
      expect(canViewAnalytics(adminUser)).toBe(true)
    })

    it('should return false for regular user', () => {
      expect(canViewAnalytics(regularUser)).toBe(false)
    })
  })

  describe('canManageAnnouncements', () => {
    it('should return true for admin', () => {
      expect(canManageAnnouncements(adminUser)).toBe(true)
    })

    it('should return false for regular user', () => {
      expect(canManageAnnouncements(regularUser)).toBe(false)
    })
  })

  describe('canViewSecuritySettings', () => {
    it('should return true for admin', () => {
      expect(canViewSecuritySettings(adminUser)).toBe(true)
    })

    it('should return false for regular user', () => {
      expect(canViewSecuritySettings(regularUser)).toBe(false)
    })
  })

  describe('canManageSystemSettings', () => {
    it('should return true for admin', () => {
      expect(canManageSystemSettings(adminUser)).toBe(true)
    })

    it('should return false for regular user', () => {
      expect(canManageSystemSettings(regularUser)).toBe(false)
    })
  })
})
