import type { User } from '@/types'

/**
 * Permission utility functions for role-based access control
 */

export function isAdmin(user: User | null): boolean {
  return user?.role === 'admin'
}

export function isUser(user: User | null): boolean {
  return user?.role === 'user'
}

export function hasPermission(user: User | null, requiredRole: 'admin' | 'user'): boolean {
  if (!user) return false

  // Admins have all permissions
  if (user.role === 'admin') return true

  // Users don't have admin permissions
  if (requiredRole === 'admin') return false

  return user.role === requiredRole
}

export function requiresAdmin(user: User | null): boolean {
  return isAdmin(user)
}

export function canManageUsers(user: User | null): boolean {
  return isAdmin(user)
}

export function canViewAnalytics(user: User | null): boolean {
  return isAdmin(user)
}

export function canManageAnnouncements(user: User | null): boolean {
  return isAdmin(user)
}

export function canViewSecuritySettings(user: User | null): boolean {
  return isAdmin(user)
}

export function canManageSystemSettings(user: User | null): boolean {
  return isAdmin(user)
}
