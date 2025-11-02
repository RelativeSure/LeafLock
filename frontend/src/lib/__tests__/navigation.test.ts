import { describe, it, expect, beforeEach, vi } from 'vitest'
import { clearAuthStorage, safeRedirectToLogin, isOnAuthRoute } from '../navigation'

describe('navigation utils', () => {
  beforeEach(() => {
    localStorage.clear()
    sessionStorage.clear()
    delete (window as any).location
    ;(window as any).location = { pathname: '/', replace: vi.fn() }
  })

  describe('clearAuthStorage', () => {
    it('should clear auth-related storage', () => {
      localStorage.setItem('token', 'test-token')
      localStorage.setItem('user', 'test-user')
      sessionStorage.setItem('encryptionKey', 'test-key')

      clearAuthStorage()

      expect(localStorage.getItem('token')).toBeNull()
      expect(localStorage.getItem('user')).toBeNull()
      expect(sessionStorage.getItem('encryptionKey')).toBeNull()
    })

    it('should not clear non-auth items', () => {
      localStorage.setItem('theme', 'dark')
      localStorage.setItem('token', 'test-token')

      clearAuthStorage()

      expect(localStorage.getItem('theme')).toBe('dark')
      expect(localStorage.getItem('token')).toBeNull()
    })
  })

  describe('isOnAuthRoute', () => {
    it('should return true for /login', () => {
      ;(window as any).location.pathname = '/login'
      expect(isOnAuthRoute()).toBe(true)
    })

    it('should return true for /register', () => {
      ;(window as any).location.pathname = '/register'
      expect(isOnAuthRoute()).toBe(true)
    })

    it('should return true for /forgot-password', () => {
      ;(window as any).location.pathname = '/forgot-password'
      expect(isOnAuthRoute()).toBe(true)
    })

    it('should return false for /dashboard', () => {
      ;(window as any).location.pathname = '/dashboard'
      expect(isOnAuthRoute()).toBe(false)
    })

    it('should return false for /', () => {
      ;(window as any).location.pathname = '/'
      expect(isOnAuthRoute()).toBe(false)
    })
  })

  describe('safeRedirectToLogin', () => {
    it('should redirect to login if not on auth route', () => {
      ;(window as any).location.pathname = '/dashboard'
      
      safeRedirectToLogin()

      expect(window.location.replace).toHaveBeenCalledWith('/login')
    })

    it('should not redirect if already on auth route', () => {
      ;(window as any).location.pathname = '/login'
      
      safeRedirectToLogin()

      expect(window.location.replace).not.toHaveBeenCalled()
    })

    it('should not redirect if on register page', () => {
      ;(window as any).location.pathname = '/register'
      
      safeRedirectToLogin()

      expect(window.location.replace).not.toHaveBeenCalled()
    })
  })
})
