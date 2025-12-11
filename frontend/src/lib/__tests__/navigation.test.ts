import { describe, it, expect, beforeEach, vi } from 'vitest'
import { safeRedirectToLogin, isOnAuthRoute } from '../navigation'

describe('navigation utils', () => {
  beforeEach(() => {
    localStorage.clear()
    sessionStorage.clear()
    delete (window as any).location
    ;(window as any).location = { pathname: '/', replace: vi.fn() }
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

    it('should return true for /forgot', () => {
      ;(window as any).location.pathname = '/forgot'
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
      ;(window as any).location.href = ''

      safeRedirectToLogin()

      expect(window.location.href).toBe('/login')
    })

    it('should not redirect if already on auth route', () => {
      ;(window as any).location.pathname = '/login'
      ;(window as any).location.href = ''

      safeRedirectToLogin()

      // Should not change href when already on auth route
      expect(window.location.href).toBe('')
    })

    it('should not redirect if on register page', () => {
      ;(window as any).location.pathname = '/register'
      ;(window as any).location.href = ''

      safeRedirectToLogin()

      expect(window.location.href).toBe('')
    })
  })
})
