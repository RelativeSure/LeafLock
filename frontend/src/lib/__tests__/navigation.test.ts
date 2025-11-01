import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'

describe('navigation utilities', () => {
  // Re-import module fresh for each test to reset module-level state
  let isOnAuthRoute: (pathname?: string) => boolean
  let safeRedirectToLogin: (options?: { force?: boolean }) => void
  let clearAuthStorage: () => void

  beforeEach(async () => {
    // Clear localStorage
    localStorage.clear()

    // Reset window.location
    delete (window as any).location
    window.location = {
      pathname: '/',
      href: '/',
    } as any

    // Reset Date.now for time-based tests
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2024-01-01T00:00:00Z'))

    // Reset module to clear module-level variables (lastRedirectAt)
    vi.resetModules()
    const nav = await import('../navigation')
    isOnAuthRoute = nav.isOnAuthRoute
    safeRedirectToLogin = nav.safeRedirectToLogin
    clearAuthStorage = nav.clearAuthStorage
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.useRealTimers()
  })

  describe('isOnAuthRoute', () => {
    it('should return true for /login', () => {
      expect(isOnAuthRoute('/login')).toBe(true)
    })

    it('should return true for /register', () => {
      expect(isOnAuthRoute('/register')).toBe(true)
    })

    it('should return true for /forgot', () => {
      expect(isOnAuthRoute('/forgot')).toBe(true)
    })

    it('should return false for /dashboard', () => {
      expect(isOnAuthRoute('/dashboard')).toBe(false)
    })

    it('should return false for /', () => {
      expect(isOnAuthRoute('/')).toBe(false)
    })

    it('should use window.location.pathname when pathname not provided', () => {
      window.location.pathname = '/login'
      expect(isOnAuthRoute()).toBe(true)

      window.location.pathname = '/dashboard'
      expect(isOnAuthRoute()).toBe(false)
    })

    it('should return false for similar but different paths', () => {
      expect(isOnAuthRoute('/login-page')).toBe(false)
      expect(isOnAuthRoute('/register-now')).toBe(false)
      expect(isOnAuthRoute('/forgot-password')).toBe(false)
    })
  })

  describe('safeRedirectToLogin', () => {
    it('should redirect to /login when not on auth route', () => {
      window.location.pathname = '/dashboard'

      safeRedirectToLogin()

      expect(window.location.href).toBe('/login')
    })

    it('should not redirect when already on auth route', () => {
      window.location.pathname = '/login'
      window.location.href = '/login'

      safeRedirectToLogin()

      expect(window.location.href).toBe('/login') // unchanged
    })

    it('should debounce redirects within 1500ms', () => {
      window.location.pathname = '/dashboard'

      // First redirect should work
      safeRedirectToLogin()
      expect(window.location.href).toBe('/login')

      // Reset href to simulate staying on page
      window.location.href = '/dashboard'

      // Second redirect within debounce window should be ignored
      vi.advanceTimersByTime(1000) // 1 second, less than 1500ms
      safeRedirectToLogin()
      expect(window.location.href).toBe('/dashboard') // unchanged

      // After debounce period, should work again
      vi.advanceTimersByTime(600) // Total 1600ms, more than 1500ms
      safeRedirectToLogin()
      expect(window.location.href).toBe('/login')
    })

    it('should allow force redirect even within debounce window', () => {
      window.location.pathname = '/dashboard'

      // First redirect
      safeRedirectToLogin()
      expect(window.location.href).toBe('/login')

      // Reset pathname and href
      window.location.pathname = '/dashboard'
      window.location.href = '/dashboard'

      // Forced redirect within debounce window should work
      vi.advanceTimersByTime(500)
      safeRedirectToLogin({ force: true })
      expect(window.location.href).toBe('/login')
    })

    it('should not redirect when window is undefined (SSR)', () => {
      const originalWindow = global.window
      delete (global as any).window

      // Should not throw
      expect(() => safeRedirectToLogin()).not.toThrow()

      global.window = originalWindow as any
    })

    it('should not redirect from /register', () => {
      window.location.pathname = '/register'
      window.location.href = '/register'

      safeRedirectToLogin()

      expect(window.location.href).toBe('/register')
    })

    it('should not redirect from /forgot', () => {
      window.location.pathname = '/forgot'
      window.location.href = '/forgot'

      safeRedirectToLogin()

      expect(window.location.href).toBe('/forgot')
    })
  })

  describe('clearAuthStorage', () => {
    it('should clear user and token from localStorage', () => {
      localStorage.setItem('user', JSON.stringify({ id: '123', email: 'test@example.com' }))
      localStorage.setItem('token', 'test-token')

      clearAuthStorage()

      expect(localStorage.getItem('user')).toBeNull()
      expect(localStorage.getItem('token')).toBeNull()
    })

    it('should handle when items do not exist', () => {
      expect(() => clearAuthStorage()).not.toThrow()

      expect(localStorage.getItem('user')).toBeNull()
      expect(localStorage.getItem('token')).toBeNull()
    })

    it('should handle localStorage errors gracefully', () => {
      // Mock localStorage to throw error
      const originalRemoveItem = Storage.prototype.removeItem
      Storage.prototype.removeItem = vi.fn(() => {
        throw new Error('localStorage error')
      })

      // Should not throw
      expect(() => clearAuthStorage()).not.toThrow()

      // Restore
      Storage.prototype.removeItem = originalRemoveItem
    })

    it('should only clear auth-related items', () => {
      localStorage.setItem('user', 'user-data')
      localStorage.setItem('token', 'token-data')
      localStorage.setItem('theme', 'dark')
      localStorage.setItem('language', 'en')

      clearAuthStorage()

      expect(localStorage.getItem('user')).toBeNull()
      expect(localStorage.getItem('token')).toBeNull()
      expect(localStorage.getItem('theme')).toBe('dark')
      expect(localStorage.getItem('language')).toBe('en')
    })
  })

  describe('integration scenarios', () => {
    it('should handle logout flow correctly', () => {
      // User is logged in on dashboard
      localStorage.setItem('user', JSON.stringify({ id: '123' }))
      localStorage.setItem('token', 'valid-token')
      window.location.pathname = '/dashboard'
      window.location.href = '/dashboard'

      // Logout: clear storage and redirect
      clearAuthStorage()
      safeRedirectToLogin()

      expect(localStorage.getItem('user')).toBeNull()
      expect(localStorage.getItem('token')).toBeNull()
      expect(window.location.href).toBe('/login')
    })

    it('should prevent redirect loops on login page', () => {
      window.location.pathname = '/login'
      window.location.href = '/login'

      // Multiple redirect attempts should not change location
      safeRedirectToLogin()
      safeRedirectToLogin()
      safeRedirectToLogin()

      expect(window.location.href).toBe('/login')
    })

    it('should handle 401 response flow', () => {
      // Simulating 401 Unauthorized response
      localStorage.setItem('user', JSON.stringify({ id: '123' }))
      localStorage.setItem('token', 'expired-token')
      window.location.pathname = '/dashboard'
      window.location.href = '/dashboard'

      // Clear auth and redirect
      clearAuthStorage()
      safeRedirectToLogin()

      expect(localStorage.getItem('token')).toBeNull()
      expect(window.location.href).toBe('/login')
    })
  })
})
