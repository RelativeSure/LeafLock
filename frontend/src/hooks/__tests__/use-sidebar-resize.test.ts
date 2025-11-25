import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useSidebarResize } from '../use-sidebar-resize'

describe('useSidebarResize', () => {
  const originalInnerWidth = window.innerWidth
  let consoleErrorSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    Object.defineProperty(window, 'innerWidth', {
      writable: true,
      configurable: true,
      value: 1920,
    })
    consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
  })

  afterEach(() => {
    Object.defineProperty(window, 'innerWidth', {
      writable: true,
      configurable: true,
      value: originalInnerWidth,
    })
    consoleErrorSpy.mockRestore()
  })

  describe('Initial state', () => {
    it('should return default width when no stored value', () => {
      const { result } = renderHook(() => useSidebarResize())
      expect(result.current.widthPx).toBe(256)
    })

    it('should load width from localStorage', () => {
      localStorage.setItem('sidebar-width', '300')
      const { result } = renderHook(() => useSidebarResize())
      expect(result.current.widthPx).toBe(300)
    })

    it('should use default for invalid stored value', () => {
      localStorage.setItem('sidebar-width', 'invalid')
      const { result } = renderHook(() => useSidebarResize())
      expect(result.current.widthPx).toBe(256)
    })

    it('should use default for out-of-range stored value (too small)', () => {
      localStorage.setItem('sidebar-width', '100')
      const { result } = renderHook(() => useSidebarResize())
      expect(result.current.widthPx).toBe(256)
    })

    it('should use default for out-of-range stored value (too large)', () => {
      localStorage.setItem('sidebar-width', '800')
      const { result } = renderHook(() => useSidebarResize())
      expect(result.current.widthPx).toBe(256)
    })
  })

  describe('Width calculations', () => {
    it('should calculate percentage correctly', () => {
      const { result } = renderHook(() => useSidebarResize())
      const expectedPercentage = (256 / 1920) * 100
      expect(result.current.widthPercentage).toBeCloseTo(expectedPercentage, 2)
    })

    it('should calculate rem correctly', () => {
      const { result } = renderHook(() => useSidebarResize())
      expect(result.current.widthRem).toBe(16)
    })
  })

  describe('setWidth', () => {
    it('should update width from percentage', () => {
      const { result } = renderHook(() => useSidebarResize())

      act(() => {
        result.current.setWidth(20)
      })

      const expectedWidth = (20 / 100) * 1920
      expect(result.current.widthPx).toBe(expectedWidth)
    })

    it('should clamp width to minimum', () => {
      const { result } = renderHook(() => useSidebarResize())

      act(() => {
        result.current.setWidth(5)
      })

      expect(result.current.widthPx).toBe(200)
    })

    it('should clamp width to maximum', () => {
      const { result } = renderHook(() => useSidebarResize())

      act(() => {
        result.current.setWidth(50)
      })

      expect(result.current.widthPx).toBe(600)
    })

    it('should persist width to localStorage', () => {
      const { result } = renderHook(() => useSidebarResize())

      act(() => {
        result.current.setWidth(20)
      })

      const stored = localStorage.getItem('sidebar-width')
      expect(stored).toBe('384')
    })

    it('should handle localStorage error gracefully', () => {
      const mockSetItem = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
        throw new Error('Storage full')
      })

      const { result } = renderHook(() => useSidebarResize())

      act(() => {
        result.current.setWidth(20)
      })

      expect(consoleErrorSpy).toHaveBeenCalledWith(
        'Failed to save sidebar width to localStorage:',
        expect.any(Error)
      )

      mockSetItem.mockRestore()
    })
  })

  describe('resetWidth', () => {
    it('should reset to default width', () => {
      localStorage.setItem('sidebar-width', '400')
      const { result } = renderHook(() => useSidebarResize())

      act(() => {
        result.current.resetWidth()
      })

      expect(result.current.widthPx).toBe(256)
    })

    it('should remove localStorage entry', () => {
      localStorage.setItem('sidebar-width', '400')
      const { result } = renderHook(() => useSidebarResize())

      act(() => {
        result.current.resetWidth()
      })

      expect(localStorage.getItem('sidebar-width')).toBeNull()
    })

    it('should handle localStorage error gracefully', () => {
      const mockRemoveItem = vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(() => {
        throw new Error('Storage error')
      })

      const { result } = renderHook(() => useSidebarResize())

      act(() => {
        result.current.resetWidth()
      })

      expect(consoleErrorSpy).toHaveBeenCalledWith(
        'Failed to remove sidebar width from localStorage:',
        expect.any(Error)
      )

      mockRemoveItem.mockRestore()
    })
  })

  describe('Window resize handling', () => {
    it('should update CSS variable on width change', () => {
      const { result } = renderHook(() => useSidebarResize())

      act(() => {
        result.current.setWidth(20)
      })

      const cssValue = document.documentElement.style.getPropertyValue('--sidebar-width')
      expect(cssValue).toBe('24rem')
    })

    it('should handle window resize events', () => {
      const { result } = renderHook(() => useSidebarResize())

      act(() => {
        result.current.setWidth(20)
      })

      act(() => {
        Object.defineProperty(window, 'innerWidth', {
          writable: true,
          configurable: true,
          value: 1200,
        })
        window.dispatchEvent(new Event('resize'))
      })

      expect(result.current.widthPx).toBeLessThanOrEqual(600)
      expect(result.current.widthPx).toBeGreaterThanOrEqual(200)
    })

    it('should clamp on window resize if width exceeds bounds', () => {
      localStorage.setItem('sidebar-width', '500')
      const { result } = renderHook(() => useSidebarResize())

      act(() => {
        Object.defineProperty(window, 'innerWidth', {
          writable: true,
          configurable: true,
          value: 800,
        })
        window.dispatchEvent(new Event('resize'))
      })

      expect(result.current.widthPx).toBeLessThanOrEqual(600)
    })
  })

  describe('localStorage read error', () => {
    it('should handle localStorage getItem error', () => {
      const mockGetItem = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
        throw new Error('Storage access denied')
      })

      const { result } = renderHook(() => useSidebarResize())

      expect(result.current.widthPx).toBe(256)
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        'Failed to load sidebar width from localStorage:',
        expect.any(Error)
      )

      mockGetItem.mockRestore()
    })
  })

  describe('Edge cases', () => {
    it('should handle zero percentage', () => {
      const { result } = renderHook(() => useSidebarResize())

      act(() => {
        result.current.setWidth(0)
      })

      expect(result.current.widthPx).toBe(200)
    })

    it('should handle 100 percentage', () => {
      const { result } = renderHook(() => useSidebarResize())

      act(() => {
        result.current.setWidth(100)
      })

      expect(result.current.widthPx).toBe(600)
    })

    it('should handle negative percentage', () => {
      const { result } = renderHook(() => useSidebarResize())

      act(() => {
        result.current.setWidth(-10)
      })

      expect(result.current.widthPx).toBe(200)
    })

    it('should maintain width when resize does not change clamped value', () => {
      localStorage.setItem('sidebar-width', '300')
      const { result } = renderHook(() => useSidebarResize())

      const initialWidth = result.current.widthPx

      act(() => {
        window.dispatchEvent(new Event('resize'))
      })

      expect(result.current.widthPx).toBe(initialWidth)
    })
  })
})
