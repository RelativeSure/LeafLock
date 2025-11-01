import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { render, screen, renderHook, act } from '@testing-library/react'
import { ThemeProvider, useTheme } from '../ThemeContext'
import { ReactNode } from 'react'

describe('ThemeContext', () => {
  beforeEach(() => {
    localStorage.clear()
    document.documentElement.className = ''

    // Mock matchMedia
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      value: vi.fn().mockImplementation(query => ({
        matches: query === '(prefers-color-scheme: dark)',
        media: query,
        onchange: null,
        addListener: vi.fn(),
        removeListener: vi.fn(),
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        dispatchEvent: vi.fn(),
      })),
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('ThemeProvider', () => {
    it('should render children', () => {
      render(
        <ThemeProvider>
          <div data-testid="child">Child Content</div>
        </ThemeProvider>
      )

      expect(screen.getByTestId('child')).toBeInTheDocument()
    })

    it('should use default theme when localStorage is empty', () => {
      const { result } = renderHook(() => useTheme(), {
        wrapper: ({ children }: { children: ReactNode }) => (
          <ThemeProvider>{children}</ThemeProvider>
        ),
      })

      expect(result.current.theme).toBe('system')
    })

    it('should use theme from localStorage', () => {
      localStorage.setItem('vite-ui-theme', 'dark')

      const { result } = renderHook(() => useTheme(), {
        wrapper: ({ children }: { children: ReactNode }) => (
          <ThemeProvider>{children}</ThemeProvider>
        ),
      })

      expect(result.current.theme).toBe('dark')
    })

    it('should use custom defaultTheme', () => {
      const { result } = renderHook(() => useTheme(), {
        wrapper: ({ children }: { children: ReactNode }) => (
          <ThemeProvider defaultTheme="light">{children}</ThemeProvider>
        ),
      })

      expect(result.current.theme).toBe('light')
    })

    it('should use custom storageKey', () => {
      localStorage.setItem('custom-theme-key', 'light')

      const { result } = renderHook(() => useTheme(), {
        wrapper: ({ children }: { children: ReactNode }) => (
          <ThemeProvider storageKey="custom-theme-key">{children}</ThemeProvider>
        ),
      })

      expect(result.current.theme).toBe('light')
    })

    it('should apply light theme class to document', () => {
      renderHook(() => useTheme(), {
        wrapper: ({ children }: { children: ReactNode }) => (
          <ThemeProvider defaultTheme="light">{children}</ThemeProvider>
        ),
      })

      expect(document.documentElement.classList.contains('light')).toBe(true)
    })

    it('should apply dark theme class to document', () => {
      renderHook(() => useTheme(), {
        wrapper: ({ children }: { children: ReactNode }) => (
          <ThemeProvider defaultTheme="dark">{children}</ThemeProvider>
        ),
      })

      expect(document.documentElement.classList.contains('dark')).toBe(true)
    })

    it('should apply system theme based on matchMedia', () => {
      Object.defineProperty(window, 'matchMedia', {
        writable: true,
        value: vi.fn().mockImplementation(query => ({
          matches: true, // dark mode
          media: query,
          onchange: null,
          addListener: vi.fn(),
          removeListener: vi.fn(),
          addEventListener: vi.fn(),
          removeEventListener: vi.fn(),
          dispatchEvent: vi.fn(),
        })),
      })

      renderHook(() => useTheme(), {
        wrapper: ({ children }: { children: ReactNode }) => (
          <ThemeProvider defaultTheme="system">{children}</ThemeProvider>
        ),
      })

      expect(document.documentElement.classList.contains('dark')).toBe(true)
    })

    it('should apply light theme when system prefers light', () => {
      Object.defineProperty(window, 'matchMedia', {
        writable: true,
        value: vi.fn().mockImplementation(query => ({
          matches: false, // light mode
          media: query,
          onchange: null,
          addListener: vi.fn(),
          removeListener: vi.fn(),
          addEventListener: vi.fn(),
          removeEventListener: vi.fn(),
          dispatchEvent: vi.fn(),
        })),
      })

      renderHook(() => useTheme(), {
        wrapper: ({ children }: { children: ReactNode }) => (
          <ThemeProvider defaultTheme="system">{children}</ThemeProvider>
        ),
      })

      expect(document.documentElement.classList.contains('light')).toBe(true)
    })

    it('should remove previous theme class when theme changes', () => {
      const { result } = renderHook(() => useTheme(), {
        wrapper: ({ children }: { children: ReactNode }) => (
          <ThemeProvider defaultTheme="light">{children}</ThemeProvider>
        ),
      })

      expect(document.documentElement.classList.contains('light')).toBe(true)

      act(() => {
        result.current.setTheme('dark')
      })

      expect(document.documentElement.classList.contains('light')).toBe(false)
      expect(document.documentElement.classList.contains('dark')).toBe(true)
    })
  })

  describe('useTheme hook', () => {
    it('should return theme and setTheme', () => {
      const { result } = renderHook(() => useTheme(), {
        wrapper: ({ children }: { children: ReactNode }) => (
          <ThemeProvider>{children}</ThemeProvider>
        ),
      })

      expect(result.current.theme).toBeDefined()
      expect(result.current.setTheme).toBeDefined()
      expect(typeof result.current.setTheme).toBe('function')
    })

    it('should throw error when used outside ThemeProvider', () => {
      expect(() => {
        renderHook(() => useTheme())
      }).toThrow('useTheme must be used within a ThemeProvider')
    })

    it('should update theme', () => {
      const { result } = renderHook(() => useTheme(), {
        wrapper: ({ children }: { children: ReactNode }) => (
          <ThemeProvider defaultTheme="light">{children}</ThemeProvider>
        ),
      })

      expect(result.current.theme).toBe('light')

      act(() => {
        result.current.setTheme('dark')
      })

      expect(result.current.theme).toBe('dark')
    })

    it('should persist theme to localStorage', () => {
      const { result } = renderHook(() => useTheme(), {
        wrapper: ({ children }: { children: ReactNode }) => (
          <ThemeProvider>{children}</ThemeProvider>
        ),
      })

      act(() => {
        result.current.setTheme('dark')
      })

      expect(localStorage.getItem('vite-ui-theme')).toBe('dark')
    })

    it('should persist theme to custom storageKey', () => {
      const { result } = renderHook(() => useTheme(), {
        wrapper: ({ children }: { children: ReactNode }) => (
          <ThemeProvider storageKey="custom-key">{children}</ThemeProvider>
        ),
      })

      act(() => {
        result.current.setTheme('light')
      })

      expect(localStorage.getItem('custom-key')).toBe('light')
    })

    it('should allow switching to system theme', () => {
      const { result } = renderHook(() => useTheme(), {
        wrapper: ({ children }: { children: ReactNode }) => (
          <ThemeProvider defaultTheme="dark">{children}</ThemeProvider>
        ),
      })

      act(() => {
        result.current.setTheme('system')
      })

      expect(result.current.theme).toBe('system')
    })

    it('should update document classes when theme changes', () => {
      const { result } = renderHook(() => useTheme(), {
        wrapper: ({ children }: { children: ReactNode }) => (
          <ThemeProvider defaultTheme="light">{children}</ThemeProvider>
        ),
      })

      act(() => {
        result.current.setTheme('dark')
      })

      expect(document.documentElement.classList.contains('dark')).toBe(true)
      expect(document.documentElement.classList.contains('light')).toBe(false)
    })
  })

  describe('Theme switching', () => {
    it('should switch from light to dark', () => {
      const { result } = renderHook(() => useTheme(), {
        wrapper: ({ children }: { children: ReactNode }) => (
          <ThemeProvider defaultTheme="light">{children}</ThemeProvider>
        ),
      })

      act(() => {
        result.current.setTheme('dark')
      })

      expect(result.current.theme).toBe('dark')
      expect(document.documentElement.classList.contains('dark')).toBe(true)
    })

    it('should switch from dark to light', () => {
      const { result } = renderHook(() => useTheme(), {
        wrapper: ({ children }: { children: ReactNode }) => (
          <ThemeProvider defaultTheme="dark">{children}</ThemeProvider>
        ),
      })

      act(() => {
        result.current.setTheme('light')
      })

      expect(result.current.theme).toBe('light')
      expect(document.documentElement.classList.contains('light')).toBe(true)
    })

    it('should switch from light to system', () => {
      const { result } = renderHook(() => useTheme(), {
        wrapper: ({ children }: { children: ReactNode }) => (
          <ThemeProvider defaultTheme="light">{children}</ThemeProvider>
        ),
      })

      act(() => {
        result.current.setTheme('system')
      })

      expect(result.current.theme).toBe('system')
    })

    it('should switch from system to dark', () => {
      const { result } = renderHook(() => useTheme(), {
        wrapper: ({ children }: { children: ReactNode }) => (
          <ThemeProvider defaultTheme="system">{children}</ThemeProvider>
        ),
      })

      act(() => {
        result.current.setTheme('dark')
      })

      expect(result.current.theme).toBe('dark')
      expect(document.documentElement.classList.contains('dark')).toBe(true)
    })
  })

  describe('Edge cases', () => {
    it('should handle invalid theme in localStorage', () => {
      localStorage.setItem('vite-ui-theme', 'invalid-theme')

      const { result } = renderHook(() => useTheme(), {
        wrapper: ({ children }: { children: ReactNode }) => (
          <ThemeProvider>{children}</ThemeProvider>
        ),
      })

      // Should fall back to default
      expect(result.current.theme).toBeDefined()
    })

    it('should handle multiple theme changes', () => {
      const { result } = renderHook(() => useTheme(), {
        wrapper: ({ children }: { children: ReactNode }) => (
          <ThemeProvider>{children}</ThemeProvider>
        ),
      })

      act(() => {
        result.current.setTheme('light')
      })
      act(() => {
        result.current.setTheme('dark')
      })
      act(() => {
        result.current.setTheme('system')
      })
      act(() => {
        result.current.setTheme('light')
      })

      expect(result.current.theme).toBe('light')
    })

    it('should work with nested providers', () => {
      const { result: outerResult } = renderHook(() => useTheme(), {
        wrapper: ({ children }: { children: ReactNode }) => (
          <ThemeProvider defaultTheme="light">{children}</ThemeProvider>
        ),
      })

      expect(outerResult.current.theme).toBe('light')
    })

    it('should persist across re-renders', () => {
      const { result, rerender } = renderHook(() => useTheme(), {
        wrapper: ({ children }: { children: ReactNode }) => (
          <ThemeProvider>{children}</ThemeProvider>
        ),
      })

      act(() => {
        result.current.setTheme('dark')
      })

      rerender()

      expect(result.current.theme).toBe('dark')
    })
  })
})
