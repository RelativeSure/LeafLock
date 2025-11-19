import { useState, useEffect, useCallback } from 'react'

const STORAGE_KEY = 'sidebar-width'
const MIN_WIDTH_PX = 200
const MAX_WIDTH_PX = 600
const DEFAULT_WIDTH_PX = 256

// Convert px to percentage based on window width
function pxToPercentage(px: number): number {
  const windowWidth = window.innerWidth
  return (px / windowWidth) * 100
}

// Convert percentage to px based on window width
function percentageToPx(percentage: number): number {
  const windowWidth = window.innerWidth
  return (percentage / 100) * windowWidth
}

// Convert px to rem (assuming 16px = 1rem)
function pxToRem(px: number): number {
  return px / 16
}

export interface SidebarResizeState {
  widthPx: number
  widthPercentage: number
  widthRem: number
  setWidth: (percentage: number) => void
  resetWidth: () => void
}

export function useSidebarResize(): SidebarResizeState {
  // Load initial width from localStorage or use default
  const getInitialWidth = useCallback((): number => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY)
      if (stored) {
        const parsed = parseFloat(stored)
        if (!isNaN(parsed) && parsed >= MIN_WIDTH_PX && parsed <= MAX_WIDTH_PX) {
          return parsed
        }
      }
    } catch (error) {
      console.error('Failed to load sidebar width from localStorage:', error)
    }
    return DEFAULT_WIDTH_PX
  }, [])

  const [widthPx, setWidthPx] = useState<number>(getInitialWidth)

  // Update CSS variable when width changes
  useEffect(() => {
    const rootElement = document.documentElement
    rootElement.style.setProperty('--sidebar-width', `${pxToRem(widthPx)}rem`)
  }, [widthPx])

  // Handle window resize to maintain proportional width
  useEffect(() => {
    const handleResize = () => {
      // Recalculate constraints on window resize
      const currentPercentage = pxToPercentage(widthPx)
      const newWidthPx = percentageToPx(currentPercentage)

      // Clamp to min/max constraints
      const clampedWidth = Math.max(MIN_WIDTH_PX, Math.min(MAX_WIDTH_PX, newWidthPx))

      if (clampedWidth !== widthPx) {
        setWidthPx(clampedWidth)
      }
    }

    window.addEventListener('resize', handleResize)
    return () => window.removeEventListener('resize', handleResize)
  }, [widthPx])

  // Set width from percentage (called by ResizablePanel)
  const setWidth = useCallback((percentage: number) => {
    const newWidthPx = percentageToPx(percentage)
    const clampedWidth = Math.max(MIN_WIDTH_PX, Math.min(MAX_WIDTH_PX, newWidthPx))

    setWidthPx(clampedWidth)

    // Persist to localStorage
    try {
      localStorage.setItem(STORAGE_KEY, clampedWidth.toString())
    } catch (error) {
      console.error('Failed to save sidebar width to localStorage:', error)
    }
  }, [])

  // Reset to default width
  const resetWidth = useCallback(() => {
    setWidthPx(DEFAULT_WIDTH_PX)
    try {
      localStorage.removeItem(STORAGE_KEY)
    } catch (error) {
      console.error('Failed to remove sidebar width from localStorage:', error)
    }
  }, [])

  return {
    widthPx,
    widthPercentage: pxToPercentage(widthPx),
    widthRem: pxToRem(widthPx),
    setWidth,
    resetWidth,
  }
}
