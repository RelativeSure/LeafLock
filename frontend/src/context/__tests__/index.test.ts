import { describe, it, expect } from 'vitest'
import { ThemeProvider, useTheme } from '../index'

describe('context/index', () => {
  it('exports ThemeProvider', () => {
    expect(ThemeProvider).toBeDefined()
    expect(typeof ThemeProvider).toBe('function')
  })

  it('exports useTheme', () => {
    expect(useTheme).toBeDefined()
    expect(typeof useTheme).toBe('function')
  })

  it('re-exports from ThemeContext module', async () => {
    const { ThemeProvider: DirectProvider, useTheme: DirectUseTheme } = await import(
      '../ThemeContext'
    )
    expect(ThemeProvider).toBe(DirectProvider)
    expect(useTheme).toBe(DirectUseTheme)
  })
})
