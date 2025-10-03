import React, { createContext, useContext } from 'react'

export type ThemeType = 'light' | 'blue' | 'dark' | 'system'

interface ThemeContextType {
  theme: ThemeType
  effectiveTheme: 'light' | 'blue' | 'dark'
  setTheme: (theme: ThemeType) => void
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined)

export const useTheme = () => {
  const context = useContext(ThemeContext)
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider')
  }
  return context
}

export { ThemeContext }
