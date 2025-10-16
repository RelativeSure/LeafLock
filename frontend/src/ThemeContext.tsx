import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  useSyncExternalStore,
  type ReactNode,
  type FC,
} from 'react'

export type ThemeType = 'light' | 'dark' | 'system'
type EffectiveTheme = 'light' | 'dark'

interface ThemeContextType {
  theme: ThemeType
  effectiveTheme: EffectiveTheme
  setTheme: (theme: ThemeType) => void
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined)

const THEME_COOKIE = 'theme'
const SUPPORTED_THEMES: ThemeType[] = ['light', 'dark', 'system']

const getSystemTheme = (): EffectiveTheme => {
  if (typeof window === 'undefined') {
    return 'light'
  }
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

const readStoredTheme = (): ThemeType => {
  if (typeof document === 'undefined') {
    return 'system'
  }

  const cookie = document.cookie
    .split('; ')
    .find((row) => row.startsWith(`${THEME_COOKIE}=`))
    ?.split('=')[1] as ThemeType | undefined

  return cookie && SUPPORTED_THEMES.includes(cookie) ? cookie : 'system'
}

const applyThemeClasses = (theme: EffectiveTheme) => {
  if (typeof document === 'undefined') {
    return
  }

  const root = document.documentElement
  root.classList.remove('light', 'dark')

  switch (theme) {
    case 'dark':
      root.classList.add('dark')
      break
    case 'light':
    default:
      // No extra class required
      break
  }
}

const useSystemTheme = (): EffectiveTheme => {
  return useSyncExternalStore(
    (callback) => {
      if (typeof window === 'undefined') {
        return () => undefined
      }

      const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')
      const listener = () => callback()
      mediaQuery.addEventListener('change', listener)
      return () => mediaQuery.removeEventListener('change', listener)
    },
    () => getSystemTheme(),
    () => 'light'
  )
}

export const ThemeProvider: FC<{ children: ReactNode }> = ({ children }) => {
  const [theme, setThemeState] = useState<ThemeType>(() => readStoredTheme())
  const systemTheme = useSystemTheme()

  const effectiveTheme = useMemo<EffectiveTheme>(() => {
    return theme === 'system' ? systemTheme : theme
  }, [theme, systemTheme])

  useEffect(() => {
    applyThemeClasses(effectiveTheme)
  }, [effectiveTheme])

  const setTheme = (newTheme: ThemeType) => {
    setThemeState(newTheme)

    if (typeof document !== 'undefined') {
      const expires = new Date()
      expires.setFullYear(expires.getFullYear() + 1)
      document.cookie = `${THEME_COOKIE}=${newTheme}; expires=${expires.toUTCString()}; path=/; SameSite=Strict`
    }
  }

  const value = useMemo<ThemeContextType>(
    () => ({ theme, effectiveTheme, setTheme }),
    [theme, effectiveTheme]
  )

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

export const useTheme = (): ThemeContextType => {
  const context = useContext(ThemeContext)
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider')
  }
  return context
}

export { ThemeContext }
