import { useState, type ReactElement } from 'react'
import { Button } from '@/components/ui/button'
import { useTheme, type ThemeType } from '@/context'

interface ThemeOption {
  value: ThemeType
  label: string
  icon: ReactElement
}

const themeOptions: ThemeOption[] = [
  {
    value: 'system',
    label: 'System',
    icon: (
      <svg
        className="w-4 h-4"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
        aria-hidden="true"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={2}
          d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"
        />
      </svg>
    ),
  },
  {
    value: 'light',
    label: 'Light',
    icon: (
      <svg
        className="w-4 h-4"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
        aria-hidden="true"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={2}
          d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"
        />
      </svg>
    ),
  },
  {
    value: 'dark',
    label: 'Dark',
    icon: (
      <svg
        className="w-4 h-4"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
        aria-hidden="true"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={2}
          d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"
        />
      </svg>
    ),
  },
]

export const ThemeToggle: React.FC = () => {
  const { theme, setTheme } = useTheme()
  const [isOpen, setIsOpen] = useState(false)

  const activeOption = themeOptions.find((option) => option.value === theme) ?? themeOptions[0]

  return (
    <div className="relative">
      <Button
        variant="outline"
        size="icon"
        onClick={() => setIsOpen((prev) => !prev)}
        className="rounded-full transition-transform duration-200 hover:rotate-12 active:scale-95"
        aria-label="Toggle theme"
      >
        {activeOption.icon}
      </Button>

      {isOpen && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setIsOpen(false)} aria-hidden="true" />
          <div className="absolute right-0 top-12 z-50 w-48 rounded-md border bg-popover p-1 shadow-lg animate-in fade-in zoom-in-95 slide-in-from-top-2 duration-200">
            <div className="space-y-1">
              {themeOptions.map((option, index) => (
                <button
                  key={option.value}
                  onClick={() => {
                    setTheme(option.value)
                    setIsOpen(false)
                  }}
                  className={`w-full flex items-center gap-3 px-3 py-2 text-sm rounded-sm transition-all duration-200 animate-in fade-in slide-in-from-left-1 ${
                    theme === option.value
                      ? 'bg-accent text-accent-foreground shadow-sm'
                      : 'hover:bg-accent hover:text-accent-foreground hover:translate-x-1'
                  }`}
                  style={{ animationDelay: `${index * 30}ms` }}
                >
                  {option.icon}
                  <span>{option.label}</span>
                  {theme === option.value && (
                    <svg
                      className="ml-auto h-4 w-4 animate-in zoom-in-50"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M5 13l4 4L19 7"
                      />
                    </svg>
                  )}
                </button>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  )
}

export default ThemeToggle
