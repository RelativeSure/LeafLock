import { Sun, Moon } from 'lucide-react'
import { Switch } from '@/components/ui/switch'
import { useTheme } from '@/context'

export const ThemeToggle: React.FC = () => {
  const { theme, setTheme } = useTheme()

  // Convert theme to boolean: dark = true, light/system = false
  const isDark = theme === 'dark'

  const handleToggle = (checked: boolean) => {
    setTheme(checked ? 'dark' : 'light')
  }

  return (
    <div className="flex items-center gap-2 px-3 py-1.5 bg-card/50 backdrop-blur-sm border border-border/50 rounded-full shadow-sm">
      <Sun
        className={`h-3 w-3 transition-colors duration-200 ${
          isDark ? 'text-muted-foreground' : 'text-amber-500'
        }`}
      />
      <Switch
        checked={isDark}
        onCheckedChange={handleToggle}
        aria-label="Toggle dark mode"
        className="h-4 w-7 data-[state=checked]:translate-x-3"
      />
      <Moon
        className={`h-3 w-3 transition-colors duration-200 ${
          isDark ? 'text-blue-400' : 'text-muted-foreground'
        }`}
      />
    </div>
  )
}

export default ThemeToggle
