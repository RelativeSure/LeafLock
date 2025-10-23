import { Sun, Moon } from 'lucide-react'
import { Switch } from '@/components/ui/switch'
import { useTheme } from '@/context'
import { motion } from 'framer-motion'

export const ThemeToggle: React.FC = () => {
  const { theme, setTheme } = useTheme()

  // Convert theme to boolean: dark = true, light/system = false
  const isDark = theme === 'dark'

  const handleToggle = (checked: boolean) => {
    setTheme(checked ? 'dark' : 'light')
  }

  return (
    <motion.div
      className="flex items-center gap-2 px-3 py-1.5 bg-card/50 backdrop-blur-sm border border-border/50 rounded-full shadow-sm"
      whileHover={{ scale: 1.05 }}
      whileTap={{ scale: 0.95 }}
      transition={{ type: "spring", stiffness: 400, damping: 17 }}
    >
      <motion.div
        animate={{
          rotate: isDark ? 180 : 0,
          scale: isDark ? 1.1 : 1
        }}
        transition={{ duration: 0.3 }}
      >
        <Sun
          className={`h-3 w-3 transition-colors duration-200 ${
            isDark ? 'text-muted-foreground' : 'text-amber-500'
          }`}
        />
      </motion.div>
      <Switch
        checked={isDark}
        onCheckedChange={handleToggle}
        aria-label="Toggle dark mode"
        className="h-4 w-7 data-[state=checked]:translate-x-3"
      />
      <motion.div
        animate={{
          rotate: isDark ? 0 : -180,
          scale: isDark ? 1 : 1.1
        }}
        transition={{ duration: 0.3 }}
      >
        <Moon
          className={`h-3 w-3 transition-colors duration-200 ${
            isDark ? 'text-blue-400' : 'text-muted-foreground'
          }`}
        />
      </motion.div>
    </motion.div>
  )
}

export default ThemeToggle
