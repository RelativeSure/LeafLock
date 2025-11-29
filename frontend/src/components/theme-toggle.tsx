/**
 * Theme Toggle Component
 *
 * @description
 * User interface component for switching between light, dark, and system themes.
 * Provides accessible theme selection with smooth icon transitions and dropdown menu.
 *
 * @features
 * - Smooth animated transitions between sun and moon icons
 * - Dropdown menu with light, dark, and system options
 * - Accessible with screen reader support
 * - Responsive design with proper touch targets
 * - Integrates with ThemeContext for global theme management
 *
 * @accessibility
 * - Screen reader announcement for theme changes
 * - Keyboard navigation support through dropdown
 * - High contrast icon visibility
 * - Proper ARIA labeling for assistive technologies
 *
 * @usage
 * <ThemeToggle /> // Renders theme switcher in header or settings
 */
'use client'
import { Moon, Sun } from 'lucide-react'
import { useTheme } from '../context/ThemeContext'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'

export function ThemeToggle() {
  const { setTheme } = useTheme()

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="icon" className="relative bg-transparent">
          <Sun className="h-[1.2rem] w-[1.2rem] rotate-0 scale-100 transition-all dark:-rotate-90 dark:scale-0" />
          <Moon className="absolute h-[1.2rem] w-[1.2rem] rotate-90 scale-0 transition-all dark:rotate-0 dark:scale-100" />
          <span className="sr-only">Toggle theme</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem onClick={() => setTheme('light')}>Light</DropdownMenuItem>
        <DropdownMenuItem onClick={() => setTheme('dark')}>Dark</DropdownMenuItem>
        <DropdownMenuItem onClick={() => setTheme('system')}>System</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
