/**
 * Button Component - Radix UI Based Button System
 * 
 * @description
 * Flexible button component built on Radix UI primitives with extensive customization options.
 * Supports multiple variants, sizes, and asChild prop for polymorphic behavior.
 * 
 * @features
 * - Multiple visual variants (default, destructive, outline, secondary, ghost, link)
 * - Flexible sizing system (default, sm, lg, icon, icon-sm, icon-lg)
 * - Radix UI Slot support for polymorphic rendering
 * - Comprehensive focus states and accessibility
 * - Smooth transitions and hover effects
 * - Dark mode support with theme-aware styling
 * 
 * @variants
 * - default: Primary action button with brand colors
 * - destructive: Danger/critical action button (red)
 * - outline: Border-only button for secondary actions
 * - secondary: Subtle background for less prominent actions
 * - ghost: No background, text-only button
 * - link: Underlined text link appearance
 * 
 * @sizes
 * - default: Standard 9px height button
 * - sm: Compact 8px height for dense interfaces
 * - lg: Large 10px height for primary actions
 * - icon: Square 9px for icon-only buttons
 * - icon-sm: Square 8px for small icon buttons
 * - icon-lg: Square 10px for large icon buttons
 * 
 * @accessibility
 * - Full keyboard navigation support
 * - Focus-visible ring for keyboard users
 * - ARIA-invalid states for form validation
 * - Screen reader friendly with proper labeling
 */
import * as React from 'react'
import { Slot } from '@radix-ui/react-slot'
import { cva, type VariantProps } from 'class-variance-authority'

import { cn } from '@/lib/utils'

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-all duration-200 disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg:not([class*='size-'])]:size-4 shrink-0 [&_svg]:shrink-0 outline-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive border border-transparent active:scale-[0.98] hover:shadow-sm",
  {
    variants: {
      variant: {
        default: 'bg-primary text-primary-foreground hover:bg-primary/90 hover:shadow-md',
        destructive:
          'bg-destructive text-white hover:bg-destructive/90 focus-visible:ring-destructive/20 dark:focus-visible:ring-destructive/40 dark:bg-destructive/60 hover:shadow-md',
        outline:
          'border bg-background shadow-xs hover:bg-accent hover:text-accent-foreground dark:bg-input/30 dark:border-input dark:hover:bg-input/50 hover:border-primary/50',
        secondary: 'bg-secondary text-secondary-foreground hover:bg-secondary/80 hover:shadow-md',
        ghost: 'hover:bg-accent hover:text-accent-foreground dark:hover:bg-accent/50',
        link: 'text-primary underline-offset-4 hover:underline',
      },
      size: {
        default: 'h-9 px-4 py-2 has-[>svg]:px-3',
        sm: 'h-8 rounded-md gap-1.5 px-3 has-[>svg]:px-2.5',
        lg: 'h-10 rounded-md px-6 has-[>svg]:px-4',
        icon: 'size-9',
        'icon-sm': 'size-8',
        'icon-lg': 'size-10',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  }
)

const Button = React.forwardRef<
  HTMLButtonElement,
  React.ComponentProps<'button'> &
    VariantProps<typeof buttonVariants> & {
      asChild?: boolean
    }
>(({ className, variant, size, asChild = false, ...props }, ref) => {
  const Comp = asChild ? Slot : 'button'

  return (
    <Comp
      ref={ref}
      data-slot="button"
      className={cn(buttonVariants({ variant, size, className }))}
      {...props}
    />
  )
})

Button.displayName = 'Button'

export { Button, buttonVariants }
