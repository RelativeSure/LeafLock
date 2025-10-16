/**
 * Helper utilities for combining padding with cn() utility
 *
 * These functions make it easier to apply semantic padding
 * while maintaining compatibility with the cn() utility.
 */

import { cn } from '@/lib/utils'
import { padding } from './padding'

/**
 * Apply padding with additional classes
 *
 * @example
 * withPadding(padding.component.page, 'bg-white rounded-lg')
 */
export const withPadding = (paddingClass: string, ...classes: string[]) => {
  return cn(paddingClass, ...classes)
}

/**
 * Apply responsive padding with additional classes
 *
 * @example
 * responsivePadding('p-4', 'md:p-6', 'bg-white')
 */
export const responsivePadding = (base: string, responsive: string, ...classes: string[]) => {
  return cn(base, responsive, ...classes)
}

/**
 * Apply conditional padding based on a condition
 *
 * @example
 * conditionalPadding(isCompact, padding.sm, padding.lg, 'bg-white')
 */
export const conditionalPadding = (
  condition: boolean,
  truePadding: string,
  falsePadding: string,
  ...classes: string[]
) => {
  return cn(condition ? truePadding : falsePadding, ...classes)
}

/**
 * Combine multiple padding utilities (e.g., horizontal + vertical)
 *
 * @example
 * combinePadding(padding.directional.xLg, padding.directional.ySm)
 */
export const combinePadding = (...paddingClasses: string[]) => {
  return cn(...paddingClasses)
}

// Re-export padding for convenience
export { padding }
