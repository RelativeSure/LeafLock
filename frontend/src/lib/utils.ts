/**
 * Utility Functions Library
 *
 * @description
 * Common utility functions used throughout the application for styling and data manipulation.
 * Provides type-safe helpers for Tailwind CSS class name management.
 *
 * @functions
 * - cn(): Conditional className utility for Tailwind CSS
 *
 * @usage
 * import { cn } from '@/lib/utils'
 *
 * // Merge conditional classes
 * <div className={cn('base-class', conditional && 'conditional-class', 'always-present')}>
 *
 * // Override conflicting Tailwind classes
 * <div className={cn('p-4', 'p-2')}> // Results in 'p-2' (last wins)
 */
import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

/**
 * Conditional className utility for Tailwind CSS
 *
 * @description
 * Merges and deduplicates Tailwind CSS classes using tailwind-merge.
 * Handles conditional classes and conflicting utility overrides intelligently.
 *
 * @param inputs - Array of ClassValue (string, boolean, object, etc.)
 * @returns Merged and deduplicated className string
 *
 * @examples
 * cn('p-4', 'bg-white') // 'p-4 bg-white'
 * cn('p-4', true && 'p-2') // 'p-2' (conflicts resolved)
 * cn('text-red-500', { 'text-blue-500': isActive }) // Conditional classes
 *
 * @dependencies
 * - clsx: Handles conditional class objects and arrays
 * - tailwind-merge: Resolves Tailwind CSS conflicts intelligently
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}
