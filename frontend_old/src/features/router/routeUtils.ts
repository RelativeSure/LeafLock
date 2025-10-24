import { type ViewType } from '@/config/constants'

// Helper function to normalize paths
export const normalizePath = (path: string): string => {
  if (!path) return '/'
  if (path === '/') return '/'
  return path.endsWith('/') ? path.slice(0, -1) : path
}

// Helper function to get current view from pathname
export const getCurrentView = (pathname: string): ViewType => {
  const normalizedPath = normalizePath(pathname)
  switch (normalizedPath) {
    case '/':
    case '/auth':
    case '/auth/login':
      return 'login'
    case '/auth/unlock':
      return 'unlock'
    case '/auth/forgot':
      return 'forgot'
    case '/auth/reset':
      return 'reset'
    case '/app':
    case '/app/notes':
      return 'notes'
    case '/app/editor':
      return 'editor'
    case '/app/settings':
      return 'settings'
    case '/app/tags':
      return 'tags'
    case '/app/folders':
      return 'folders'
    case '/app/templates':
      return 'templates'
    case '/app/admin':
      return 'admin'
    default:
      return 'login'
  }
}

// Valid application paths for routing validation
export const VALID_PATHS = [
  '/',
  '/auth',
  '/auth/login',
  '/auth/unlock',
  '/auth/forgot',
  '/auth/reset',
  '/app',
  '/app/notes',
  '/app/editor',
  '/app/settings',
  '/app/tags',
  '/app/folders',
  '/app/templates',
  '/app/admin',
] as const

// Check if a path is valid
export const isValidPath = (path: string): boolean => {
  return VALID_PATHS.includes(path as (typeof VALID_PATHS)[number])
}
