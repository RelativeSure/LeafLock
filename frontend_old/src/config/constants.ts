export type ViewType =
  | 'login'
  | 'unlock'
  | 'forgot'
  | 'reset'
  | 'notes'
  | 'editor'
  | 'settings'
  | 'tags'
  | 'folders'
  | 'templates'
  | 'admin'

export const APP_VIEWS = new Set<ViewType>([
  'notes',
  'editor',
  'settings',
  'tags',
  'folders',
  'templates',
  'admin',
])

export const POST_LOGIN_REDIRECT_VIEWS = new Set<ViewType>(['login', 'forgot'])

// Fallback paths based on authentication and encryption status
export const FALLBACK_PATHS = {
  unauthenticated: '/auth/login',
  authenticated_locked: '/auth/unlock',
  authenticated_unlocked: '/app/notes',
} as const

// Route paths for navigation
export const ROUTES = {
  login: '/auth/login',
  unlock: '/auth/unlock',
  forgot: '/auth/forgot',
  reset: '/auth/reset',
  notes: '/app/notes',
  editor: '/app/editor',
  settings: '/app/settings',
  tags: '/app/tags',
  folders: '/app/folders',
  templates: '/app/templates',
  admin: '/app/admin',
} as const
