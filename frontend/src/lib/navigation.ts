// Centralized navigation helpers to prevent redirect loops

const AUTH_PATHS = new Set(['/login', '/register', '/forgot'])

let lastRedirectAt = 0
const REDIRECT_DEBOUNCE_MS = 1500

export function isOnAuthRoute(pathname?: string): boolean {
  const path = pathname ?? (typeof window !== 'undefined' ? window.location.pathname : '')
  return AUTH_PATHS.has(path)
}

export function safeRedirectToLogin(options?: { force?: boolean }): void {
  if (typeof window === 'undefined') return

  const now = Date.now()
  if (!options?.force && now - lastRedirectAt < REDIRECT_DEBOUNCE_MS) {
    return
  }

  if (isOnAuthRoute()) {
    return
  }

  lastRedirectAt = now
  window.location.href = '/login'
}
