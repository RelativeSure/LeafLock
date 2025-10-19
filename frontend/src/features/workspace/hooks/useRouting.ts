import { useEffect, useMemo } from 'react'
import { useRouterState } from '@tanstack/react-router'
import { APP_VIEWS, POST_LOGIN_REDIRECT_VIEWS, ROUTES } from '@/config/constants'
import { normalizePath, getCurrentView, isValidPath } from '@/features/router/routeUtils'

interface UseRoutingProps {
  isAuthenticated: boolean
  encryptionStatus: 'locked' | 'unlocked'
  navigateToPath: (path: string) => void
}

export const useRouting = ({
  isAuthenticated,
  encryptionStatus,
  navigateToPath,
}: UseRoutingProps) => {
  const location = useRouterState({ select: (state) => state.location })

  const normalizedPath = useMemo(() => normalizePath(location.pathname), [location.pathname])

  const currentView = useMemo(() => getCurrentView(location.pathname), [location.pathname])

  // Get fallback path based on authentication and encryption status
  const fallbackPath = useMemo(() => {
    if (!isAuthenticated) return ROUTES.login
    return encryptionStatus === 'unlocked' ? ROUTES.notes : ROUTES.unlock
  }, [isAuthenticated, encryptionStatus])

  // Handle route validation and redirects
  useEffect(() => {
    const currentPath = location.pathname
    const normalizedCurrentPath = normalizePath(currentPath)

    // Handle unknown paths
    if (!isValidPath(currentPath)) {
      navigateToPath(fallbackPath)
      return
    }

    // Authentication and encryption status redirects
    if (!isAuthenticated) {
      if (APP_VIEWS.has(currentView) || currentView === 'unlock') {
        navigateToPath(ROUTES.login)
        return
      }
    } else {
      if (encryptionStatus === 'locked' && APP_VIEWS.has(currentView)) {
        navigateToPath(ROUTES.unlock)
        return
      }

      if (encryptionStatus === 'unlocked') {
        if (currentView === 'unlock' || POST_LOGIN_REDIRECT_VIEWS.has(currentView)) {
          navigateToPath(ROUTES.notes)
          return
        }
      }
    }

    // Handle root paths
    if (normalizedCurrentPath === '/' || normalizedCurrentPath === '/auth') {
      navigateToPath(fallbackPath)
    } else if (normalizedCurrentPath === '/app') {
      navigateToPath(ROUTES.notes)
    }
  }, [
    location.pathname,
    fallbackPath,
    navigateToPath,
    isAuthenticated,
    encryptionStatus,
    currentView,
  ])

  // Security check: Force logout if locked while authenticated outside unlock view
  useEffect(() => {
    if (encryptionStatus === 'locked' && isAuthenticated && currentView !== 'unlock') {
      console.log(
        '🚨 Security check: Locked while authenticated outside unlock view - forcing logout'
      )
      navigateToPath(ROUTES.login)
    }
  }, [encryptionStatus, isAuthenticated, currentView, navigateToPath])

  return {
    normalizedPath,
    currentView,
    fallbackPath,
  }
}
