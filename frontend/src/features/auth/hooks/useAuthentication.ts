import { useState, useCallback, useRef } from 'react'
import { useNavigate } from '@tanstack/react-router'
import { secureApi as api } from '@/services/api/secureApi'
import { cryptoService } from '@/services/crypto/cryptoService'
import { getStoredAuthToken } from '@/utils/auth'
import { FALLBACK_PATHS, ROUTES } from '@/config/constants'

interface UseAuthenticationProps {
  onNotesLoad?: () => Promise<void>
  onNotesError?: (error: string | null) => void
  onSelectedNoteChange?: (note: any) => void
}

export const useAuthentication = ({
  onNotesLoad,
  onNotesError,
  onSelectedNoteChange,
}: UseAuthenticationProps = {}) => {
  const navigate = useNavigate({ from: '/' })
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [encryptionStatus, setEncryptionStatus] = useState<'locked' | 'unlocked'>('locked')
  const [isAdmin, setIsAdmin] = useState(false)
  const [initializing, setInitializing] = useState(true)
  const [resetToken, setResetToken] = useState<string | null>(null)

  // Track if initialization has completed to prevent re-running on navigation
  const hasInitialized = useRef(false)

  // Direct navigation helper
  const navigateToPath = useCallback(
    (path: string) => {
      void navigate({ to: path as any })
    },
    [navigate]
  )

  // Get fallback path based on current auth state
  const getFallbackPath = useCallback(() => {
    if (!isAuthenticated) return FALLBACK_PATHS.unauthenticated
    return encryptionStatus === 'unlocked'
      ? FALLBACK_PATHS.authenticated_unlocked
      : FALLBACK_PATHS.authenticated_locked
  }, [isAuthenticated, encryptionStatus])

  const handleLogout = useCallback(() => {
    console.log('🚪 Performing complete logout...')

    api.clearToken()
    cryptoService.masterKey = null
    localStorage.removeItem('user_salt')

    setIsAuthenticated(false)
    navigateToPath(ROUTES.login)
    setEncryptionStatus('locked')
    setIsAdmin(false)

    // Reset parent state if callbacks provided
    onSelectedNoteChange?.(null)
    onNotesError?.(null)

    console.log('✅ Complete logout finished')
  }, [navigateToPath, onSelectedNoteChange, onNotesError])

  const handleUnlockWithPassword = useCallback(
    async (password: string) => {
      const trimmed = password.trim()
      if (!trimmed) {
        throw new Error('Password is required')
      }

      const storedSalt = localStorage.getItem('user_salt')
      if (!storedSalt) {
        console.log('🚨 No stored salt found - redirecting to login')
        handleLogout()
        throw new Error('Session expired. Please log in again.')
      }

      try {
        await cryptoService.initSodium()
        const salt = new Uint8Array(Array.from(atob(storedSalt), (c) => c.charCodeAt(0)))
        const key = await cryptoService.deriveKeyFromPassword(trimmed, salt)
        await cryptoService.setMasterKey(key)

        navigateToPath(ROUTES.notes)
        setEncryptionStatus('unlocked')
        await onNotesLoad?.()
      } catch (error) {
        console.error('💥 Failed to unlock with provided password:', error)
        throw error instanceof Error ? error : new Error('Failed to unlock notes')
      }
    },
    [onNotesLoad, handleLogout, navigateToPath]
  )

  const handleAuthenticated = useCallback(async () => {
    setIsAuthenticated(true)
    navigateToPath(ROUTES.notes)
    setEncryptionStatus('unlocked')

    try {
      const adminOk = await api.adminHealth()
      setIsAdmin(!!adminOk)
    } catch {
      setIsAdmin(false)
    }

    try {
      await onNotesLoad?.()
    } catch (e) {
      console.error('Failed to load notes after auth:', e)
    }
  }, [navigateToPath, onNotesLoad])

  const initializeApp = useCallback(async () => {
    if (hasInitialized.current) {
      return
    }

    try {
      // TEMPORARY: Force unlock state for testing button layout
      console.log('🧪 TESTING: Forcing unlock state for button layout testing')
      setIsAuthenticated(true)
      void navigate({ to: ROUTES.unlock as any })
      setEncryptionStatus('locked')
      setInitializing(false)
      hasInitialized.current = true
      return

      console.log('🚀 Starting app initialization...')
      const token = getStoredAuthToken()

      if (token && !localStorage.getItem('current_user_id')) {
        try {
          const payload = JSON.parse(atob(token.split('.')[1] || ''))
          if (payload && typeof payload.user_id === 'string') {
            localStorage.setItem('current_user_id', payload.user_id)
          }
        } catch {
          // ignore payload parsing failures; setup continues without cached id
        }
      }

      if (token) {
        console.log('🔐 Found stored token, validating...')
        let isValid = false
        try {
          console.log('🔍 Validating token with 3-second timeout...')
          const timeoutPromise = new Promise<boolean>((_, reject) =>
            setTimeout(() => reject(new Error('Validation timeout')), 3000)
          )
          isValid = await Promise.race([api.validateToken(), timeoutPromise])
        } catch (err) {
          console.warn('⚠️ Token validation failed:', err)
          isValid = false
        }

        if (isValid) {
          console.log('✅ Token valid, checking encryption key...')
          try {
            const adminOk = await api.adminHealth()
            setIsAdmin(!!adminOk)
          } catch {
            setIsAdmin(false)
          }

          if (!cryptoService.masterKey) {
            console.log('🔐 No master key - user needs to re-enter password')
            setIsAuthenticated(true)
            void navigate({ to: ROUTES.unlock as any })
            setEncryptionStatus('locked')
          } else {
            console.log('🔑 Master key found, initializing app...')
            setIsAuthenticated(true)
            void navigate({ to: ROUTES.notes as any })
            setEncryptionStatus('unlocked')
            try {
              await onNotesLoad?.()
            } catch (e) {
              console.error('Failed to load notes during init:', e)
            }
          }
        } else {
          console.log('❌ Token invalid, clearing and redirecting to login')
          api.clearToken()
          localStorage.removeItem('user_salt')
          cryptoService.masterKey = null
          setIsAuthenticated(false)
          void navigate({ to: ROUTES.login as any })
          setEncryptionStatus('locked')
        }
      } else {
        console.log('ℹ️ No stored token found - showing login')
        setIsAuthenticated(false)
        void navigate({ to: ROUTES.login as any })
        setEncryptionStatus('locked')
      }
    } catch (err) {
      console.error('💥 Failed to initialize app:', err)
      setIsAuthenticated(false)
      void navigate({ to: ROUTES.login as any })
      setEncryptionStatus('locked')
    } finally {
      console.log('🏁 App initialization complete, setting initializing = false')
      setInitializing(false)
      hasInitialized.current = true
    }
  }, [navigate, onNotesLoad])

  return {
    // State
    isAuthenticated,
    encryptionStatus,
    isAdmin,
    initializing,
    resetToken,

    // Actions
    handleLogout,
    handleUnlockWithPassword,
    handleAuthenticated,
    initializeApp,
    setResetToken,
    navigateToPath,
    getFallbackPath,
  }
}
