import React, { createContext, useCallback, useContext, useEffect, useState } from 'react'

import {
  deriveKey,
  encryptTextWithKey,
  decryptTextWithKey,
  ensureEncryptionReady,
  getStoredKey,
  setStoredKey,
  getStoredSalt,
  ENCRYPTION_VERSION,
} from '@/lib/encryption-utils'

interface EncryptionContextType {
  isUnlocked: boolean
  encryptionVersion: number
  encryptText: (text: string) => Promise<string>
  decryptText: (payload: string) => Promise<string>
  setEncryptionKey: (password: string) => Promise<void>
  clearEncryptionKey: () => void
}

const EncryptionContext = createContext<EncryptionContextType | undefined>(undefined)

export function EncryptionProvider({ children }: { children: React.ReactNode }) {
  const [isUnlocked, setIsUnlocked] = useState(false)
  const [keyBase64, setKeyBase64] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false

    const initialize = async () => {
      try {
        await ensureEncryptionReady()
        if (cancelled) return

        const storedKey = getStoredKey()
        if (storedKey) {
          setKeyBase64(storedKey)
          setIsUnlocked(true)
        }
      } catch (error) {
        console.error('Failed to initialize encryption:', error)
      }
    }

    initialize()

    const handleKeyUpdated = () => {
      if (cancelled) return
      const storedKey = getStoredKey()
      setKeyBase64(storedKey)
      setIsUnlocked(Boolean(storedKey))
    }

    if (typeof window !== 'undefined') {
      window.addEventListener('encryption-key-updated', handleKeyUpdated)
    }

    return () => {
      cancelled = true
      if (typeof window !== 'undefined') {
        window.removeEventListener('encryption-key-updated', handleKeyUpdated)
      }
    }
  }, [])

  const encryptText = useCallback(
    async (text: string): Promise<string> => {
      if (!keyBase64) {
        throw new Error('Encryption key not set')
      }
      return encryptTextWithKey(text, keyBase64)
    },
    [keyBase64]
  )

  const decryptText = useCallback(
    async (payload: string): Promise<string> => {
      if (!keyBase64) {
        throw new Error('Encryption key not set')
      }
      return decryptTextWithKey(payload, keyBase64)
    },
    [keyBase64]
  )

  const handleSetEncryptionKey = useCallback(async (password: string) => {
    if (!password || !password.trim()) {
      throw new Error('Encryption password is required')
    }

    const salt = getStoredSalt()
    if (!salt) {
      throw new Error('Encryption salt not found. Please log in again.')
    }

    const derivedKey = await deriveKey(password, salt)
    setStoredKey(derivedKey)
    setKeyBase64(derivedKey)
    setIsUnlocked(true)
  }, [])

  const clearEncryptionKey = useCallback(() => {
    setStoredKey(null)
    setKeyBase64(null)
    setIsUnlocked(false)
  }, [])

  return (
    <EncryptionContext.Provider
      value={{
        isUnlocked,
        encryptionVersion: ENCRYPTION_VERSION,
        encryptText,
        decryptText,
        setEncryptionKey: handleSetEncryptionKey,
        clearEncryptionKey,
      }}
    >
      {children}
    </EncryptionContext.Provider>
  )
}

export function useEncryption() {
  const context = useContext(EncryptionContext)
  if (context === undefined) {
    throw new Error('useEncryption must be used within an EncryptionProvider')
  }
  return context
}
