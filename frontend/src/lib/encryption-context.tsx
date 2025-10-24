import React, { createContext, useContext, useState, useCallback } from 'react'

interface EncryptionContextType {
  isUnlocked: boolean
  encryptText: (text: string) => Promise<string>
  decryptText: (text: string) => Promise<string>
  setEncryptionKey: (key: string) => void
}

const EncryptionContext = createContext<EncryptionContextType | undefined>(undefined)

export function EncryptionProvider({ children }: { children: React.ReactNode }) {
  const [isUnlocked, setIsUnlocked] = useState(false)
  const [encryptionKey, setEncryptionKey] = useState<string | null>(null)

  // Initialize encryption key from localStorage on mount
  React.useEffect(() => {
    const storedKey = localStorage.getItem('encryptionKey')
    if (storedKey) {
      setEncryptionKey(storedKey)
      setIsUnlocked(true)
    }
  }, [])

  const encryptText = useCallback(async (text: string): Promise<string> => {
    if (!encryptionKey) {
      throw new Error('Encryption key not set')
    }

    // Simple base64 encoding for now - in production, use proper encryption
    // This is a placeholder implementation
    const encoded = btoa(unescape(encodeURIComponent(text)))
    return encoded
  }, [encryptionKey])

  const decryptText = useCallback(async (text: string): Promise<string> => {
    if (!encryptionKey) {
      throw new Error('Encryption key not set')
    }

    try {
      // Simple base64 decoding for now - in production, use proper decryption
      const decoded = decodeURIComponent(escape(atob(text)))
      return decoded
    } catch (error) {
      console.error('Decryption error:', error)
      return text // Return original text if decryption fails
    }
  }, [encryptionKey])

  const handleSetEncryptionKey = useCallback((key: string) => {
    setEncryptionKey(key)
    setIsUnlocked(true)
    localStorage.setItem('encryptionKey', key)
  }, [])

  return (
    <EncryptionContext.Provider
      value={{
        isUnlocked,
        encryptText,
        decryptText,
        setEncryptionKey: handleSetEncryptionKey,
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
