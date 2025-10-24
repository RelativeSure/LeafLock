"use client"

import { createContext, useContext, useState, type ReactNode } from "react"
import { EncryptionService } from "./encryption"

interface EncryptionContextType {
  encryptionKey: string | null
  setEncryptionKey: (key: string) => void
  clearEncryptionKey: () => void
  encryptText: (text: string) => Promise<string>
  decryptText: (encryptedText: string) => Promise<string>
  isUnlocked: boolean
}

const EncryptionContext = createContext<EncryptionContextType | undefined>(undefined)

export function EncryptionProvider({ children }: { children: ReactNode }) {
  const [encryptionKey, setEncryptionKeyState] = useState<string | null>(null)

  const setEncryptionKey = (key: string) => {
    setEncryptionKeyState(key)
    // Store in session storage (not localStorage for security)
    sessionStorage.setItem("encryption_key", key)
  }

  const clearEncryptionKey = () => {
    setEncryptionKeyState(null)
    sessionStorage.removeItem("encryption_key")
  }

  const encryptText = async (text: string): Promise<string> => {
    if (!encryptionKey) {
      throw new Error("No encryption key set")
    }
    return EncryptionService.encrypt(text, encryptionKey)
  }

  const decryptText = async (encryptedText: string): Promise<string> => {
    if (!encryptionKey) {
      throw new Error("No encryption key set")
    }
    return EncryptionService.decrypt(encryptedText, encryptionKey)
  }

  return (
    <EncryptionContext.Provider
      value={{
        encryptionKey,
        setEncryptionKey,
        clearEncryptionKey,
        encryptText,
        decryptText,
        isUnlocked: !!encryptionKey,
      }}
    >
      {children}
    </EncryptionContext.Provider>
  )
}

export function useEncryption() {
  const context = useContext(EncryptionContext)
  if (context === undefined) {
    throw new Error("useEncryption must be used within an EncryptionProvider")
  }
  return context
}
