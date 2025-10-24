"use client"

import { createContext, useContext, useState, useEffect, type ReactNode } from "react"
import type { UserSettings } from "./types"

interface SettingsContextType {
  settings: UserSettings
  updateSettings: (settings: Partial<UserSettings>) => void
}

const defaultSettings: UserSettings = {
  theme: "system",
  autoSave: true,
  autoSaveInterval: 30,
  defaultView: "list",
  notificationsEnabled: true,
  emailNotifications: false,
  encryptionEnabled: true,
  language: "en",
}

const SettingsContext = createContext<SettingsContextType | undefined>(undefined)

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [settings, setSettings] = useState<UserSettings>(defaultSettings)

  useEffect(() => {
    const stored = localStorage.getItem("user_settings")
    if (stored) {
      setSettings(JSON.parse(stored))
    }
  }, [])

  const updateSettings = (newSettings: Partial<UserSettings>) => {
    const updated = { ...settings, ...newSettings }
    setSettings(updated)
    localStorage.setItem("user_settings", JSON.stringify(updated))
  }

  return <SettingsContext.Provider value={{ settings, updateSettings }}>{children}</SettingsContext.Provider>
}

export function useSettings() {
  const context = useContext(SettingsContext)
  if (context === undefined) {
    throw new Error("useSettings must be used within a SettingsProvider")
  }
  return context
}
