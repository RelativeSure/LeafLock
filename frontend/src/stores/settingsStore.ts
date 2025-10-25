import { create } from 'zustand'
import type { UserSettings } from '../types'
import { apiClient } from '../services/api/secureApi'

interface SettingsState {
  settings: UserSettings
  isLoading: boolean
  updateSettings: (settings: Partial<UserSettings>) => Promise<void>
  loadSettings: () => Promise<void>
}

const defaultSettings: UserSettings = {
  theme: 'system',
  autoSave: true,
  autoSaveInterval: 30,
  defaultView: 'list',
  notificationsEnabled: true,
  emailNotifications: false,
  encryptionEnabled: true,
  language: 'en',
  profilePicture: {
    type: 'gravatar',
  },
}

export const useSettingsStore = create<SettingsState>((set) => ({
  settings: defaultSettings,
  isLoading: false,

  loadSettings: async () => {
    const storedUser = localStorage.getItem('user')
    if (!storedUser) return

    set({ isLoading: true })
    try {
      const userSettings = await apiClient.getSettings()
      set({ settings: userSettings })
    } catch (error) {
      console.error('Failed to load settings:', error)
      // Use default settings if loading fails
      set({ settings: defaultSettings })
    } finally {
      set({ isLoading: false })
    }
  },

  updateSettings: async (newSettings: Partial<UserSettings>) => {
    const storedUser = localStorage.getItem('user')
    if (!storedUser) return

    try {
      const updatedSettings = await apiClient.updateSettings(newSettings)
      set({ settings: updatedSettings })
    } catch (error) {
      console.error('Failed to update settings:', error)
      throw error
    }
  },
}))
