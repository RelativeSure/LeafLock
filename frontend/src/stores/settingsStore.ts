import { create } from 'zustand'
import { organizationService, type UserSettings } from '@/services/api'

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
  defaultNoteBehavior: 'last-seen',
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
      const userSettings = await organizationService.getSettings()
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
      const updatedSettings = await organizationService.updateSettings(newSettings)
      set({ settings: updatedSettings })
    } catch (error) {
      console.error('Failed to update settings:', error)
      throw error
    }
  },
}))
