import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { useSettingsStore } from '../settingsStore'
import { apiClient } from '@/services/api/secureApi'
import type { UserSettings } from '../../types'

// Mock dependencies
vi.mock('@/services/api/secureApi', () => ({
  apiClient: {
    getSettings: vi.fn(),
    updateSettings: vi.fn(),
  },
}))

describe('settingsStore', () => {
  const mockUser = {
    id: '123',
    email: 'test@example.com',
    name: 'Test User',
    role: 'user' as const,
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

  const customSettings: UserSettings = {
    theme: 'dark',
    autoSave: false,
    autoSaveInterval: 60,
    defaultView: 'grid',
    notificationsEnabled: false,
    emailNotifications: true,
    encryptionEnabled: true,
    language: 'es',
    defaultNoteBehavior: 'new-note',
    profilePicture: {
      type: 'initials',
    },
  }

  beforeEach(() => {
    // Clear store state
    useSettingsStore.setState({
      settings: defaultSettings,
      isLoading: false,
    })

    // Clear localStorage
    localStorage.clear()

    // Reset all mocks
    vi.clearAllMocks()

    // Mock console methods to reduce noise
    vi.spyOn(console, 'log').mockImplementation(vi.fn())
    vi.spyOn(console, 'error').mockImplementation(vi.fn())
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('Initial state', () => {
    it('should have correct initial state with default settings', () => {
      const state = useSettingsStore.getState()
      expect(state.settings).toEqual(defaultSettings)
      expect(state.isLoading).toBe(false)
    })

    it('should have all required methods', () => {
      const state = useSettingsStore.getState()
      expect(typeof state.loadSettings).toBe('function')
      expect(typeof state.updateSettings).toBe('function')
    })

    it('should have correct default settings structure', () => {
      const state = useSettingsStore.getState()
      expect(state.settings.theme).toBe('system')
      expect(state.settings.autoSave).toBe(true)
      expect(state.settings.autoSaveInterval).toBe(30)
      expect(state.settings.defaultView).toBe('list')
      expect(state.settings.encryptionEnabled).toBe(true)
      expect(state.settings.language).toBe('en')
    })
  })

  describe('loadSettings', () => {
    it('should load settings successfully', async () => {
      localStorage.setItem('user', JSON.stringify(mockUser))
      vi.mocked(apiClient.getSettings).mockResolvedValue(customSettings)

      await useSettingsStore.getState().loadSettings()

      const state = useSettingsStore.getState()
      expect(state.settings).toEqual(customSettings)
      expect(state.isLoading).toBe(false)
      expect(apiClient.getSettings).toHaveBeenCalled()
    })

    it('should not load settings if no user is logged in', async () => {
      await useSettingsStore.getState().loadSettings()

      expect(apiClient.getSettings).not.toHaveBeenCalled()
      expect(useSettingsStore.getState().settings).toEqual(defaultSettings)
    })

    it('should set isLoading state correctly', async () => {
      localStorage.setItem('user', JSON.stringify(mockUser))

      let loadingDuringCall = false

      vi.mocked(apiClient.getSettings).mockImplementation(async () => {
        loadingDuringCall = useSettingsStore.getState().isLoading
        return customSettings
      })

      await useSettingsStore.getState().loadSettings()

      expect(loadingDuringCall).toBe(true)
      expect(useSettingsStore.getState().isLoading).toBe(false)
    })

    it('should handle API errors gracefully and use default settings', async () => {
      localStorage.setItem('user', JSON.stringify(mockUser))
      vi.mocked(apiClient.getSettings).mockRejectedValue(new Error('API error'))

      await useSettingsStore.getState().loadSettings()

      const state = useSettingsStore.getState()
      expect(state.settings).toEqual(defaultSettings)
      expect(state.isLoading).toBe(false)
      expect(console.error).toHaveBeenCalledWith('Failed to load settings:', expect.any(Error))
    })

    it('should ensure isLoading is false after error', async () => {
      localStorage.setItem('user', JSON.stringify(mockUser))
      vi.mocked(apiClient.getSettings).mockRejectedValue(new Error('API error'))

      await useSettingsStore.getState().loadSettings()

      expect(useSettingsStore.getState().isLoading).toBe(false)
    })
  })

  describe('updateSettings', () => {
    beforeEach(() => {
      localStorage.setItem('user', JSON.stringify(mockUser))
    })

    it('should update settings successfully', async () => {
      const updates: Partial<UserSettings> = {
        theme: 'dark',
        autoSave: false,
      }

      const updatedSettings = { ...defaultSettings, ...updates }
      vi.mocked(apiClient.updateSettings).mockResolvedValue(updatedSettings)

      await useSettingsStore.getState().updateSettings(updates)

      const state = useSettingsStore.getState()
      expect(state.settings.theme).toBe('dark')
      expect(state.settings.autoSave).toBe(false)
      expect(apiClient.updateSettings).toHaveBeenCalledWith(updates)
    })

    it('should update theme setting', async () => {
      const updates: Partial<UserSettings> = { theme: 'light' }
      const updatedSettings = { ...defaultSettings, theme: 'light' }

      vi.mocked(apiClient.updateSettings).mockResolvedValue(updatedSettings)

      await useSettingsStore.getState().updateSettings(updates)

      expect(useSettingsStore.getState().settings.theme).toBe('light')
    })

    it('should update autoSave and autoSaveInterval', async () => {
      const updates: Partial<UserSettings> = {
        autoSave: true,
        autoSaveInterval: 60,
      }

      const updatedSettings = { ...defaultSettings, ...updates }
      vi.mocked(apiClient.updateSettings).mockResolvedValue(updatedSettings)

      await useSettingsStore.getState().updateSettings(updates)

      const state = useSettingsStore.getState()
      expect(state.settings.autoSave).toBe(true)
      expect(state.settings.autoSaveInterval).toBe(60)
    })

    it('should update notification settings', async () => {
      const updates: Partial<UserSettings> = {
        notificationsEnabled: false,
        emailNotifications: true,
      }

      const updatedSettings = { ...defaultSettings, ...updates }
      vi.mocked(apiClient.updateSettings).mockResolvedValue(updatedSettings)

      await useSettingsStore.getState().updateSettings(updates)

      const state = useSettingsStore.getState()
      expect(state.settings.notificationsEnabled).toBe(false)
      expect(state.settings.emailNotifications).toBe(true)
    })

    it('should update language setting', async () => {
      const updates: Partial<UserSettings> = { language: 'fr' }
      const updatedSettings = { ...defaultSettings, language: 'fr' }

      vi.mocked(apiClient.updateSettings).mockResolvedValue(updatedSettings)

      await useSettingsStore.getState().updateSettings(updates)

      expect(useSettingsStore.getState().settings.language).toBe('fr')
    })

    it('should update defaultView setting', async () => {
      const updates: Partial<UserSettings> = { defaultView: 'grid' }
      const updatedSettings = { ...defaultSettings, defaultView: 'grid' }

      vi.mocked(apiClient.updateSettings).mockResolvedValue(updatedSettings)

      await useSettingsStore.getState().updateSettings(updates)

      expect(useSettingsStore.getState().settings.defaultView).toBe('grid')
    })

    it('should update defaultNoteBehavior setting', async () => {
      const updates: Partial<UserSettings> = { defaultNoteBehavior: 'new-note' }
      const updatedSettings = { ...defaultSettings, defaultNoteBehavior: 'new-note' }

      vi.mocked(apiClient.updateSettings).mockResolvedValue(updatedSettings)

      await useSettingsStore.getState().updateSettings(updates)

      expect(useSettingsStore.getState().settings.defaultNoteBehavior).toBe('new-note')
    })

    it('should update profilePicture setting', async () => {
      const updates: Partial<UserSettings> = {
        profilePicture: { type: 'initials' },
      }

      const updatedSettings = { ...defaultSettings, ...updates }
      vi.mocked(apiClient.updateSettings).mockResolvedValue(updatedSettings)

      await useSettingsStore.getState().updateSettings(updates)

      expect(useSettingsStore.getState().settings.profilePicture.type).toBe('initials')
    })

    it('should update multiple settings at once', async () => {
      const updates: Partial<UserSettings> = {
        theme: 'dark',
        language: 'es',
        autoSave: false,
        defaultView: 'grid',
      }

      const updatedSettings = { ...defaultSettings, ...updates }
      vi.mocked(apiClient.updateSettings).mockResolvedValue(updatedSettings)

      await useSettingsStore.getState().updateSettings(updates)

      const state = useSettingsStore.getState()
      expect(state.settings.theme).toBe('dark')
      expect(state.settings.language).toBe('es')
      expect(state.settings.autoSave).toBe(false)
      expect(state.settings.defaultView).toBe('grid')
    })

    it('should not update settings if no user is logged in', async () => {
      localStorage.removeItem('user')

      await useSettingsStore.getState().updateSettings({ theme: 'dark' })

      expect(apiClient.updateSettings).not.toHaveBeenCalled()
      expect(useSettingsStore.getState().settings.theme).toBe('system')
    })

    it('should throw error on API failure', async () => {
      vi.mocked(apiClient.updateSettings).mockRejectedValue(new Error('Update failed'))

      await expect(useSettingsStore.getState().updateSettings({ theme: 'dark' })).rejects.toThrow(
        'Update failed'
      )

      expect(console.error).toHaveBeenCalledWith('Failed to update settings:', expect.any(Error))
    })

    it('should not update state if API call fails', async () => {
      const originalSettings = useSettingsStore.getState().settings

      vi.mocked(apiClient.updateSettings).mockRejectedValue(new Error('Update failed'))

      try {
        await useSettingsStore.getState().updateSettings({ theme: 'dark' })
      } catch {
        // Expected to throw
      }

      expect(useSettingsStore.getState().settings).toEqual(originalSettings)
    })

    it('should handle empty updates', async () => {
      vi.mocked(apiClient.updateSettings).mockResolvedValue(defaultSettings)

      await useSettingsStore.getState().updateSettings({})

      expect(apiClient.updateSettings).toHaveBeenCalledWith({})
      expect(useSettingsStore.getState().settings).toEqual(defaultSettings)
    })
  })

  describe('Settings persistence', () => {
    it('should maintain encryptionEnabled as true', async () => {
      localStorage.setItem('user', JSON.stringify(mockUser))

      const settingsWithEncryption = { ...customSettings, encryptionEnabled: true }
      vi.mocked(apiClient.getSettings).mockResolvedValue(settingsWithEncryption)

      await useSettingsStore.getState().loadSettings()

      expect(useSettingsStore.getState().settings.encryptionEnabled).toBe(true)
    })

    it('should handle all theme options', async () => {
      localStorage.setItem('user', JSON.stringify(mockUser))

      const themes: Array<'light' | 'dark' | 'system'> = ['light', 'dark', 'system']

      for (const theme of themes) {
        const settingsWithTheme = { ...defaultSettings, theme }
        vi.mocked(apiClient.updateSettings).mockResolvedValue(settingsWithTheme)

        await useSettingsStore.getState().updateSettings({ theme })

        expect(useSettingsStore.getState().settings.theme).toBe(theme)
      }
    })

    it('should handle all defaultView options', async () => {
      localStorage.setItem('user', JSON.stringify(mockUser))

      const views: Array<'list' | 'grid'> = ['list', 'grid']

      for (const view of views) {
        const settingsWithView = { ...defaultSettings, defaultView: view }
        vi.mocked(apiClient.updateSettings).mockResolvedValue(settingsWithView)

        await useSettingsStore.getState().updateSettings({ defaultView: view })

        expect(useSettingsStore.getState().settings.defaultView).toBe(view)
      }
    })

    it('should handle all defaultNoteBehavior options', async () => {
      localStorage.setItem('user', JSON.stringify(mockUser))

      const behaviors: Array<'last-seen' | 'new-note'> = ['last-seen', 'new-note']

      for (const behavior of behaviors) {
        const settingsWithBehavior = { ...defaultSettings, defaultNoteBehavior: behavior }
        vi.mocked(apiClient.updateSettings).mockResolvedValue(settingsWithBehavior)

        await useSettingsStore.getState().updateSettings({ defaultNoteBehavior: behavior })

        expect(useSettingsStore.getState().settings.defaultNoteBehavior).toBe(behavior)
      }
    })
  })
})
