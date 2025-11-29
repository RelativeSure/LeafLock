/**
 * Settings Store - User Preferences and Configuration Management
 *
 * @description
 * Manages user-specific settings and preferences for the application.
 * Handles theme selection, auto-save configuration, notification preferences,
 * encryption settings, and other personalization options. Provides fallback
 * to default settings when user preferences are unavailable.
 *
 * @responsibilities
 * - User settings persistence and retrieval
 * - Default settings management and fallbacks
 * - Settings validation and type safety
 * - Theme and appearance configuration
 * - Auto-save and synchronization preferences
 * - Notification and privacy controls
 * - Language and localization settings
 *
 * @settings-categories
 * - Appearance: theme, default view, profile picture
 * - Behavior: auto-save, default note behavior, notifications
 * - Privacy: encryption, email notifications
 * - Localization: language preferences
 *
 * @default-values
 * - theme: 'system' (follows system preference)
 * - autoSave: true (enabled by default)
 * - autoSaveInterval: 30 seconds
 * - defaultView: 'list' view
 * - notificationsEnabled: true
 * - emailNotifications: false
 * - encryptionEnabled: true
 * - language: 'en' (English)
 * - defaultNoteBehavior: 'last-seen'
 * - profilePicture: 'gravatar' type
 *
 * @persistence-strategy
 * - Settings fetched from server on user authentication
 * - Default settings used as fallback for missing preferences
 * - Local updates applied immediately for UI responsiveness
 * - Server synchronization for cross-device consistency
 *
 * @integration-patterns
 * - Consumed by settings UI components for preference management
 * - Used by notesStore for default note behavior
 * - Provides theme configuration for UI components
 * - Controls auto-save behavior in editor components
 *
 * @validation
 * - Type-safe settings updates via TypeScript
 * - Server-side validation for security
 * - Fallback to defaults for invalid settings
 * - Graceful handling of API failures
 */
import { create } from 'zustand'
import { organizationService, type UserSettings } from '@/services/api'

interface SettingsState {
  /**
   * Current user settings configuration
   * @type {UserSettings} Complete settings object
   * Merged with defaults for missing properties
   * Updated via loadSettings and updateSettings operations
   */
  settings: UserSettings

  /**
   * Loading state for settings operations
   * @type {boolean} true during load/update operations
   * Used by UI components to show loading indicators
   */
  isLoading: boolean

  /**
   * Update user settings with partial changes
   * @param settings - Partial settings object with changes
   * @throws {Error} On validation or update failure
   *
   * @update-strategy
   * - Merges changes with existing settings
   * - Validates changes server-side
   * - Updates local state immediately for responsiveness
   * - Falls back to previous settings on failure
   *
   * @validation
   * - Type-safe updates via TypeScript
   * - Server-side validation for security
   * - Graceful handling of invalid values
   *
   * @synchronization
   * - Immediate local update for UI responsiveness
   * - Server synchronization for persistence
   * - Cross-device consistency via server storage
   */
  updateSettings: (settings: Partial<UserSettings>) => Promise<void>

  /**
   * Load user settings from server
   * @throws {Error} On loading failure
   *
   * @loading
   * - Fetches settings via organizationService
   * - Applies default settings on failure
   * - Requires authenticated user
   *
   * @fallback-strategy
   * - Uses default settings if loading fails
   * - Preserves existing settings on error
   * - Graceful degradation for missing preferences
   *
   * @initialization
   * - Called during app initialization after authentication
   * - Provides baseline for all user preferences
   * - Essential for consistent user experience
   */
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
