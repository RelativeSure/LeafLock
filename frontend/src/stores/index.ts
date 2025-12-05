// Export stores in dependency order to prevent circular dependencies
// Clerk auth store should be loaded first as other stores may depend on it
export { useClerkAuthStore, useSyncClerkAuth, useAuth, useUser, useSession } from './clerkAuthStore'

// Notes store should be loaded second as it's used by most components
export { useNotesStore } from './notesStore'

// Settings and templates stores can be loaded after the core stores
export { useSettingsStore } from './settingsStore'
export { useTemplatesStore } from './templatesStore'
