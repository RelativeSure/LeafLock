// Export all services
export { authService } from './authService'
export { contentService } from './contentService'
export { socialService } from './socialService'
export { organizationService } from './organizationService'

// Export types
export type {
  RegisterResponse,
  MFAStatusResponse,
  Note,
  Folder,
  Template,
  Tag,
  NoteVersion,
  UserSettings,
} from './types'

// Export utilities
export { normalizeNoteResponse, API_BASE_URL, DEFAULT_NOTE_FIELDS } from './types'
