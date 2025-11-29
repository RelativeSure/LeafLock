/**
 * Notes Store - Centralized Note and Content Management
 *
 * @description
 * Manages the complete lifecycle of notes, folders, tags, and related content.
 * Handles client-side encryption, version control, trash management, and
 * organizational features. This is the primary data store for the application's
 * core note-taking functionality.
 *
 * @responsibilities
 * - Note CRUD operations with encryption support
 * - Folder and hierarchical organization management
 * - Tag-based categorization and filtering
 * - Note version control and history tracking
 * - Trash/soft delete functionality
 * - Bulk operations for efficiency
 * - Note linking and relationship management
 * - Template integration for content creation
 *
 * @security-considerations
 * - All note content encrypted client-side before API transmission
 * - Encryption keys managed by authStore and stored securely
 * - Encrypted content tagged with version for future compatibility
 * - No plain text storage of sensitive note content
 *
 * @performance-optimizations
 * - Selective state updates to prevent unnecessary re-renders
 * - Shallow equality checks for meaningful change detection
 * - Bulk operations to reduce API calls
 * - Local state management with optimistic updates
 *
 * @data-relationships
 * - Notes belong to folders (many-to-one)
 * - Notes have multiple tags (many-to-many)
 * - Notes have versions for history tracking (one-to-many)
 * - Notes can link to other notes (many-to-many)
 * - Templates used for note creation (one-to-many)
 *
 * @integration-patterns
 * - Consumed by NoteEditor, NoteList, FolderTree components
 * - Integrates with authStore for user context and encryption
 * - Uses settingsStore for user preferences (default behaviors)
 * - Provides data to search and filtering components
 * - Works with templatesStore for template-based note creation
 *
 * @state-persistence
 * - No persistent storage - all data fetched from server
 * - Last seen note ID stored in localStorage for UX continuity
 * - Real-time synchronization via WebSocket (future enhancement)
 *
 * @error-handling
 * - API errors logged and re-thrown for component handling
 * - Graceful fallbacks for missing notes or folders
 * - Validation before encryption operations
 * - User-friendly error messages for UI display
 */
import { create } from 'zustand'
import {
  contentService,
  organizationService,
  socialService,
  type Note,
  type Folder,
  type Tag,
  type NoteVersion,
} from '@/services/api'
import { ENCRYPTION_VERSION, encryptTextWithStoredKey } from '@/lib/encryption-utils'

interface NotesState {
  /**
   * Complete collection of user's notes
   * @type {Note[]} Array of all notes including trashed ones
   * Updated via loadData, CRUD operations, and bulk actions
   * Filtered by components for specific views (active, trashed, by folder, etc.)
   */
  notes: Note[]

  /**
   * Hierarchical folder structure for note organization
   * @type {Folder[]} Supports nested folders with parent-child relationships
   * Used for tree navigation and note categorization
   * Updated independently from notes collection
   */
  folders: Folder[]

  /**
   * User-defined tags for note categorization
   * @type {Tag[]} Flat collection of available tags
   * Applied to notes via many-to-many relationship
   * Used for filtering and organization
   */
  tags: Tag[]

  /**
   * Currently selected/active note for editing/viewing
   * @type {Note | null} null when no note is selected
   * Controls editor content and detail views
   * Automatically updated by selectNote and note operations
   */
  selectedNote: Note | null

  /**
   * Currently selected folder for filtering
   * @type {string | null} Folder ID or null for all notes view
   * Used to filter note lists and create new notes
   * Updated by folder navigation and selection
   */
  selectedFolder: string | null

  /**
   * Global loading state for data operations
   * @type {boolean} true during API calls and data loading
   * Used by UI components to show loading indicators
   * Set during loadData and individual CRUD operations
   */
  isLoading: boolean

  /**
   * Create new note with encryption support
   * @param note - Partial note data (title, content, tags, etc.)
   * @returns Promise resolving to created note
   * @throws {Error} On authentication or encryption failures
   *
   * @encryption
   * - Title and content encrypted client-side before API call
   * - Uses stored encryption key from authStore
   * - Marks note as encrypted with current version
   *
   * @note-creation
   * - Automatically assigns to selected folder if none specified
   * - Adds to beginning of notes array for immediate visibility
   * - Selects newly created note for editing
   */
  createNote: (note: Partial<Note>) => Promise<Note>

  /**
   * Update existing note with change detection
   * @param id - Note ID to update
   * @param updates - Partial note data to modify
   * @returns Promise resolving to updated note
   * @throws {Error} If note not found or update fails
   *
   * @optimization
   * - Performs shallow equality check to avoid redundant updates
   * - Selective state updates based on changed properties
   * - Prevents editor decrypt loops on encrypted content saves
   *
   * @encryption
   * - Re-encrypts title/content if modified
   * - Preserves existing encryption if only metadata changes
   * - Updates encryption version if encryption state changes
   */
  updateNote: (id: string, updates: Partial<Note>) => Promise<Note>

  /**
   * Permanently delete note from system
   * @param id - Note ID to delete
   * @throws {Error} On deletion failure
   *
   * @warning
   * - This is a permanent operation (use moveToTrash for soft delete)
   * - Removes note from all collections and references
   * - Clears selection if deleted note was active
   */
  deleteNote: (id: string) => Promise<void>

  /**
   * Select note for editing/viewing with duplicate prevention
   * @param id - Note ID to select, or null to clear selection
   *
   * @behavior
   * - Prevents duplicate selection of same note
   * - Clears selection on null ID
   * - Stores last seen note ID in localStorage for UX continuity
   * - Skips storage for trashed notes
   */
  selectNote: (id: string | null) => void

  /**
   * Create new folder for note organization
   * @param folder - Partial folder data (name, parentId, etc.)
   * @returns Promise resolving to created folder
   * @throws {Error} On creation failure
   *
   * @hierarchy
   * - Supports nested folders via parentId
   * - Automatically assigns to current user
   * - Added to folders collection for immediate use
   */
  createFolder: (folder: Partial<Folder>) => Promise<Folder>

  /**
   * Update folder properties
   * @param id - Folder ID to update
   * @param updates - Partial folder data to modify
   * @throws {Error} On update failure
   *
   * @local-update
   * - Updates folder in local collection immediately
   * - Preserves other folder properties
   * - No effect on contained notes
   */
  updateFolder: (id: string, updates: Partial<Folder>) => Promise<void>

  /**
   * Delete folder and move contents to root
   * @param id - Folder ID to delete
   * @throws {Error} On deletion failure
   *
   * @cascade-behavior
   * - Moves all contained notes to root level (folderId: null)
   * - Clears selected folder if deleted folder was active
   * - Preserves all note content and metadata
   */
  deleteFolder: (id: string) => Promise<void>

  /**
   * Select folder for filtering and new note creation
   * @param id - Folder ID or null for all notes view
   *
   * @filtering
   * - Controls note list filtering in UI components
   * - Affects default folder for new note creation
   * - No effect on existing note locations
   */
  selectFolder: (id: string | null) => void

  /**
   * Fetch hierarchical folder tree from server
   * @returns Promise resolving to nested folder structure
   * @throws {Error} On fetch failure
   *
   * @hierarchy
   * - Returns folders with nested children structure
   * - Used for tree navigation components
   * - Replaces local folders collection
   */
  getFolderTree: () => Promise<Folder[]>

  /**
   * Move folder to different parent location
   * @param folderId - Folder ID to move
   * @param parentId - New parent folder ID (null for root)
   * @throws {Error} On move failure
   *
   * @hierarchy-update
   * - Refreshes entire folder tree after move
   * - Maintains folder contents and structure
   * - Used by drag-and-drop interfaces
   */
  moveFolderToParent: (folderId: string, parentId: string | null) => Promise<void>

  /**
   * Select tag for filtering (placeholder implementation)
   * @param tagName - Tag name or null to clear selection
   *
   * @todo
   * - Implement actual filtering logic
   * - Connect to UI filtering components
   * - Add to URL state for deep linking
   */
  selectTag: (tagName: string | null) => void

  /**
   * Create new tag for note categorization
   * @param tag - Partial tag data (name, color, etc.)
   * @returns Promise resolving to created tag
   * @throws {Error} On creation failure
   *
   * @categorization
   * - Tags are user-specific
   * - Can be applied to multiple notes
   * - Used for filtering and organization
   */
  createTag: (tag: Partial<Tag>) => Promise<Tag>

  /**
   * Delete tag and remove from all notes
   * @param id - Tag ID to delete
   * @throws {Error} On deletion failure
   *
   * @cascade-behavior
   * - Removes tag from all notes that contain it
   * - Deletes tag from available tags collection
   * - Preserves note content and other tags
   */
  deleteTag: (id: string) => Promise<void>

  /**
   * Filter notes by tag name
   * @param tagName - Tag to filter by
   * @returns Array of notes containing the specified tag
   *
   * @filtering
   * - Returns only active (non-trashed) notes
   * - Case-sensitive tag name matching
   * - Used by tag-based navigation
   */
  filterByTag: (tagName: string) => Note[]

  /**
   * Soft delete note by moving to trash
   * @param id - Note ID to trash
   * @throws {Error} On trash operation failure
   *
   * @soft-delete
   * - Sets isTrashed flag and trashedAt timestamp
   * - Clears selection if trashed note was active
   * - Note can be restored with restoreFromTrash
   * - Permanently deleted with emptyTrash operation
   */
  moveToTrash: (id: string) => Promise<void>

  /**
   * Restore note from trash to active state
   * @param id - Note ID to restore
   * @throws {Error} On restore failure
   *
   * @ restoration
   * - Clears isTrashed flag and trashedAt timestamp
   * - Returns note to previous location (folder, tags, etc.)
   * - Note becomes visible in active note lists
   */
  restoreFromTrash: (id: string) => Promise<void>

  /**
   * Permanently delete all trashed notes
   * @throws {Error} On bulk deletion failure
   *
   * @bulk-operation
   * - Deletes all notes with isTrashed: true
   * - Individual API calls for each note
   * - Removes from local collection after successful deletion
   *
   * @warning
   * - This operation cannot be undone
   * - Considered dangerous operation - confirm with user
   */
  emptyTrash: () => Promise<void>

  /**
   * Fetch all trashed notes from server
   * @returns Promise resolving to array of trashed notes
   *
   * @fetching
   * - Returns only soft-deleted notes
   * - Used by trash management UI
   * - Does not affect local notes collection
   */
  getTrashedNotes: () => Promise<Note[]>

  /**
   * Create version snapshot of current note state
   * @param noteId - Note ID to version
   * @param changeDescription - Optional description of changes
   * @returns Promise resolving to created version
   * @throws {Error} If note not found or versioning fails
   *
   * @versioning
   * - Captures current title and content state
   * - Creates immutable snapshot for history tracking
   * - Used by auto-save and manual save operations
   */
  createNoteVersion: (noteId: string, changeDescription?: string) => Promise<NoteVersion>

  /**
   * Fetch all versions for specified note
   * @param noteId - Note ID to get versions for
   * @returns Promise resolving to array of versions
   *
   * @history
   * - Returns chronological list of versions
   * - Used by version history UI components
   * - Does not include current state (only snapshots)
   */
  getNoteVersions: (noteId: string) => Promise<NoteVersion[]>

  /**
   * Restore note to previous version state
   * @param versionId - Version ID to restore
   * @throws {Error} On restoration failure
   *
   * @restoration
   * - Overwrites current note with version snapshot
   * - Updates local note collection
   * - Updates selected note if currently active
   * - Creates new version entry for the restoration
   */
  restoreNoteVersion: (versionId: string) => Promise<void>

  /**
   * Delete specific note version
   * @param versionId - Version ID to delete
   * @throws {Error} On deletion failure
   *
   * @cleanup
   * - Removes version from history
   * - Does not affect current note state
   * - Used for version history management
   */
  deleteNoteVersion: (versionId: string) => Promise<void>

  /**
   * Compare two versions of a note
   * @param noteId - Note ID for versions
   * @param v1 - First version number
   * @param v2 - Second version number
   * @returns Promise resolving to version comparison
   *
   * @diffing
   * - Returns both version snapshots for comparison
   * - Used by diff view components
   * - Server-side comparison for accuracy
   */
  compareNoteVersions: (
    noteId: string,
    v1: number,
    v2: number
  ) => Promise<{ v1: NoteVersion; v2: NoteVersion }>

  /**
   * Update note retention policy for automatic cleanup
   * @param noteId - Note ID to update
   * @param policy - Retention period in days
   * @throws {Error} On policy update failure
   *
   * @retention
   * - Controls automatic deletion timeframe
   * - Used by cleanup processes
   * - Updates local note state after successful API call
   */
  updateRetentionPolicy: (noteId: string, policy: number) => Promise<void>

  /**
   * Bulk delete multiple notes efficiently
   * @param noteIds - Array of note IDs to delete
   * @returns Promise resolving to operation results
   *
   * @bulk-operation
   * - Server-side batch processing for efficiency
   * - Returns success/failure counts and error details
   * - Refreshes local data after operation
   *
   * @results
   * - successful: number of successfully deleted notes
   * - failed: number of failed deletions
   * - errors: array of error messages for failed operations
   */
  bulkDeleteNotes: (
    noteIds: string[]
  ) => Promise<{ successful: number; failed: number; errors: string[] }>

  /**
   * Bulk restore multiple trashed notes
   * @param noteIds - Array of note IDs to restore
   * @returns Promise resolving to operation results
   *
   * @bulk-operation
   * - Server-side batch processing for efficiency
   * - Returns success/failure counts and error details
   * - Refreshes local data after operation
   */
  bulkRestoreNotes: (
    noteIds: string[]
  ) => Promise<{ successful: number; failed: number; errors: string[] }>

  /**
   * Bulk permanently delete multiple notes
   * @param noteIds - Array of note IDs to permanently delete
   * @returns Promise resolving to operation results
   *
   * @bulk-operation
   * - Server-side batch processing for efficiency
   * - Returns success/failure counts and error details
   * - Refreshes local data after operation
   *
   * @warning
   * - This operation cannot be undone
   * - Considered dangerous operation - confirm with user
   */
  bulkPermanentlyDeleteNotes: (
    noteIds: string[]
  ) => Promise<{ successful: number; failed: number; errors: string[] }>

  /**
   * Move multiple notes to specified folder
   * @param noteIds - Array of note IDs to move
   * @param folderId - Target folder ID (null for root)
   * @throws {Error} On bulk move failure
   *
   * @bulk-operation
   * - Updates folder assignment for all specified notes
   * - Optimistic local update for immediate UI feedback
   * - Single API call for efficiency
   */
  moveNotesToFolder: (noteIds: string[], folderId: string) => Promise<void>

  /**
   * Add tags to multiple notes
   * @param noteIds - Array of note IDs to tag
   * @param tagNames - Array of tag names to add
   * @throws {Error} On bulk tagging failure
   *
   * @bulk-operation
   * - Adds tags to specified notes
   * - Prevents duplicate tags with Set operation
   * - Optimistic local update for immediate UI feedback
   */
  addTagsToNotes: (noteIds: string[], tagNames: string[]) => Promise<void>

  /**
   * Remove tags from multiple notes
   * @param noteIds - Array of note IDs to untag
   * @param tagNames - Array of tag names to remove
   * @throws {Error} On bulk untagging failure
   *
   * @bulk-operation
   * - Removes specified tags from notes
   * - Preserves other tags on affected notes
   * - Optimistic local update for immediate UI feedback
   */
  removeTagsFromNotes: (noteIds: string[], tagNames: string[]) => Promise<void>

  /**
   * Load all notes, folders, and tags from server
   * @throws {Error} On data loading failure
   *
   * @initialization
   * - Fetches notes, folders, and tags in parallel
   * - Called during app initialization and data refresh
   * - Requires authenticated user (checked via localStorage)
   *
   * @performance
   * - Parallel API calls for optimal loading time
   * - Single loading state for all data types
   * - Graceful error handling for partial failures
   */
  loadData: () => Promise<void>

  /**
   * Initialize default note selection based on user preferences
   * @throws {Error} On initialization failure
   *
   * @behavior
   * - Respects user settings for default note behavior
   * - Options: 'last-seen' (restore previous) or 'new-note' (create fresh)
   * - Falls back to most recent note if preferences unavailable
   * - Stores selection in localStorage for persistence
   *
   * @settings-integration
   * - Dynamically imports settingsStore to avoid circular dependencies
   * - Uses defaultNoteBehavior setting to determine action
   * - Graceful fallback for missing settings
   */
  initializeDefaultNote: () => Promise<void>

  /**
   * Create bidirectional link between notes
   * @param sourceNoteId - Note creating the link
   * @param targetNoteId - Note being linked to
   * @param linkText - Optional link text/label
   * @returns Promise resolving to link object
   * @throws {Error} On link creation failure
   *
   * @relationships
   * - Creates navigable connections between related notes
   * - Supports backlink discovery
   * - Used for knowledge graph navigation
   */
  createNoteLink: (sourceNoteId: string, targetNoteId: string, linkText?: string) => Promise<any>

  /**
   * Fetch all outbound links from specified note
   * @param noteId - Note ID to get links for
   * @returns Promise resolving to array of links
   *
   * @navigation
   * - Returns links created from this note to others
   * - Used for "related notes" displays
   * - Supports bidirectional relationship discovery
   */
  getNoteLinks: (noteId: string) => Promise<any[]>

  /**
   * Fetch all inbound links to specified note
   * @param noteId - Note ID to get backlinks for
   * @returns Promise resolving to array of backlinks
   *
   * @discovery
   * - Returns links from other notes to this one
   * - Used for "what links here" functionality
   * - Supports knowledge graph exploration
   */
  getNoteBacklinks: (noteId: string) => Promise<any[]>

  /**
   * Delete specific note link
   * @param noteId - Note containing the link
   * @param linkId - Link ID to delete
   * @throws {Error} On deletion failure
   *
   * @cleanup
   * - Removes bidirectional link relationship
   * - Updates both notes' link collections
   * - Used for relationship management
   */
  deleteNoteLink: (noteId: string, linkId: string) => Promise<void>

  /**
   * Toggle note pinned status for priority display
   * @param noteId - Note ID to pin/unpin
   * @param isPinned - New pinned state
   * @param pinnedOrder - Optional order for pinned notes
   * @throws {Error} On pin toggle failure
   *
   * @organization
   * - Controls note priority in lists and displays
   * - Supports custom ordering for pinned items
   * - Used for important note highlighting
   */
  togglePin: (noteId: string, isPinned: boolean, pinnedOrder?: number) => Promise<void>

  /**
   * Toggle note locked status for editing protection
   * @param noteId - Note ID to lock/unlock
   * @param isLocked - New locked state
   * @throws {Error} On lock toggle failure
   *
   * @protection
   * - Prevents accidental editing when locked
   * - Visual indicator in UI for locked state
   * - Used for template notes and important content
   */
  toggleLock: (noteId: string, isLocked: boolean) => Promise<void>
}

export const useNotesStore = create<NotesState>((set, get) => ({
  notes: [],
  folders: [],
  tags: [],
  selectedNote: null,
  selectedFolder: null,
  isLoading: false,

  loadData: async () => {
    // Get user from localStorage to avoid circular dependency
    const storedUser = localStorage.getItem('user')
    if (!storedUser) return

    set({ isLoading: true })
    try {
      const [notesData, foldersData, tagsData] = await Promise.all([
        contentService.getNotes(),
        contentService.getFolders(),
        organizationService.getTags(),
      ])

      set({ notes: notesData, folders: foldersData, tags: tagsData })
    } catch (error) {
      console.error('Failed to load data:', error)
    } finally {
      set({ isLoading: false })
    }
  },

  createNote: async (note: Partial<Note>): Promise<Note> => {
    const storedUser = localStorage.getItem('user')
    if (!storedUser) throw new Error('No user logged in')

    const user = JSON.parse(storedUser)
    const { selectedFolder } = get()
    const folderId = note.folderId ?? selectedFolder ?? null

    const titlePayload = await encryptTextWithStoredKey(note.title ?? '')
    const contentPayload = await encryptTextWithStoredKey(note.content ?? '')

    const createdNote = await contentService.createNote({
      title: titlePayload,
      content: contentPayload,
      folderId,
      tags: note.tags ?? [],
      pinned: note.pinned ?? false,
      encrypted: true,
      encryptionVersion: ENCRYPTION_VERSION,
      userId: user.id,
    })

    set((state) => ({
      notes: [createdNote, ...state.notes.filter((existing) => existing.id !== createdNote.id)],
      selectedNote: createdNote,
    }))

    return createdNote
  },

  updateNote: async (id: string, updates: Partial<Note>): Promise<Note> => {
    if (!id) {
      throw new Error('Note ID is required')
    }

    const currentNote = get().notes.find((note) => note.id === id)
    if (!currentNote) {
      throw new Error('Note not found')
    }

    const shouldEncrypt = updates.encrypted !== true

    let titlePayload = updates.title
    let contentPayload = updates.content

    if (typeof updates.title === 'string' && shouldEncrypt) {
      titlePayload = await encryptTextWithStoredKey(updates.title)
    }

    if (typeof updates.content === 'string' && shouldEncrypt) {
      contentPayload = await encryptTextWithStoredKey(updates.content)
    }

    const encryptionVersion =
      updates.encryptionVersion ?? currentNote.encryptionVersion ?? ENCRYPTION_VERSION

    const payload: Partial<Note> = {
      title: titlePayload ?? currentNote.title,
      content: contentPayload ?? currentNote.content,
      tags: updates.tags ?? currentNote.tags,
      folderId: updates.folderId ?? currentNote.folderId,
      pinned: updates.pinned ?? currentNote.pinned,
      encrypted: true,
      encryptionVersion,
    }

    const updatedNote = await contentService.updateNote(id, payload)

    // Avoid redundant state updates when nothing meaningfully changed
    const shallowEqual = (a?: string[] | null, b?: string[] | null) => {
      if (a === b) return true
      if (!a || !b) return false
      if (a.length !== b.length) return false
      for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
      return true
    }

    const hasMeaningfulChange =
      updatedNote.title !== currentNote.title ||
      updatedNote.content !== currentNote.content ||
      updatedNote.folderId !== currentNote.folderId ||
      updatedNote.pinned !== currentNote.pinned ||
      !shallowEqual(updatedNote.tags, currentNote.tags)

    if (!hasMeaningfulChange) {
      return currentNote
    }
    set((state) => {
      const nextNotes = state.notes.map((note) => (note.id === id ? updatedNote : note))
      // Avoid replacing selectedNote reference on encrypted content saves to prevent editor decrypt loop
      const shouldReplaceSelected =
        state.selectedNote?.id === id &&
        // Replace only if structural props changed that UI outside editor depends on
        (updates.folderId !== undefined || updates.pinned !== undefined)

      return {
        notes: nextNotes,
        selectedNote: shouldReplaceSelected ? updatedNote : state.selectedNote,
      }
    })

    return updatedNote
  },

  deleteNote: async (id: string) => {
    try {
      await contentService.deleteNote(id)
      set((state) => ({
        notes: state.notes.filter((note) => note.id !== id),
        selectedNote: state.selectedNote?.id === id ? null : state.selectedNote,
      }))
    } catch (error) {
      console.error('Failed to delete note:', error)
      throw error
    }
  },

  selectNote: (id: string | null) => {
    const { notes, selectedNote } = get()

    if (id === null) {
      if (selectedNote !== null) set({ selectedNote: null })
      return
    }

    if (selectedNote?.id === id) {
      return
    }

    const note = notes.find((n) => n.id === id) || null
    if (note !== selectedNote) {
      set({ selectedNote: note })
      if (note && !note.isTrashed) {
        localStorage.setItem('lastSeenNoteId', note.id)
      }
    }
  },

  createFolder: async (folder: Partial<Folder>) => {
    const storedUser = localStorage.getItem('user')
    if (!storedUser) throw new Error('No user logged in')

    const user = JSON.parse(storedUser)

    try {
      const newFolder = await contentService.createFolder({
        ...folder,
        userId: user.id,
      })

      set((state) => ({ folders: [...state.folders, newFolder] }))
      return newFolder
    } catch (error) {
      console.error('Failed to create folder:', error)
      throw error
    }
  },

  updateFolder: async (id: string, updates: Partial<Folder>) => {
    try {
      const updatedFolder = await contentService.updateFolder(id, updates)
      set((state) => ({
        folders: state.folders.map((folder) => (folder.id === id ? updatedFolder : folder)),
      }))
    } catch (error) {
      console.error('Failed to update folder:', error)
      throw error
    }
  },

  deleteFolder: async (id: string) => {
    try {
      await contentService.deleteFolder(id)

      // Move notes in this folder to root
      set((state) => ({
        notes: state.notes.map((note) =>
          note.folderId === id ? { ...note, folderId: null } : note
        ),
        folders: state.folders.filter((folder) => folder.id !== id),
        selectedFolder: state.selectedFolder === id ? null : state.selectedFolder,
      }))
    } catch (error) {
      console.error('Failed to delete folder:', error)
      throw error
    }
  },

  selectFolder: (id: string | null) => {
    set({ selectedFolder: id })
  },

  getFolderTree: async () => {
    try {
      const folderTree = await contentService.getFolderTree()
      set({ folders: folderTree })
      return folderTree
    } catch (error) {
      console.error('Failed to fetch folder tree:', error)
      throw error
    }
  },

  moveFolderToParent: async (folderId: string, parentId: string | null) => {
    try {
      await contentService.moveFolderToParent(folderId, parentId)

      // Refresh folder tree after moving
      const folderTree = await contentService.getFolderTree()
      set({ folders: folderTree })
    } catch (error) {
      console.error('Failed to move folder:', error)
      throw error
    }
  },

  selectTag: (tagName: string | null) => {
    // For now, just log the selected tag - filtering logic can be added later
    console.log('Selected tag:', tagName)
  },

  createTag: async (tag: Partial<Tag>) => {
    const storedUser = localStorage.getItem('user')
    if (!storedUser) throw new Error('No user logged in')

    const user = JSON.parse(storedUser)

    try {
      const newTag = await organizationService.createTag({
        ...tag,
        userId: user.id,
      })

      set((state) => ({ tags: [...state.tags, newTag] }))
      return newTag
    } catch (error) {
      console.error('Failed to create tag:', error)
      throw error
    }
  },

  deleteTag: async (id: string) => {
    try {
      await organizationService.deleteTag(id)

      const { tags } = get()
      const tag = tags.find((t) => t.id === id)
      if (tag) {
        // Remove tag from all notes
        set((state) => ({
          notes: state.notes.map((note) => ({
            ...note,
            tags: note.tags.filter((t) => t !== tag.name),
          })),
          tags: state.tags.filter((t) => t.id !== id),
        }))
      }
    } catch (error) {
      console.error('Failed to delete tag:', error)
      throw error
    }
  },

  filterByTag: (tagName: string) => {
    const { notes } = get()
    return notes.filter((note) => !note.isTrashed && note.tags.includes(tagName))
  },

  moveToTrash: async (id: string) => {
    try {
      await contentService.deleteNote(id) // Backend handles soft delete

      set((state) => ({
        notes: state.notes.map((note) =>
          note.id === id
            ? {
                ...note,
                isTrashed: true,
                trashedAt: new Date().toISOString(),
              }
            : note
        ),
        selectedNote: state.selectedNote?.id === id ? null : state.selectedNote,
      }))
    } catch (error) {
      console.error('Failed to move note to trash:', error)
      throw error
    }
  },

  restoreFromTrash: async (id: string) => {
    try {
      await contentService.restoreNote(id)

      set((state) => ({
        notes: state.notes.map((note) =>
          note.id === id
            ? {
                ...note,
                isTrashed: false,
                trashedAt: undefined,
              }
            : note
        ),
      }))
    } catch (error) {
      console.error('Failed to restore note:', error)
      throw error
    }
  },

  emptyTrash: async () => {
    try {
      const { notes } = get()
      const trashedNotes = notes.filter((note) => note.isTrashed)
      await Promise.all(trashedNotes.map((note) => contentService.permanentlyDeleteNote(note.id)))

      set((state) => ({ notes: state.notes.filter((note) => !note.isTrashed) }))
    } catch (error) {
      console.error('Failed to empty trash:', error)
      throw error
    }
  },

  getTrashedNotes: async () => {
    try {
      return await contentService.getTrash()
    } catch (error) {
      console.error('Failed to get trashed notes:', error)
      return []
    }
  },

  createNoteVersion: async (noteId: string, changeDescription?: string) => {
    try {
      const { notes } = get()
      const note = notes.find((n) => n.id === noteId)
      if (!note) throw new Error('Note not found')

      const version = await contentService.createNoteVersion({
        noteId,
        title: note.title,
        content: note.content,
        changeDescription,
      })

      return version
    } catch (error) {
      console.error('Failed to create note version:', error)
      throw error
    }
  },

  getNoteVersions: async (noteId: string) => {
    try {
      return await contentService.getNoteVersions(noteId)
    } catch (error) {
      console.error('Failed to get note versions:', error)
      return []
    }
  },

  restoreNoteVersion: async (versionId: string) => {
    try {
      const restoredNote = await contentService.restoreNoteVersion(versionId)

      set((state) => ({
        notes: state.notes.map((note) => (note.id === restoredNote.id ? restoredNote : note)),
        selectedNote:
          state.selectedNote?.id === restoredNote.id ? restoredNote : state.selectedNote,
      }))
    } catch (error) {
      console.error('Failed to restore note version:', error)
      throw error
    }
  },

  deleteNoteVersion: async (versionId: string) => {
    try {
      await contentService.deleteNoteVersion(versionId)
    } catch (error) {
      console.error('Failed to delete note version:', error)
      throw error
    }
  },

  compareNoteVersions: async (noteId: string, v1: number, v2: number) => {
    try {
      return await contentService.compareNoteVersions(noteId, v1, v2)
    } catch (error) {
      console.error('Failed to compare note versions:', error)
      throw error
    }
  },

  updateRetentionPolicy: async (noteId: string, policy: number) => {
    try {
      await contentService.updateRetentionPolicy(noteId, policy)
      // Update local note with new retention policy if needed
      set((state) => ({
        notes: state.notes.map((note) =>
          note.id === noteId ? { ...note, retentionPolicy: policy } : note
        ),
      }))
    } catch (error) {
      console.error('Failed to update retention policy:', error)
      throw error
    }
  },

  bulkDeleteNotes: async (noteIds: string[]) => {
    try {
      const result = await contentService.bulkDeleteNotes(noteIds)
      // Refresh notes after bulk operation
      await get().loadData()
      return result
    } catch (error) {
      console.error('Failed to bulk delete notes:', error)
      throw error
    }
  },

  bulkRestoreNotes: async (noteIds: string[]) => {
    try {
      const result = await contentService.bulkRestoreNotes(noteIds)
      // Refresh notes after bulk operation
      await get().loadData()
      return result
    } catch (error) {
      console.error('Failed to bulk restore notes:', error)
      throw error
    }
  },

  bulkPermanentlyDeleteNotes: async (noteIds: string[]) => {
    try {
      const result = await contentService.bulkPermanentlyDeleteNotes(noteIds)
      // Refresh notes after bulk operation
      await get().loadData()
      return result
    } catch (error) {
      console.error('Failed to bulk permanently delete notes:', error)
      throw error
    }
  },

  moveNotesToFolder: async (noteIds: string[], folderId: string) => {
    try {
      await contentService.moveNotesToFolder(noteIds, folderId)

      set((state) => ({
        notes: state.notes.map((note) =>
          noteIds.includes(note.id) ? { ...note, folderId: folderId || null } : note
        ),
      }))
    } catch (error) {
      console.error('Failed to move notes to folder:', error)
      throw error
    }
  },

  addTagsToNotes: async (noteIds: string[], tagNames: string[]) => {
    try {
      await contentService.addTagsToNotes(noteIds, tagNames)

      set((state) => ({
        notes: state.notes.map((note) =>
          noteIds.includes(note.id)
            ? { ...note, tags: [...new Set([...note.tags, ...tagNames])] }
            : note
        ),
      }))
    } catch (error) {
      console.error('Failed to add tags to notes:', error)
      throw error
    }
  },

  removeTagsFromNotes: async (noteIds: string[], tagNames: string[]) => {
    try {
      await contentService.removeTagsFromNotes(noteIds, tagNames)

      set((state) => ({
        notes: state.notes.map((note) =>
          noteIds.includes(note.id)
            ? { ...note, tags: note.tags.filter((tag) => !tagNames.includes(tag)) }
            : note
        ),
      }))
    } catch (error) {
      console.error('Failed to remove tags from notes:', error)
      throw error
    }
  },

  initializeDefaultNote: async () => {
    const { notes, selectedNote } = get()

    // If a note is already selected, don't change it
    if (selectedNote) return

    // Get user settings to determine default behavior
    const storedUser = localStorage.getItem('user')
    if (!storedUser) return

    try {
      // Dynamically import settings store to avoid circular dependency
      const { useSettingsStore } = await import('./settingsStore')
      const settingsStore = useSettingsStore.getState()
      const { settings } = settingsStore

      if (settings.defaultNoteBehavior === 'last-seen') {
        // Get last seen note from localStorage
        const lastSeenNoteId = localStorage.getItem('lastSeenNoteId')
        if (lastSeenNoteId) {
          const lastSeenNote = notes.find((note) => note.id === lastSeenNoteId && !note.isTrashed)
          if (lastSeenNote) {
            set({ selectedNote: lastSeenNote })
            return
          }
        }

        // If no last seen note or it doesn't exist, select the most recent note
        const activeNotes = notes.filter((note) => !note.isTrashed)
        if (activeNotes.length > 0) {
          const mostRecentNote = activeNotes.sort(
            (a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime()
          )[0]
          set({ selectedNote: mostRecentNote })
          localStorage.setItem('lastSeenNoteId', mostRecentNote.id)
        }
      } else if (settings.defaultNoteBehavior === 'new-note') {
        // Create a new note
        const newNote = await get().createNote({})
        set({ selectedNote: newNote })
        localStorage.setItem('lastSeenNoteId', newNote.id)
      }
    } catch (error) {
      console.error('Failed to initialize default note:', error)
      // Fallback: select the most recent note
      const activeNotes = notes.filter((note) => !note.isTrashed)
      if (activeNotes.length > 0) {
        const mostRecentNote = activeNotes.sort(
          (a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime()
        )[0]
        set({ selectedNote: mostRecentNote })
        localStorage.setItem('lastSeenNoteId', mostRecentNote.id)
      }
    }
  },

  // Note links methods
  createNoteLink: async (sourceNoteId: string, targetNoteId: string, linkText?: string) => {
    try {
      return await socialService.createNoteLink(sourceNoteId, targetNoteId, linkText)
    } catch (error) {
      console.error('Failed to create note link:', error)
      throw error
    }
  },

  getNoteLinks: async (noteId: string) => {
    try {
      const response = await socialService.getNoteLinks(noteId)
      return response.links ?? []
    } catch (error) {
      console.error('Failed to get note links:', error)
      throw error
    }
  },

  getNoteBacklinks: async (noteId: string) => {
    try {
      const response = await socialService.getNoteBacklinks(noteId)
      return response.backlinks ?? []
    } catch (error) {
      console.error('Failed to get note backlinks:', error)
      throw error
    }
  },

  deleteNoteLink: async (noteId: string, linkId: string) => {
    try {
      await socialService.deleteNoteLink(noteId, linkId)
    } catch (error) {
      console.error('Failed to delete note link:', error)
      throw error
    }
  },

  togglePin: async (noteId: string, isPinned: boolean, pinnedOrder?: number) => {
    try {
      await socialService.togglePin(noteId, isPinned, pinnedOrder)

      // Update local state
      set((state) => ({
        notes: state.notes.map((note) =>
          note.id === noteId ? { ...note, pinned: isPinned, pinnedOrder: pinnedOrder ?? 0 } : note
        ),
      }))
    } catch (error) {
      console.error('Failed to toggle pin:', error)
      throw error
    }
  },

  toggleLock: async (noteId: string, isLocked: boolean) => {
    try {
      await socialService.toggleLock(noteId, isLocked)

      // Update local state
      set((state) => ({
        notes: state.notes.map((note) =>
          note.id === noteId ? { ...note, locked: isLocked } : note
        ),
      }))
    } catch (error) {
      console.error('Failed to toggle lock:', error)
      throw error
    }
  },
}))

// Expose store globally for debugging
if (typeof window !== 'undefined') {
  ;(window as any).__NOTES_STORE__ = useNotesStore
}
