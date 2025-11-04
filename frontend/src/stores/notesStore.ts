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
  notes: Note[]
  folders: Folder[]
  tags: Tag[]
  selectedNote: Note | null
  selectedFolder: string | null
  isLoading: boolean
  createNote: (note: Partial<Note>) => Promise<Note>
  updateNote: (id: string, updates: Partial<Note>) => Promise<Note>
  deleteNote: (id: string) => Promise<void>
  selectNote: (id: string | null) => void
  createFolder: (folder: Partial<Folder>) => Promise<Folder>
  updateFolder: (id: string, updates: Partial<Folder>) => Promise<void>
  deleteFolder: (id: string) => Promise<void>
  selectFolder: (id: string | null) => void
  selectTag: (tagName: string | null) => void
  createTag: (tag: Partial<Tag>) => Promise<Tag>
  deleteTag: (id: string) => Promise<void>
  filterByTag: (tagName: string) => Note[]
  moveToTrash: (id: string) => Promise<void>
  restoreFromTrash: (id: string) => Promise<void>
  emptyTrash: () => Promise<void>
  getTrashedNotes: () => Promise<Note[]>
  createNoteVersion: (noteId: string, changeDescription?: string) => Promise<NoteVersion>
  getNoteVersions: (noteId: string) => Promise<NoteVersion[]>
  restoreNoteVersion: (versionId: string) => Promise<void>
  deleteNoteVersion: (versionId: string) => Promise<void>
  compareNoteVersions: (
    noteId: string,
    v1: number,
    v2: number
  ) => Promise<{ v1: NoteVersion; v2: NoteVersion }>
  updateRetentionPolicy: (noteId: string, policy: number) => Promise<void>
  bulkDeleteNotes: (
    noteIds: string[]
  ) => Promise<{ successful: number; failed: number; errors: string[] }>
  bulkRestoreNotes: (
    noteIds: string[]
  ) => Promise<{ successful: number; failed: number; errors: string[] }>
  bulkPermanentlyDeleteNotes: (
    noteIds: string[]
  ) => Promise<{ successful: number; failed: number; errors: string[] }>
  moveNotesToFolder: (noteIds: string[], folderId: string) => Promise<void>
  addTagsToNotes: (noteIds: string[], tagNames: string[]) => Promise<void>
  removeTagsFromNotes: (noteIds: string[], tagNames: string[]) => Promise<void>
  loadData: () => Promise<void>
  initializeDefaultNote: () => Promise<void>
  createNoteLink: (sourceNoteId: string, targetNoteId: string, linkText?: string) => Promise<any>
  getNoteLinks: (noteId: string) => Promise<any[]>
  getNoteBacklinks: (noteId: string) => Promise<any[]>
  deleteNoteLink: (noteId: string, linkId: string) => Promise<void>
  togglePin: (noteId: string, isPinned: boolean, pinnedOrder?: number) => Promise<void>
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
          note.id === noteId
            ? { ...note, pinned: isPinned, pinnedOrder: pinnedOrder ?? 0 }
            : note
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
