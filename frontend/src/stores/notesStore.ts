import { create } from 'zustand'
import type { Note, Folder, Tag, NoteVersion } from '../types'
import { apiClient } from '../services/api/secureApi'

interface NotesState {
  notes: Note[]
  folders: Folder[]
  tags: Tag[]
  selectedNote: Note | null
  selectedFolder: string | null
  isLoading: boolean
  createNote: (note: Partial<Note>) => Promise<Note>
  updateNote: (id: string, updates: Partial<Note>) => Promise<void>
  deleteNote: (id: string) => Promise<void>
  selectNote: (id: string | null) => void
  createFolder: (folder: Partial<Folder>) => Promise<Folder>
  updateFolder: (id: string, updates: Partial<Folder>) => Promise<void>
  deleteFolder: (id: string) => Promise<void>
  selectFolder: (id: string | null) => void
  createTag: (tag: Partial<Tag>) => Promise<Tag>
  deleteTag: (id: string) => Promise<void>
  searchNotes: (query: string) => Promise<Note[]>
  filterByTag: (tagName: string) => Note[]
  moveToTrash: (id: string) => Promise<void>
  restoreFromTrash: (id: string) => Promise<void>
  emptyTrash: () => Promise<void>
  getTrashedNotes: () => Promise<Note[]>
  createNoteVersion: (noteId: string, changeDescription?: string) => Promise<NoteVersion>
  getNoteVersions: (noteId: string) => Promise<NoteVersion[]>
  restoreNoteVersion: (versionId: string) => Promise<void>
  deleteNoteVersion: (versionId: string) => Promise<void>
  moveNotesToFolder: (noteIds: string[], folderId: string) => Promise<void>
  addTagsToNotes: (noteIds: string[], tagNames: string[]) => Promise<void>
  removeTagsFromNotes: (noteIds: string[], tagNames: string[]) => Promise<void>
  loadData: () => Promise<void>
  initializeDefaultNote: () => Promise<void>
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
        apiClient.getNotes(),
        apiClient.getFolders(),
        apiClient.getTags(),
      ])

      set({ notes: notesData, folders: foldersData, tags: tagsData })
    } catch (error) {
      console.error('Failed to load data:', error)
    } finally {
      set({ isLoading: false })
    }
  },

      createNote: async (note: Partial<Note>) => {
        const storedUser = localStorage.getItem('user')
        if (!storedUser) throw new Error('No user logged in')

        const user = JSON.parse(storedUser)
        const { selectedFolder, folders } = get()

        // If no folder is selected, assign to "Uncategorized" folder
        let folderId = note.folderId || selectedFolder
        if (!folderId) {
          // Find or create "Uncategorized" folder
          let uncategorizedFolder = folders.find(f => f.name === 'Uncategorized')
          if (!uncategorizedFolder) {
            // Create Uncategorized folder
            uncategorizedFolder = await apiClient.createFolder({
              name: 'Uncategorized',
              color: '#6b7280', // Gray color
              userId: user.id,
            })
            set((state) => ({ folders: [...state.folders, uncategorizedFolder] }))
          }
          folderId = uncategorizedFolder.id
        }

        // Create a local note first without saving to API
        const localNote: Note = {
          id: `local-${Date.now()}`,
          title: note.title || '',
          content: note.content || '',
          userId: user.id,
          folderId: folderId,
          tags: note.tags || [],
          pinned: note.pinned || false,
          encrypted: note.encrypted || false,
          isTrashed: false,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          trashedAt: null,
        }

        set((state) => ({ notes: [localNote, ...state.notes], selectedNote: localNote }))
        return localNote
      },

  updateNote: async (id: string, updates: Partial<Note>) => {
    try {
      let updatedNote: Note

      // If it's a local note (not saved to API yet), create it first
      if (id.startsWith('local-')) {
        const storedUser = localStorage.getItem('user')
        if (!storedUser) throw new Error('No user logged in')
        const user = JSON.parse(storedUser)

        const currentNote = get().notes.find(note => note.id === id)
        if (!currentNote) throw new Error('Note not found')

        // Only create on API if there's actual content
        if (updates.title?.trim() || updates.content?.trim()) {
          updatedNote = await apiClient.createNote({
            ...currentNote,
            ...updates,
            userId: user.id,
          })

          // Replace the local note with the API note
          set((state) => ({
            notes: state.notes.map((note) => (note.id === id ? updatedNote : note)),
            selectedNote: state.selectedNote?.id === id ? updatedNote : state.selectedNote,
          }))
        } else {
          // Just update locally if no content
          updatedNote = { ...currentNote, ...updates, updatedAt: new Date().toISOString() }
          set((state) => ({
            notes: state.notes.map((note) => (note.id === id ? updatedNote : note)),
            selectedNote: state.selectedNote?.id === id ? updatedNote : state.selectedNote,
          }))
        }
      } else {
        // Regular API update for existing notes
        updatedNote = await apiClient.updateNote(id, updates)
        set((state) => ({
          notes: state.notes.map((note) => (note.id === id ? updatedNote : note)),
          selectedNote: state.selectedNote?.id === id ? updatedNote : state.selectedNote,
        }))
      }

      return updatedNote
    } catch (error) {
      console.error('Failed to update note:', error)
      throw error
    }
  },

  deleteNote: async (id: string) => {
    try {
      await apiClient.deleteNote(id)
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
    if (id === null) {
      set({ selectedNote: null })
    } else {
      const { notes } = get()
      const note = notes.find((n) => n.id === id)
      set({ selectedNote: note || null })

      // Track last seen note for default behavior
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
      const newFolder = await apiClient.createFolder({
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
      const updatedFolder = await apiClient.updateFolder(id, updates)
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
      await apiClient.deleteFolder(id)

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

  createTag: async (tag: Partial<Tag>) => {
    const storedUser = localStorage.getItem('user')
    if (!storedUser) throw new Error('No user logged in')

    const user = JSON.parse(storedUser)

    try {
      const newTag = await apiClient.createTag({
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
      await apiClient.deleteTag(id)

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

  searchNotes: async (query: string) => {
    try {
      return await apiClient.searchNotes(query)
    } catch (error) {
      console.error('Failed to search notes:', error)
      return []
    }
  },

  filterByTag: (tagName: string) => {
    const { notes } = get()
    return notes.filter((note) => !note.isTrashed && note.tags.includes(tagName))
  },

  moveToTrash: async (id: string) => {
    try {
      await apiClient.deleteNote(id) // Backend handles soft delete

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
      await apiClient.restoreNote(id)

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
      await Promise.all(trashedNotes.map((note) => apiClient.permanentlyDeleteNote(note.id)))

      set((state) => ({ notes: state.notes.filter((note) => !note.isTrashed) }))
    } catch (error) {
      console.error('Failed to empty trash:', error)
      throw error
    }
  },

  getTrashedNotes: async () => {
    try {
      return await apiClient.getTrash()
    } catch (error) {
      console.error('Failed to get trashed notes:', error)
      return []
    }
  },

  createNoteVersion: async (noteId: string, changeDescription?: string) => {
    try {
      const { notes } = get()
      const note = notes.find(n => n.id === noteId)
      if (!note) throw new Error('Note not found')

      const version = await apiClient.createNoteVersion({
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
      return await apiClient.getNoteVersions(noteId)
    } catch (error) {
      console.error('Failed to get note versions:', error)
      return []
    }
  },

  restoreNoteVersion: async (versionId: string) => {
    try {
      const restoredNote = await apiClient.restoreNoteVersion(versionId)

      set((state) => ({
        notes: state.notes.map((note) =>
          note.id === restoredNote.id ? restoredNote : note
        ),
        selectedNote: state.selectedNote?.id === restoredNote.id ? restoredNote : state.selectedNote,
      }))
    } catch (error) {
      console.error('Failed to restore note version:', error)
      throw error
    }
  },

  deleteNoteVersion: async (versionId: string) => {
    try {
      await apiClient.deleteNoteVersion(versionId)
    } catch (error) {
      console.error('Failed to delete note version:', error)
      throw error
    }
  },

  moveNotesToFolder: async (noteIds: string[], folderId: string) => {
    try {
      await apiClient.moveNotesToFolder(noteIds, folderId)

      set((state) => ({
        notes: state.notes.map((note) =>
          noteIds.includes(note.id)
            ? { ...note, folderId: folderId || null }
            : note
        ),
      }))
    } catch (error) {
      console.error('Failed to move notes to folder:', error)
      throw error
    }
  },

  addTagsToNotes: async (noteIds: string[], tagNames: string[]) => {
    try {
      await apiClient.addTagsToNotes(noteIds, tagNames)

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
      await apiClient.removeTagsFromNotes(noteIds, tagNames)

      set((state) => ({
        notes: state.notes.map((note) =>
          noteIds.includes(note.id)
            ? { ...note, tags: note.tags.filter(tag => !tagNames.includes(tag)) }
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
          const lastSeenNote = notes.find(note => note.id === lastSeenNoteId && !note.isTrashed)
          if (lastSeenNote) {
            set({ selectedNote: lastSeenNote })
            return
          }
        }

        // If no last seen note or it doesn't exist, select the most recent note
        const activeNotes = notes.filter(note => !note.isTrashed)
        if (activeNotes.length > 0) {
          const mostRecentNote = activeNotes.sort((a, b) =>
            new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime()
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
      const activeNotes = notes.filter(note => !note.isTrashed)
      if (activeNotes.length > 0) {
        const mostRecentNote = activeNotes.sort((a, b) =>
          new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime()
        )[0]
        set({ selectedNote: mostRecentNote })
        localStorage.setItem('lastSeenNoteId', mostRecentNote.id)
      }
    }
  },
}))
