import { create } from 'zustand'
import type { Note, Folder, Tag } from '../types'
import { useAuthStore } from './authStore'
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
  loadData: () => Promise<void>
}

export const useNotesStore = create<NotesState>((set, get) => ({
  notes: [],
  folders: [],
  tags: [],
  selectedNote: null,
  selectedFolder: null,
  isLoading: false,

  loadData: async () => {
    const { user } = useAuthStore.getState()
    if (!user) return

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
    const { user } = useAuthStore.getState()
    const { selectedFolder } = get()
    if (!user) throw new Error('No user logged in')

    try {
      const newNote = await apiClient.createNote({
        ...note,
        folderId: note.folderId || selectedFolder,
        userId: user.id,
      })

      set((state) => ({ notes: [newNote, ...state.notes], selectedNote: newNote }))
      return newNote
    } catch (error) {
      console.error('Failed to create note:', error)
      throw error
    }
  },

  updateNote: async (id: string, updates: Partial<Note>) => {
    try {
      const updatedNote = await apiClient.updateNote(id, updates)

      set((state) => ({
        notes: state.notes.map((note) => (note.id === id ? updatedNote : note)),
        selectedNote: state.selectedNote?.id === id ? updatedNote : state.selectedNote,
      }))
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
    }
  },

  createFolder: async (folder: Partial<Folder>) => {
    const { user } = useAuthStore.getState()
    if (!user) throw new Error('No user logged in')

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
    const { user } = useAuthStore.getState()
    if (!user) throw new Error('No user logged in')

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
}))
