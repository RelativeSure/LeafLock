"use client"

import { createContext, useContext, useState, useEffect, type ReactNode } from "react"
import type { Note, Folder, Tag } from "./types"
import { useAuth } from "./auth-context"

interface NotesContextType {
  notes: Note[]
  folders: Folder[]
  tags: Tag[]
  selectedNote: Note | null
  selectedFolder: string | null
  createNote: (note: Partial<Note>) => Note
  updateNote: (id: string, updates: Partial<Note>) => void
  deleteNote: (id: string) => void
  selectNote: (id: string | null) => void
  createFolder: (folder: Partial<Folder>) => Folder
  updateFolder: (id: string, updates: Partial<Folder>) => void
  deleteFolder: (id: string) => void
  selectFolder: (id: string | null) => void
  createTag: (tag: Partial<Tag>) => Tag
  deleteTag: (id: string) => void
  searchNotes: (query: string) => Note[]
  filterByTag: (tagName: string) => Note[]
  moveToTrash: (id: string) => void
  restoreFromTrash: (id: string) => void
  emptyTrash: () => void
  getTrashedNotes: () => Note[]
}

const NotesContext = createContext<NotesContextType | undefined>(undefined)

export function NotesProvider({ children }: { children: ReactNode }) {
  const { user } = useAuth()
  const [notes, setNotes] = useState<Note[]>([])
  const [folders, setFolders] = useState<Folder[]>([])
  const [tags, setTags] = useState<Tag[]>([])
  const [selectedNote, setSelectedNote] = useState<Note | null>(null)
  const [selectedFolder, setSelectedFolder] = useState<string | null>(null)

  // Load data from localStorage
  useEffect(() => {
    if (user) {
      const storedNotes = localStorage.getItem(`notes_${user.id}`)
      const storedFolders = localStorage.getItem(`folders_${user.id}`)
      const storedTags = localStorage.getItem(`tags_${user.id}`)

      if (storedNotes) setNotes(JSON.parse(storedNotes))
      if (storedFolders) setFolders(JSON.parse(storedFolders))
      if (storedTags) setTags(JSON.parse(storedTags))
    }
  }, [user])

  // Save notes to localStorage
  useEffect(() => {
    if (user && notes.length > 0) {
      localStorage.setItem(`notes_${user.id}`, JSON.stringify(notes))
    }
  }, [notes, user])

  // Save folders to localStorage
  useEffect(() => {
    if (user && folders.length > 0) {
      localStorage.setItem(`folders_${user.id}`, JSON.stringify(folders))
    }
  }, [folders, user])

  // Save tags to localStorage
  useEffect(() => {
    if (user && tags.length > 0) {
      localStorage.setItem(`tags_${user.id}`, JSON.stringify(tags))
    }
  }, [tags, user])

  const createNote = (note: Partial<Note>) => {
    if (!user) throw new Error("No user logged in")

    const newNote: Note = {
      id: crypto.randomUUID(),
      title: note.title || "Untitled Note",
      content: note.content || "",
      folderId: note.folderId || selectedFolder,
      tags: note.tags || [],
      encrypted: note.encrypted || false,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      userId: user.id,
      sharedWith: note.sharedWith || [],
      isTemplate: note.isTemplate || false,
      isTrashed: false,
      pinned: note.pinned || false,
    }

    setNotes((prev) => [newNote, ...prev])
    setSelectedNote(newNote)
    return newNote
  }

  const updateNote = (id: string, updates: Partial<Note>) => {
    setNotes((prev) =>
      prev.map((note) =>
        note.id === id
          ? {
              ...note,
              ...updates,
              updatedAt: new Date().toISOString(),
            }
          : note,
      ),
    )

    if (selectedNote?.id === id) {
      setSelectedNote((prev) =>
        prev
          ? {
              ...prev,
              ...updates,
              updatedAt: new Date().toISOString(),
            }
          : null,
      )
    }
  }

  const deleteNote = (id: string) => {
    setNotes((prev) => prev.filter((note) => note.id !== id))
    if (selectedNote?.id === id) {
      setSelectedNote(null)
    }
  }

  const selectNote = (id: string | null) => {
    if (id === null) {
      setSelectedNote(null)
    } else {
      const note = notes.find((n) => n.id === id)
      setSelectedNote(note || null)
    }
  }

  const createFolder = (folder: Partial<Folder>) => {
    if (!user) throw new Error("No user logged in")

    const newFolder: Folder = {
      id: crypto.randomUUID(),
      name: folder.name || "New Folder",
      color: folder.color || "#3b82f6",
      userId: user.id,
      parentId: folder.parentId || null,
      createdAt: new Date().toISOString(),
    }

    setFolders((prev) => [...prev, newFolder])
    return newFolder
  }

  const updateFolder = (id: string, updates: Partial<Folder>) => {
    setFolders((prev) => prev.map((folder) => (folder.id === id ? { ...folder, ...updates } : folder)))
  }

  const deleteFolder = (id: string) => {
    // Move notes in this folder to root
    setNotes((prev) => prev.map((note) => (note.folderId === id ? { ...note, folderId: null } : note)))

    // Delete folder
    setFolders((prev) => prev.filter((folder) => folder.id !== id))

    if (selectedFolder === id) {
      setSelectedFolder(null)
    }
  }

  const selectFolder = (id: string | null) => {
    setSelectedFolder(id)
  }

  const createTag = (tag: Partial<Tag>) => {
    if (!user) throw new Error("No user logged in")

    const newTag: Tag = {
      id: crypto.randomUUID(),
      name: tag.name || "New Tag",
      color: tag.color || "#8b5cf6",
      userId: user.id,
    }

    setTags((prev) => [...prev, newTag])
    return newTag
  }

  const deleteTag = (id: string) => {
    const tag = tags.find((t) => t.id === id)
    if (!tag) return

    // Remove tag from all notes
    setNotes((prev) => prev.map((note) => ({ ...note, tags: note.tags.filter((t) => t !== tag.name) })))

    setTags((prev) => prev.filter((t) => t.id !== id))
  }

  const searchNotes = (query: string) => {
    const lowerQuery = query.toLowerCase()
    return notes.filter(
      (note) =>
        !note.isTrashed &&
        (note.title.toLowerCase().includes(lowerQuery) || note.content.toLowerCase().includes(lowerQuery)),
    )
  }

  const filterByTag = (tagName: string) => {
    return notes.filter((note) => !note.isTrashed && note.tags.includes(tagName))
  }

  const moveToTrash = (id: string) => {
    setNotes((prev) =>
      prev.map((note) =>
        note.id === id
          ? {
              ...note,
              isTrashed: true,
              trashedAt: new Date().toISOString(),
            }
          : note,
      ),
    )

    if (selectedNote?.id === id) {
      setSelectedNote(null)
    }
  }

  const restoreFromTrash = (id: string) => {
    setNotes((prev) =>
      prev.map((note) =>
        note.id === id
          ? {
              ...note,
              isTrashed: false,
              trashedAt: undefined,
            }
          : note,
      ),
    )
  }

  const emptyTrash = () => {
    setNotes((prev) => prev.filter((note) => !note.isTrashed))
  }

  const getTrashedNotes = () => {
    return notes.filter((note) => note.isTrashed)
  }

  return (
    <NotesContext.Provider
      value={{
        notes,
        folders,
        tags,
        selectedNote,
        selectedFolder,
        createNote,
        updateNote,
        deleteNote,
        selectNote,
        createFolder,
        updateFolder,
        deleteFolder,
        selectFolder,
        createTag,
        deleteTag,
        searchNotes,
        filterByTag,
        moveToTrash,
        restoreFromTrash,
        emptyTrash,
        getTrashedNotes,
      }}
    >
      {children}
    </NotesContext.Provider>
  )
}

export function useNotes() {
  const context = useContext(NotesContext)
  if (context === undefined) {
    throw new Error("useNotes must be used within a NotesProvider")
  }
  return context
}
