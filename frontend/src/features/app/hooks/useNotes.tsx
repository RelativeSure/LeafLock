import { useState, useCallback, useEffect, useRef } from 'react'
import { type Note } from '../types'
import { type SecureAPI } from '@/services/secureApi'

export const useNotes = (api: SecureAPI, onLogout: () => void) => {
  const [notes, setNotes] = useState<Note[]>([])
  const [trashedNotes, setTrashedNotes] = useState<Note[]>([])
  const [selectedNote, setSelectedNote] = useState<Note | null>(null)
  const [loading, setLoading] = useState(false)
  const [notesError, setNotesError] = useState<string | null>(null)
  const logoutRef = useRef(onLogout)

  useEffect(() => {
    logoutRef.current = onLogout
  }, [onLogout])

  const loadNotes = useCallback(async () => {
    try {
      setLoading(true)
      setNotesError(null)
      console.log('📝 Loading notes...')
      const fetchedNotes = await api.getNotes()
      setNotes(fetchedNotes)
      console.log(`✅ Loaded ${fetchedNotes.length} notes`)
    } catch (err) {
      console.error('💥 Failed to load notes:', err)
      const message = (err as Error).message || 'Failed to load notes'

      if (message.includes('401') || message.includes('Unauthorized')) {
        console.log('🚨 Authentication error while loading notes - logging out')
        logoutRef.current()
        return
      }

      setNotesError(message)
    } finally {
      setLoading(false)
    }
  }, [api])

  const loadTrash = useCallback(async () => {
    try {
      setLoading(true)
      setNotesError(null)
      console.log('🗑️ Loading trash...')
      const fetchedTrash = await api.getTrash()
      setTrashedNotes(fetchedTrash)
      console.log(`✅ Loaded ${fetchedTrash.length} trashed notes`)
    } catch (err) {
      console.error('💥 Failed to load trash:', err)
      const message = (err as Error).message || 'Failed to load trash'

      if (message.includes('401') || message.includes('Unauthorized')) {
        console.log('🚨 Authentication error while loading trash - logging out')
        logoutRef.current()
        return
      }

      setNotesError(message)
    } finally {
      setLoading(false)
    }
  }, [api])

  const handleRestoreNote = useCallback(
    async (noteId: string) => {
      try {
        console.log('♻️ Restoring note:', noteId)
        await api.restoreNote(noteId)
        console.log('✅ Note restored successfully')

        await Promise.all([loadNotes(), loadTrash()])

        if (selectedNote && selectedNote.id === noteId) {
          setSelectedNote(null)
        }
      } catch (err) {
        console.error('💥 Failed to restore note:', err)
        setNotesError((err as Error).message || 'Failed to restore note')
      }
    },
    [api, loadNotes, loadTrash, selectedNote]
  )

  const handlePermanentDelete = useCallback(
    async (noteId: string) => {
      try {
        console.log('🗑️ Permanently deleting note:', noteId)
        await api.permanentlyDeleteNote(noteId)
        console.log('✅ Note permanently deleted')

        await loadTrash()

        if (selectedNote && selectedNote.id === noteId) {
          setSelectedNote(null)
        }
      } catch (err) {
        console.error('💥 Failed to permanently delete note:', err)
        setNotesError((err as Error).message || 'Failed to permanently delete note')
      }
    },
    [api, loadTrash, selectedNote]
  )

  const handleMoveNoteToTrash = useCallback(
    async (noteId: string): Promise<boolean> => {
      try {
        await api.deleteNote(noteId)
        setNotes((prevNotes) => prevNotes.filter((note) => note.id !== noteId))

        if (selectedNote?.id === noteId) {
          setSelectedNote(null)
        }

        return true
      } catch (err) {
        console.error('Failed to delete note:', err)
        setNotesError((err as Error).message || 'Failed to delete note')
        return false
      }
    },
    [api, selectedNote]
  )

  const handleStartNewNote = useCallback(() => {
    const now = new Date().toISOString()
    setSelectedNote({
      id: '',
      title: '',
      content: '',
      created_at: now,
      updated_at: now,
    })
  }, [])

  return {
    notes,
    setNotes,
    trashedNotes,
    setTrashedNotes,
    selectedNote,
    setSelectedNote,
    loading,
    notesError,
    setNotesError,
    loadNotes,
    loadTrash,
    handleRestoreNote,
    handlePermanentDelete,
    handleMoveNoteToTrash,
    handleStartNewNote,
  }
}
