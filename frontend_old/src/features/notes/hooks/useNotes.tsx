import { useState, useCallback, useEffect, useRef, type SetStateAction } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { type Note } from '@/types/auth'
import { type SecureAPI } from '@/services/api/secureApi'

export const useNotes = (api: SecureAPI, onLogout: () => void) => {
  const queryClient = useQueryClient()
  const [selectedNote, setSelectedNote] = useState<Note | null>(null)
  const [manualLoading, setManualLoading] = useState(false)
  const [notesError, setNotesError] = useState<string | null>(null)
  const logoutRef = useRef(onLogout)

  useEffect(() => {
    logoutRef.current = onLogout
  }, [onLogout])

  const handleApiError = useCallback((error: unknown, fallback: string) => {
    const message = error instanceof Error && error.message ? error.message : fallback

    if (message.includes('401') || message.includes('Unauthorized')) {
      console.log('🚨 Authentication error detected while handling notes - logging out')
      logoutRef.current()
    }

    return message
  }, [])

  const {
    data: notes = [],
    refetch: refetchNotes,
    isFetching: isNotesFetching,
    error: notesQueryError,
  } = useQuery<Note[], Error>({
    queryKey: ['notes'],
    enabled: false,
    queryFn: async () => {
      try {
        console.log('📝 Loading notes via TanStack Query...')
        const fetchedNotes = await api.getNotes()
        console.log(`✅ Loaded ${fetchedNotes.length} notes`)
        return fetchedNotes
      } catch (err) {
        const message = handleApiError(err, 'Failed to load notes')
        throw new Error(message)
      }
    },
  })

  const {
    data: trashedNotes = [],
    refetch: refetchTrash,
    isFetching: isTrashFetching,
    error: trashQueryError,
  } = useQuery<Note[], Error>({
    queryKey: ['notes', 'trash'],
    enabled: false,
    queryFn: async () => {
      try {
        console.log('🗑️ Loading trash via TanStack Query...')
        const fetchedTrash = await api.getTrash()
        console.log(`✅ Loaded ${fetchedTrash.length} trashed notes`)
        return fetchedTrash
      } catch (err) {
        const message = handleApiError(err, 'Failed to load trash')
        throw new Error(message)
      }
    },
  })

  const setNotes = useCallback(
    (updater: SetStateAction<Note[]>) => {
      queryClient.setQueryData<Note[]>(['notes'], (prev = []) =>
        typeof updater === 'function' ? (updater as (prev: Note[]) => Note[])(prev) : updater
      )
    },
    [queryClient]
  )

  const setTrashedNotes = useCallback(
    (updater: SetStateAction<Note[]>) => {
      queryClient.setQueryData<Note[]>(['notes', 'trash'], (prev = []) =>
        typeof updater === 'function' ? (updater as (prev: Note[]) => Note[])(prev) : updater
      )
    },
    [queryClient]
  )

  const loadNotes = useCallback(async () => {
    try {
      setManualLoading(true)
      setNotesError(null)
      await refetchNotes({ throwOnError: true })
    } catch (err) {
      const message = handleApiError(err, 'Failed to load notes')
      console.error('💥 Failed to load notes:', err)
      setNotesError(message)
    } finally {
      setManualLoading(false)
    }
  }, [handleApiError, refetchNotes])

  const loadTrash = useCallback(async () => {
    try {
      setManualLoading(true)
      setNotesError(null)
      await refetchTrash({ throwOnError: true })
    } catch (err) {
      const message = handleApiError(err, 'Failed to load trash')
      console.error('💥 Failed to load trash:', err)
      setNotesError(message)
    } finally {
      setManualLoading(false)
    }
  }, [handleApiError, refetchTrash])

  const { mutateAsync: restoreNote, isPending: isRestoring } = useMutation({
    mutationFn: async (noteId: string) => {
      console.log('♻️ Restoring note:', noteId)
      return await api.restoreNote(noteId)
    },
  })

  const { mutateAsync: permanentlyDeleteNote, isPending: isDeletingForever } = useMutation({
    mutationFn: async (noteId: string) => {
      console.log('🗑️ Permanently deleting note:', noteId)
      return await api.permanentlyDeleteNote(noteId)
    },
  })

  const { mutateAsync: moveNoteToTrash, isPending: isMovingToTrash } = useMutation({
    mutationFn: async (noteId: string) => {
      console.log('🗑️ Moving note to trash:', noteId)
      return await api.deleteNote(noteId)
    },
  })

  const handleRestoreNote = useCallback(
    async (noteId: string) => {
      try {
        await restoreNote(noteId)
        console.log('✅ Note restored successfully')

        await Promise.all([loadNotes(), loadTrash()])

        if (selectedNote && selectedNote.id === noteId) {
          setSelectedNote(null)
        }
      } catch (err) {
        console.error('💥 Failed to restore note:', err)
        const message = handleApiError(err, 'Failed to restore note')
        setNotesError(message)
      }
    },
    [loadNotes, loadTrash, restoreNote, selectedNote, handleApiError]
  )

  const handlePermanentDelete = useCallback(
    async (noteId: string) => {
      try {
        await permanentlyDeleteNote(noteId)
        console.log('✅ Note permanently deleted')

        await loadTrash()

        if (selectedNote && selectedNote.id === noteId) {
          setSelectedNote(null)
        }
      } catch (err) {
        console.error('💥 Failed to permanently delete note:', err)
        const message = handleApiError(err, 'Failed to permanently delete note')
        setNotesError(message)
      }
    },
    [loadTrash, permanentlyDeleteNote, selectedNote, handleApiError]
  )

  const handleMoveNoteToTrash = useCallback(
    async (noteId: string): Promise<boolean> => {
      try {
        await moveNoteToTrash(noteId)
        setNotes((prevNotes) => prevNotes.filter((note) => note.id !== noteId))

        if (selectedNote?.id === noteId) {
          setSelectedNote(null)
        }

        await refetchTrash()
        return true
      } catch (err) {
        console.error('Failed to delete note:', err)
        const message = handleApiError(err, 'Failed to delete note')
        setNotesError(message)
        return false
      }
    },
    [moveNoteToTrash, selectedNote, setNotes, refetchTrash, handleApiError]
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

  useEffect(() => {
    if (notes.length > 0 && !selectedNote && !(manualLoading || isNotesFetching)) {
      setSelectedNote(notes[0])
    }
  }, [notes.length, selectedNote, manualLoading, isNotesFetching])

  useEffect(() => {
    if (notesQueryError) {
      setNotesError(notesQueryError.message)
    }
  }, [notesQueryError])

  useEffect(() => {
    if (trashQueryError) {
      setNotesError(trashQueryError.message)
    }
  }, [trashQueryError])

  const loading =
    manualLoading ||
    isNotesFetching ||
    isTrashFetching ||
    isRestoring ||
    isDeletingForever ||
    isMovingToTrash

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
