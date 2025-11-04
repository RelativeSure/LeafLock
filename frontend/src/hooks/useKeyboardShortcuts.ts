import { useEffect } from 'react'
import { useNavigate } from '@tanstack/react-router'
import { useNotesStore } from '@/stores/notesStore'
import { toast } from 'sonner'

interface KeyboardShortcutsOptions {
  onSearch?: () => void
  onHelp?: () => void
  onToggleEncryption?: () => void
}

export function useKeyboardShortcuts(options: KeyboardShortcutsOptions = {}) {
  const navigate = useNavigate()
  const { createNote, deleteNote, selectedNote, togglePin } = useNotesStore()

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const isMac = navigator.platform.toUpperCase().indexOf('MAC') >= 0
      const modKey = isMac ? e.metaKey : e.ctrlKey

      // Ignore if user is typing in an input/textarea
      const target = e.target as HTMLElement
      const isEditing =
        target.tagName === 'INPUT' ||
        target.tagName === 'TEXTAREA' ||
        target.isContentEditable

      // Ctrl/Cmd + K - Search notes
      if (modKey && e.key === 'k' && !e.shiftKey) {
        e.preventDefault()
        options.onSearch?.()
        return
      }

      // Ctrl/Cmd + N - Create new note
      if (modKey && e.key === 'n' && !e.shiftKey && !isEditing) {
        e.preventDefault()
        handleCreateNote()
        return
      }

      // Ctrl/Cmd + D - Delete note
      if (modKey && e.key === 'd' && !e.shiftKey && !isEditing) {
        e.preventDefault()
        handleDeleteNote()
        return
      }

      // Ctrl/Cmd + P - Pin/Unpin note
      if (modKey && e.key === 'p' && !e.shiftKey && !isEditing) {
        e.preventDefault()
        handleTogglePin()
        return
      }

      // Ctrl/Cmd + E - Toggle encryption (if handler provided)
      if (modKey && e.key === 'e' && !e.shiftKey && !isEditing) {
        e.preventDefault()
        options.onToggleEncryption?.()
        return
      }

      // Ctrl/Cmd + / or ? - Show keyboard shortcuts
      if (modKey && (e.key === '/' || e.key === '?')) {
        e.preventDefault()
        window.dispatchEvent(new CustomEvent('open-keyboard-shortcuts'))
        return
      }
    }

    const handleCreateNote = async () => {
      try {
        await createNote({
          title: 'Untitled Note',
          content: '',
        })
        toast.success('Note created')
        navigate({ to: `/` })
      } catch (error) {
        toast.error('Failed to create note')
        console.error(error)
      }
    }

    const handleDeleteNote = async () => {
      if (!selectedNote) {
        toast.error('No note selected')
        return
      }

      try {
        await deleteNote(selectedNote.id)
        toast.success('Note moved to trash')
      } catch (error) {
        toast.error('Failed to delete note')
        console.error(error)
      }
    }

    const handleTogglePin = async () => {
      if (!selectedNote) {
        toast.error('No note selected')
        return
      }

      try {
        const isPinned = !(selectedNote as any).pinned
        await togglePin(selectedNote.id, isPinned)
        toast.success(isPinned ? 'Note pinned' : 'Note unpinned')
      } catch (error) {
        toast.error('Failed to toggle pin')
        console.error(error)
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [
    createNote,
    deleteNote,
    selectedNote,
    togglePin,
    navigate,
    options.onSearch,
    options.onToggleEncryption,
  ])
}
