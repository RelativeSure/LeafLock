import React, { Suspense, useEffect } from 'react'
import { useNotesStore } from '@/stores/notesStore'

const NoteEditor = React.lazy(() =>
  import('./note-editor').then((m) => ({ default: m.NoteEditor }))
)

export function DashboardView() {
  const { selectedNote, createNote, notes } = useNotesStore()

  useEffect(() => {
    // Create a new note when dashboard loads if no note is selected
    const initializeNewNote = async () => {
      // Only create a new note if no note is currently selected and we don't have a last seen note
      if (!selectedNote) {
        const lastSeenNoteId = localStorage.getItem('lastSeenNoteId')
        const hasLastSeenNote = lastSeenNoteId && notes.some(note => note.id === lastSeenNoteId)
        
        if (!hasLastSeenNote) {
          try {
            // Create a new empty note - it won't be saved until user writes something
            const newNote = await createNote({
              title: '',
              content: '',
            })
            console.log('Created new note on dashboard load:', newNote.id)
          } catch (error) {
            console.error('Failed to create new note:', error)
          }
        }
      }
    }

    initializeNewNote()
  }, []) // Only run on mount

  return (
    <div className="h-full w-full flex flex-col bg-background">
      <Suspense
        fallback={
          <div className="flex h-full items-center justify-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          </div>
        }
      >
        <NoteEditor />
      </Suspense>
    </div>
  )
}
