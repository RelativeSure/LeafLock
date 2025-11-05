import { useState, useEffect } from 'react'
import { useNavigate } from '@tanstack/react-router'
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from '@/components/ui/command'
import { useNotesStore } from '@/stores/notesStore'
import { decryptTextWithStoredKey } from '@/lib/encryption-utils'
import { FileText, Plus, Trash2, Pin, Search, FolderOpen, Tag, Settings } from 'lucide-react'
import { toast } from 'sonner'

export function CommandPalette() {
  const [open, setOpen] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [decryptedNotes, setDecryptedNotes] = useState<Array<{ id: string; title: string }>>([])

  const navigate = useNavigate()
  const { notes, folders, tags, createNote, selectNote, selectedNote, togglePin, moveToTrash } =
    useNotesStore()

  // Decrypt note titles for search
  useEffect(() => {
    if (open && notes.length > 0) {
      Promise.all(
        notes.map(async (note) => {
          try {
            const title = await decryptTextWithStoredKey(note.title)
            return { id: note.id, title }
          } catch {
            return { id: note.id, title: 'Untitled' }
          }
        })
      ).then(setDecryptedNotes)
    }
  }, [open, notes])

  // Handle Ctrl+K
  useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.key === 'k' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault()
        setOpen((open) => !open)
      }
    }

    document.addEventListener('keydown', down)
    return () => document.removeEventListener('keydown', down)
  }, [])

  const handleCommand = (callback: () => void) => {
    setOpen(false)
    setSearchQuery('')
    callback()
  }

  const filteredNotes = decryptedNotes.filter((note) =>
    note.title.toLowerCase().includes(searchQuery.toLowerCase())
  )

  return (
    <CommandDialog open={open} onOpenChange={setOpen}>
      <CommandInput
        placeholder="Search notes, folders, or run a command..."
        value={searchQuery}
        onValueChange={setSearchQuery}
      />
      <CommandList>
        <CommandEmpty>No results found.</CommandEmpty>

        {/* Actions */}
        <CommandGroup heading="Actions">
          <CommandItem
            onSelect={() =>
              handleCommand(async () => {
                try {
                  const newNote = await createNote({
                    title: 'Untitled Note',
                    content: '',
                  })
                  selectNote(newNote.id)
                  toast.success('Note created')
                } catch (error) {
                  toast.error('Failed to create note')
                }
              })
            }
          >
            <Plus className="mr-2 h-4 w-4" />
            Create New Note
          </CommandItem>

          {selectedNote && (
            <>
              <CommandItem
                onSelect={() =>
                  handleCommand(async () => {
                    try {
                      const isPinned = !(selectedNote as any).pinned
                      await togglePin(selectedNote.id, isPinned)
                      toast.success(isPinned ? 'Note pinned' : 'Note unpinned')
                    } catch (error) {
                      toast.error('Failed to toggle pin')
                    }
                  })
                }
              >
                <Pin className="mr-2 h-4 w-4" />
                {(selectedNote as any).pinned ? 'Unpin' : 'Pin'} Current Note
              </CommandItem>

              <CommandItem
                onSelect={() =>
                  handleCommand(async () => {
                    try {
                      await moveToTrash(selectedNote.id)
                      toast.success('Note moved to trash')
                    } catch (error) {
                      toast.error('Failed to delete note')
                    }
                  })
                }
              >
                <Trash2 className="mr-2 h-4 w-4" />
                Delete Current Note
              </CommandItem>
            </>
          )}

          <CommandItem onSelect={() => handleCommand(() => navigate({ to: '/settings' }))}>
            <Settings className="mr-2 h-4 w-4" />
            Open Settings
          </CommandItem>

          <CommandItem
            onSelect={() =>
              handleCommand(() => {
                window.dispatchEvent(new CustomEvent('open-keyboard-shortcuts'))
              })
            }
          >
            <Search className="mr-2 h-4 w-4" />
            Show Keyboard Shortcuts
          </CommandItem>
        </CommandGroup>

        {/* Notes */}
        {filteredNotes.length > 0 && (
          <>
            <CommandSeparator />
            <CommandGroup heading="Notes">
              {filteredNotes.slice(0, 8).map((note) => (
                <CommandItem
                  key={note.id}
                  onSelect={() =>
                    handleCommand(() => {
                      selectNote(note.id)
                      navigate({ to: '/' })
                    })
                  }
                >
                  <FileText className="mr-2 h-4 w-4" />
                  {note.title}
                </CommandItem>
              ))}
            </CommandGroup>
          </>
        )}

        {/* Folders */}
        {folders.length > 0 && (
          <>
            <CommandSeparator />
            <CommandGroup heading="Folders">
              {folders.slice(0, 5).map((folder) => (
                <CommandItem
                  key={folder.id}
                  onSelect={() =>
                    handleCommand(() => {
                      // selectFolder(folder.id)
                      navigate({ to: '/' })
                    })
                  }
                >
                  <FolderOpen className="mr-2 h-4 w-4" />
                  {folder.name}
                </CommandItem>
              ))}
            </CommandGroup>
          </>
        )}

        {/* Tags */}
        {tags.length > 0 && (
          <>
            <CommandSeparator />
            <CommandGroup heading="Tags">
              {tags.slice(0, 5).map((tag) => (
                <CommandItem
                  key={tag.id}
                  onSelect={() =>
                    handleCommand(() => {
                      // filterByTag(tag.name)
                      navigate({ to: '/' })
                    })
                  }
                >
                  <Tag className="mr-2 h-4 w-4" />
                  {tag.name}
                </CommandItem>
              ))}
            </CommandGroup>
          </>
        )}
      </CommandList>
    </CommandDialog>
  )
}
