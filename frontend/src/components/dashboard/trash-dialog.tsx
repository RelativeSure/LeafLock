import { useState, useEffect } from 'react'
import { useNotesStore } from '@/stores'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { Trash2, RotateCcw, X } from 'lucide-react'
import { ScrollArea } from '@/components/ui/scroll-area'
import { formatDistanceToNow } from 'date-fns'
import { useToast } from '@/hooks/use-toast'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog'

export function TrashDialog() {
  const { getTrashedNotes, restoreFromTrash, deleteNote, emptyTrash } = useNotesStore()
  const { toast } = useToast()
  const [trashedNotes, setTrashedNotes] = useState<any[]>([])
  const [_isLoading, setIsLoading] = useState(false)

  useEffect(() => {
    loadTrashedNotes()
  }, [])

  const loadTrashedNotes = async () => {
    try {
      const notes = await getTrashedNotes()
      setTrashedNotes(Array.isArray(notes) ? notes : [])
    } catch (error) {
      console.error('Failed to load trashed notes:', error)
      setTrashedNotes([])
    }
  }

  const handleRestore = async (noteId: string, noteTitle: string) => {
    try {
      await restoreFromTrash(noteId)
      await loadTrashedNotes() // Reload the list
      toast('Note restored', {
        description: `"${noteTitle}" has been restored.`,
      })
    } catch (error) {
      console.error('Failed to restore note:', error)
      toast('Error', {
        description: 'Failed to restore note.',
      })
    }
  }

  const handleDelete = async (noteId: string, noteTitle: string) => {
    try {
      await deleteNote(noteId)
      await loadTrashedNotes() // Reload the list
      toast('Note deleted permanently', {
        description: `"${noteTitle}" has been permanently deleted.`,
      })
    } catch (error) {
      console.error('Failed to delete note:', error)
      toast('Error', {
        description: 'Failed to delete note.',
      })
    }
  }

  const handleEmptyTrash = async () => {
    try {
      setIsLoading(true)
      await emptyTrash()
      await loadTrashedNotes() // Reload the list
      toast('Trash emptied', {
        description: 'All notes in trash have been permanently deleted.',
      })
    } catch (error) {
      console.error('Failed to empty trash:', error)
      toast('Error', {
        description: 'Failed to empty trash.',
      })
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button variant="outline" className="gap-2 bg-transparent">
          <Trash2 className="h-4 w-4" />
          Trash ({trashedNotes.length})
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Trash</DialogTitle>
          <DialogDescription>
            Notes in trash will be kept for 30 days before being permanently deleted.
          </DialogDescription>
        </DialogHeader>

        {trashedNotes.length === 0 ? (
          <div className="text-center py-8 text-muted-foreground">
            <Trash2 className="h-12 w-12 mx-auto mb-2 opacity-50" />
            <p>Trash is empty</p>
          </div>
        ) : (
          <>
            <ScrollArea className="max-h-[400px]">
              <div className="space-y-2">
                {(trashedNotes || []).map((note) => (
                  <div
                    key={note.id}
                    className="p-3 rounded-lg border border-border hover:bg-accent transition-smooth"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex-1 min-w-0">
                        <h3 className="font-medium mb-1 truncate">{note.title}</h3>
                        <p className="text-sm text-muted-foreground line-clamp-2 mb-2">
                          {note.content || 'No content'}
                        </p>
                        <span className="text-xs text-muted-foreground">
                          Deleted{' '}
                          {note.trashedAt ? formatDistanceToNow(new Date(note.trashedAt), { addSuffix: true }) : 'Unknown'}
                        </span>
                      </div>
                      <div className="flex gap-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleRestore(note.id, note.title)}
                          className="gap-1"
                        >
                          <RotateCcw className="h-3 w-3" />
                          Restore
                        </Button>
                        <AlertDialog>
                          <AlertDialogTrigger asChild>
                            <Button variant="ghost" size="sm" className="text-destructive">
                              <X className="h-3 w-3" />
                            </Button>
                          </AlertDialogTrigger>
                          <AlertDialogContent>
                            <AlertDialogHeader>
                              <AlertDialogTitle>Delete permanently?</AlertDialogTitle>
                              <AlertDialogDescription>
                                This action cannot be undone. This will permanently delete "
                                {note.title}".
                              </AlertDialogDescription>
                            </AlertDialogHeader>
                            <AlertDialogFooter>
                              <AlertDialogCancel>Cancel</AlertDialogCancel>
                              <AlertDialogAction onClick={() => handleDelete(note.id, note.title)}>
                                Delete
                              </AlertDialogAction>
                            </AlertDialogFooter>
                          </AlertDialogContent>
                        </AlertDialog>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>

            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button variant="destructive" className="w-full gap-2">
                  <Trash2 className="h-4 w-4" />
                  Empty Trash ({trashedNotes.length})
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>Empty trash?</AlertDialogTitle>
                  <AlertDialogDescription>
                    This will permanently delete all {trashedNotes.length} notes in trash. This
                    action cannot be undone.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                  <AlertDialogAction onClick={handleEmptyTrash}>Empty Trash</AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}
