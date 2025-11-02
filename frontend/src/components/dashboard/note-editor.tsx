/* eslint-disable react-hooks/set-state-in-effect */
import { useEffect, useRef, useState } from 'react'
import { useNotesStore } from '../../stores/notesStore'
import { useCollaboration } from '@/lib/collaboration-context'
import { useEncryption } from '@/lib/encryption-context'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import {
  Lock,
  TagIcon,
  Share2,
  MoreVertical,
  Trash2,
  Copy,
  FileText,
  X,
  Plus,
  ShieldCheck,
  Pin,
  // History,
} from 'lucide-react'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { SaveTemplateDialog } from './save-template-dialog'
import { ShareNoteDialog } from './share-note-dialog'
// Temporarily disable collaboration bar to isolate post-login crash
import { EncryptionUnlockDialog } from './encryption-unlock-dialog'
import { Alert, AlertDescription } from '@/components/ui/alert'
// import { NoteStats } from './note-stats'
// Temporarily disable keyboard shortcuts dialog to isolate React ref error after login
// import { BacklinksSection } from './note-linking-utils'
// Temporarily disable version history dialog to isolate post-login crash
import { RichTextEditor } from './rich-text-editor'

export function NoteEditor() {
  const { selectedNote, updateNote, moveToTrash, selectNote, tags, createTag } = useNotesStore()
  const { joinSession, leaveSession } = useCollaboration()
  const { isUnlocked, encryptText, decryptText, encryptionVersion } = useEncryption()
  const [title, setTitle] = useState('')
  const [_content, setContent] = useState('')
  const [displayContent, setDisplayContent] = useState('')
  const [noteTags, setNoteTags] = useState<string[]>([])
  const [isAddingTag, setIsAddingTag] = useState(false)
  const [newTagName, setNewTagName] = useState('')
  const [isSaveTemplateOpen, setIsSaveTemplateOpen] = useState(false)
  const [isShareOpen, setIsShareOpen] = useState(false)
  const [isUnlockDialogOpen, setIsUnlockDialogOpen] = useState(false)
  const [isDecrypting, setIsDecrypting] = useState(false)
  const [decryptError, setDecryptError] = useState('')
  // Prevent autosave from running while we are programmatically syncing decrypted content
  const isSyncingRef = useRef<{ syncing: boolean }>({ syncing: false })
  // Baseline of decrypted content to detect first user edit
  const decryptedBaselineRef = useRef<{ title: string; content: string }>({
    title: '',
    content: '',
  })
  const userEditedRef = useRef<boolean>(false)
  const saveTimeoutRef = useRef<number | null>(null)
  const mountedRef = useRef<boolean>(false)
  const lastSavedRef = useRef<{ title: string; content: string; tagsKey: string }>({
    title: '',
    content: '',
    tagsKey: '',
  })

  const handleDelete = () => {
    if (selectedNote) {
      moveToTrash(selectedNote.id)
      selectNote(null)
      toast.success('Note moved to trash', { duration: 2000 })
    }
  }

  const handleTogglePin = async () => {
    if (selectedNote) {
      try {
        await updateNote(selectedNote.id, { pinned: !selectedNote.pinned })
      } catch (error) {
        console.error('Failed to toggle pin:', error)
      }
    }
  }

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (!selectedNote) return

      const isMac = navigator.platform.toUpperCase().indexOf('MAC') >= 0
      const modifier = isMac ? e.metaKey : e.ctrlKey

      if (modifier && e.key === 's') {
        e.preventDefault()
        // Auto-save is handled by the store, just show feedback
        console.log('Note saved')
      } else if (modifier && e.key === 'p') {
        e.preventDefault()
        handleTogglePin()
      } else if (modifier && e.key === 'd') {
        e.preventDefault()
        handleDelete()
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [selectedNote])

  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
      if (saveTimeoutRef.current) {
        clearTimeout(saveTimeoutRef.current)
        saveTimeoutRef.current = null
      }
    }
  }, [])

  useEffect(() => {
    if (selectedNote) {
      console.log('[Editor] selection changed to note', selectedNote.id)
      setNoteTags(selectedNote.tags || [])
      // Don't auto-join collaboration session - only join when Share button is clicked

      // Always decrypt title and content since all notes are encrypted
      if (isUnlocked) {
        setIsDecrypting(true)
        setDecryptError('')

        const decryptData = async () => {
          try {
            isSyncingRef.current.syncing = true
            console.log('[Editor] decrypt start', selectedNote.id)
            // Decrypt title
            const decryptedTitle = selectedNote.title ? await decryptText(selectedNote.title) : ''
            if (decryptedTitle !== title) {
              setTitle(decryptedTitle)
            }

            // Decrypt content if it exists
            if (selectedNote.content) {
              const decryptedContent = await decryptText(selectedNote.content)
              if (decryptedContent !== _content) {
                setContent(decryptedContent)
              }
              if (decryptedContent !== displayContent) {
                setDisplayContent(decryptedContent)
              }
            } else {
              if (_content !== '') setContent('')
              if (displayContent !== '') setDisplayContent('')
            }

            // Update decrypted baseline and clear user-edited flag
            decryptedBaselineRef.current = {
              title: selectedNote.title ? await decryptText(selectedNote.title) : '',
              content: selectedNote.content ? await decryptText(selectedNote.content) : '',
            }
            userEditedRef.current = false

            // Initialize last saved snapshot to the freshly decrypted state to avoid immediate autosave
            const trimmedTitle = (decryptedTitle || '').trim()
            const trimmedContent = (
              selectedNote.content ? await decryptText(selectedNote.content) : displayContent || ''
            ).trim()
            const tagsKey = (selectedNote.tags || []).slice().sort().join('|')
            lastSavedRef.current.title = trimmedTitle
            lastSavedRef.current.content = trimmedContent
            lastSavedRef.current.tagsKey = tagsKey

            setIsDecrypting(false)
            isSyncingRef.current.syncing = false
            console.log('[Editor] decrypt done', selectedNote.id)
          } catch (err) {
            console.error('[v0] Decryption failed:', err)
            setDecryptError('Failed to decrypt note. The password may be incorrect.')
            if (title !== '') setTitle('')
            if (_content !== '') setContent('')
            if (displayContent !== '') setDisplayContent('')
            setIsDecrypting(false)
            isSyncingRef.current.syncing = false
            console.log('[Editor] decrypt failed', selectedNote.id)
          }
        }

        decryptData()
      } else {
        setIsUnlockDialogOpen(true)
        if (title !== '') setTitle('')
        if (_content !== '') setContent('')
        if (displayContent !== '') setDisplayContent('')
        decryptedBaselineRef.current = { title: '', content: '' }
        userEditedRef.current = false
      }

      // Don't automatically leave collaboration session
      // Only leave when explicitly sharing or closing
    }
  }, [selectedNote?.id, isUnlocked])

  useEffect(() => {
    if (selectedNote && displayContent !== undefined) {
      if (saveTimeoutRef.current) {
        clearTimeout(saveTimeoutRef.current)
        saveTimeoutRef.current = null
      }

      const scheduledNoteId = selectedNote.id
      const timeoutId = window.setTimeout(async () => {
        try {
          if (!mountedRef.current) return
          // Guard clause: only save if we have a valid selected note
          if (!selectedNote?.id) {
            return
          }

          // Don't save while decrypting to avoid race conditions
          if (isDecrypting || isSyncingRef.current.syncing) {
            return
          }

          // Only save after the user has actually edited content vs decrypted baseline
          if (!userEditedRef.current) {
            return
          }

          // If selection changed since scheduling, skip this save
          if (selectedNote.id !== scheduledNoteId) {
            return
          }

          // Skip saving if both title and content are empty
          const trimmedTitle = title.trim()
          const trimmedContent = displayContent.trim()

          if (!trimmedTitle && !trimmedContent) {
            // Don't save empty notes - show info toast
            toast.info('Empty notes are not saved automatically', { duration: 2000 })
            return
          }

          // Skip if unchanged vs last saved snapshot (by plaintext)
          const tagsKey = (noteTags || []).slice().sort().join('|')
          if (
            lastSavedRef.current.title === trimmedTitle &&
            lastSavedRef.current.content === trimmedContent &&
            lastSavedRef.current.tagsKey === tagsKey
          ) {
            return
          }

          // Always encrypt title and content before saving
          if (isUnlocked) {
            const encryptedTitle = await encryptText(title)
            const encryptedContent = await encryptText(displayContent)
            console.log('[Editor] autosave -> updateNote', selectedNote.id)

            await updateNote(selectedNote.id, {
              title: encryptedTitle,
              content: encryptedContent,
              tags: noteTags,
              encrypted: true,
              encryptionVersion,
            })
            // Show success toast only if note was saved to API
            if (!selectedNote.id.startsWith('local-')) {
              toast.success('Note saved', { duration: 2000 })
            }
            console.log('[Editor] autosave complete', selectedNote.id)

            // Update last saved snapshot
            lastSavedRef.current.title = trimmedTitle
            lastSavedRef.current.content = trimmedContent
            lastSavedRef.current.tagsKey = tagsKey
          } else {
            // If not unlocked, don't save
            return
          }
        } catch (err) {
          console.error('[Editor] Failed to save note:', err)
          toast.error('Failed to save note', { duration: 3000 })
        }
      }, 500)

      saveTimeoutRef.current = timeoutId
      return () => {
        if (saveTimeoutRef.current) {
          clearTimeout(saveTimeoutRef.current)
          saveTimeoutRef.current = null
        }
      }
    }
  }, [title, displayContent, noteTags, selectedNote?.id])

  const handleUnlock = () => {
    // Trigger re-decryption by updating the effect dependency
    if (selectedNote) {
      setIsDecrypting(true)
    }
  }

  const handleAddTag = (tagName: string) => {
    if (!noteTags.includes(tagName)) {
      setNoteTags([...noteTags, tagName])
    }
    setIsAddingTag(false)
  }

  const handleCreateAndAddTag = async () => {
    if (newTagName.trim()) {
      const tag = await createTag({ name: newTagName.trim() })
      handleAddTag(tag.name)
      setNewTagName('')
    }
  }

  const handleRemoveTag = (tagName: string) => {
    setNoteTags(noteTags.filter((t) => t !== tagName))
  }

  if (!selectedNote) {
    return (
      <div className="flex-1 flex items-center justify-center text-muted-foreground">
        <div className="text-center space-y-2">
          <FileText className="h-16 w-16 mx-auto opacity-50" />
          <p className="text-lg">Select a note to start editing</p>
          <p className="text-sm">Or create a new one from the sidebar</p>
        </div>
      </div>
    )
  }

  if (selectedNote.encrypted && !isUnlocked) {
    return (
      <>
        <div className="flex-1 flex items-center justify-center text-muted-foreground">
          <div className="text-center space-y-4 max-w-md">
            <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center mx-auto">
              <Lock className="h-8 w-8 text-primary" />
            </div>
            <div className="space-y-2">
              <h3 className="text-lg font-semibold text-foreground">This note is encrypted</h3>
              <p className="text-sm">Enter your encryption password to view and edit this note.</p>
            </div>
            <Button onClick={() => setIsUnlockDialogOpen(true)} className="gap-2">
              <ShieldCheck className="h-4 w-4" />
              Unlock Note
            </Button>
          </div>
        </div>
        <EncryptionUnlockDialog
          open={isUnlockDialogOpen}
          onOpenChange={setIsUnlockDialogOpen}
          onUnlock={handleUnlock}
        />
      </>
    )
  }

  return (
    <div className="flex-1 flex flex-col h-full">
      {/* <CollaborationBar noteId={selectedNote.id} /> */}

      {/* Toolbar - Responsive */}
      <div className="border-b border-border p-2 sm:p-4 flex items-center justify-between gap-2 sm:gap-4">
        <div className="flex items-center gap-2 flex-1 flex-wrap">
          <Button
            variant={selectedNote.pinned ? 'default' : 'outline'}
            size="sm"
            onClick={handleTogglePin}
            className="gap-2"
          >
            <Pin className="h-4 w-4" />
            {selectedNote.pinned ? 'Pinned' : 'Pin'}
          </Button>

          {/* Versions temporarily disabled */}

          <Dialog open={isAddingTag} onOpenChange={setIsAddingTag}>
            <DialogTrigger asChild>
              <Button variant="outline" size="sm" className="gap-2 bg-transparent">
                <TagIcon className="h-4 w-4" />
                Add Tag
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Add Tags</DialogTitle>
              </DialogHeader>
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label>Existing Tags</Label>
                  <div className="flex flex-wrap gap-2">
                    {(tags || []).map((tag) => (
                      <Button
                        key={tag.id}
                        variant={noteTags.includes(tag.name) ? 'default' : 'outline'}
                        size="sm"
                        onClick={() => handleAddTag(tag.name)}
                      >
                        {tag.name}
                      </Button>
                    ))}
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="new-tag">Create New Tag</Label>
                  <div className="flex gap-2">
                    <Input
                      id="new-tag"
                      value={newTagName}
                      onChange={(e) => setNewTagName(e.target.value)}
                      placeholder="Tag name"
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') {
                          handleCreateAndAddTag()
                        }
                      }}
                    />
                    <Button onClick={handleCreateAndAddTag}>
                      <Plus className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              </div>
            </DialogContent>
          </Dialog>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            className="gap-2 bg-transparent"
            onClick={() => {
              setIsShareOpen(true)
              // Join collaboration session when Share button is clicked
              if (selectedNote) {
                joinSession(selectedNote.id)
              }
            }}
          >
            <Share2 className="h-4 w-4" />
            Share
          </Button>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm">
                <MoreVertical className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem>
                <Copy className="h-4 w-4 mr-2" />
                Duplicate
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => setIsSaveTemplateOpen(true)}>
                <FileText className="h-4 w-4 mr-2" />
                Save as Template
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={handleDelete} className="text-danger">
                <Trash2 className="h-4 w-4 mr-2" />
                Move to Trash
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      {/* Editor */}
      <div className="flex-1 flex flex-col p-6 overflow-auto">
        {selectedNote.encrypted && (
          <Alert className="mb-4">
            <ShieldCheck className="h-4 w-4" />
            <AlertDescription className="text-xs">
              This note is end-to-end encrypted. Your content is secure and only you can read it.
            </AlertDescription>
          </Alert>
        )}

        {decryptError && (
          <Alert variant="destructive" className="mb-4">
            <AlertDescription className="text-xs">{decryptError}</AlertDescription>
          </Alert>
        )}

        <Input
          value={title}
          onChange={(e) => {
            setTitle(e.target.value)
          }}
          placeholder="Add Title"
          className="text-3xl font-bold mb-4"
          disabled={isDecrypting}
        />

        {/* Tags */}
        {noteTags.length > 0 && (
          <div className="flex flex-wrap gap-2 mb-4">
            {noteTags.map((tag) => (
              <Badge key={tag} variant="secondary" className="gap-1">
                <TagIcon className="h-3 w-3" />
                {tag}
                <button onClick={() => handleRemoveTag(tag)} className="ml-1 hover:text-danger">
                  <X className="h-3 w-3" />
                </button>
              </Badge>
            ))}
          </div>
        )}

        <div className="flex-1 overflow-auto">
          <RichTextEditor
            content={displayContent}
            onChange={(html) => {
              if (html !== displayContent) {
                setDisplayContent(html)
                // Mark as user-edited when diverging from decrypted baseline
                if (html.trim() !== (decryptedBaselineRef.current.content || '').trim()) {
                  userEditedRef.current = true
                }
              }
            }}
            placeholder="Start writing your note..."
          />
        </div>

        {/* NoteStats temporarily disabled to isolate update loop */}
        {/* <div className="mt-4 pt-4 border-t border-border">
          <NoteStats content={displayContent} />
        </div> */}

        {/* BacklinksSection temporarily disabled to isolate update loop */}
        {/* <BacklinksSection currentNoteId={selectedNote.id} onNoteSelect={selectNote} /> */}
      </div>

      {/* Save Template Dialog */}
      <SaveTemplateDialog
        open={isSaveTemplateOpen}
        onOpenChange={setIsSaveTemplateOpen}
        content={displayContent}
        tags={noteTags}
      />

      <ShareNoteDialog
        open={isShareOpen}
        onOpenChange={(open) => {
          setIsShareOpen(open)
          // Leave collaboration session when Share dialog is closed
          if (!open && selectedNote) {
            leaveSession(selectedNote.id)
          }
        }}
        noteId={selectedNote.id}
      />

      <EncryptionUnlockDialog
        open={isUnlockDialogOpen}
        onOpenChange={setIsUnlockDialogOpen}
        onUnlock={handleUnlock}
      />
    </div>
  )
}
