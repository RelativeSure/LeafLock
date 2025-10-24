/* eslint-disable react-hooks/set-state-in-effect */
import { useEffect, useState } from "react"
import { useNotesStore } from "@/stores"
import { useCollaboration } from "@/lib/collaboration-context"
import { useEncryption } from "@/lib/encryption-context"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import {
  Lock,
  Unlock,
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
} from "lucide-react"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Label } from "@/components/ui/label"
import { SaveTemplateDialog } from "./save-template-dialog"
import { ShareNoteDialog } from "./share-note-dialog"
import { CollaborationBar } from "./collaboration-bar"
import { EncryptionUnlockDialog } from "./encryption-unlock-dialog"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { RichTextEditor } from "./rich-text-editor"
import { NoteStats } from "./note-stats"
import { KeyboardShortcutsDialog } from "./keyboard-shortcuts-dialog"

export function NoteEditor() {
  const { selectedNote, updateNote, moveToTrash, selectNote, tags, createTag } = useNotesStore()
  const { joinSession, leaveSession } = useCollaboration()
  const { isUnlocked, encryptText, decryptText } = useEncryption()
  const [title, setTitle] = useState("")
  const [_content, setContent] = useState("")
  const [displayContent, setDisplayContent] = useState("")
  const [noteTags, setNoteTags] = useState<string[]>([])
  const [isAddingTag, setIsAddingTag] = useState(false)
  const [newTagName, setNewTagName] = useState("")
  const [isSaveTemplateOpen, setIsSaveTemplateOpen] = useState(false)
  const [isShareOpen, setIsShareOpen] = useState(false)
  const [isUnlockDialogOpen, setIsUnlockDialogOpen] = useState(false)
  const [isDecrypting, setIsDecrypting] = useState(false)
  const [decryptError, setDecryptError] = useState("")

  const handleDelete = () => {
    if (selectedNote) {
      moveToTrash(selectedNote.id)
      selectNote(null)
    }
  }

  const handleTogglePin = async () => {
    if (selectedNote) {
      try {
        await updateNote(selectedNote.id, { pinned: !selectedNote.pinned })
      } catch (error) {
        console.error("Failed to toggle pin:", error)
      }
    }
  }

  const handleToggleEncryption = async () => {
    if (!selectedNote) return

    if (!selectedNote.encrypted) {
      // Enabling encryption
      if (!isUnlocked) {
        setIsUnlockDialogOpen(true)
        return
      }

      try {
        const encryptedContent = await encryptText(displayContent)
        await updateNote(selectedNote.id, { encrypted: true, content: encryptedContent })
      } catch (err) {
        console.error("[v0] Failed to encrypt:", err)
      }
    } else {
      // Disabling encryption
      try {
        await updateNote(selectedNote.id, { encrypted: false, content: displayContent })
      } catch (err) {
        console.error("[v0] Failed to disable encryption:", err)
      }
    }
  }

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (!selectedNote) return

      const isMac = navigator.platform.toUpperCase().indexOf("MAC") >= 0
      const modifier = isMac ? e.metaKey : e.ctrlKey

      if (modifier && e.key === "p") {
        e.preventDefault()
        handleTogglePin()
      } else if (modifier && e.key === "e") {
        e.preventDefault()
        handleToggleEncryption()
      } else if (modifier && e.key === "d") {
        e.preventDefault()
        handleDelete()
      }
    }

    window.addEventListener("keydown", handleKeyDown)
    return () => window.removeEventListener("keydown", handleKeyDown)
  }, [selectedNote])

  useEffect(() => {
    if (selectedNote) {
      setTitle(selectedNote.title)
      setNoteTags(selectedNote.tags)
      joinSession(selectedNote.id)

      // Handle encrypted notes
      if (selectedNote.encrypted && selectedNote.content) {
        if (isUnlocked) {
          setIsDecrypting(true)
          setDecryptError("")
          decryptText(selectedNote.content)
            .then((decrypted) => {
              setContent(decrypted)
              setDisplayContent(decrypted)
              setIsDecrypting(false)
            })
            .catch((err) => {
              console.error("[v0] Decryption failed:", err)
              setDecryptError("Failed to decrypt note. The password may be incorrect.")
              setContent("")
              setDisplayContent("")
              setIsDecrypting(false)
            })
        } else {
          setIsUnlockDialogOpen(true)
          setContent("")
          setDisplayContent("")
        }
      } else {
        setContent(selectedNote.content)
        setDisplayContent(selectedNote.content)
      }

      return () => {
        leaveSession(selectedNote.id)
      }
    }
  }, [selectedNote, isUnlocked])

  useEffect(() => {
    if (selectedNote && displayContent !== undefined) {
      const timeoutId = setTimeout(async () => {
        try {
          let contentToSave = displayContent

          // Encrypt content if note is marked as encrypted
          if (selectedNote.encrypted && isUnlocked) {
            contentToSave = await encryptText(displayContent)
          }

          await updateNote(selectedNote.id, { title, content: contentToSave, tags: noteTags })
        } catch (err) {
          console.error("[v0] Failed to save note:", err)
        }
      }, 500)

      return () => clearTimeout(timeoutId)
    }
  }, [title, displayContent, noteTags])

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
      setNewTagName("")
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
      <CollaborationBar noteId={selectedNote.id} />

      {/* Toolbar */}
      <div className="border-b border-border p-4 flex items-center justify-between gap-4">
        <div className="flex items-center gap-2 flex-1 flex-wrap">
          <Button
            variant={selectedNote.pinned ? "default" : "outline"}
            size="sm"
            onClick={handleTogglePin}
            className="gap-2"
          >
            <Pin className="h-4 w-4" />
            {selectedNote.pinned ? "Pinned" : "Pin"}
          </Button>

          <Button
            variant={selectedNote.encrypted ? "default" : "outline"}
            size="sm"
            onClick={handleToggleEncryption}
            className="gap-2"
          >
            {selectedNote.encrypted ? (
              <>
                <Lock className="h-4 w-4" />
                Encrypted
              </>
            ) : (
              <>
                <Unlock className="h-4 w-4" />
                Not Encrypted
              </>
            )}
          </Button>

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
                    {tags.map((tag) => (
                      <Button
                        key={tag.id}
                        variant={noteTags.includes(tag.name) ? "default" : "outline"}
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
                        if (e.key === "Enter") {
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
          <KeyboardShortcutsDialog />

          <Button variant="outline" size="sm" className="gap-2 bg-transparent" onClick={() => setIsShareOpen(true)}>
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
          onChange={(e) => setTitle(e.target.value)}
          placeholder="Note title..."
          className="text-3xl font-bold border-none shadow-none px-0 mb-4 focus-visible:ring-0"
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

        <RichTextEditor
          content={displayContent}
          onChange={setDisplayContent}
          placeholder={isDecrypting ? "Decrypting..." : "Start writing..."}
          disabled={isDecrypting}
        />

        <div className="mt-4 pt-4 border-t border-border">
          <NoteStats content={displayContent} />
        </div>
      </div>

      {/* Save Template Dialog */}
      <SaveTemplateDialog
        open={isSaveTemplateOpen}
        onOpenChange={setIsSaveTemplateOpen}
        content={displayContent}
        tags={noteTags}
      />

      <ShareNoteDialog open={isShareOpen} onOpenChange={setIsShareOpen} noteId={selectedNote.id} />

      <EncryptionUnlockDialog open={isUnlockDialogOpen} onOpenChange={setIsUnlockDialogOpen} onUnlock={handleUnlock} />
    </div>
  )
}
