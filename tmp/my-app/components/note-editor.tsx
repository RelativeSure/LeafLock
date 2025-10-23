"use client"

import { useState } from "react"
import type { Note } from "@/app/notes/page"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Badge } from "@/components/ui/badge"
import { X, Tag, Trash2 } from "lucide-react"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"

interface NoteEditorProps {
  note: Note
  onUpdate: (note: Note) => void
  onClose: () => void
  onDelete: () => void
}

export function NoteEditor({ note, onUpdate, onClose, onDelete }: NoteEditorProps) {
  const [title, setTitle] = useState(note.title)
  const [content, setContent] = useState(note.content)
  const [tags, setTags] = useState<string[]>(note.tags)
  const [newTag, setNewTag] = useState("")
  const [showTagDialog, setShowTagDialog] = useState(false)

  const handleSave = () => {
    onUpdate({
      ...note,
      title,
      content,
      tags,
    })
  }

  const addTag = () => {
    if (newTag.trim() && !tags.includes(newTag.trim())) {
      const updatedTags = [...tags, newTag.trim()]
      setTags(updatedTags)
      setNewTag("")
      onUpdate({
        ...note,
        title,
        content,
        tags: updatedTags,
      })
    }
  }

  const removeTag = (tagToRemove: string) => {
    const updatedTags = tags.filter((tag) => tag !== tagToRemove)
    setTags(updatedTags)
    onUpdate({
      ...note,
      title,
      content,
      tags: updatedTags,
    })
  }

  return (
    <div className="h-full flex flex-col bg-background">
      {/* Editor Header */}
      <div className="border-b border-border bg-card px-8 py-4">
        <div className="flex items-center justify-between mb-4">
          <Button variant="ghost" onClick={onClose} className="gap-2">
            <X className="h-4 w-4" />
            Close
          </Button>

          <div className="flex items-center gap-2">
            <Dialog open={showTagDialog} onOpenChange={setShowTagDialog}>
              <DialogTrigger asChild>
                <Button variant="outline" size="sm" className="gap-2 bg-transparent">
                  <Tag className="h-4 w-4" />
                  Tags
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Manage Tags</DialogTitle>
                </DialogHeader>
                <div className="space-y-4">
                  <div className="flex gap-2">
                    <Input
                      placeholder="Add a tag..."
                      value={newTag}
                      onChange={(e) => setNewTag(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") {
                          e.preventDefault()
                          addTag()
                        }
                      }}
                    />
                    <Button onClick={addTag}>Add</Button>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {tags.map((tag) => (
                      <Badge key={tag} variant="secondary" className="gap-1.5">
                        {tag}
                        <button onClick={() => removeTag(tag)} className="hover:text-destructive">
                          <X className="h-3 w-3" />
                        </button>
                      </Badge>
                    ))}
                  </div>
                </div>
              </DialogContent>
            </Dialog>

            <Button
              variant="outline"
              size="sm"
              onClick={onDelete}
              className="gap-2 text-destructive hover:text-destructive bg-transparent"
            >
              <Trash2 className="h-4 w-4" />
              Delete
            </Button>
          </div>
        </div>

        <Input
          value={title}
          onChange={(e) => {
            setTitle(e.target.value)
            handleSave()
          }}
          placeholder="Note title..."
          className="text-3xl font-serif font-semibold border-0 px-0 focus-visible:ring-0 bg-transparent"
        />

        {tags.length > 0 && (
          <div className="flex flex-wrap gap-2 mt-3">
            {tags.map((tag) => (
              <Badge key={tag} variant="secondary">
                {tag}
              </Badge>
            ))}
          </div>
        )}
      </div>

      {/* Editor Content */}
      <div className="flex-1 overflow-auto px-8 py-6">
        <Textarea
          value={content}
          onChange={(e) => {
            setContent(e.target.value)
            handleSave()
          }}
          placeholder="Start writing..."
          className="min-h-full text-base leading-relaxed border-0 focus-visible:ring-0 resize-none bg-transparent font-serif"
        />
      </div>
    </div>
  )
}
