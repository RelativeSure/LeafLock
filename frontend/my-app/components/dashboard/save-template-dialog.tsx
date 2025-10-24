"use client"

import { useState } from "react"
import { useTemplates } from "@/lib/templates-context"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Switch } from "@/components/ui/switch"
import { Badge } from "@/components/ui/badge"
import { FileText, Globe, TagIcon, X } from "lucide-react"

interface SaveTemplateDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  content: string
  tags: string[]
}

export function SaveTemplateDialog({ open, onOpenChange, content, tags }: SaveTemplateDialogProps) {
  const { createTemplate } = useTemplates()
  const [name, setName] = useState("")
  const [isPublic, setIsPublic] = useState(false)
  const [selectedTags, setSelectedTags] = useState<string[]>(tags)

  const handleSave = () => {
    if (name.trim()) {
      createTemplate({
        name: name.trim(),
        content,
        tags: selectedTags,
        isPublic,
      })
      setName("")
      setIsPublic(false)
      setSelectedTags([])
      onOpenChange(false)
    }
  }

  const handleRemoveTag = (tag: string) => {
    setSelectedTags(selectedTags.filter((t) => t !== tag))
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            Save as Template
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="template-name">Template Name</Label>
            <Input
              id="template-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="My Template"
              autoFocus
            />
          </div>

          {selectedTags.length > 0 && (
            <div className="space-y-2">
              <Label>Tags</Label>
              <div className="flex flex-wrap gap-2">
                {selectedTags.map((tag) => (
                  <Badge key={tag} variant="secondary" className="gap-1">
                    <TagIcon className="h-3 w-3" />
                    {tag}
                    <button onClick={() => handleRemoveTag(tag)} className="ml-1 hover:text-danger">
                      <X className="h-3 w-3" />
                    </button>
                  </Badge>
                ))}
              </div>
            </div>
          )}

          <div className="flex items-center justify-between p-3 border border-border rounded-lg">
            <div className="flex items-center gap-3">
              <Globe className="h-5 w-5 text-muted" />
              <div>
                <p className="text-sm font-medium">Share Publicly</p>
                <p className="text-xs text-muted-foreground">Make this template available to everyone</p>
              </div>
            </div>
            <Switch checked={isPublic} onCheckedChange={setIsPublic} />
          </div>

          <div className="flex gap-2">
            <Button onClick={handleSave} className="flex-1" disabled={!name.trim()}>
              Save Template
            </Button>
            <Button variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
