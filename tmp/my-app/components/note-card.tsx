"use client"

import type { Note } from "@/app/notes/page"
import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Trash2, MoreVertical } from "lucide-react"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"

interface NoteCardProps {
  note: Note
  onClick: () => void
  onDelete: () => void
}

export function NoteCard({ note, onClick, onDelete }: NoteCardProps) {
  const formatDate = (dateString: string) => {
    const date = new Date(dateString)
    return date.toLocaleDateString("en-US", { month: "short", day: "numeric" })
  }

  const getPreview = (content: string) => {
    const plainText = content.replace(/<[^>]*>/g, "").replace(/\n/g, " ")
    return plainText.slice(0, 120) + (plainText.length > 120 ? "..." : "")
  }

  return (
    <Card
      className="group relative p-5 cursor-pointer hover:shadow-lg transition-all duration-200 border-border bg-card hover:border-primary/20"
      onClick={onClick}
    >
      <div className="absolute top-3 right-3 opacity-0 group-hover:opacity-100 transition-opacity">
        <DropdownMenu>
          <DropdownMenuTrigger asChild onClick={(e) => e.stopPropagation()}>
            <Button variant="ghost" size="icon" className="h-8 w-8">
              <MoreVertical className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem
              onClick={(e) => {
                e.stopPropagation()
                onDelete()
              }}
              className="text-destructive"
            >
              <Trash2 className="h-4 w-4 mr-2" />
              Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      <h3 className="font-serif text-lg font-semibold mb-2 text-foreground text-balance pr-8">{note.title}</h3>

      {note.content && (
        <p className="text-sm text-muted-foreground mb-3 line-clamp-3 text-pretty">{getPreview(note.content)}</p>
      )}

      <div className="flex items-center justify-between mt-4">
        <div className="flex flex-wrap gap-1.5">
          {note.tags.slice(0, 3).map((tag) => (
            <Badge key={tag} variant="secondary" className="text-xs">
              {tag}
            </Badge>
          ))}
          {note.tags.length > 3 && (
            <Badge variant="secondary" className="text-xs">
              +{note.tags.length - 3}
            </Badge>
          )}
        </div>

        <span className="text-xs text-muted-foreground">{formatDate(note.updatedAt)}</span>
      </div>
    </Card>
  )
}
