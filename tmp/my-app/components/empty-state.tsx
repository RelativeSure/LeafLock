"use client"

import { Button } from "@/components/ui/button"
import { Plus, FileText } from "lucide-react"

interface EmptyStateProps {
  onCreateNote: () => void
  hasNotes: boolean
}

export function EmptyState({ onCreateNote, hasNotes }: EmptyStateProps) {
  return (
    <div className="flex items-center justify-center min-h-[60vh]">
      <div className="text-center max-w-md">
        <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-primary/10 mb-6">
          <FileText className="h-8 w-8 text-primary" />
        </div>

        <h2 className="text-2xl font-serif font-semibold mb-3 text-foreground">
          {hasNotes ? "No notes found" : "Start your first note"}
        </h2>

        <p className="text-muted-foreground mb-6 text-pretty">
          {hasNotes
            ? "Try adjusting your search or create a new note."
            : "Capture your thoughts, ideas, and inspirations in a beautiful, distraction-free space."}
        </p>

        <Button onClick={onCreateNote} size="lg" className="gap-2">
          <Plus className="h-5 w-5" />
          {hasNotes ? "Create Note" : "Choose a Template"}
        </Button>
      </div>
    </div>
  )
}
