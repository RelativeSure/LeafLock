'use client'

import { FileText, Clock, Hash } from 'lucide-react'

interface NoteStatsProps {
  content: string
}

export function NoteStats({ content }: NoteStatsProps) {
  // Strip HTML tags for accurate word count
  const textContent = content
    .replace(/<[^>]*>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()

  const wordCount = textContent ? textContent.split(/\s+/).length : 0
  const charCount = textContent.length
  const readingTime = Math.ceil(wordCount / 200) // Average reading speed: 200 words/min

  return (
    <div className="flex items-center gap-4 text-xs text-muted-foreground">
      <div className="flex items-center gap-1">
        <FileText className="h-3 w-3" />
        <span>{wordCount} words</span>
      </div>
      <div className="flex items-center gap-1">
        <Hash className="h-3 w-3" />
        <span>{charCount} characters</span>
      </div>
      <div className="flex items-center gap-1">
        <Clock className="h-3 w-3" />
        <span>{readingTime} min read</span>
      </div>
    </div>
  )
}
