'use client'

import { useState, useEffect, useRef } from 'react'
import { useNotesStore } from '../../stores/notesStore'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { FileText, Link, ExternalLink, X } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import type { Note } from '@/types'
import { useDecryptedNotes } from '@/hooks/use-decrypted-notes'

interface NoteLinkPreviewProps {
  noteId: string
  onClose: () => void
  onNavigate: (noteId: string) => void
}

export function NoteLinkPreview({ noteId, onClose, onNavigate }: NoteLinkPreviewProps) {
  const { notes } = useNotesStore()
  const [note, setNote] = useState<Note | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const { decryptedNotes, isUnlocked, isDecrypting } = useDecryptedNotes(notes)

  useEffect(() => {
    // Use setTimeout to avoid synchronous setState in effect
    const timeoutId = setTimeout(() => {
      const foundNote = notes.find((n) => n.id === noteId)
      setNote(foundNote || null)
      setIsLoading(false)
    }, 0)

    return () => clearTimeout(timeoutId)
  }, [noteId, notes])

  if (isLoading) {
    return (
      <Card className="max-w-md">
        <CardContent className="p-4">
          <div className="flex items-center justify-center py-4">
            <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary"></div>
          </div>
        </CardContent>
      </Card>
    )
  }

  if (!note) {
    return (
      <Card className="max-w-md">
        <CardContent className="p-4">
          <div className="text-center py-4">
            <FileText className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">Note not found</p>
          </div>
        </CardContent>
      </Card>
    )
  }

  if (!isUnlocked) {
    return (
      <Card className="max-w-md">
        <CardContent className="p-4">
          <div className="text-center py-4 text-muted-foreground">
            <p className="text-sm">Unlock your notes to preview linked content.</p>
          </div>
        </CardContent>
      </Card>
    )
  }

  if (isDecrypting) {
    return (
      <Card className="max-w-md">
        <CardContent className="p-4">
          <div className="flex items-center justify-center py-4">
            <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary"></div>
          </div>
        </CardContent>
      </Card>
    )
  }

  const decrypted = decryptedNotes[note.id]
  const title = decrypted?.title || 'Untitled'
  const contentPreview =
    (decrypted?.content || '')
      .replace(/<[^>]*>/g, ' ')
      .replace(/\s+/g, ' ')
      .trim()
      .substring(0, 150) || 'No content'

  return (
    <Card className="max-w-md">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between">
          <div className="flex-1 min-w-0">
            <CardTitle className="text-sm line-clamp-2">{title}</CardTitle>
            <CardDescription className="text-xs mt-1">
              {note.updatedAt
                ? (() => {
                    try {
                      const date = new Date(note.updatedAt)
                      return isNaN(date.getTime())
                        ? 'Unknown'
                        : formatDistanceToNow(date, { addSuffix: true })
                    } catch {
                      return 'Unknown'
                    }
                  })()
                : 'Unknown'}
            </CardDescription>
          </div>
          <Button variant="ghost" size="sm" onClick={onClose} className="h-6 w-6 p-0 ml-2">
            <X className="h-3 w-3" />
          </Button>
        </div>
      </CardHeader>
      <CardContent className="pt-0">
        <p className="text-xs text-muted-foreground line-clamp-3 mb-3">
          {contentPreview}
          {contentPreview.length >= 150 && '...'}
        </p>

        {note.tags && note.tags.length > 0 && (
          <div className="flex flex-wrap gap-1 mb-3">
            {note.tags.slice(0, 3).map((tag) => (
              <Badge key={tag} variant="outline" className="text-xs">
                {tag}
              </Badge>
            ))}
            {note.tags.length > 3 && (
              <Badge variant="outline" className="text-xs">
                +{note.tags.length - 3}
              </Badge>
            )}
          </div>
        )}

        <div className="flex items-center justify-between">
          <Button variant="outline" size="sm" onClick={() => onNavigate(noteId)} className="gap-2">
            <ExternalLink className="h-3 w-3" />
            Open Note
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

interface NoteLinkingUtilsProps {
  content: string
  onNoteSelect: (noteId: string) => void
}

export function NoteLinkingUtils({ content, onNoteSelect }: NoteLinkingUtilsProps) {
  const { notes } = useNotesStore()
  const { decryptedNotes, isUnlocked } = useDecryptedNotes(notes)
  const [hoveredLink, setHoveredLink] = useState<string | null>(null)
  const [previewPosition, setPreviewPosition] = useState({ x: 0, y: 0 })
  const [showPreview, setShowPreview] = useState(false)
  const hoverTimeoutRef = useRef<NodeJS.Timeout | null>(null)

  // Extract note links from content
  const extractNoteLinks = (text: string) => {
    const linkRegex = /\[\[([^\]]+)\]\]/g
    const links: Array<{ title: string; start: number; end: number }> = []
    let match

    while ((match = linkRegex.exec(text)) !== null) {
      links.push({
        title: match[1],
        start: match.index,
        end: match.index + match[0].length,
      })
    }

    return links
  }

  // Find note by title (case-insensitive)
  const findNoteByTitle = (title: string) => {
    if (!isUnlocked) return undefined
    const normalized = title.toLowerCase()
    return notes.find((note) => decryptedNotes[note.id]?.title?.toLowerCase() === normalized)
  }

  // Handle link hover
  const handleLinkHover = (event: React.MouseEvent, noteTitle: string) => {
    const note = findNoteByTitle(noteTitle)
    if (!note) return

    setHoveredLink(noteTitle)
    setPreviewPosition({
      x: event.clientX + 10,
      y: event.clientY - 10,
    })
    setShowPreview(true)

    // Clear existing timeout
    if (hoverTimeoutRef.current) {
      clearTimeout(hoverTimeoutRef.current)
    }
  }

  // Handle link leave
  const handleLinkLeave = () => {
    hoverTimeoutRef.current = setTimeout(() => {
      setShowPreview(false)
      setHoveredLink(null)
    }, 200)
  }

  // Handle link click
  const handleLinkClick = (noteTitle: string) => {
    const note = findNoteByTitle(noteTitle)
    if (note) {
      onNoteSelect(note.id)
    }
  }

  // Render content with note links
  const renderContentWithLinks = () => {
    const links = extractNoteLinks(content)
    if (links.length === 0) {
      return <div dangerouslySetInnerHTML={{ __html: content }} />
    }

    let result = ''
    let lastIndex = 0

    links.forEach((link, _index) => {
      const note = findNoteByTitle(link.title)
      const isFound = !!note

      // Add text before the link
      result += content.slice(lastIndex, link.start)

      // Add the link
      result += `<span
        class="note-link ${isFound ? 'note-link-found' : 'note-link-not-found'}"
        data-note-title="${link.title}"
        style="color: ${isFound ? '#3b82f6' : '#ef4444'}; text-decoration: underline; cursor: pointer;"
      >[[${link.title}]]</span>`

      lastIndex = link.end
    })

    // Add remaining text
    result += content.slice(lastIndex)

    return (
      <div
        dangerouslySetInnerHTML={{ __html: result }}
        onMouseEnter={(e) => {
          const target = e.target as HTMLElement
          if (target.classList.contains('note-link')) {
            const noteTitle = target.getAttribute('data-note-title')
            if (noteTitle) {
              handleLinkHover(e as any, noteTitle)
            }
          }
        }}
        onMouseLeave={handleLinkLeave}
        onClick={(e) => {
          const target = e.target as HTMLElement
          if (target.classList.contains('note-link')) {
            const noteTitle = target.getAttribute('data-note-title')
            if (noteTitle) {
              handleLinkClick(noteTitle)
            }
          }
        }}
      />
    )
  }

  // Add global event handlers
  useEffect(() => {
    const handleNoteLinkHover = (event: MouseEvent, noteTitle: string) => {
      const note = findNoteByTitle(noteTitle)
      if (!note) return

      setHoveredLink(noteTitle)
      setPreviewPosition({
        x: event.clientX + 10,
        y: event.clientY - 10,
      })
      setShowPreview(true)
    }

    const handleNoteLinkLeave = () => {
      if (hoverTimeoutRef.current) {
        clearTimeout(hoverTimeoutRef.current)
      }
      hoverTimeoutRef.current = setTimeout(() => {
        setShowPreview(false)
        setHoveredLink(null)
      }, 200)
    }

    const handleNoteLinkClick = (noteTitle: string) => {
      const note = findNoteByTitle(noteTitle)
      if (note) {
        onNoteSelect(note.id)
      }
    }

    // Add global handlers
    ;(window as any).handleNoteLinkHover = handleNoteLinkHover
    ;(window as any).handleNoteLinkLeave = handleNoteLinkLeave
    ;(window as any).handleNoteLinkClick = handleNoteLinkClick

    return () => {
      if (hoverTimeoutRef.current) {
        clearTimeout(hoverTimeoutRef.current)
      }
    }
  }, [notes, onNoteSelect])

  return (
    <>
      {renderContentWithLinks()}

      {showPreview && hoveredLink && (
        <div
          className="fixed z-50 pointer-events-none"
          style={{
            left: previewPosition.x,
            top: previewPosition.y,
          }}
        >
          <NoteLinkPreview
            noteId={findNoteByTitle(hoveredLink)?.id || ''}
            onClose={() => setShowPreview(false)}
            onNavigate={onNoteSelect}
          />
        </div>
      )}
    </>
  )
}

interface BacklinksSectionProps {
  currentNoteId: string
  onNoteSelect: (noteId: string) => void
}

export function BacklinksSection({ currentNoteId, onNoteSelect }: BacklinksSectionProps) {
  const { notes } = useNotesStore()
  const [backlinks, setBacklinks] = useState<Note[]>([])

  useEffect(() => {
    // Use setTimeout to avoid synchronous setState in effect
    const timeoutId = setTimeout(() => {
      const currentNote = notes.find((n) => n.id === currentNoteId)
      if (!currentNote) {
        setBacklinks([])
        return
      }

      const currentTitle = currentNote.title?.toLowerCase()
      if (!currentTitle) {
        setBacklinks([])
        return
      }

      const links = notes.filter((note) => {
        if (note.id === currentNoteId) return false

        const content = note.content || ''
        const linkRegex = new RegExp(`\\[\\[${currentTitle}\\]\\]`, 'i')
        return linkRegex.test(content)
      })

      setBacklinks(links)
    }, 0)

    return () => clearTimeout(timeoutId)
  }, [currentNoteId, notes])

  if (backlinks.length === 0) return null

  return (
    <div className="mt-6 p-4 border-t border-border">
      <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
        <Link className="h-4 w-4" />
        Backlinks ({backlinks.length})
      </h3>
      <div className="space-y-2">
        {backlinks.map((note) => (
          <button
            key={note.id}
            onClick={() => onNoteSelect(note.id)}
            className="w-full text-left p-2 rounded-md hover:bg-accent transition-colors"
          >
            <div className="flex items-center gap-2">
              <FileText className="h-3 w-3 text-muted-foreground" />
              <span className="text-sm font-medium">{note.title || 'Untitled'}</span>
            </div>
            <div className="text-xs text-muted-foreground ml-5">
              {note.updatedAt
                ? (() => {
                    try {
                      const date = new Date(note.updatedAt)
                      return isNaN(date.getTime())
                        ? 'Unknown'
                        : formatDistanceToNow(date, { addSuffix: true })
                    } catch {
                      return 'Unknown'
                    }
                  })()
                : 'Unknown'}
            </div>
          </button>
        ))}
      </div>
    </div>
  )
}
