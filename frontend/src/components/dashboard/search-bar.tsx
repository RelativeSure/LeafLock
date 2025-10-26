'use client'

import { useState, useMemo } from 'react'
import { useNotesStore } from '../../stores/notesStore'
import { Input } from '@/components/ui/input'
import { Search, X, Lock } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { ScrollArea } from '@/components/ui/scroll-area'
import { formatDistanceToNow } from 'date-fns'
import { Badge } from '@/components/ui/badge'
import { useDecryptedNotes } from '@/hooks/use-decrypted-notes'
import type { Note } from '@/types'

export function SearchBar() {
  const { notes, selectNote } = useNotesStore()
  const { decryptedNotes, isUnlocked, isDecrypting } = useDecryptedNotes(notes)
  const [query, setQuery] = useState('')
  const [isOpen, setIsOpen] = useState(false)
  const trimmedQuery = query.trim()

  const results = useMemo(() => {
    const normalized = trimmedQuery.toLowerCase()

    if (!normalized || !isUnlocked) {
      return [] as Note[]
    }

    return notes
      .filter((note) => {
        const decrypted = decryptedNotes[note.id]
        if (!decrypted) {
          return false
        }

        const title = decrypted.title?.toLowerCase() ?? ''
        const content = decrypted.content?.toLowerCase() ?? ''
        const tags = (note.tags || []).map((tag) => tag.toLowerCase())

        return (
          title.includes(normalized) ||
          content.includes(normalized) ||
          tags.some((tag) => tag.includes(normalized))
        )
      })
      .sort((a, b) => {
        const aTime = a.updatedAt ? new Date(a.updatedAt).getTime() : 0
        const bTime = b.updatedAt ? new Date(b.updatedAt).getTime() : 0
        return bTime - aTime
      })
      .slice(0, 20)
  }, [trimmedQuery, isUnlocked, notes, decryptedNotes])

  const handleSelectNote = (noteId: string) => {
    selectNote(noteId)
    setIsOpen(false)
    setQuery('')
  }

  return (
    <>
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          placeholder="Search notes..."
          className="pl-9 bg-background"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value)
            if (!isOpen) {
              setIsOpen(true)
            }
          }}
          onFocus={() => setIsOpen(true)}
        />
        {query && (
          <Button
            variant="ghost"
            size="sm"
            className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7 p-0"
            onClick={() => {
              setQuery('')
            }}
          >
            <X className="h-4 w-4" />
          </Button>
        )}
      </div>

      <Dialog open={isOpen && query.length > 0} onOpenChange={setIsOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Search Results</DialogTitle>
          </DialogHeader>
          <ScrollArea className="max-h-[400px]">
            {!isUnlocked ? (
              <div className="text-center py-8 text-muted-foreground">
                <Lock className="h-12 w-12 mx-auto mb-2 opacity-50" />
                <p>Unlock your vault to search notes.</p>
              </div>
            ) : isDecrypting ? (
              <div className="text-center py-8 text-muted-foreground">
                <Search className="h-12 w-12 mx-auto mb-2 animate-pulse opacity-50" />
                <p>Decrypting notes…</p>
              </div>
            ) : results.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                <Search className="h-12 w-12 mx-auto mb-2 opacity-50" />
                <p>No notes found for "{query}"</p>
              </div>
            ) : (
              <div className="space-y-2">
                {results.map((note) => {
                  const decrypted = decryptedNotes[note.id]
                  const title = decrypted?.title || 'Untitled'
                  const content = decrypted?.content || ''

                  return (
                    <button
                      key={note.id}
                      onClick={() => handleSelectNote(note.id)}
                      className="w-full text-left p-3 rounded-lg hover:bg-accent transition-smooth border border-border"
                    >
                      <h3 className="font-medium mb-1 line-clamp-1">{title}</h3>
                      <p className="text-xs text-muted-foreground line-clamp-2 mb-2">
                        {content
                          .replace(/<[^>]*>/g, ' ')
                          .replace(/\s+/g, ' ')
                          .trim() || 'No content'}
                      </p>
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-1 flex-wrap">
                          {(note.tags || []).slice(0, 2).map((tag) => (
                            <Badge key={tag} variant="outline" className="text-xs">
                              {tag}
                            </Badge>
                          ))}
                          {(note.tags || []).length > 2 && (
                            <span className="text-xs text-muted">
                              +{(note.tags || []).length - 2}
                            </span>
                          )}
                        </div>

                        <span className="text-xs text-muted-foreground flex-shrink-0">
                          {note.updatedAt
                            ? formatDistanceToNow(new Date(note.updatedAt), { addSuffix: true })
                            : 'Unknown'}
                        </span>
                      </div>
                    </button>
                  )
                })}
              </div>
            )}
          </ScrollArea>
        </DialogContent>
      </Dialog>
    </>
  )
}
