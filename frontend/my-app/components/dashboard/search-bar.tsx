"use client"

import { useState } from "react"
import { useNotes } from "@/lib/notes-context"
import { Input } from "@/components/ui/input"
import { Search, X } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { ScrollArea } from "@/components/ui/scroll-area"
import { formatDistanceToNow } from "date-fns"

export function SearchBar() {
  const { searchNotes, selectNote } = useNotes()
  const [query, setQuery] = useState("")
  const [isOpen, setIsOpen] = useState(false)
  const [results, setResults] = useState<ReturnType<typeof searchNotes>>([])

  const handleSearch = (value: string) => {
    setQuery(value)
    if (value.trim()) {
      const searchResults = searchNotes(value)
      setResults(searchResults)
    } else {
      setResults([])
    }
  }

  const handleSelectNote = (noteId: string) => {
    selectNote(noteId)
    setIsOpen(false)
    setQuery("")
    setResults([])
  }

  return (
    <>
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          placeholder="Search notes..."
          className="pl-9 bg-background"
          value={query}
          onChange={(e) => handleSearch(e.target.value)}
          onFocus={() => setIsOpen(true)}
        />
        {query && (
          <Button
            variant="ghost"
            size="sm"
            className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7 p-0"
            onClick={() => {
              setQuery("")
              setResults([])
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
            {results.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                <Search className="h-12 w-12 mx-auto mb-2 opacity-50" />
                <p>No notes found for "{query}"</p>
              </div>
            ) : (
              <div className="space-y-2">
                {results.map((note) => (
                  <button
                    key={note.id}
                    onClick={() => handleSelectNote(note.id)}
                    className="w-full text-left p-3 rounded-lg hover:bg-accent transition-smooth border border-border"
                  >
                    <h3 className="font-medium mb-1">{note.title}</h3>
                    <p className="text-sm text-muted-foreground line-clamp-2 mb-2">{note.content || "No content"}</p>
                    <span className="text-xs text-muted-foreground">
                      {formatDistanceToNow(new Date(note.updatedAt), { addSuffix: true })}
                    </span>
                  </button>
                ))}
              </div>
            )}
          </ScrollArea>
        </DialogContent>
      </Dialog>
    </>
  )
}
