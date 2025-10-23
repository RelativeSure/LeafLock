"use client"

import { useState, useEffect } from "react"
import { Plus, Search, Menu, LogOut, Settings, Edit3, FileText } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { NoteEditor } from "@/components/note-editor"
import { NoteCard } from "@/components/note-card"
import { EmptyState } from "@/components/empty-state"
import { TemplateDialog } from "@/components/template-dialog"

export interface Note {
  id: string
  title: string
  content: string
  tags: string[]
  template?: string
  createdAt: string
  updatedAt: string
}

export default function NotesPage() {
  const [notes, setNotes] = useState<Note[]>([])
  const [selectedNote, setSelectedNote] = useState<Note | null>(null)
  const [isEditing, setIsEditing] = useState(false)
  const [searchQuery, setSearchQuery] = useState("")
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [showTemplateDialog, setShowTemplateDialog] = useState(false)

  useEffect(() => {
    const savedNotes = localStorage.getItem("elegant-notes")
    if (savedNotes) {
      setNotes(JSON.parse(savedNotes))
    }
  }, [])

  useEffect(() => {
    if (notes.length > 0) {
      localStorage.setItem("elegant-notes", JSON.stringify(notes))
    }
  }, [notes])

  const createNewNote = (template?: { title: string; content: string; tags: string[] }) => {
    const newNote: Note = {
      id: Date.now().toString(),
      title: template?.title || "Untitled Note",
      content: template?.content || "",
      tags: template?.tags || [],
      template: template ? "custom" : undefined,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    }
    setNotes([newNote, ...notes])
    setSelectedNote(newNote)
    setIsEditing(true)
  }

  const updateNote = (updatedNote: Note) => {
    setNotes(
      notes.map((note) =>
        note.id === updatedNote.id ? { ...updatedNote, updatedAt: new Date().toISOString() } : note,
      ),
    )
    setSelectedNote(updatedNote)
  }

  const deleteNote = (id: string) => {
    setNotes(notes.filter((note) => note.id !== id))
    if (selectedNote?.id === id) {
      setSelectedNote(null)
      setIsEditing(false)
    }
  }

  const filteredNotes = notes.filter(
    (note) =>
      note.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      note.content.toLowerCase().includes(searchQuery.toLowerCase()) ||
      note.tags.some((tag) => tag.toLowerCase().includes(searchQuery.toLowerCase())),
  )

  return (
    <div className="flex h-screen bg-background">
      {/* Sidebar */}
      <aside
        className={`${
          sidebarOpen ? "w-64" : "w-0"
        } border-r border-border bg-card transition-all duration-300 overflow-hidden flex flex-col`}
      >
        <div className="p-6 border-b border-border">
          <h1 className="text-2xl font-serif font-semibold text-foreground">Elegant Notes</h1>
        </div>

        <nav className="flex-1 p-4 space-y-2">
          <Button variant="ghost" className="w-full justify-start gap-3 text-foreground/80 hover:text-foreground">
            <Edit3 className="h-4 w-4" />
            All Notes
          </Button>
          <Button
            variant="ghost"
            className="w-full justify-start gap-3 text-foreground/60 hover:text-foreground"
            onClick={() => setShowTemplateDialog(true)}
          >
            <FileText className="h-4 w-4" />
            Templates
          </Button>
          <Button variant="ghost" className="w-full justify-start gap-3 text-foreground/60 hover:text-foreground">
            <Settings className="h-4 w-4" />
            Settings
          </Button>
        </nav>

        <div className="p-4 border-t border-border">
          <Button variant="ghost" className="w-full justify-start gap-3 text-foreground/60 hover:text-foreground">
            <LogOut className="h-4 w-4" />
            Sign Out
          </Button>
        </div>
      </aside>

      {/* Main Content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Header */}
        <header className="border-b border-border bg-card">
          <div className="flex items-center justify-between p-4">
            <div className="flex items-center gap-4 flex-1">
              <Button
                variant="ghost"
                size="icon"
                onClick={() => setSidebarOpen(!sidebarOpen)}
                className="text-foreground/60 hover:text-foreground"
              >
                <Menu className="h-5 w-5" />
              </Button>

              <div className="relative flex-1 max-w-md">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  type="search"
                  placeholder="Search notes..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-10 bg-background border-border"
                />
              </div>
            </div>

            <Button onClick={() => setShowTemplateDialog(true)} className="gap-2">
              <Plus className="h-4 w-4" />
              New Note
            </Button>
          </div>
        </header>

        {/* Notes Grid or Editor */}
        <main className="flex-1 overflow-auto">
          {isEditing && selectedNote ? (
            <NoteEditor
              note={selectedNote}
              onUpdate={updateNote}
              onClose={() => {
                setIsEditing(false)
                setSelectedNote(null)
              }}
              onDelete={() => deleteNote(selectedNote.id)}
            />
          ) : (
            <div className="p-8">
              {filteredNotes.length === 0 ? (
                <EmptyState onCreateNote={createNewNote} hasNotes={notes.length > 0} />
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                  {filteredNotes.map((note) => (
                    <NoteCard
                      key={note.id}
                      note={note}
                      onClick={() => {
                        setSelectedNote(note)
                        setIsEditing(true)
                      }}
                      onDelete={() => deleteNote(note.id)}
                    />
                  ))}
                </div>
              )}
            </div>
          )}
        </main>
      </div>

      {/* Template Dialog */}
      <TemplateDialog
        open={showTemplateDialog}
        onOpenChange={setShowTemplateDialog}
        onSelectTemplate={(template) => {
          createNewNote(template)
          setShowTemplateDialog(false)
        }}
        onCreateBlank={() => {
          createNewNote()
          setShowTemplateDialog(false)
        }}
      />
    </div>
  )
}
