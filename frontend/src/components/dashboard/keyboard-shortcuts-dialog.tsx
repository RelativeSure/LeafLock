'use client'

import { useState, useEffect } from 'react'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Keyboard } from 'lucide-react'
import { Badge } from '@/components/ui/badge'

export function KeyboardShortcutsDialog() {
  const [open, setOpen] = useState(false)

  useEffect(() => {
    const handleOpenShortcuts = () => setOpen(true)
    window.addEventListener('open-keyboard-shortcuts', handleOpenShortcuts)
    return () => window.removeEventListener('open-keyboard-shortcuts', handleOpenShortcuts)
  }, [])

  const shortcuts = [
    { keys: ['Cmd/Ctrl', 'N'], description: 'Create new note' },
    { keys: ['Cmd/Ctrl', 'K'], description: 'Search notes' },
    { keys: ['Cmd/Ctrl', 'S'], description: 'Save note (auto-saves)' },
    { keys: ['Cmd/Ctrl', 'E'], description: 'Toggle encryption' },
    { keys: ['Cmd/Ctrl', 'P'], description: 'Pin/Unpin note' },
    { keys: ['Cmd/Ctrl', 'D'], description: 'Delete note' },
    { keys: ['Cmd/Ctrl', 'B'], description: 'Bold text' },
    { keys: ['Cmd/Ctrl', 'I'], description: 'Italic text' },
    { keys: ['Cmd/Ctrl', 'Shift', 'X'], description: 'Strikethrough' },
    { keys: ['Cmd/Ctrl', 'Shift', 'H'], description: 'Highlight text' },
    { keys: ['Cmd/Ctrl', 'Shift', 'K'], description: 'Add link' },
    { keys: ['Cmd/Ctrl', 'Z'], description: 'Undo' },
    { keys: ['Cmd/Ctrl', 'Shift', 'Z'], description: 'Redo' },
    { keys: ['Esc'], description: 'Close dialogs' },
  ]

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Keyboard className="h-5 w-5" />
            Keyboard Shortcuts
          </DialogTitle>
        </DialogHeader>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
          {shortcuts.map((shortcut, index) => (
            <div
              key={index}
              className="flex items-center justify-between gap-4 p-2 rounded-lg hover:bg-accent/50"
            >
              <span className="text-sm">{shortcut.description}</span>
              <div className="flex items-center gap-1">
                {shortcut.keys.map((key, i) => (
                  <span key={i} className="flex items-center gap-1">
                    <Badge variant="outline" className="font-mono text-xs">
                      {key}
                    </Badge>
                    {i < shortcut.keys.length - 1 && (
                      <span className="text-muted-foreground">+</span>
                    )}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </DialogContent>
    </Dialog>
  )
}
