import React, { useState, useEffect, useCallback, useMemo, useRef, Suspense, lazy } from 'react'
import { createPortal } from 'react-dom'
import { Maximize2, Minimize2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { ButtonGroup, ButtonGroupSeparator } from '@/components/ui/button-group'
import { Card } from '@/components/ui/card'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
import { Spinner } from '@/components/ui/spinner'
import { ErrorNotice } from '@/features/common/ErrorNotice'
import Footer from '@/components/Footer'
import { debounce, type DebounceFunction } from '@/utils/debounce'
import { type Note } from '@/features/app/types'
import { type SecureAPI } from '@/services/secureApi'
import { type CryptoService } from '@/services/cryptoService'
import ComponentLoader from '@/components/loaders/ComponentLoader'
import { padding } from '@/lib/padding'
import { cn } from '@/lib/utils'

const TagSelector = lazy(() => import('@/components/TagSelector'))
const RichTextEditor = lazy(() =>
  import('@/components/RichTextEditor').then((module) => ({ default: module.RichTextEditor }))
)

interface NotesEditorProps {
  selectedNote: Note | null
  onSelectNote: (note: Note | null) => void
  onNotesChange: React.Dispatch<React.SetStateAction<Note[]>>
  api: SecureAPI
  cryptoService: CryptoService
}

export const NotesEditor: React.FC<NotesEditorProps> = ({
  selectedNote,
  onSelectNote,
  onNotesChange,
  api,
  cryptoService,
}) => {
  const [title, setTitle] = useState(selectedNote?.title || '')
  const [content, setContent] = useState(selectedNote?.content || '')
  const [saving, setSaving] = useState(false)
  const [lastSaved, setLastSaved] = useState<Date | null>(null)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [isFullscreen, setIsFullscreen] = useState(false)

  const titleRef = useRef(title)
  const contentRef = useRef(content)
  const selectedNoteRef = useRef(selectedNote)
  const debouncedAutosaveRef = useRef<DebounceFunction<() => Promise<void>> | null>(null)

  useEffect(() => {
    titleRef.current = title
    contentRef.current = content
    selectedNoteRef.current = selectedNote
  }, [title, content, selectedNote])

  useEffect(() => {
    if (selectedNote) {
      setTitle(selectedNote.title || '')
      setContent(selectedNote.content || '')
      setLastSaved(selectedNote.updated_at ? new Date(selectedNote.updated_at) : null)
    } else {
      setTitle('')
      setContent('')
      setLastSaved(null)
    }
  }, [selectedNote])

  useEffect(() => {
    if (!selectedNote && isFullscreen) {
      setIsFullscreen(false)
    }
  }, [selectedNote, isFullscreen])

  useEffect(() => {
    if (typeof document === 'undefined' || typeof window === 'undefined') {
      return
    }

    const body = document.body
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setIsFullscreen(false)
      }
    }

    if (isFullscreen) {
      body.classList.add('overflow-hidden')
      window.addEventListener('keydown', handleKeyDown)
    } else {
      body.classList.remove('overflow-hidden')
    }

    return () => {
      body.classList.remove('overflow-hidden')
      window.removeEventListener('keydown', handleKeyDown)
    }
  }, [isFullscreen])

  const handleSave = useCallback(async () => {
    if (saving) {
      console.log('💾 Save already in progress, skipping duplicate')
      return
    }

    setSaving(true)
    setSaveError(null)

    if (debouncedAutosaveRef.current) {
      debouncedAutosaveRef.current.cancel()
      console.log('🚫 Cancelled pending autosave due to manual save')
    }

    try {
      if (!cryptoService.isSodiumReady()) {
        console.warn('⚠️ Sodium not ready, skipping autosave')
        setSaveError('Encryption not ready - please try manual save')
        return
      }

      const currentTitle = titleRef.current
      const currentContent = contentRef.current
      const currentSelectedNote = selectedNoteRef.current

      if (currentSelectedNote && currentSelectedNote.id) {
        await api.updateNote(currentSelectedNote.id, currentTitle, currentContent)
        console.log('✅ Updated existing note:', currentSelectedNote.id)

        const updatedNote: Note = {
          ...currentSelectedNote,
          title: currentTitle,
          content: currentContent,
          updated_at: new Date().toISOString(),
        }

        onSelectNote(updatedNote)
        onNotesChange((prevNotes) =>
          prevNotes.map((note) => (note.id === updatedNote.id ? updatedNote : note))
        )
      } else {
        const response = await api.createNote(currentTitle, currentContent)
        console.log('✅ Created new note with ID:', response.id)

        const newNote: Note = {
          id: response.id,
          title: currentTitle || 'Untitled',
          content: currentContent,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        }

        onSelectNote(newNote)
        onNotesChange((prevNotes) => [newNote, ...prevNotes])
      }

      setLastSaved(new Date())
    } catch (err) {
      console.error('Failed to save note:', err)
      setSaveError((err as Error).message || 'Failed to save note')
    } finally {
      setSaving(false)
    }
  }, [api, cryptoService, onNotesChange, onSelectNote, saving])

  const debouncedSave = useMemo(() => {
    const debouncedFunc = debounce(async () => {
      const currentNote = selectedNoteRef.current
      const currentTitle = titleRef.current
      const currentContent = contentRef.current

      if (
        currentNote &&
        (currentTitle !== currentNote.title || currentContent !== currentNote.content)
      ) {
        try {
          await handleSave()
          console.log('✅ Autosave completed')
        } catch (err) {
          console.error('💥 Autosave failed:', err)
          setSaveError((err as Error).message || 'Autosave failed')
        }
      }
    }, 3000)

    debouncedAutosaveRef.current = debouncedFunc
    return debouncedFunc
  }, [handleSave])

  useEffect(() => {
    if (
      (title || content) &&
      selectedNote &&
      (title !== selectedNote.title || content !== selectedNote.content)
    ) {
      debouncedSave()
    }
  }, [title, content, debouncedSave, selectedNote])

  const toggleFullscreen = useCallback(() => {
    setIsFullscreen((prev) => !prev)
  }, [])

  const editorHeightClass = isFullscreen ? 'min-h-[calc(100vh-11rem)]' : 'min-h-[calc(100vh-14rem)]'

  const editorContent = (
    <div
      className={cn(
        'h-full flex flex-col',
        isFullscreen ? 'bg-background' : 'bg-background/95',
        'transition-colors duration-200'
      )}
      role="main"
      aria-label="Note editor"
      data-fullscreen={isFullscreen}
    >
      {/* Title Bar */}
      <Card
        className={cn(
          'rounded-none border-0 border-b-2 border-border flex-shrink-0 bg-card backdrop-blur-sm transition-all duration-200',
          isFullscreen ? 'shadow-md' : 'shadow-sm'
        )}
      >
        <div
          className={cn(
            'flex flex-col gap-3 md:flex-row md:items-center md:justify-between',
            padding.editor.titleBar
          )}
        >
          <label htmlFor="note-title" className="sr-only">
            Note title
          </label>
          <div className="flex flex-col gap-3 w-full md:flex-1">
            <input
              id="note-title"
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Untitled"
              className="w-full bg-transparent text-base font-semibold text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/30 rounded-md px-3 py-2 transition-colors duration-200 border border-transparent hover:border-border"
            />

            <div
              className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground md:justify-between"
              aria-live="polite"
            >
              <div className="flex items-center gap-2">
                {saving && (
                  <span className="flex items-center">
                    <Spinner className="mr-1 h-3 w-3" aria-hidden="true" />
                    <span className="hidden sm:inline">Saving...</span>
                    <span className="sr-only">Your note is being saved</span>
                  </span>
                )}
                {!saving && lastSaved && (
                  <span className="hidden sm:inline">{lastSaved.toLocaleTimeString()}</span>
                )}
                {!saving && !lastSaved && (title || content) && (
                  <span className="hidden sm:inline text-yellow-500">Unsaved</span>
                )}
              </div>

              <ButtonGroup>
                {selectedNote && selectedNote.id && (
                  <>
                    <Suspense
                      fallback={<div className="h-8 w-20 bg-muted rounded animate-pulse" />}
                    >
                      <TagSelector noteId={selectedNote.id} size="sm" />
                    </Suspense>
                    <ButtonGroupSeparator />
                  </>
                )}

                <Button
                  onClick={toggleFullscreen}
                  variant="ghost"
                  size="sm"
                  className="h-8 w-8 p-0 transition-transform duration-200 hover:scale-105"
                  title={isFullscreen ? 'Exit full screen' : 'Enter full screen'}
                  aria-label={isFullscreen ? 'Exit full screen editor' : 'Enter full screen editor'}
                  aria-pressed={isFullscreen}
                  type="button"
                >
                  {isFullscreen ? (
                    <Minimize2 className="h-4 w-4" aria-hidden="true" />
                  ) : (
                    <Maximize2 className="h-4 w-4" aria-hidden="true" />
                  )}
                  <span className="sr-only">
                    {isFullscreen ? 'Exit full screen editor view' : 'Enter full screen editor view'}
                  </span>
                </Button>
                <ButtonGroupSeparator />

                <Button
                  data-save-action
                  onClick={handleSave}
                  disabled={saving || (!title && !content)}
                  variant="default"
                  size="sm"
                  className="h-8 transition-transform duration-200 hover:scale-[1.02]"
                  title="Save note manually (Ctrl+S)"
                  type="button"
                >
                  <svg
                    className="mr-1 h-4 w-4"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                    aria-hidden="true"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3-3m0 0l-3 3m3-3v12"
                    />
                  </svg>
                  Save
                </Button>
              </ButtonGroup>
            </div>
          </div>
        </div>
      </Card>

      {/* Error Notice */}
      {saveError && (
        <div className="flex-shrink-0 px-4 py-3">
          <ErrorNotice error={saveError} onRetry={handleSave} onDismiss={() => setSaveError(null)} />
        </div>
      )}

      {/* Scrollable Editor Content */}
      <ScrollArea className="flex-1 px-4 py-4">
        <div className="min-h-full space-y-4">
          <Suspense fallback={<ComponentLoader />}>
            <RichTextEditor
              content={content}
              onChange={setContent}
              noteId={selectedNote?.id}
              placeholder="Start writing your secure note... You can use rich text formatting or Markdown!"
              className={cn(
                'w-full rounded-xl border border-border bg-background shadow-sm transition-all duration-300 animate-fade-in',
                editorHeightClass
              )}
              editable
            />
          </Suspense>
        </div>
        <p id="editor-help" className="sr-only">
          This note is automatically encrypted and saved as you type. Supports rich text and
          Markdown formatting.
        </p>

        {/* Footer inside scroll area */}
        <Separator className="my-4" />
        <Footer className="!py-0 !px-0" />
      </ScrollArea>
    </div>
  )

  if (isFullscreen && typeof document !== 'undefined') {
    return createPortal(
      <div className="fixed inset-0 z-50 bg-background flex flex-col">
        <div className="flex-1 overflow-hidden">{editorContent}</div>
      </div>,
      document.body
    )
  }

  return editorContent
}

export default NotesEditor
