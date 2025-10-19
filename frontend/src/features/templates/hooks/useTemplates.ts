import { useState, useCallback } from 'react'
import { secureApi as api } from '@/services/api/secureApi'
import { Template } from '@/services/data/templatesService'

interface UseTemplatesProps {
  notes: any[]
  onNotesLoad: () => Promise<void>
  onSelectedNoteChange: (note: any) => void
  onNavigate: (path: string) => void
  onError: (error: string | null) => void
}

export const useTemplates = ({
  notes,
  onNotesLoad,
  onSelectedNoteChange,
  onNavigate,
  onError,
}: UseTemplatesProps) => {
  const [showTemplateSelector, setShowTemplateSelector] = useState(false)

  const handleTemplateSelect = useCallback(
    async (template: Template) => {
      try {
        const response = await api.useTemplate(template.id, {
          title: `${template.name} - ${new Date().toLocaleDateString()}`,
        })

        console.log('✅ Note created from template:', response)

        setShowTemplateSelector(false)
        await onNotesLoad()

        const newNote = notes.find((note) => note.id === response.id)
        if (newNote) {
          onSelectedNoteChange(newNote)
          onNavigate('/app/editor')
        }
      } catch (err) {
        console.error('Failed to create note from template:', err)
        onError(err instanceof Error ? err.message : 'Failed to create note from template')
      }
    },
    [onNotesLoad, notes, onSelectedNoteChange, onNavigate, onError]
  )

  const openTemplateSelector = useCallback(() => {
    setShowTemplateSelector(true)
  }, [])

  const closeTemplateSelector = useCallback(() => {
    setShowTemplateSelector(false)
  }, [])

  return {
    showTemplateSelector,
    handleTemplateSelect,
    openTemplateSelector,
    closeTemplateSelector,
  }
}
