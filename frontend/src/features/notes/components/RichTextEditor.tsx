import React from 'react'
import { LexicalEditor } from './LexicalEditor'

interface RichTextEditorProps {
  content: string
  onChange: (content: string) => void
  noteId?: string
  placeholder?: string
  editable?: boolean
  className?: string
  defaultMode?: 'wysiwyg' | 'markdown'
  showModeToggle?: boolean
}

// Simple wrapper component that delegates to LexicalEditor
export const RichTextEditor: React.FC<RichTextEditorProps> = (props) => {
  return <LexicalEditor {...props} />
}

export default RichTextEditor
