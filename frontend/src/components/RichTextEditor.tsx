import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import ReactQuill, { Quill } from 'react-quill'
import 'quill/dist/quill.snow.css'
import QuillBetterTable from 'quill-better-table'
import {
  Bold,
  Italic,
  Strikethrough,
  Code,
  Link as LinkIcon,
  List,
  ListOrdered,
  Quote,
  Table as TableIcon,
  Image as ImageIcon,
  Heading1,
  Heading2,
  Heading3,
  Edit3,
  FileText,
  Upload,
} from 'lucide-react'
import { markdownToHtml, htmlToMarkdown, isHtmlContent } from '../utils/markdownConverter'
import DOMPurify from 'dompurify'
import { attachmentService } from '../services/attachmentService'

// Register Quill modules
Quill.register('modules/better-table', QuillBetterTable)

interface RichTextEditorProps {
  content: string
  onChange: (content: string) => void
  noteId?: string // Note ID for file uploads
  placeholder?: string
  editable?: boolean
  className?: string
  defaultMode?: 'wysiwyg' | 'markdown'
  showModeToggle?: boolean
}

type EditorMode = 'wysiwyg' | 'markdown'

interface ToolbarButtonProps {
  onClick: () => void
  isActive?: boolean
  disabled?: boolean
  children: React.ReactNode
  title: string
}

const ToolbarButton: React.FC<ToolbarButtonProps> = ({
  onClick,
  isActive = false,
  disabled = false,
  children,
  title,
}) => (
  <button
    onMouseDown={(e) => {
      e.preventDefault() // Prevent editor from losing focus
    }}
    onClick={(e) => {
      e.preventDefault()
      e.stopPropagation()
      onClick()
    }}
    disabled={disabled}
    title={title}
    type="button"
    className={`
      p-2 rounded border transition-colors duration-200
      ${isActive
        ? 'bg-primary text-primary-foreground border-primary'
        : 'bg-background text-foreground border-border hover:bg-accent hover:text-accent-foreground'
      }
      ${disabled
        ? 'opacity-50 cursor-not-allowed'
        : 'hover:border-muted-foreground/50'
      }
    `}
  >
    {children}
  </button>
)

const ToolbarSeparator: React.FC = () => (
  <div className="w-px h-6 bg-border mx-1" />
)

export const RichTextEditor: React.FC<RichTextEditorProps> = ({
  content,
  onChange,
  noteId,
  placeholder = 'Start writing your note...',
  editable = true,
  className = '',
  defaultMode = 'wysiwyg',
  showModeToggle = true,
}) => {
  const [editorMode, setEditorMode] = useState<EditorMode>(defaultMode)
  const [markdownContent, setMarkdownContent] = useState('')
  const [htmlContent, setHtmlContent] = useState('')
  const quillRef = useRef<ReactQuill>(null)

  // Quill modules configuration
  const modules = useMemo(() => ({
    toolbar: false, // We'll use custom toolbar
    'better-table': {
      operationMenu: {
        items: {
          unmergeCells: {
            text: 'Unmerge cells'
          }
        }
      }
    },
    keyboard: {
      bindings: QuillBetterTable.keyboardBindings
    }
  }), [])

  const formats = [
    'header',
    'bold', 'italic', 'underline', 'strike',
    'blockquote', 'code-block',
    'list', 'bullet',
    'link', 'image',
    'table'
  ]

  // Initialize content based on format
  useEffect(() => {
    if (editorMode === 'wysiwyg') {
      // If content looks like markdown, convert to HTML
      let html = content
      if (!isHtmlContent(content)) {
        html = markdownToHtml(content)
      }
      setHtmlContent(html)
    } else {
      // For markdown mode, convert HTML to markdown if needed
      const markdown = isHtmlContent(content) ? htmlToMarkdown(content) : content
      setMarkdownContent(markdown)
    }
  }, [content, editorMode])

  // Handle mode switching
  const handleModeSwitch = useCallback((newMode: EditorMode) => {
    if (newMode === editorMode) return

    if (newMode === 'markdown') {
      // Switch to markdown: convert current HTML to markdown
      const markdown = htmlToMarkdown(htmlContent)
      setMarkdownContent(markdown)
    } else {
      // Switch to WYSIWYG: convert markdown to HTML
      const html = markdownToHtml(markdownContent)
      setHtmlContent(html)
    }

    setEditorMode(newMode)
  }, [editorMode, htmlContent, markdownContent])

  // Handle WYSIWYG content changes
  const handleQuillChange = useCallback((value: string) => {
    setHtmlContent(value)
    // Security: Sanitize HTML content to prevent XSS attacks
    const sanitizedHtml = DOMPurify.sanitize(value, {
      ALLOWED_TAGS: [
        'p', 'br', 'strong', 'em', 'u', 's', 'code', 'pre',
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'ul', 'ol', 'li', 'blockquote', 'hr',
        'a', 'img', 'table', 'thead', 'tbody', 'tr', 'th', 'td'
      ],
      ALLOWED_ATTR: [
        'href', 'title', 'alt', 'src', 'class', 'style',
        'target', 'rel', 'colspan', 'rowspan'
      ]
    })
    onChange(sanitizedHtml)
  }, [onChange])

  // Handle markdown textarea changes
  const handleMarkdownChange = useCallback((value: string) => {
    setMarkdownContent(value)
    // Convert to HTML and notify parent
    const html = markdownToHtml(value)
    onChange(html)
  }, [onChange])

  // Toolbar actions
  const getQuill = () => quillRef.current?.getEditor()

  const applyFormat = (format: string, value?: any) => {
    const quill = getQuill()
    if (!quill) return

    const currentFormat = quill.getFormat()
    if (value === undefined) {
      // Toggle format
      quill.format(format, !currentFormat[format])
    } else {
      // Apply specific value
      quill.format(format, value)
    }
  }

  const isFormatActive = (format: string, value?: any): boolean => {
    const quill = getQuill()
    if (!quill) return false
    const currentFormat = quill.getFormat()
    if (value !== undefined) {
      return currentFormat[format] === value
    }
    return !!currentFormat[format]
  }

  const insertLink = () => {
    const quill = getQuill()
    if (!quill) return

    const url = window.prompt('Enter URL:')
    if (url) {
      const selection = quill.getSelection()
      if (selection) {
        quill.format('link', url)
      }
    }
  }

  const insertImage = () => {
    const quill = getQuill()
    if (!quill) return

    const url = window.prompt('Enter image URL:')
    if (url) {
      // Security: Validate and sanitize the URL
      try {
        const urlObj = new URL(url)
        // Only allow http/https protocols
        if (urlObj.protocol === 'http:' || urlObj.protocol === 'https:') {
          const sanitizedUrl = DOMPurify.sanitize(url)
          const selection = quill.getSelection()
          if (selection) {
            quill.insertEmbed(selection.index, 'image', sanitizedUrl)
          }
        } else {
          alert('Only HTTP and HTTPS URLs are allowed.')
        }
      } catch {
        alert('Please enter a valid URL.')
      }
    }
  }

  const insertTable = () => {
    const quill = getQuill()
    if (!quill) return

    const tableModule = quill.getModule('better-table')
    if (tableModule) {
      tableModule.insertTable(3, 3)
    }
  }

  // File upload handler
  const handleFileUpload = useCallback(async (file: File) => {
    const quill = getQuill()
    if (!quill || !noteId) {
      if (!noteId) {
        alert('Please save the note first before uploading files.')
      }
      return
    }

    // Security: Validate file type and size
    const maxFileSize = 10 * 1024 * 1024 // 10MB limit
    if (file.size > maxFileSize) {
      alert('File size too large. Maximum size is 10MB.')
      return
    }

    // Security: Validate file type
    const allowedTypes = [
      'image/jpeg', 'image/png', 'image/gif', 'image/webp',
      'text/plain', 'application/pdf', 'text/markdown'
    ]

    if (!allowedTypes.includes(file.type)) {
      alert('File type not allowed. Supported types: images (JPEG, PNG, GIF, WebP), text files, PDFs.')
      return
    }

    try {
      const attachment = await attachmentService.uploadAttachment(noteId, file)
      const selection = quill.getSelection()
      const index = selection ? selection.index : quill.getLength()

      if (file.type.startsWith('image/')) {
        // For images, embed them directly in the editor
        const imageUrl = attachmentService.getAttachmentUrl(noteId, attachment.id)
        quill.insertEmbed(index, 'image', imageUrl)
      } else {
        // For other files, insert as a link
        const downloadUrl = attachmentService.getAttachmentUrl(noteId, attachment.id)
        quill.insertText(index, `📎 ${attachment.filename}`)
        quill.setSelection(index, attachment.filename.length + 2)
        quill.format('link', downloadUrl)
      }
    } catch (error) {
      console.error('File upload failed:', error)
      alert(`Failed to upload file: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }, [noteId])

  // Drag and drop handlers
  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
  }, [])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()

    const files = Array.from(e.dataTransfer.files)
    files.forEach(handleFileUpload)
  }, [handleFileUpload])

  // File input handler
  const handleFileInputChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files || [])
    files.forEach(handleFileUpload)
    // Reset input value to allow selecting the same file again
    e.target.value = ''
  }, [handleFileUpload])

  return (
    <div className={`w-full ${className}`}>
      {/* Mode Toggle and Toolbar */}
      {editable && (
        <div className="flex flex-wrap items-center justify-between gap-2 p-3 border border-border border-b-0 rounded-t-lg bg-muted">
          {/* Mode Toggle */}
          {showModeToggle && (
            <div className="flex items-center gap-1 mr-4">
              <ToolbarButton
                onClick={() => handleModeSwitch('wysiwyg')}
                isActive={editorMode === 'wysiwyg'}
                title="WYSIWYG Editor"
              >
                <Edit3 className="w-4 h-4" />
              </ToolbarButton>
              <ToolbarButton
                onClick={() => handleModeSwitch('markdown')}
                isActive={editorMode === 'markdown'}
                title="Markdown Editor"
              >
                <FileText className="w-4 h-4" />
              </ToolbarButton>
            </div>
          )}

          {/* Formatting Toolbar - only show in WYSIWYG mode */}
          {editorMode === 'wysiwyg' && (
            <div className="flex flex-wrap items-center gap-1">
              {/* Text Formatting */}
              <ToolbarButton
                onClick={() => applyFormat('bold')}
                isActive={isFormatActive('bold')}
                title="Bold (Ctrl+B)"
              >
                <Bold className="w-4 h-4" />
              </ToolbarButton>

              <ToolbarButton
                onClick={() => applyFormat('italic')}
                isActive={isFormatActive('italic')}
                title="Italic (Ctrl+I)"
              >
                <Italic className="w-4 h-4" />
              </ToolbarButton>

              <ToolbarButton
                onClick={() => applyFormat('strike')}
                isActive={isFormatActive('strike')}
                title="Strikethrough"
              >
                <Strikethrough className="w-4 h-4" />
              </ToolbarButton>

              <ToolbarButton
                onClick={() => applyFormat('code')}
                isActive={isFormatActive('code')}
                title="Inline Code"
              >
                <Code className="w-4 h-4" />
              </ToolbarButton>

              <ToolbarSeparator />

              {/* Headings */}
              <ToolbarButton
                onClick={() => applyFormat('header', isFormatActive('header', 1) ? false : 1)}
                isActive={isFormatActive('header', 1)}
                title="Heading 1"
              >
                <Heading1 className="w-4 h-4" />
              </ToolbarButton>

              <ToolbarButton
                onClick={() => applyFormat('header', isFormatActive('header', 2) ? false : 2)}
                isActive={isFormatActive('header', 2)}
                title="Heading 2"
              >
                <Heading2 className="w-4 h-4" />
              </ToolbarButton>

              <ToolbarButton
                onClick={() => applyFormat('header', isFormatActive('header', 3) ? false : 3)}
                isActive={isFormatActive('header', 3)}
                title="Heading 3"
              >
                <Heading3 className="w-4 h-4" />
              </ToolbarButton>

              <ToolbarSeparator />

              {/* Lists */}
              <ToolbarButton
                onClick={() => applyFormat('list', 'bullet')}
                isActive={isFormatActive('list', 'bullet')}
                title="Bullet List"
              >
                <List className="w-4 h-4" />
              </ToolbarButton>

              <ToolbarButton
                onClick={() => applyFormat('list', 'ordered')}
                isActive={isFormatActive('list', 'ordered')}
                title="Numbered List"
              >
                <ListOrdered className="w-4 h-4" />
              </ToolbarButton>

              <ToolbarSeparator />

              {/* Block Elements */}
              <ToolbarButton
                onClick={() => applyFormat('blockquote')}
                isActive={isFormatActive('blockquote')}
                title="Quote"
              >
                <Quote className="w-4 h-4" />
              </ToolbarButton>

              <ToolbarButton
                onClick={() => applyFormat('code-block')}
                isActive={isFormatActive('code-block')}
                title="Code Block"
              >
                <Code className="w-4 h-4" />
              </ToolbarButton>

              <ToolbarSeparator />

              {/* Links and Media */}
              <ToolbarButton
                onClick={insertLink}
                isActive={isFormatActive('link')}
                title="Add Link"
              >
                <LinkIcon className="w-4 h-4" />
              </ToolbarButton>

              <ToolbarButton
                onClick={insertImage}
                title="Add Image (URL)"
              >
                <ImageIcon className="w-4 h-4" />
              </ToolbarButton>

              <div className="relative">
                <input
                  type="file"
                  accept="image/*,*"
                  multiple
                  onChange={handleFileInputChange}
                  className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                  title="Upload Files"
                />
                <ToolbarButton
                  onClick={() => { /* File input handles the click */ }}
                  title="Upload Files"
                >
                  <Upload className="w-4 h-4" />
                </ToolbarButton>
              </div>

              <ToolbarButton
                onClick={insertTable}
                title="Insert Table"
              >
                <TableIcon className="w-4 h-4" />
              </ToolbarButton>
            </div>
          )}
        </div>
      )}

      {/* Editor Content */}
      <div
        className={editable ? 'border border-border border-t-0 rounded-b-lg bg-background' : ''}
        onDragOver={editable ? handleDragOver : undefined}
        onDrop={editable ? handleDrop : undefined}
      >
        {editorMode === 'wysiwyg' ? (
          <ReactQuill
            ref={quillRef}
            theme="snow"
            value={htmlContent}
            onChange={handleQuillChange}
            modules={modules}
            formats={formats}
            readOnly={!editable}
            placeholder={placeholder}
            className="quill-custom"
          />
        ) : (
          /* Markdown Textarea with drag-and-drop */
          <div className="relative">
            <textarea
              value={markdownContent}
              onChange={(e) => handleMarkdownChange(e.target.value)}
              placeholder={placeholder}
              className="
                w-full min-h-[200px] p-4 border-0 resize-none focus:outline-none
                font-mono text-sm leading-relaxed
                bg-background text-foreground
              "
              disabled={!editable}
            />
            {/* Drag overlay for markdown mode */}
            <div className="absolute inset-0 pointer-events-none opacity-0 bg-primary/10 border-2 border-dashed border-primary flex items-center justify-center transition-opacity duration-200 [.drag-over_&]:opacity-100">
              <div className="text-primary font-medium">Drop files here to upload</div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default RichTextEditor
