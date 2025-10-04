import React, { useState, useEffect, useCallback, useMemo } from 'react'
import { useEditor, EditorContent } from '@tiptap/react'
import StarterKit from '@tiptap/starter-kit'
import Placeholder from '@tiptap/extension-placeholder'
import Link from '@tiptap/extension-link'
import Typography from '@tiptap/extension-typography'
import { Table } from '@tiptap/extension-table'
import { TableRow } from '@tiptap/extension-table-row'
import { TableHeader } from '@tiptap/extension-table-header'
import { TableCell } from '@tiptap/extension-table-cell'
import CodeBlockLowlight from '@tiptap/extension-code-block-lowlight'
import Image from '@tiptap/extension-image'
import { common, createLowlight } from 'lowlight'

// Create lowlight instance
const lowlight = createLowlight(common)

import {
  Bold,
  Italic,
  Strikethrough,
  Code,
  Link as LinkIcon,
  List,
  ListOrdered,
  Quote,
  Minus,
  Table as TableIcon,
  Image as ImageIcon,
  Undo,
  Redo,
  Type,
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
  const editorClassTokens = useMemo(() => {
    const raw = `
          prose prose-sm sm:prose lg:prose-lg xl:prose-2xl mx-auto focus:outline-none
          min-h-[200px] p-4 border-0 rounded-lg
          prose-headings:text-foreground prose-p:text-foreground
          prose-a:text-primary prose-a:hover:text-primary/80
          prose-strong:text-foreground prose-em:text-foreground
          prose-code:text-primary prose-code:bg-muted/50 prose-code:px-1.5 prose-code:py-0.5 prose-code:rounded
          prose-pre:bg-muted prose-pre:text-foreground prose-pre:border prose-pre:border-border
          prose-blockquote:border-l-primary prose-blockquote:bg-muted/30 prose-blockquote:text-muted-foreground
          prose-table:border prose-table:border-border
          prose-th:border prose-th:border-border prose-th:bg-muted prose-th:text-foreground
          prose-td:border prose-td:border-border prose-td:text-foreground
          prose-ul:text-foreground prose-ol:text-foreground
          prose-li:text-foreground
        `
    return raw
      .split(/\s+/)
      .filter(Boolean)
      .join(' ')
  }, [])
  const editor = useEditor({
    extensions: [
      StarterKit.configure({
        codeBlock: false, // We'll use CodeBlockLowlight instead
        link: false,
      }),
      Placeholder.configure({
        placeholder,
      }),
      Link.configure({
        openOnClick: false,
        HTMLAttributes: {
          class: 'text-primary hover:text-primary/80 underline cursor-pointer transition-colors',
        },
      }),
      Typography,
      Table.configure({
        resizable: true,
      }),
      TableRow,
      TableHeader,
      TableCell,
      CodeBlockLowlight.configure({
        lowlight,
        defaultLanguage: 'plaintext',
      }),
      Image.configure({
        HTMLAttributes: {
          class: 'max-w-full h-auto rounded-lg',
        },
      }),
    ],
    content,
    editable,
    onUpdate: ({ editor }) => {
      const html = editor.getHTML()
      // Security: Sanitize HTML content to prevent XSS attacks
      const sanitizedHtml = DOMPurify.sanitize(html, {
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
    },
    editorProps: {
      attributes: {
        class: editorClassTokens,
      },
    },
  })

  // Initialize content based on format
  useEffect(() => {
    if (editor) {
      let htmlContent = content

      if (editorMode === 'wysiwyg') {
        // If content looks like markdown, convert to HTML
        if (!isHtmlContent(content)) {
          htmlContent = markdownToHtml(content)
        }
        editor.commands.setContent(htmlContent)
      } else {
        // For markdown mode, convert HTML to markdown if needed
        const markdown = isHtmlContent(content) ? htmlToMarkdown(content) : content
        setMarkdownContent(markdown)
      }
    }
  }, [content, editor, editorMode])

  // Handle mode switching
  const handleModeSwitch = useCallback((newMode: EditorMode) => {
    if (newMode === editorMode) return

    if (newMode === 'markdown') {
      // Switch to markdown: convert current HTML to markdown
      const currentHtml = editor?.getHTML() || ''
      const markdown = htmlToMarkdown(currentHtml)
      setMarkdownContent(markdown)
    } else {
      // Switch to WYSIWYG: convert markdown to HTML
      const html = markdownToHtml(markdownContent)
      editor?.commands.setContent(html)
    }

    setEditorMode(newMode)
  }, [editor, editorMode, markdownContent])

  // Handle markdown textarea changes
  const handleMarkdownChange = useCallback((value: string) => {
    setMarkdownContent(value)
    // Convert to HTML and notify parent
    const html = markdownToHtml(value)
    onChange(html)
  }, [onChange])

  const addLink = () => {
    const url = window.prompt('Enter URL:')
    if (url) {
      editor?.chain().focus().setLink({ href: url }).run()
    }
  }

  const addImage = () => {
    const url = window.prompt('Enter image URL:')
    if (url) {
      // Security: Validate and sanitize the URL
      try {
        const urlObj = new URL(url)
        // Only allow http/https protocols
        if (urlObj.protocol === 'http:' || urlObj.protocol === 'https:') {
          const sanitizedUrl = DOMPurify.sanitize(url)
          editor?.chain().focus().setImage({ src: sanitizedUrl }).run()
        } else {
          alert('Only HTTP and HTTPS URLs are allowed.')
        }
      } catch {
        alert('Please enter a valid URL.')
      }
    }
  }

  // File upload handler
  const handleFileUpload = useCallback(async (file: File) => {
    if (!editor || !noteId) {
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
      // Show upload progress (you could add a loading state here)
      const attachment = await attachmentService.uploadAttachment(noteId, file)

      if (file.type.startsWith('image/')) {
        // For images, embed them directly in the editor
        const imageUrl = attachmentService.getAttachmentUrl(noteId, attachment.id)
        editor.chain().focus().setImage({
          src: imageUrl,
          alt: attachment.filename,
          title: attachment.filename
        }).run()
      } else {
        // For other files, insert as a link
        const downloadUrl = attachmentService.getAttachmentUrl(noteId, attachment.id)
        editor.chain().focus().setLink({ href: downloadUrl })
          .insertContent(`📎 ${attachment.filename}`)
          .run()
      }
    } catch (error) {
      console.error('File upload failed:', error)
      alert(`Failed to upload file: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }, [editor, noteId])

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

  const addTable = () => {
    editor?.chain().focus().insertTable({ rows: 3, cols: 3, withHeaderRow: true }).run()
  }

  if (!editor) {
    return <div className="animate-pulse bg-gray-200 h-48 rounded-lg" />
  }

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
                onClick={() => editor.chain().focus().toggleBold().run()}
                isActive={editor.isActive('bold')}
                title="Bold (Ctrl+B)"
              >
                <Bold className="w-4 h-4" />
              </ToolbarButton>

              <ToolbarButton
                onClick={() => editor.chain().focus().toggleItalic().run()}
                isActive={editor.isActive('italic')}
                title="Italic (Ctrl+I)"
              >
                <Italic className="w-4 h-4" />
              </ToolbarButton>

              <ToolbarButton
                onClick={() => editor.chain().focus().toggleStrike().run()}
                isActive={editor.isActive('strike')}
                title="Strikethrough"
              >
                <Strikethrough className="w-4 h-4" />
              </ToolbarButton>

              <ToolbarButton
                onClick={() => editor.chain().focus().toggleCode().run()}
                isActive={editor.isActive('code')}
                title="Inline Code"
              >
                <Code className="w-4 h-4" />
              </ToolbarButton>

              <ToolbarSeparator />

              {/* Headings */}
              <ToolbarButton
                onClick={() => {
                  if (editor.isActive('heading', { level: 1 })) {
                    editor.chain().focus().setParagraph().run()
                  } else {
                    editor.chain().focus().setHeading({ level: 1 }).run()
                  }
                }}
                isActive={editor.isActive('heading', { level: 1 })}
                title="Heading 1"
              >
                <Heading1 className="w-4 h-4" />
              </ToolbarButton>

              <ToolbarButton
                onClick={() => {
                  if (editor.isActive('heading', { level: 2 })) {
                    editor.chain().focus().setParagraph().run()
                  } else {
                    editor.chain().focus().setHeading({ level: 2 }).run()
                  }
                }}
                isActive={editor.isActive('heading', { level: 2 })}
                title="Heading 2"
              >
                <Heading2 className="w-4 h-4" />
              </ToolbarButton>

              <ToolbarButton
                onClick={() => {
                  if (editor.isActive('heading', { level: 3 })) {
                    editor.chain().focus().setParagraph().run()
                  } else {
                    editor.chain().focus().setHeading({ level: 3 }).run()
                  }
                }}
                isActive={editor.isActive('heading', { level: 3 })}
                title="Heading 3"
              >
                <Heading3 className="w-4 h-4" />
              </ToolbarButton>

              <ToolbarSeparator />

              {/* Lists */}
              <ToolbarButton
                onClick={() => editor.chain().focus().toggleBulletList().run()}
                isActive={editor.isActive('bulletList')}
                title="Bullet List"
              >
                <List className="w-4 h-4" />
              </ToolbarButton>

              <ToolbarButton
                onClick={() => editor.chain().focus().toggleOrderedList().run()}
                isActive={editor.isActive('orderedList')}
                title="Numbered List"
              >
                <ListOrdered className="w-4 h-4" />
              </ToolbarButton>

              <ToolbarSeparator />

              {/* Block Elements */}
              <ToolbarButton
                onClick={() => editor.chain().focus().toggleBlockquote().run()}
                isActive={editor.isActive('blockquote')}
                title="Quote"
              >
                <Quote className="w-4 h-4" />
              </ToolbarButton>

              <ToolbarButton
                onClick={() => {
                  if (editor.isActive('codeBlock')) {
                    editor.chain().focus().setParagraph().run()
                  } else {
                    editor.chain().focus().setCodeBlock().run()
                  }
                }}
                isActive={editor.isActive('codeBlock')}
                title="Code Block"
              >
                <Type className="w-4 h-4" />
              </ToolbarButton>

              <ToolbarButton
                onClick={() => editor.chain().focus().setHorizontalRule().run()}
                title="Horizontal Rule"
              >
                <Minus className="w-4 h-4" />
              </ToolbarButton>

              <ToolbarSeparator />

              {/* Links and Media */}
              <ToolbarButton
                onClick={addLink}
                isActive={editor.isActive('link')}
                title="Add Link"
              >
                <LinkIcon className="w-4 h-4" />
              </ToolbarButton>

              <div className="relative">
                <ToolbarButton
                  onClick={addImage}
                  title="Add Image (URL)"
                >
                  <ImageIcon className="w-4 h-4" />
                </ToolbarButton>
              </div>

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
                onClick={addTable}
                title="Insert Table"
              >
                <TableIcon className="w-4 h-4" />
              </ToolbarButton>

              <ToolbarSeparator />

              {/* Undo/Redo */}
              <ToolbarButton
                onClick={() => editor.chain().focus().undo().run()}
                disabled={!editor.can().undo()}
                title="Undo (Ctrl+Z)"
              >
                <Undo className="w-4 h-4" />
              </ToolbarButton>

              <ToolbarButton
                onClick={() => editor.chain().focus().redo().run()}
                disabled={!editor.can().redo()}
                title="Redo (Ctrl+Y)"
              >
                <Redo className="w-4 h-4" />
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
          <div className="relative">
            <EditorContent editor={editor} />
            {/* Drag overlay for visual feedback */}
            <div className="absolute inset-0 pointer-events-none opacity-0 bg-primary/10 border-2 border-dashed border-primary flex items-center justify-center transition-opacity duration-200 [.drag-over_&]:opacity-100">
              <div className="text-primary font-medium">Drop files here to upload</div>
            </div>
          </div>
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
