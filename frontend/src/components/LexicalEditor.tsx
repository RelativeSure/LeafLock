import React, { useState, useCallback, useRef, useEffect } from 'react'
import { LexicalComposer } from '@lexical/react/LexicalComposer.js'
import { RichTextPlugin } from '@lexical/react/LexicalRichTextPlugin.js'
import { ContentEditable } from '@lexical/react/LexicalContentEditable.js'
import { HistoryPlugin } from '@lexical/react/LexicalHistoryPlugin.js'
import { OnChangePlugin } from '@lexical/react/LexicalOnChangePlugin.js'
import LexicalErrorBoundary from '@lexical/react/LexicalErrorBoundary.js'
import { HeadingNode, QuoteNode } from '@lexical/rich-text'
import { TableCellNode, TableNode, TableRowNode } from '@lexical/table'
import { ListItemNode, ListNode } from '@lexical/list'
import { CodeHighlightNode, CodeNode } from '@lexical/code'
import { AutoLinkNode, LinkNode } from '@lexical/link'
import { $generateHtmlFromNodes, $generateNodesFromDOM } from '@lexical/html'
import { useLexicalComposerContext } from '@lexical/react/LexicalComposerContext.js'
import {
  $getRoot,
  $getSelection,
  $createParagraphNode,
  $createTextNode,
  EditorState,
  LexicalEditor as LexicalEditorType,
  FORMAT_TEXT_COMMAND,
  FORMAT_ELEMENT_COMMAND,
} from 'lexical'
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
import { cn } from '@/lib/utils'
import { useTheme } from '@/ThemeContext'
import DOMPurify from 'dompurify'
import { attachmentService } from '../services/attachmentService'
import { markdownToHtml, htmlToMarkdown, isHtmlContent } from '../utils/markdownConverter'

interface LexicalEditorProps {
  content: string
  onChange: (content: string) => void
  noteId?: string
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
      e.preventDefault()
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
      ${
        isActive
          ? 'bg-primary text-primary-foreground border-primary'
          : 'bg-background text-foreground border-border hover:bg-accent hover:text-accent-foreground'
      }
      ${disabled ? 'opacity-50 cursor-not-allowed' : 'hover:border-muted-foreground/50'}
    `}
  >
    {children}
  </button>
)

const ToolbarSeparator: React.FC = () => <div className="w-px h-6 bg-border mx-1" />

// Toolbar Plugin
function ToolbarPlugin({
  onModeSwitch,
  editorMode,
  showModeToggle,
}: {
  onModeSwitch: (mode: EditorMode) => void
  editorMode: EditorMode
  showModeToggle: boolean
}) {
  const [editor] = useLexicalComposerContext()
  const [isBold, setIsBold] = useState(false)
  const [isItalic, setIsItalic] = useState(false)
  const [isStrikethrough, setIsStrikethrough] = useState(false)
  const [isCode, setIsCode] = useState(false)

  const updateToolbar = useCallback(() => {
    const selection = $getSelection()
    // Update toolbar state based on selection
  }, [])

  useEffect(() => {
    return editor.registerUpdateListener(({ editorState }) => {
      editorState.read(() => {
        updateToolbar()
      })
    })
  }, [editor, updateToolbar])

  const formatBold = () => {
    editor.dispatchCommand(FORMAT_TEXT_COMMAND, 'bold')
  }

  const formatItalic = () => {
    editor.dispatchCommand(FORMAT_TEXT_COMMAND, 'italic')
  }

  const formatStrikethrough = () => {
    editor.dispatchCommand(FORMAT_TEXT_COMMAND, 'strikethrough')
  }

  const formatCode = () => {
    editor.dispatchCommand(FORMAT_TEXT_COMMAND, 'code')
  }

  const insertLink = () => {
    const url = window.prompt('Enter URL:')
    if (url) {
      editor.update(() => {
        // Insert link logic
      })
    }
  }

  const insertImage = () => {
    const url = window.prompt('Enter image URL:')
    if (url) {
      try {
        const urlObj = new URL(url)
        if (urlObj.protocol === 'http:' || urlObj.protocol === 'https:') {
          const sanitizedUrl = DOMPurify.sanitize(url)
          editor.update(() => {
            // Insert image logic
            const root = $getRoot()
            const paragraph = $createParagraphNode()
            const imageHtml = `<img src="${sanitizedUrl}" alt="Image" />`
            paragraph.append($createTextNode(imageHtml))
            root.append(paragraph)
          })
        } else {
          alert('Only HTTP and HTTPS URLs are allowed.')
        }
      } catch {
        alert('Please enter a valid URL.')
      }
    }
  }

  if (editorMode === 'markdown') return null

  return (
    <div className="flex flex-wrap items-center justify-between gap-2 p-3 border border-border border-b-0 rounded-t-lg bg-muted">
      {showModeToggle && (
        <div className="flex items-center gap-1 mr-4">
          <ToolbarButton
            onClick={() => onModeSwitch('wysiwyg')}
            isActive={editorMode === 'wysiwyg'}
            title="WYSIWYG Editor"
          >
            <Edit3 className="w-4 h-4" />
          </ToolbarButton>
          <ToolbarButton
            onClick={() => onModeSwitch('markdown')}
            isActive={editorMode === 'markdown'}
            title="Markdown Editor"
          >
            <FileText className="w-4 h-4" />
          </ToolbarButton>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-1">
        <ToolbarButton onClick={formatBold} isActive={isBold} title="Bold (Ctrl+B)">
          <Bold className="w-4 h-4" />
        </ToolbarButton>

        <ToolbarButton onClick={formatItalic} isActive={isItalic} title="Italic (Ctrl+I)">
          <Italic className="w-4 h-4" />
        </ToolbarButton>

        <ToolbarButton
          onClick={formatStrikethrough}
          isActive={isStrikethrough}
          title="Strikethrough"
        >
          <Strikethrough className="w-4 h-4" />
        </ToolbarButton>

        <ToolbarButton onClick={formatCode} isActive={isCode} title="Inline Code">
          <Code className="w-4 h-4" />
        </ToolbarButton>

        <ToolbarSeparator />

        <ToolbarButton onClick={insertLink} title="Add Link">
          <LinkIcon className="w-4 h-4" />
        </ToolbarButton>

        <ToolbarButton onClick={insertImage} title="Add Image (URL)">
          <ImageIcon className="w-4 h-4" />
        </ToolbarButton>
      </div>
    </div>
  )
}

// HTML Conversion Plugin
function HtmlConverterPlugin({
  content,
  onChange,
  noteId,
}: {
  content: string
  onChange: (html: string) => void
  noteId?: string
}) {
  const [editor] = useLexicalComposerContext()
  const isFirstRender = useRef(true)

  // Load initial content
  useEffect(() => {
    if (isFirstRender.current && content) {
      editor.update(() => {
        const parser = new DOMParser()
        const dom = parser.parseFromString(content, 'text/html')
        const nodes = $generateNodesFromDOM(editor, dom)
        const root = $getRoot()
        root.clear()
        root.append(...nodes)
      })
      isFirstRender.current = false
    }
  }, [editor, content])

  // Export HTML on change
  const handleChange = useCallback(
    (editorState: EditorState) => {
      editorState.read(() => {
        const html = $generateHtmlFromNodes(editor)
        const sanitizedHtml = DOMPurify.sanitize(html, {
          ALLOWED_TAGS: [
            'p',
            'br',
            'strong',
            'em',
            'u',
            's',
            'code',
            'pre',
            'h1',
            'h2',
            'h3',
            'h4',
            'h5',
            'h6',
            'ul',
            'ol',
            'li',
            'blockquote',
            'hr',
            'a',
            'img',
            'table',
            'thead',
            'tbody',
            'tr',
            'th',
            'td',
          ],
          ALLOWED_ATTR: [
            'href',
            'title',
            'alt',
            'src',
            'class',
            'style',
            'target',
            'rel',
            'colspan',
            'rowspan',
          ],
        })
        onChange(sanitizedHtml)
      })
    },
    [editor, onChange]
  )

  // Drag and drop file upload
  useEffect(() => {
    return editor.registerCommand(
      'DROP',
      (event: DragEvent) => {
        event.preventDefault()
        event.stopPropagation()

        if (!noteId) {
          alert('Please save the note first before uploading files.')
          return true
        }

        const files = Array.from(event.dataTransfer?.files || [])
        files.forEach(async (file) => {
          // Security: Validate file type and size
          const maxFileSize = 10 * 1024 * 1024 // 10MB limit
          if (file.size > maxFileSize) {
            alert('File size too large. Maximum size is 10MB.')
            return
          }

          const allowedTypes = [
            'image/jpeg',
            'image/png',
            'image/gif',
            'image/webp',
            'text/plain',
            'application/pdf',
            'text/markdown',
          ]

          if (!allowedTypes.includes(file.type)) {
            alert(
              'File type not allowed. Supported types: images (JPEG, PNG, GIF, WebP), text files, PDFs.'
            )
            return
          }

          try {
            const attachment = await attachmentService.uploadAttachment(noteId, file)
            editor.update(() => {
              const root = $getRoot()
              const paragraph = $createParagraphNode()

              if (file.type.startsWith('image/')) {
                const imageUrl = attachmentService.getAttachmentUrl(noteId, attachment.id)
                const imageHtml = `<img src="${imageUrl}" alt="${attachment.filename}" />`
                paragraph.append($createTextNode(imageHtml))
              } else {
                const downloadUrl = attachmentService.getAttachmentUrl(noteId, attachment.id)
                const linkHtml = `<a href="${downloadUrl}">📎 ${attachment.filename}</a>`
                paragraph.append($createTextNode(linkHtml))
              }

              root.append(paragraph)
            })
          } catch (error) {
            console.error('File upload failed:', error)
            alert(
              `Failed to upload file: ${error instanceof Error ? error.message : 'Unknown error'}`
            )
          }
        })

        return true
      },
      1 // Low priority
    )
  }, [editor, noteId])

  return <OnChangePlugin onChange={handleChange} />
}

export const LexicalEditor: React.FC<LexicalEditorProps> = ({
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
  const { effectiveTheme } = useTheme()

  const initialConfig = {
    namespace: 'LeafLockEditor',
    theme: {
      paragraph: 'mb-2',
      heading: {
        h1: 'text-3xl font-bold mb-4',
        h2: 'text-2xl font-bold mb-3',
        h3: 'text-xl font-bold mb-2',
      },
      list: {
        ul: 'list-disc ml-4 mb-2',
        ol: 'list-decimal ml-4 mb-2',
        listitem: 'mb-1',
      },
      quote: 'border-l-4 border-muted-foreground pl-4 italic my-4',
      code: 'bg-muted px-1 py-0.5 rounded font-mono text-sm',
      codeblock: 'bg-muted p-4 rounded font-mono text-sm mb-4 overflow-x-auto',
      link: 'text-primary underline hover:text-primary/80',
    },
    nodes: [
      HeadingNode,
      QuoteNode,
      TableNode,
      TableCellNode,
      TableRowNode,
      ListNode,
      ListItemNode,
      CodeNode,
      CodeHighlightNode,
      AutoLinkNode,
      LinkNode,
    ],
    editable,
    onError: (error: Error) => {
      console.error('Lexical error:', error)
    },
  }

  // Initialize markdown content from HTML content
  useEffect(() => {
    if (editorMode === 'markdown' && content) {
      const markdown = isHtmlContent(content) ? htmlToMarkdown(content) : content
      setMarkdownContent(markdown)
    }
  }, [editorMode, content])

  const handleModeSwitch = useCallback(
    (newMode: EditorMode) => {
      if (newMode === editorMode) return

      if (newMode === 'markdown') {
        // Convert HTML to markdown
        const markdown = htmlToMarkdown(content)
        setMarkdownContent(markdown)
      } else {
        // Convert markdown to HTML
        const html = markdownToHtml(markdownContent)
        onChange(html)
      }

      setEditorMode(newMode)
    },
    [editorMode, content, markdownContent, onChange]
  )

  const handleMarkdownChange = useCallback(
    (value: string) => {
      setMarkdownContent(value)
      // Convert to HTML and notify parent
      const html = markdownToHtml(value)
      onChange(html)
    },
    [onChange]
  )

  if (editorMode === 'markdown') {
    return (
      <div className={cn('w-full', className)}>
        {showModeToggle && (
          <div className="flex flex-wrap items-center justify-between gap-2 p-3 border border-border border-b-0 rounded-t-lg bg-muted">
            <div className="flex items-center gap-1">
              <ToolbarButton
                onClick={() => handleModeSwitch('wysiwyg')}
                isActive={false}
                title="WYSIWYG Editor"
              >
                <Edit3 className="w-4 h-4" />
              </ToolbarButton>
              <ToolbarButton
                onClick={() => handleModeSwitch('markdown')}
                isActive={true}
                title="Markdown Editor"
              >
                <FileText className="w-4 h-4" />
              </ToolbarButton>
            </div>
          </div>
        )}

        <div className="border border-border border-t-0 rounded-b-lg bg-background">
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
        </div>
      </div>
    )
  }

  return (
    <div className={cn('w-full', className)}>
      <LexicalComposer initialConfig={initialConfig}>
        {editable && (
          <ToolbarPlugin
            onModeSwitch={handleModeSwitch}
            editorMode={editorMode}
            showModeToggle={showModeToggle}
          />
        )}

        <div
          className={cn(
            'relative',
            editable ? 'border border-border border-t-0 rounded-b-lg bg-background' : ''
          )}
        >
          <RichTextPlugin
            contentEditable={
              <ContentEditable
                className="min-h-[200px] p-4 focus:outline-none"
                data-theme={effectiveTheme}
              />
            }
            placeholder={
              <div className="absolute top-4 left-4 text-muted-foreground pointer-events-none">
                {placeholder}
              </div>
            }
            ErrorBoundary={LexicalErrorBoundary}
          />
          <HistoryPlugin />
          <HtmlConverterPlugin content={content} onChange={onChange} noteId={noteId} />
        </div>
      </LexicalComposer>
    </div>
  )
}

export default LexicalEditor
