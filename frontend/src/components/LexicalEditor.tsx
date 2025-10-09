import React, { useState, useCallback, useRef, useEffect } from 'react'
import { LexicalComposer } from '@lexical/react/LexicalComposer.js'
import { RichTextPlugin } from '@lexical/react/LexicalRichTextPlugin.js'
import { ContentEditable } from '@lexical/react/LexicalContentEditable.js'
import { HistoryPlugin } from '@lexical/react/LexicalHistoryPlugin.js'
import { OnChangePlugin } from '@lexical/react/LexicalOnChangePlugin.js'
import { LexicalErrorBoundary } from '@lexical/react/LexicalErrorBoundary.js'
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
  $isRangeSelection,
  $createParagraphNode,
  $createTextNode,
  EditorState,
  FORMAT_TEXT_COMMAND,
  DROP_COMMAND,
} from 'lexical'
import { Bold, Italic, Strikethrough, Code, Link as LinkIcon, Image as ImageIcon, List, ListOrdered, Quote, Heading1, Heading2, Heading3, Minus } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useTheme } from '@/ThemeContext'
import DOMPurify from 'dompurify'
import { attachmentService } from '../services/attachmentService'
// Markdown helpers are no longer used; editor runs WYSIWYG-only

interface LexicalEditorProps {
  content: string
  onChange: (content: string) => void
  noteId?: string
  placeholder?: string
  editable?: boolean
  className?: string
  // WYSIWYG only
}

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
function ToolbarPlugin() {
  const [editor] = useLexicalComposerContext()
  const [isBold, setIsBold] = useState(false)
  const [isItalic, setIsItalic] = useState(false)
  const [isStrikethrough, setIsStrikethrough] = useState(false)
  const [isCode, setIsCode] = useState(false)

  const updateToolbar = useCallback(() => {
    const selection = $getSelection()

    if ($isRangeSelection(selection)) {
      setIsBold(selection.hasFormat('bold'))
      setIsItalic(selection.hasFormat('italic'))
      setIsStrikethrough(selection.hasFormat('strikethrough'))
      setIsCode(selection.hasFormat('code'))
    } else {
      setIsBold(false)
      setIsItalic(false)
      setIsStrikethrough(false)
      setIsCode(false)
    }
  }, [setIsBold, setIsItalic, setIsStrikethrough, setIsCode])

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

  const insertCodeBlock = () => {
    editor.update(() => {
      const root = $getRoot()
      const paragraph = $createParagraphNode()
      paragraph.append($createTextNode('```\n// code\n```'))
      root.append(paragraph)
    })
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

  const formatHeading = (level: 1 | 2 | 3) => {
    editor.update(() => {
      const root = $getRoot()
      const paragraph = $createParagraphNode()
      paragraph.append($createTextNode(level === 1 ? '# ' : level === 2 ? '## ' : '### '))
      root.append(paragraph)
    })
  }

  const insertList = (ordered: boolean) => {
    editor.update(() => {
      const root = $getRoot()
      const paragraph = $createParagraphNode()
      paragraph.append($createTextNode(ordered ? '1. ' : '- '))
      root.append(paragraph)
    })
  }

  const insertQuote = () => {
    editor.update(() => {
      const root = $getRoot()
      const paragraph = $createParagraphNode()
      paragraph.append($createTextNode('> '))
      root.append(paragraph)
    })
  }

  const insertHr = () => {
    editor.update(() => {
      const root = $getRoot()
      const paragraph = $createParagraphNode()
      paragraph.append($createTextNode('\n---\n'))
      root.append(paragraph)
    })
  }

  return (
    <div className="flex flex-wrap items-center justify-between gap-2 p-3 border border-border border-b-0 rounded-t-lg bg-muted">
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

        <ToolbarButton onClick={() => formatHeading(1)} title="Heading 1">
          <Heading1 className="w-4 h-4" />
        </ToolbarButton>
        <ToolbarButton onClick={() => formatHeading(2)} title="Heading 2">
          <Heading2 className="w-4 h-4" />
        </ToolbarButton>
        <ToolbarButton onClick={() => formatHeading(3)} title="Heading 3">
          <Heading3 className="w-4 h-4" />
        </ToolbarButton>

        <ToolbarSeparator />

        <ToolbarButton onClick={() => insertList(false)} title="Bulleted List">
          <List className="w-4 h-4" />
        </ToolbarButton>
        <ToolbarButton onClick={() => insertList(true)} title="Numbered List">
          <ListOrdered className="w-4 h-4" />
        </ToolbarButton>

        <ToolbarButton onClick={insertQuote} title="Blockquote">
          <Quote className="w-4 h-4" />
        </ToolbarButton>

        <ToolbarButton onClick={insertLink} title="Add Link">
          <LinkIcon className="w-4 h-4" />
        </ToolbarButton>

        <ToolbarButton onClick={insertImage} title="Add Image (URL)">
          <ImageIcon className="w-4 h-4" />
        </ToolbarButton>

      <ToolbarSeparator />

      <ToolbarButton onClick={insertCodeBlock} title="Insert Code Block">
        <Code className="w-4 h-4" />
      </ToolbarButton>

        <ToolbarButton onClick={insertHr} title="Horizontal Rule">
          <Minus className="w-4 h-4" />
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
  const lastImportedContent = useRef<{ content: string; noteId?: string } | null>(null)
  const lastEmittedContent = useRef<string | null>(null)

  // Load or refresh content when parent prop changes
  useEffect(() => {
    const importedKey = lastImportedContent.current

    const alreadyImported =
      importedKey?.content === content && importedKey?.noteId === noteId
    const justEmitted =
      lastEmittedContent.current === content && importedKey?.noteId === noteId

    if (alreadyImported || justEmitted) {
      lastImportedContent.current = { content, noteId }
      return
    }

    editor.update(() => {
      const parser = new DOMParser()
      const dom = parser.parseFromString(content || '', 'text/html')
      const nodes = $generateNodesFromDOM(editor, dom)
      const root = $getRoot()
      root.clear()
      root.append(...nodes)
    })

    lastImportedContent.current = { content, noteId }
  }, [editor, content, noteId])

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
        lastEmittedContent.current = sanitizedHtml
        onChange(sanitizedHtml)
      })
    },
    [editor, onChange]
  )

  // Drag and drop file upload
  useEffect(() => {
    return editor.registerCommand(
      DROP_COMMAND,
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
}) => {
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

  // WYSIWYG-only: no markdown mode

  return (
    <div className={cn('w-full', className)}>
      <LexicalComposer initialConfig={initialConfig}>
        {editable && <ToolbarPlugin />}

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
