import { Note } from '@/services/api'
import { decryptTextWithStoredKey } from './encryption-utils'

/**
 * Export utilities for notes
 * Supports Markdown, HTML, and plain text exports
 */

export interface ExportOptions {
  format: 'markdown' | 'html' | 'txt' | 'pdf'
  includeMetadata?: boolean
  filename?: string
}

/**
 * Convert HTML content to Markdown
 */
function htmlToMarkdown(html: string): string {
  let markdown = html

  // Headers
  markdown = markdown.replace(/<h1[^>]*>(.*?)<\/h1>/gi, '# $1\n\n')
  markdown = markdown.replace(/<h2[^>]*>(.*?)<\/h2>/gi, '## $1\n\n')
  markdown = markdown.replace(/<h3[^>]*>(.*?)<\/h3>/gi, '### $1\n\n')
  markdown = markdown.replace(/<h4[^>]*>(.*?)<\/h4>/gi, '#### $1\n\n')
  markdown = markdown.replace(/<h5[^>]*>(.*?)<\/h5>/gi, '##### $1\n\n')
  markdown = markdown.replace(/<h6[^>]*>(.*?)<\/h6>/gi, '###### $1\n\n')

  // Bold and italic
  markdown = markdown.replace(/<strong[^>]*>(.*?)<\/strong>/gi, '**$1**')
  markdown = markdown.replace(/<b[^>]*>(.*?)<\/b>/gi, '**$1**')
  markdown = markdown.replace(/<em[^>]*>(.*?)<\/em>/gi, '*$1*')
  markdown = markdown.replace(/<i[^>]*>(.*?)<\/i>/gi, '*$1*')

  // Code
  markdown = markdown.replace(/<code[^>]*>(.*?)<\/code>/gi, '`$1`')
  markdown = markdown.replace(/<pre[^>]*>(.*?)<\/pre>/gi, (_match, code) => {
    return '```\n' + code.replace(/<[^>]*>/g, '') + '\n```\n\n'
  })

  // Links
  markdown = markdown.replace(/<a[^>]*href="([^"]*)"[^>]*>(.*?)<\/a>/gi, '[$2]($1)')

  // Lists
  markdown = markdown.replace(/<ul[^>]*>/gi, '\n')
  markdown = markdown.replace(/<\/ul>/gi, '\n')
  markdown = markdown.replace(/<ol[^>]*>/gi, '\n')
  markdown = markdown.replace(/<\/ol>/gi, '\n')
  markdown = markdown.replace(/<li[^>]*>(.*?)<\/li>/gi, '- $1\n')

  // Task lists
  markdown = markdown.replace(
    /<li[^>]*data-type="taskItem"[^>]*data-checked="true"[^>]*>(.*?)<\/li>/gi,
    '- [x] $1\n'
  )
  markdown = markdown.replace(
    /<li[^>]*data-type="taskItem"[^>]*data-checked="false"[^>]*>(.*?)<\/li>/gi,
    '- [ ] $1\n'
  )

  // Blockquote
  markdown = markdown.replace(/<blockquote[^>]*>(.*?)<\/blockquote>/gi, (_match, content) => {
    return content
      .split('\n')
      .map((line: string) => '> ' + line)
      .join('\n') + '\n\n'
  })

  // Paragraphs
  markdown = markdown.replace(/<p[^>]*>(.*?)<\/p>/gi, '$1\n\n')

  // Line breaks
  markdown = markdown.replace(/<br\s*\/?>/gi, '\n')

  // Remove remaining HTML tags
  markdown = markdown.replace(/<[^>]*>/g, '')

  // Decode HTML entities
  markdown = markdown
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")

  // Clean up excessive newlines
  markdown = markdown.replace(/\n{3,}/g, '\n\n')

  return markdown.trim()
}

/**
 * Generate metadata header for export
 */
function generateMetadata(note: Note, title: string): string {
  const date = new Date(note.createdAt).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  })

  return `---
Title: ${title}
Created: ${date}
Modified: ${new Date(note.updatedAt).toLocaleDateString('en-US')}
---

`
}

/**
 * Export note to Markdown format
 */
export async function exportToMarkdown(note: Note, options: ExportOptions = { format: 'markdown' }): Promise<string> {
  const title = await decryptTextWithStoredKey(note.title)
  const content = await decryptTextWithStoredKey(note.content)

  let markdown = ''

  if (options.includeMetadata) {
    markdown += generateMetadata(note, title)
  }

  markdown += `# ${title}\n\n`
  markdown += htmlToMarkdown(content)

  return markdown
}

/**
 * Export note to HTML format
 */
export async function exportToHTML(note: Note, options: ExportOptions = { format: 'html' }): Promise<string> {
  const title = await decryptTextWithStoredKey(note.title)
  const content = await decryptTextWithStoredKey(note.content)

  let html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title}</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      line-height: 1.6;
      color: #333;
      max-width: 800px;
      margin: 0 auto;
      padding: 2rem;
    }
    h1, h2, h3, h4, h5, h6 {
      margin-top: 1.5rem;
      margin-bottom: 0.5rem;
      font-weight: 600;
    }
    code {
      background: #f4f4f4;
      padding: 0.2rem 0.4rem;
      border-radius: 3px;
      font-family: 'Monaco', 'Courier New', monospace;
      font-size: 0.9em;
    }
    pre {
      background: #f4f4f4;
      padding: 1rem;
      border-radius: 5px;
      overflow-x: auto;
    }
    pre code {
      background: none;
      padding: 0;
    }
    blockquote {
      border-left: 4px solid #ddd;
      padding-left: 1rem;
      margin-left: 0;
      color: #666;
    }
    a {
      color: #0066cc;
      text-decoration: none;
    }
    a:hover {
      text-decoration: underline;
    }
    .metadata {
      background: #f9f9f9;
      padding: 1rem;
      border-radius: 5px;
      margin-bottom: 2rem;
      font-size: 0.9em;
      color: #666;
    }
    ul[data-type="taskList"] {
      list-style: none;
      padding-left: 0;
    }
    li[data-type="taskItem"] {
      display: flex;
      align-items: center;
    }
    li[data-type="taskItem"] input[type="checkbox"] {
      margin-right: 0.5rem;
    }
  </style>
</head>
<body>
`

  if (options.includeMetadata) {
    const date = new Date(note.createdAt).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    })
    html += `  <div class="metadata">
    <strong>Created:</strong> ${date}<br>
    <strong>Modified:</strong> ${new Date(note.updatedAt).toLocaleDateString('en-US')}
  </div>
`
  }

  html += `  <h1>${title}</h1>
  ${content}
</body>
</html>`

  return html
}

/**
 * Export note to plain text format
 */
export async function exportToText(note: Note, options: ExportOptions = { format: 'txt' }): Promise<string> {
  const title = await decryptTextWithStoredKey(note.title)
  const content = await decryptTextWithStoredKey(note.content)

  let text = ''

  if (options.includeMetadata) {
    const date = new Date(note.createdAt).toLocaleDateString('en-US')
    text += `Title: ${title}\n`
    text += `Created: ${date}\n`
    text += `Modified: ${new Date(note.updatedAt).toLocaleDateString('en-US')}\n`
    text += `${'='.repeat(50)}\n\n`
  }

  text += `${title}\n\n`

  // Strip all HTML tags for plain text
  const plainContent = content.replace(/<[^>]*>/g, '')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\n{3,}/g, '\n\n')

  text += plainContent

  return text
}

/**
 * Download exported content as file
 */
export function downloadExport(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}

/**
 * Export note with specified format
 */
export async function exportNote(note: Note, options: ExportOptions): Promise<void> {
  const title = await decryptTextWithStoredKey(note.title)
  const sanitizedTitle = title.replace(/[^a-z0-9]/gi, '_').toLowerCase()
  const filename = options.filename || `${sanitizedTitle}_${Date.now()}`

  let content: string
  let mimeType: string
  let extension: string

  switch (options.format) {
    case 'markdown':
      content = await exportToMarkdown(note, options)
      mimeType = 'text/markdown'
      extension = 'md'
      break
    case 'html':
      content = await exportToHTML(note, options)
      mimeType = 'text/html'
      extension = 'html'
      break
    case 'txt':
      content = await exportToText(note, options)
      mimeType = 'text/plain'
      extension = 'txt'
      break
    case 'pdf':
      throw new Error('PDF export requires jsPDF library. Please install it with: pnpm add jspdf')
    default:
      throw new Error(`Unsupported export format: ${options.format}`)
  }

  downloadExport(content, `${filename}.${extension}`, mimeType)
}

/**
 * Batch export multiple notes
 */
export async function exportNotes(notes: Note[], options: ExportOptions): Promise<void> {
  const exports = await Promise.all(
    notes.map(async (note) => {
      const title = await decryptTextWithStoredKey(note.title)
      let content: string

      switch (options.format) {
        case 'markdown':
          content = await exportToMarkdown(note, options)
          break
        case 'html':
          content = await exportToHTML(note, options)
          break
        case 'txt':
          content = await exportToText(note, options)
          break
        default:
          throw new Error(`Unsupported format: ${options.format}`)
      }

      return { title, content }
    })
  )

  // Combine all exports into a single file with separators
  const combined = exports
    .map((exp, i) => {
      const separator = '\n\n' + '='.repeat(80) + '\n\n'
      return i === 0 ? exp.content : separator + exp.content
    })
    .join('')

  const filename = options.filename || `notes_export_${Date.now()}`
  const extension = options.format === 'markdown' ? 'md' : options.format === 'html' ? 'html' : 'txt'
  const mimeType =
    options.format === 'markdown' ? 'text/markdown' : options.format === 'html' ? 'text/html' : 'text/plain'

  downloadExport(combined, `${filename}.${extension}`, mimeType)
}
