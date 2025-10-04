/**
 * Utilities for converting between markdown and HTML for TipTap editor
 */

import { marked } from 'marked'
import TurndownService from 'turndown'
import { gfm } from 'turndown-plugin-gfm'
import DOMPurify from 'dompurify'

// Configure marked for markdown to HTML conversion
marked.setOptions({
  gfm: true, // GitHub Flavored Markdown
  breaks: true, // Convert line breaks to <br>
})

const renderer = new marked.Renderer()
renderer.heading = ({ tokens, depth }) => `<h${depth}>${renderer.parser.parseInline(tokens)}</h${depth}>`
marked.use({ renderer })

// Configure turndown for HTML to markdown conversion
const turndownService = new TurndownService({
  headingStyle: 'atx', // Use # for headers
  hr: '---',
  bulletListMarker: '-',
  codeBlockStyle: 'fenced',
  fence: '```',
  emDelimiter: '*',
  strongDelimiter: '**',
  linkStyle: 'inlined',
  linkReferenceStyle: 'full',
})

// Add GitHub Flavored Markdown support
turndownService.use(gfm)

// Custom rules for better conversion
turndownService.addRule('codeBlock', {
  filter: function (node) {
    return (
      node.nodeName === 'PRE' &&
      node.firstChild !== null &&
      (node.firstChild as HTMLElement).nodeName === 'CODE'
    )
  },
  replacement: function (content, node) {
    const codeElement = node.firstChild as HTMLElement
    const language = codeElement.className.replace('language-', '') || ''
    return '\n```' + language + '\n' + content + '\n```\n'
  }
})

/**
 * Convert markdown string to HTML
 */
export const markdownToHtml = (markdown: string): string => {
  if (!markdown.trim()) return ''

  try {
    const parsed = marked.parse(markdown)
    if (typeof parsed !== 'string') {
      console.error('Async markdown parsing is not supported in this context')
      return markdown
    }
    const html = parsed
    // Security: Sanitize the generated HTML to prevent XSS
    return DOMPurify.sanitize(html, {
      ALLOWED_TAGS: [
        'p', 'br', 'strong', 'em', 'u', 's', 'code', 'pre',
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'ul', 'ol', 'li', 'blockquote', 'hr',
        'a', 'img', 'table', 'thead', 'tbody', 'tr', 'th', 'td'
      ],
      ALLOWED_ATTR: [
        'href', 'title', 'alt', 'src', 'class',
        'target', 'rel', 'colspan', 'rowspan'
      ]
    })
  } catch (error) {
    console.error('Error converting markdown to HTML:', error)
    return markdown // Fallback to original content
  }
}

/**
 * Convert HTML string to markdown
 */
export const htmlToMarkdown = (html: string): string => {
  if (!html.trim()) return ''

  try {
    return turndownService.turndown(html)
  } catch (error) {
    console.error('Error converting HTML to markdown:', error)
    return html // Fallback to original content
  }
}

/**
 * Detect if content is likely HTML or plain text/markdown
 */
export const isHtmlContent = (content: string): boolean => {
  if (!content.trim()) return false

  // Check for HTML tags
  const htmlTagRegex = /<[^>]*>/
  return htmlTagRegex.test(content)
}

/**
 * Smart content converter that detects format and converts appropriately
 */
export const convertContentForEditor = (content: string): string => {
  if (!content.trim()) return ''

  // If it's already HTML, sanitize it first
  if (isHtmlContent(content)) {
    return DOMPurify.sanitize(content, {
      ALLOWED_TAGS: [
        'p', 'br', 'strong', 'em', 'u', 's', 'code', 'pre',
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'ul', 'ol', 'li', 'blockquote', 'hr',
        'a', 'img', 'table', 'thead', 'tbody', 'tr', 'th', 'td'
      ],
      ALLOWED_ATTR: [
        'href', 'title', 'alt', 'src', 'class',
        'target', 'rel', 'colspan', 'rowspan'
      ]
    })
  }

  // If it's markdown/plain text, convert to HTML (already sanitized)
  return markdownToHtml(content)
}

/**
 * Export content from editor for storage
 */
export const exportContentFromEditor = (html: string, format: 'html' | 'markdown' = 'html'): string => {
  if (!html.trim()) return ''

  if (format === 'markdown') {
    return htmlToMarkdown(html)
  }

  return html
}

/**
 * Clean HTML content for display or storage
 */
export const cleanHtmlContent = (html: string): string => {
  if (!html.trim()) return ''

  // Remove empty paragraphs
  return html.replace(/<p><\/p>/g, '').trim()
}
