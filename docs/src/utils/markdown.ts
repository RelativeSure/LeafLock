import { marked } from 'marked'
import matter from 'gray-matter'
import hljs from 'highlight.js'
import fs from 'fs/promises'
import path from 'path'
import createDOMPurify from 'dompurify'
import { JSDOM } from 'jsdom'
import validator from 'validator'

// Set up DOMPurify for server-side HTML sanitization
const window = new JSDOM('').window
const DOMPurify = createDOMPurify(window as any)

// Configure marked with syntax highlighting
marked.setOptions({
  highlight: function(code, lang) {
    if (lang && hljs.getLanguage(lang)) {
      try {
        return hljs.highlight(code, { language: lang }).value
      } catch (err) {
        console.error('Syntax highlighting error:', err)
      }
    }
    return hljs.highlightAuto(code).value
  },
  breaks: true,
  gfm: true
})

interface FrontMatter {
  title?: string
  summary?: string
  weight?: number
  categories?: string[]
  tags?: string[]
  slug?: string
  [key: string]: any
}

interface MarkdownContent {
  content: string
  data: FrontMatter
}

interface NavigationItem {
  name: string
  url: string
  weight: number
  children?: NavigationItem[]
}

// Cache for rendered markdown content
const markdownCache = new Map<string, { html: string; timestamp: number }>()
const CACHE_TTL = 5 * 60 * 1000 // 5 minutes

/**
 * Validates and sanitizes page parameter to prevent path traversal attacks
 */
function validatePageParameter(page: string): string {
  // Remove any path traversal attempts
  const sanitized = page.replace(/[\/\\]/g, '').replace(/\.\./g, '')
  
  // Whitelist allowed characters (alphanumeric, hyphens, underscores)
  if (!validator.matches(sanitized, /^[a-zA-Z0-9_-]+$/)) {
    throw new Error('Invalid page parameter')
  }
  
  return sanitized
}

/**
 * Validates that the resolved file path is within the content directory
 */
function validateFilePath(filePath: string, contentDir: string): boolean {
  const resolvedPath = path.resolve(filePath)
  const resolvedContentDir = path.resolve(contentDir)
  return resolvedPath.startsWith(resolvedContentDir)
}

export async function renderMarkdownPage(page: string): Promise<string> {
  // Validate and sanitize the page parameter
  const sanitizedPage = validatePageParameter(page)
  
  // Check cache first
  const cacheKey = sanitizedPage
  const cached = markdownCache.get(cacheKey)
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.html
  }
  
  const contentDir = path.join(process.cwd(), 'content')
  let filePath: string
  
  if (sanitizedPage === 'index') {
    filePath = path.join(contentDir, 'index.md')
  } else {
    // Try to find the markdown file
    const possiblePaths = [
      path.join(contentDir, `${sanitizedPage}.md`),
      path.join(contentDir, sanitizedPage, 'index.md'),
      path.join(contentDir, `${sanitizedPage}/index.md`)
    ]
    
    filePath = ''
    for (const p of possiblePaths) {
      try {
        // Validate path is within content directory
        if (!validateFilePath(p, contentDir)) {
          continue
        }
        
        await fs.access(p)
        filePath = p
        break
      } catch {
        continue
      }
    }
    
    if (!filePath) {
      throw new Error(`Markdown file not found for page: ${sanitizedPage}`)
    }
  }
  
  // Final validation that the resolved path is safe
  if (!validateFilePath(filePath, contentDir)) {
    throw new Error('Invalid file path detected')
  }
  
  const fileContent = await fs.readFile(filePath, 'utf-8')
  const { content, data } = matter(fileContent) as { content: string; data: FrontMatter }
  
  // Convert markdown to HTML
  const rawHtml = await marked(content)
  
  // Sanitize HTML to prevent XSS attacks
  const sanitizedHtml = DOMPurify.sanitize(rawHtml, {
    ALLOWED_TAGS: [
      'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
      'p', 'br', 'hr',
      'ul', 'ol', 'li',
      'strong', 'em', 'b', 'i', 'u',
      'a', 'img',
      'pre', 'code',
      'blockquote',
      'table', 'thead', 'tbody', 'tr', 'th', 'td',
      'div', 'span'
    ],
    ALLOWED_ATTR: [
      'href', 'title', 'alt', 'src',
      'class', 'id',
      'target', 'rel'
    ],
    ALLOWED_URI_REGEXP: /^https?:\/\/|^\/|^#/
  })
  
  // Cache the result
  markdownCache.set(cacheKey, {
    html: sanitizedHtml,
    timestamp: Date.now()
  })
  
  return sanitizedHtml
}

export async function getNavigation(): Promise<NavigationItem[]> {
  // This would typically read from your content directory and build navigation
  // For now, we'll return a static navigation based on your existing Hugo setup
  return [
    { name: 'Home', url: '/docs', weight: 10 },
    { name: 'Admin Guide', url: '/docs/admin-guide', weight: 20 },
    { name: 'Developer Guide', url: '/docs/developer-guide', weight: 30 },
    { name: 'Privacy Policy', url: '/docs/privacy-policy', weight: 40 },
    { name: 'GDPR Compliance', url: '/docs/gdpr-compliance', weight: 50 },
    { name: 'Global Compliance', url: '/docs/global-compliance', weight: 60 },
    { name: 'Terms of Use', url: '/docs/terms-of-use', weight: 70 }
  ]
}

interface TemplateData {
  title: string
  content: string
  navigation: NavigationItem[]
  currentPage: string
}

export function renderTemplate(data: TemplateData): string {
  const { title, content, navigation, currentPage } = data
  
  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title}</title>
    <link rel="stylesheet" href="/assets/css/main.css">
    <link rel="stylesheet" href="/assets/css/highlight.css">
    <link rel="icon" href="/assets/favicon.svg" type="image/svg+xml">
    <meta name="description" content="Secure, end-to-end encrypted notes with zero-knowledge architecture">
    <meta name="keywords" content="leaflock, encryption, privacy, end-to-end, zero-knowledge, secure notes">
</head>
<body>
    <header class="header">
        <div class="container">
            <div class="header-content">
                <a href="/docs" class="logo">
                    <img src="/assets/favicon.svg" alt="LeafLock" width="32" height="32">
                    <span>LeafLock Docs</span>
                </a>
                <nav class="navigation">
                    ${navigation.map(item => `
                        <a href="${item.url}" class="${currentPage === item.url.replace('/docs/', '') || (item.url === '/docs' && currentPage === 'index') ? 'active' : ''}">${item.name}</a>
                    `).join('')}
                </nav>
            </div>
        </div>
    </header>
    
    <main class="main">
        <div class="container">
            <div class="content">
                ${content}
            </div>
        </div>
    </main>
    
    <footer class="footer">
        <div class="container">
            <p>&copy; 2025 LeafLock Team. <a href="mailto:contact@leaflock.app">contact@leaflock.app</a></p>
            <p>
                <a href="https://github.com/RelativeSure/LeafLock">GitHub Repository</a> |
                <a href="/api-docs">API Documentation</a>
            </p>
        </div>
    </footer>
</body>
</html>`
}