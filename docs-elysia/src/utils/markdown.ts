import { marked } from 'marked'
import matter from 'gray-matter'
import hljs from 'highlight.js'
import fs from 'fs/promises'
import path from 'path'

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

export async function renderMarkdownPage(page: string): Promise<string> {
  const contentDir = path.join(process.cwd(), 'content')
  let filePath: string
  
  if (page === 'index') {
    filePath = path.join(contentDir, 'index.md')
  } else {
    // Try to find the markdown file
    const possiblePaths = [
      path.join(contentDir, `${page}.md`),
      path.join(contentDir, page, 'index.md'),
      path.join(contentDir, `${page}/index.md`)
    ]
    
    filePath = ''
    for (const p of possiblePaths) {
      try {
        await fs.access(p)
        filePath = p
        break
      } catch {
        continue
      }
    }
    
    if (!filePath) {
      throw new Error(`Markdown file not found for page: ${page}`)
    }
  }
  
  const fileContent = await fs.readFile(filePath, 'utf-8')
  const { content, data } = matter(fileContent) as { content: string; data: FrontMatter }
  
  // Convert markdown to HTML
  const html = await marked(content)
  
  return html
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