import { Elysia, t } from 'elysia'
import { renderMarkdownPage, getNavigation, renderTemplate } from '../utils/markdown'

export const docsRoutes = new Elysia({ prefix: '/docs' })
  .get('/', async ({ set }) => {
    try {
      const content = await renderMarkdownPage('index')
      const navigation = await getNavigation()
      
      set.headers['content-type'] = 'text/html'
      set.headers['X-Content-Type-Options'] = 'nosniff'
      set.headers['X-Frame-Options'] = 'DENY'
      set.headers['X-XSS-Protection'] = '1; mode=block'
      set.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data: https:; connect-src 'self'"
      
      return renderTemplate({
        title: 'LeafLock Documentation',
        content,
        navigation,
        currentPage: 'index'
      })
    } catch (err) {
      console.error('Error rendering index page:', err)
      set.status = 500
      return 'Internal server error'
    }
  })
  .get('/:page', {
    params: t.Object({
      page: t.String({
        pattern: '^[a-zA-Z0-9_-]+$',
        minLength: 1,
        maxLength: 50,
        description: 'Page name (alphanumeric, hyphens, underscores only)'
      })
    })
  }, async ({ params, set, error }) => {
    try {
      const content = await renderMarkdownPage(params.page)
      const navigation = await getNavigation()
      
      set.headers['content-type'] = 'text/html'
      set.headers['X-Content-Type-Options'] = 'nosniff'
      set.headers['X-Frame-Options'] = 'DENY'
      set.headers['X-XSS-Protection'] = '1; mode=block'
      set.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data: https:; connect-src 'self'"
      
      return renderTemplate({
        title: `${params.page} | LeafLock Documentation`,
        content,
        navigation,
        currentPage: params.page
      })
    } catch (err) {
      console.error(`Error rendering page ${params.page}:`, err)
      if (err instanceof Error && err.message.includes('not found')) {
        return error(404, 'Documentation page not found')
      }
      if (err instanceof Error && err.message.includes('Invalid')) {
        return error(400, 'Invalid page parameter')
      }
      return error(500, 'Internal server error')
    }
  })
  .get('/search', {
    query: t.Object({
      q: t.Optional(t.String({
        maxLength: 100,
        description: 'Search query'
      }))
    })
  }, async ({ query, set, error }) => {
    try {
      set.headers['content-type'] = 'application/json'
      set.headers['X-Content-Type-Options'] = 'nosniff'
      
      // Basic search implementation placeholder
      return { 
        results: [], 
        query: query.q || '',
        message: 'Search functionality coming soon'
      }
    } catch (err) {
      console.error('Search error:', err)
      return error(500, { error: 'Search service unavailable' })
    }
  })