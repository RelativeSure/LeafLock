import { Elysia } from 'elysia'
import { renderMarkdownPage, getNavigation, renderTemplate } from '../utils/markdown'

export const docsRoutes = new Elysia({ prefix: '/docs' })
  .get('/', async ({ set }) => {
    const content = await renderMarkdownPage('index')
    const navigation = await getNavigation()
    
    set.headers['content-type'] = 'text/html'
    return renderTemplate({
      title: 'LeafLock Documentation',
      content,
      navigation,
      currentPage: 'index'
    })
  })
  .get('/:page', async ({ params, set, error }) => {
    try {
      const content = await renderMarkdownPage(params.page)
      const navigation = await getNavigation()
      
      set.headers['content-type'] = 'text/html'
      return renderTemplate({
        title: `${params.page} | LeafLock Documentation`,
        content,
        navigation,
        currentPage: params.page
      })
    } catch (err) {
      return error(404, 'Documentation page not found')
    }
  })
  .get('/search', async ({ query, set }) => {
    // TODO: Implement search functionality
    set.headers['content-type'] = 'application/json'
    return { results: [], query: query.q || '' }
  })