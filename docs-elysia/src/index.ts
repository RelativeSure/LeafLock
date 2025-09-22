import { Elysia } from 'elysia'
import { swagger } from '@elysiajs/swagger'
import { staticPlugin } from '@elysiajs/static'
import { html } from '@elysiajs/html'

import { docsRoutes } from './routes/docs'
import { apiRoutes } from './routes/api'

const app = new Elysia()
  .use(html())
  .use(staticPlugin({
    assets: 'public',
    prefix: '/assets'
  }))
  .use(swagger({
    documentation: {
      info: {
        title: 'LeafLock API Documentation',
        version: '1.0.0',
        description: 'Secure, end-to-end encrypted notes API documentation',
        contact: {
          name: 'LeafLock Team',
          email: 'contact@leaflock.app'
        }
      },
      servers: [
        { url: 'https://api.leaflock.app', description: 'Production' },
        { url: 'http://localhost:8080', description: 'Development' }
      ],
      tags: [
        { name: 'Documentation', description: 'Static documentation pages' },
        { name: 'API', description: 'API endpoints documentation' }
      ]
    },
    path: '/api-docs',
    exclude: ['/docs', '/assets', '/']
  }))
  .use(docsRoutes)
  .use(apiRoutes)
  .get('/', () => {
    return Response.redirect('/docs', 302)
  })
  .listen(3000)

console.log(`📚 LeafLock Documentation is running at http://localhost:3000`)
console.log(`🔧 API Documentation available at http://localhost:3000/api-docs`)

export default app