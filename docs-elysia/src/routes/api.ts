import { Elysia, t } from 'elysia'

export const apiRoutes = new Elysia({ prefix: '/api' })
  .get('/health', () => {
    return { 
      status: 'healthy', 
      timestamp: new Date().toISOString(),
      service: 'leaflock-docs'
    }
  }, {
    detail: {
      summary: 'Health Check',
      description: 'Check if the documentation service is running',
      tags: ['API']
    }
  })
  .get('/navigation', async () => {
    // This would typically fetch from your actual API
    return {
      main: [
        { name: 'Home', url: '/docs', weight: 10 },
        { name: 'Admin Guide', url: '/docs/admin-guide', weight: 20 },
        { name: 'Developer Guide', url: '/docs/developer-guide', weight: 30 },
        { name: 'Privacy Policy', url: '/docs/privacy-policy', weight: 40 },
        { name: 'GDPR Compliance', url: '/docs/gdpr-compliance', weight: 50 }
      ],
      categories: [
        { name: 'Administration', slug: 'administration' },
        { name: 'Development', slug: 'development' },
        { name: 'Legal', slug: 'legal' },
        { name: 'Privacy', slug: 'privacy' }
      ]
    }
  }, {
    detail: {
      summary: 'Get Navigation',
      description: 'Get the navigation structure for the documentation',
      tags: ['API']
    }
  })