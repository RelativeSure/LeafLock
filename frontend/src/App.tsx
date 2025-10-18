import React from 'react'
import { ThemeProvider } from '@/ThemeContext'
import { Toaster } from '@/components/ui/sonner'
import { LeafLockApp } from '@/features/app/LeafLockApp'
import { Outlet, RouterProvider, createRoute, createRouter, createRootRoute } from '@tanstack/react-router'

class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean; error: Error | null }
> {
  constructor(props: { children: React.ReactNode }) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('React Error Boundary caught:', error, errorInfo)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div
          style={{ fontFamily: 'system-ui', padding: '2rem', maxWidth: '600px', margin: '0 auto' }}
        >
          <h1 style={{ color: '#dc2626' }}>LeafLock Error</h1>
          <p>
            <strong>Error:</strong> {this.state.error?.message}
          </p>
          <pre
            style={{
              background: '#f3f4f6',
              padding: '1rem',
              borderRadius: '0.5rem',
              overflowX: 'auto',
            }}
          >
            {this.state.error?.stack}
          </pre>
          <button
            onClick={() => window.location.reload()}
            style={{ marginTop: '1rem', padding: '0.5rem 1rem', cursor: 'pointer' }}
          >
            Reload Page
          </button>
        </div>
      )
    }

    return this.props.children
  }
}

const RootLayout: React.FC = () => (
  <ErrorBoundary>
    <ThemeProvider>
      <LeafLockApp />
      <Outlet />
      <Toaster />
    </ThemeProvider>
  </ErrorBoundary>
)

const rootRoute = createRootRoute({
  component: RootLayout,
})

const NullRouteComponent: React.FC = () => null
const OutletRouteComponent: React.FC = () => <Outlet />

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  component: NullRouteComponent,
})

const authRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'auth',
  component: OutletRouteComponent,
})

const authLoginRoute = createRoute({
  getParentRoute: () => authRoute,
  path: 'login',
  component: NullRouteComponent,
})

const authUnlockRoute = createRoute({
  getParentRoute: () => authRoute,
  path: 'unlock',
  component: NullRouteComponent,
})

const authForgotRoute = createRoute({
  getParentRoute: () => authRoute,
  path: 'forgot',
  component: NullRouteComponent,
})

const authResetRoute = createRoute({
  getParentRoute: () => authRoute,
  path: 'reset',
  component: NullRouteComponent,
})

const appRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'app',
  component: OutletRouteComponent,
})

const appIndexRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/',
  component: NullRouteComponent,
})

const appNotesRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'notes',
  component: NullRouteComponent,
})

const appEditorRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'editor',
  component: NullRouteComponent,
})

const appSettingsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'settings',
  component: NullRouteComponent,
})

const appTagsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'tags',
  component: NullRouteComponent,
})

const appFoldersRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'folders',
  component: NullRouteComponent,
})

const appTemplatesRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'templates',
  component: NullRouteComponent,
})

const appAdminRoute = createRoute({
  getParentRoute: () => appRoute,
  path: 'admin',
  component: NullRouteComponent,
})

const notFoundRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '*',
  component: NullRouteComponent,
})

const routeTree = rootRoute.addChildren([
  indexRoute,
  authRoute.addChildren([authLoginRoute, authUnlockRoute, authForgotRoute, authResetRoute]),
  appRoute.addChildren([
    appIndexRoute,
    appNotesRoute,
    appEditorRoute,
    appSettingsRoute,
    appTagsRoute,
    appFoldersRoute,
    appTemplatesRoute,
    appAdminRoute,
  ]),
  notFoundRoute,
])

const router = createRouter({
  routeTree,
})

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}

const App: React.FC = () => {
  return <RouterProvider router={router} />
}

export default App
