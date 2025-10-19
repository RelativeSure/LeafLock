import React from 'react'
import { Outlet, createRoute, createRouter, createRootRoute } from '@tanstack/react-router'

import { ThemeProvider } from '@/context'
import { Toaster } from '@/components/ui/sonner'
import { AppRouter } from '@/features/router'
import { AppErrorBoundary } from '@/components/common/AppErrorBoundary'

const RootLayout: React.FC = () => (
  <AppErrorBoundary>
    <ThemeProvider>
      <AppRouter />
      <Outlet />
      <Toaster />
    </ThemeProvider>
  </AppErrorBoundary>
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

export const router = createRouter({
  routeTree,
})

export type AppRouterInstance = typeof router
