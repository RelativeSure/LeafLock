import type { ReactElement } from 'react'
import { RouterProvider } from '@tanstack/react-router'

import { router } from '@/app-router'

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}

/* c8 ignore start */
export function App(): ReactElement {
  return <RouterProvider router={router} />
}

export default App
/* c8 ignore stop */
