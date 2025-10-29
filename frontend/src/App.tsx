import React from 'react'
import { RouterProvider } from '@tanstack/react-router'
import { ThemeProvider } from './context/ThemeContext'
import { EncryptionProvider } from './lib/encryption-context'
import { ConfigDebug } from './components/debug/ConfigDebug'
// Temporarily remove wrappers to isolate update loop

// Lazy load router to prevent circular dependency
let routerInstance: any = null

const App: React.FC = () => {
  const [router, setRouter] = React.useState<any>(null)

  React.useEffect(() => {
    // Dynamically import router to break circular dependency
    if (!routerInstance) {
      import('./router').then((module) => {
        routerInstance = module.router
        setRouter(routerInstance)
      })
    } else {
      setRouter(routerInstance)
    }
  }, [])

  if (!router) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
      </div>
    )
  }

  return (
    <ThemeProvider>
      <EncryptionProvider>
        <RouterProvider router={router} />
        <ConfigDebug />
      </EncryptionProvider>
    </ThemeProvider>
  )
}

export default App
