import React from 'react'
import { RouterProvider } from '@tanstack/react-router'
import { router } from './app-router'
import { ThemeProvider } from './context/ThemeContext'
import { EncryptionProvider } from './lib/encryption-context'
import { ConfigDebug } from './components/debug/ConfigDebug'
import { AppErrorBoundary } from './components/common/AppErrorBoundary'
import { Toaster } from './components/ui/sonner'

const App: React.FC = () => {
  console.log('🎯 App component rendering...')

  return (
    <AppErrorBoundary>
      <ThemeProvider>
        <EncryptionProvider>
          <RouterProvider router={router} />
          <Toaster />
          <ConfigDebug />
        </EncryptionProvider>
      </ThemeProvider>
    </AppErrorBoundary>
  )
}

export default App
