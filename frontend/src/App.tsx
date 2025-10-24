import React from 'react'
import { RouterProvider } from '@tanstack/react-router'
import { router } from './app-router'
import { ThemeProvider } from './context/ThemeContext'
import { EncryptionProvider } from './lib/encryption-context'
import { Toaster } from './components/ui/sonner'
import { AppErrorBoundary } from './components/common/AppErrorBoundary'

const App: React.FC = () => (
  <AppErrorBoundary>
    <ThemeProvider>
      <EncryptionProvider>
        <RouterProvider router={router} />
        <Toaster />
      </EncryptionProvider>
    </ThemeProvider>
  </AppErrorBoundary>
)

export default App
