import React from 'react'
import { ThemeProvider } from '@/ThemeContext'
import { Toaster } from '@/components/ui/sonner'
import { LeafLockApp } from '@/features/app/LeafLockApp'

const App: React.FC = () => (
  <ThemeProvider>
    <LeafLockApp />
    <Toaster />
  </ThemeProvider>
)

export default App
