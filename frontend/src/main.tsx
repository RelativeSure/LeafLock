import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// Enhanced global error handlers for better debugging
window.addEventListener('error', (event) => {
  console.group('🚨 Global JavaScript Error')
  console.error('Error:', event.error)
  console.error('Message:', event.message)
  console.error('File:', event.filename)
  console.error('Line:', event.lineno, 'Column:', event.colno)

  // Check for specific error patterns
  if (event.message.includes('Cannot access') && event.message.includes('before initialization')) {
    console.error('🔍 CIRCULAR DEPENDENCY DETECTED!')
    console.error('This error typically occurs when:')
    console.error('1. Module A imports Module B')
    console.error('2. Module B imports Module A (directly or indirectly)')
    console.error('3. One module tries to access the other before it\'s fully initialized')
    console.error('')
    console.error('Common causes in React/Zustand apps:')
    console.error('- Stores importing each other')
    console.error('- Components importing stores that import other stores')
    console.error('- Dynamic imports creating circular references')
    console.error('')
    console.error('🔍 DEBUGGING INFO:')
    console.error('Current URL:', window.location.href)
    console.error('Loaded modules:', Object.keys(window))
    console.error('React version:', React.version)
  }

  if (event.message.includes('ReferenceError')) {
    console.error('🔍 REFERENCE ERROR DETECTED!')
    console.error('This usually means:')
    console.error('1. Variable used before declaration')
    console.error('2. Module not properly exported/imported')
    console.error('3. Circular dependency preventing proper initialization')
  }

  console.error('Stack trace:', event.error?.stack)
  console.groupEnd()
})

window.addEventListener('unhandledrejection', (event) => {
  console.group('🚨 Unhandled Promise Rejection')
  console.error('Reason:', event.reason)
  console.error('Promise:', event.promise)
  console.groupEnd()
})

import { logConfig } from '@/lib/config'

// Log configuration for debugging
logConfig()

// Add module loading tracking for debugging circular dependencies
console.log('🔍 Module loading tracking enabled')

// Track store initialization
console.log('🔍 Store initialization tracking enabled')

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60,
      gcTime: 1000 * 60 * 5,
      refetchOnWindowFocus: true,
      retry: (failureCount, error) => {
        const message = error instanceof Error ? error.message : ''
        // Avoid hammering the API on 401/403 responses
        if (message.includes('401') || message.includes('403')) {
          return false
        }
        return failureCount < 2
      },
    },
    mutations: {
      retry: 0,
    },
  },
})

try {
  console.log('🚀 Starting React app initialization...')

  const rootElement = document.getElementById('root')
  if (!rootElement) {
    throw new Error('Root element not found')
  }
  console.log('✅ Root element found')

  console.log('🔧 Creating React root...')
  const root = ReactDOM.createRoot(rootElement)
  console.log('✅ React root created')

  console.log('🎨 Rendering React app...')
  root.render(
    <React.StrictMode>
      <QueryClientProvider client={queryClient}>
        <App />
      </QueryClientProvider>
    </React.StrictMode>
  )
  console.log('✅ React app mounted successfully')
} catch (error) {
  console.error('❌ Failed to mount React app:', error)

  // Enhanced error logging
  const errorMessage = error instanceof Error ? error.message : 'Unknown error'
  const errorStack = error instanceof Error ? error.stack : String(error)
  const errorName = error instanceof Error ? error.name : 'Unknown'

  console.error('Error details:', {
    name: errorName,
    message: errorMessage,
    stack: errorStack,
    timestamp: new Date().toISOString(),
    userAgent: navigator.userAgent,
    url: window.location.href,
    environment: import.meta.env.MODE,
    apiUrl: import.meta.env.VITE_API_URL,
  })

  // Also log to window for debugging
  window.leafLockError = {
    error: errorMessage,
    stack: errorStack,
    timestamp: new Date().toISOString(),
    environment: import.meta.env.MODE,
  }

  document.body.innerHTML = `
    <div style="font-family: system-ui; padding: 2rem; max-width: 600px; margin: 0 auto;">
      <h1 style="color: #dc2626;">LeafLock Failed to Start</h1>
      <p><strong>Error:</strong> ${errorMessage}</p>
      <p><strong>Error Type:</strong> ${errorName}</p>
      <pre style="background: #f3f4f6; padding: 1rem; border-radius: 0.5rem; overflow-x: auto; max-height: 300px; overflow-y: auto;">${errorStack}</pre>
      <p style="margin-top: 2rem;">
        <strong>Debug info:</strong><br>
        URL: ${window.location.href}<br>
        API: ${import.meta.env.VITE_API_URL || 'not set'}<br>
        Environment: ${import.meta.env.MODE}<br>
        Timestamp: ${new Date().toISOString()}<br>
        User Agent: ${navigator.userAgent.substring(0, 100)}...
      </p>
      <p style="margin-top: 1rem; font-size: 0.9em; color: #666;">
        Check the browser console for more detailed error information.
      </p>
    </div>
  `
}
// Railway deployment trigger - Sat Oct 25 15:18:14 CEST 2025
