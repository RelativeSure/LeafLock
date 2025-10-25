import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// Add global error handlers for debugging
window.addEventListener('error', (event) => {
  console.error('Global error:', event.error)
  console.error('Error details:', {
    message: event.message,
    filename: event.filename,
    lineno: event.lineno,
    colno: event.colno,
    stack: event.error?.stack,
  })
})

window.addEventListener('unhandledrejection', (event) => {
  console.error('Unhandled promise rejection:', event.reason)
})

import { logConfig } from '@/lib/config'

// Log configuration for debugging
logConfig()

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
