import React from 'react'
import { ThemeProvider } from '@/ThemeContext'
import { Toaster } from '@/components/ui/sonner'
import { LeafLockApp } from '@/features/app/LeafLockApp'

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
        <div style={{ fontFamily: 'system-ui', padding: '2rem', maxWidth: '600px', margin: '0 auto' }}>
          <h1 style={{ color: '#dc2626' }}>LeafLock Error</h1>
          <p><strong>Error:</strong> {this.state.error?.message}</p>
          <pre style={{ background: '#f3f4f6', padding: '1rem', borderRadius: '0.5rem', overflowX: 'auto' }}>
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

const App: React.FC = () => {
  console.log('App component rendering')

  return (
    <ErrorBoundary>
      <ThemeProvider>
        <LeafLockApp />
        <Toaster />
      </ThemeProvider>
    </ErrorBoundary>
  )
}

export default App
