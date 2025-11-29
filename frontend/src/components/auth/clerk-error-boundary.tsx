import React from 'react'
import { AlertTriangle, RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

interface ClerkErrorBoundaryState {
  hasError: boolean
  error: Error | null
}

interface ClerkErrorBoundaryProps {
  children: React.ReactNode
  onReset?: () => void
}

export class ClerkErrorBoundary extends React.Component<
  ClerkErrorBoundaryProps,
  ClerkErrorBoundaryState
> {
  constructor(props: ClerkErrorBoundaryProps) {
    super(props)
    this.state = {
      hasError: false,
      error: null,
    }
  }

  static getDerivedStateFromError(error: Error): ClerkErrorBoundaryState {
    return {
      hasError: true,
      error,
    }
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('Clerk Authentication Error:', error, errorInfo)
  }

  handleReset = () => {
    this.setState({
      hasError: false,
      error: null,
    })

    // Clear any cached Clerk data
    if (typeof window !== 'undefined') {
      window.location.reload()
    }

    this.props.onReset?.()
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center p-4 bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
          <Card className="w-full max-w-md bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60 border border-border/50">
            <CardHeader className="text-center">
              <div className="flex justify-center mb-4">
                <AlertTriangle className="h-12 w-12 text-destructive" />
              </div>
              <CardTitle className="text-xl font-bold text-foreground">
                Authentication Error
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="text-center space-y-2">
                <p className="text-muted-foreground">
                  We're experiencing an issue with authentication.
                </p>
                <p className="text-sm text-muted-foreground">
                  {this.state.error?.message || 'An unexpected error occurred.'}
                </p>
              </div>

              <div className="space-y-3">
                <Button onClick={this.handleReset} className="w-full" variant="default">
                  <RefreshCw className="mr-2 h-4 w-4" />
                  Try Again
                </Button>

                <Button
                  onClick={() => (window.location.href = '/login')}
                  className="w-full"
                  variant="outline"
                >
                  Go to Login
                </Button>
              </div>

              <div className="text-center">
                <p className="text-xs text-muted-foreground">
                  If the problem persists, please contact support.
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      )
    }

    return this.props.children
  }
}

// Wrapper component for Clerk authentication with error boundary
export function ClerkAuthWithErrorBoundary({ children }: { children: React.ReactNode }) {
  return <ClerkErrorBoundary>{children}</ClerkErrorBoundary>
}
