import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { AppErrorBoundary } from '../AppErrorBoundary'

describe('AppErrorBoundary', () => {
  let consoleErrorSpy: any

  beforeEach(() => {
    consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(vi.fn())

    // Mock window.location.reload
    delete (window as any).location
    window.location = { reload: vi.fn() } as any
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('should render children when no error', () => {
    render(
      <AppErrorBoundary>
        <div>Test Content</div>
      </AppErrorBoundary>
    )

    expect(screen.getByText('Test Content')).toBeInTheDocument()
  })

  it('should render multiple children when no error', () => {
    render(
      <AppErrorBoundary>
        <div>Child 1</div>
        <div>Child 2</div>
      </AppErrorBoundary>
    )

    expect(screen.getByText('Child 1')).toBeInTheDocument()
    expect(screen.getByText('Child 2')).toBeInTheDocument()
  })

  it('should catch and display error', () => {
    const ThrowError = () => {
      throw new Error('Test error')
    }

    render(
      <AppErrorBoundary>
        <ThrowError />
      </AppErrorBoundary>
    )

    expect(screen.getByText(/something went wrong/i)).toBeInTheDocument()
  })

  it('should display error heading', () => {
    const ThrowError = () => {
      throw new Error('Test error')
    }

    render(
      <AppErrorBoundary>
        <ThrowError />
      </AppErrorBoundary>
    )

    expect(screen.getByText('Something went wrong')).toBeInTheDocument()
  })

  it('should display error message', () => {
    const ThrowError = () => {
      throw new Error('Test error')
    }

    render(
      <AppErrorBoundary>
        <ThrowError />
      </AppErrorBoundary>
    )

    expect(screen.getByText(/We're sorry, but something unexpected happened/i)).toBeInTheDocument()
  })

  it('should display refresh instruction', () => {
    const ThrowError = () => {
      throw new Error('Test error')
    }

    render(
      <AppErrorBoundary>
        <ThrowError />
      </AppErrorBoundary>
    )

    expect(screen.getByText(/Please try refreshing the page/i)).toBeInTheDocument()
  })

  it('should render refresh page button', () => {
    const ThrowError = () => {
      throw new Error('Test error')
    }

    render(
      <AppErrorBoundary>
        <ThrowError />
      </AppErrorBoundary>
    )

    expect(screen.getByRole('button', { name: /refresh page/i })).toBeInTheDocument()
  })

  it('should reload page when refresh button clicked', () => {
    const reloadSpy = vi.fn()
    window.location.reload = reloadSpy

    const ThrowError = () => {
      throw new Error('Test error')
    }

    render(
      <AppErrorBoundary>
        <ThrowError />
      </AppErrorBoundary>
    )

    const refreshButton = screen.getByRole('button', { name: /refresh page/i })
    fireEvent.click(refreshButton)

    expect(reloadSpy).toHaveBeenCalled()
  })

  it('should display error details section', () => {
    const ThrowError = () => {
      throw new Error('Test error')
    }

    render(
      <AppErrorBoundary>
        <ThrowError />
      </AppErrorBoundary>
    )

    expect(screen.getByText('Error Details')).toBeInTheDocument()
  })

  it('should display error message in details', () => {
    const ThrowError = () => {
      throw new Error('Custom error message')
    }

    render(
      <AppErrorBoundary>
        <ThrowError />
      </AppErrorBoundary>
    )

    expect(screen.getByText(/Custom error message/)).toBeInTheDocument()
  })

  it('should log error to console', () => {
    const ThrowError = () => {
      throw new Error('Test error')
    }

    render(
      <AppErrorBoundary>
        <ThrowError />
      </AppErrorBoundary>
    )

    expect(consoleErrorSpy).toHaveBeenCalled()
  })

  it('should log error with message', () => {
    const ThrowError = () => {
      throw new Error('Specific error')
    }

    render(
      <AppErrorBoundary>
        <ThrowError />
      </AppErrorBoundary>
    )

    expect(consoleErrorSpy).toHaveBeenCalledWith(
      expect.stringContaining('Uncaught error:'),
      expect.any(Error),
      expect.any(Object)
    )
  })

  it('should display error stack in details', () => {
    const ThrowError = () => {
      const error = new Error('Error with stack')
      throw error
    }

    render(
      <AppErrorBoundary>
        <ThrowError />
      </AppErrorBoundary>
    )

    const details = screen.getByText('Error Details')
    fireEvent.click(details)

    // Stack trace should be visible after clicking details
    expect(screen.getByText(/Error with stack/)).toBeInTheDocument()
  })

  it('should not render children after error', () => {
    const ThrowError = () => {
      throw new Error('Test error')
    }

    render(
      <AppErrorBoundary>
        <ThrowError />
        <div>Should not be visible</div>
      </AppErrorBoundary>
    )

    expect(screen.queryByText('Should not be visible')).not.toBeInTheDocument()
  })

  it('should render error UI in centered container', () => {
    const ThrowError = () => {
      throw new Error('Test error')
    }

    const { container } = render(
      <AppErrorBoundary>
        <ThrowError />
      </AppErrorBoundary>
    )

    const errorContainer = container.querySelector('.min-h-screen')
    expect(errorContainer).toBeInTheDocument()
  })

  it('should have error state after catching error', () => {
    const ThrowError = () => {
      throw new Error('Test error')
    }

    render(
      <AppErrorBoundary>
        <ThrowError />
      </AppErrorBoundary>
    )

    // Verify error UI is rendered (hasError state is true)
    expect(screen.getByText('Something went wrong')).toBeInTheDocument()
  })

  it('should use getDerivedStateFromError static method', () => {
    const error = new Error('Test error')
    const state = AppErrorBoundary.getDerivedStateFromError(error)

    expect(state).toEqual({
      hasError: true,
      error: error,
    })
  })

  it('should handle errors without stack trace', () => {
    const ThrowError = () => {
      const error = new Error('Simple error')
      error.stack = undefined
      throw error
    }

    render(
      <AppErrorBoundary>
        <ThrowError />
      </AppErrorBoundary>
    )

    expect(screen.getByText('Something went wrong')).toBeInTheDocument()
  })

  it('should render details as closed by default', () => {
    const ThrowError = () => {
      throw new Error('Test error')
    }

    const { container } = render(
      <AppErrorBoundary>
        <ThrowError />
      </AppErrorBoundary>
    )

    const details = container.querySelector('details')
    expect(details).toBeInTheDocument()
    expect(details?.hasAttribute('open')).toBe(false)
  })

  it('should make details clickable', () => {
    const ThrowError = () => {
      throw new Error('Test error')
    }

    render(
      <AppErrorBoundary>
        <ThrowError />
      </AppErrorBoundary>
    )

    const summary = screen.getByText('Error Details')
    expect(summary).toHaveClass('cursor-pointer')
  })

  it('should display pre-formatted error text', () => {
    const ThrowError = () => {
      throw new Error('Test error')
    }

    const { container } = render(
      <AppErrorBoundary>
        <ThrowError />
      </AppErrorBoundary>
    )

    const pre = container.querySelector('pre')
    expect(pre).toBeInTheDocument()
  })

  it('should log to window.console for debugging', () => {
    const windowConsoleErrorSpy = vi.spyOn(window.console, 'error').mockImplementation(vi.fn())

    const ThrowError = () => {
      throw new Error('Window console error')
    }

    render(
      <AppErrorBoundary>
        <ThrowError />
      </AppErrorBoundary>
    )

    expect(windowConsoleErrorSpy).toHaveBeenCalled()
    windowConsoleErrorSpy.mockRestore()
  })
})
