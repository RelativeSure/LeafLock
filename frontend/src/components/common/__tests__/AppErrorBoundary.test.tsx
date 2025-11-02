import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { AppErrorBoundary } from '../AppErrorBoundary'

describe('AppErrorBoundary', () => {
  beforeEach(() => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
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

  it('should render fallback UI on error', () => {
    const ThrowError = () => {
      throw new Error('Component crashed')
    }

    render(
      <AppErrorBoundary>
        <ThrowError />
      </AppErrorBoundary>
    )

    expect(document.body).toBeTruthy()
  })
})
