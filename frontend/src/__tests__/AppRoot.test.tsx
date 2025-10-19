import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'

import App from '@/App'
import { AppErrorBoundary } from '@/components/common/AppErrorBoundary'
import {
  mockFetch,
  mockLocalStorage,
  renderWithProviders,
  mockApiResponse,
} from '@/__tests__/test-utils'

describe('App root integration', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockLocalStorage.clear()
    mockFetch.mockResolvedValue(mockApiResponse({ success: true }))
    global.__LEAFLOCK_REGISTRATION__ = true
  })

  it('renders the login experience by default', async () => {
    renderWithProviders(<App />)

    await waitFor(() => {
      expect(screen.getByText('LeafLock')).toBeInTheDocument()
      expect(screen.getByText(/your secure note-taking application/i)).toBeInTheDocument()
    })
  })

  it('creates a router provider element', () => {
    const element = App()
    expect(element).toMatchObject({ props: { router: expect.any(Object) } })
  })
})

describe('AppErrorBoundary', () => {
  let consoleErrorSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
  })

  afterEach(() => {
    consoleErrorSpy.mockRestore()
  })

  it('renders children when no error occurs', () => {
    render(
      <AppErrorBoundary>
        <div>Happy Path</div>
      </AppErrorBoundary>
    )

    expect(screen.getByText('Happy Path')).toBeInTheDocument()
    expect(screen.queryByText('LeafLock Error')).not.toBeInTheDocument()
  })

  it('renders fallback UI when a child throws', () => {
    const ThrowingComponent = () => {
      throw new Error('Boom')
    }

    render(
      <AppErrorBoundary>
        <ThrowingComponent />
      </AppErrorBoundary>
    )

    expect(screen.getByText('LeafLock Error')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /reload page/i })).toBeInTheDocument()
  })
})
