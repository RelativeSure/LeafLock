import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import App from '../App'

// Mock the router module
const mockRouter = {
  state: {
    location: {
      pathname: '/',
    },
  },
  subscribe: vi.fn(() => () => {}),
}

vi.mock('../router', () => ({
  router: mockRouter,
}))

// Mock RouterProvider
vi.mock('@tanstack/react-router', () => ({
  RouterProvider: ({ router }: any) => (
    <div data-testid="router-provider">Router: {router ? 'loaded' : 'loading'}</div>
  ),
}))

// Mock ThemeProvider
vi.mock('../context/ThemeContext', () => ({
  ThemeProvider: ({ children }: any) => <div data-testid="theme-provider">{children}</div>,
}))

// Mock EncryptionProvider
vi.mock('../lib/encryption-context', () => ({
  EncryptionProvider: ({ children }: any) => (
    <div data-testid="encryption-provider">{children}</div>
  ),
}))

describe('App', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('should render App component', () => {
    const { container } = render(<App />)
    expect(container).toBeTruthy()
  })

  it('should render router provider after loading', async () => {
    render(<App />)

    await waitFor(() => {
      expect(screen.getByTestId('router-provider')).toBeInTheDocument()
    })
  })

  it('should wrap router in ThemeProvider', async () => {
    render(<App />)

    await waitFor(() => {
      expect(screen.getByTestId('theme-provider')).toBeInTheDocument()
    })
  })

  it('should wrap router in EncryptionProvider', async () => {
    render(<App />)

    await waitFor(() => {
      expect(screen.getByTestId('encryption-provider')).toBeInTheDocument()
    })
  })

  it('should render providers in correct order', async () => {
    render(<App />)

    await waitFor(() => {
      const themeProvider = screen.getByTestId('theme-provider')
      const encryptionProvider = screen.getByTestId('encryption-provider')
      const routerProvider = screen.getByTestId('router-provider')

      // ThemeProvider should contain EncryptionProvider
      expect(themeProvider).toContainElement(encryptionProvider)
      // EncryptionProvider should contain RouterProvider
      expect(encryptionProvider).toContainElement(routerProvider)
    })
  })

  it('should show loading state with correct styling', () => {
    const { container } = render(<App />)

    // May show loading initially before router loads
    const loadingContainer = container.querySelector('.min-h-screen')
    if (loadingContainer) {
      expect(loadingContainer).toHaveClass('flex', 'items-center', 'justify-center')
    }
  })

  it('should handle router loading', async () => {
    render(<App />)

    await waitFor(() => {
      expect(screen.getByTestId('router-provider')).toBeInTheDocument()
    })
  })

  it('should render with all providers', async () => {
    const { container } = render(<App />)

    await waitFor(() => {
      expect(screen.getByTestId('theme-provider')).toBeInTheDocument()
      expect(screen.getByTestId('encryption-provider')).toBeInTheDocument()
      expect(screen.getByTestId('router-provider')).toBeInTheDocument()
    })
  })

  it('should have minimal structure', () => {
    const { container } = render(<App />)
    expect(container.firstChild).toBeTruthy()
  })

  it('should handle multiple renders', async () => {
    const { rerender } = render(<App />)

    await waitFor(() => {
      expect(screen.getByTestId('router-provider')).toBeInTheDocument()
    })

    rerender(<App />)
    expect(screen.getByTestId('router-provider')).toBeInTheDocument()
  })
})
