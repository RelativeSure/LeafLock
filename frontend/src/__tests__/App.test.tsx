import { describe, it, expect, vi, beforeEach } from 'vitest'

// Mock ALL dependencies before imports
vi.mock('../router', () => ({
  router: {
    state: {
      location: {
        pathname: '/',
      },
    },
    subscribe: vi.fn(() => () => undefined),
  },
  default: {
    state: {
      location: {
        pathname: '/',
      },
    },
    subscribe: vi.fn(() => () => undefined),
  },
}))

// Mock RouterProvider
vi.mock('@tanstack/react-router', async () => {
  const actual = await vi.importActual('@tanstack/react-router')
  return {
    ...(actual as any),
    RouterProvider: ({ router }: any) => (
      <div data-testid="router-provider">Router: {router ? 'loaded' : 'loading'}</div>
    ),
  }
})

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

// Import AFTER mocks
import { render } from '@testing-library/react'
import App from '../App'

describe('App', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('should render App component', () => {
    const { container } = render(<App />)
    expect(container).toBeTruthy()
  })

  it('should have minimal structure', () => {
    const { container } = render(<App />)
    expect(container.firstChild).toBeTruthy()
  })

  it('should show loading state with correct styling', () => {
    const { container } = render(<App />)

    const appElement = container.querySelector('.min-h-screen')
    expect(appElement).toBeTruthy()
  })
})
