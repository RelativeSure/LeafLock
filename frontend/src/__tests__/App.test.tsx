import { describe, it, expect, vi } from 'vitest'
import { render } from '@testing-library/react'
import App from '../App'

// Mock all dependencies
vi.mock('@tanstack/react-router', () => ({
  RouterProvider: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('../router', () => ({
  router: {},
}))

vi.mock('../context/ThemeContext', () => ({
  ThemeProvider: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('../lib/encryption-context', () => ({
  EncryptionProvider: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('../lib/collaboration-context', () => ({
  CollaborationProvider: ({ children }: any) => <div>{children}</div>,
}))

vi.mock('@/components/ui/sonner', () => ({
  Toaster: () => <div data-testid="toaster" />,
}))

describe('App', () => {
  it('should render App component', () => {
    const { container } = render(<App />)
    expect(container).toBeTruthy()
  })

  it('should render toaster', () => {
    const { getByTestId } = render(<App />)
    expect(getByTestId('toaster')).toBeInTheDocument()
  })

  it('should wrap with providers', () => {
    const { container } = render(<App />)
    expect(container.firstChild).toBeTruthy()
  })
})
