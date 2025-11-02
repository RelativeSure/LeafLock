import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { CollaborationProvider, useCollaboration } from '../collaboration-context'

// Mock WebSocket
global.WebSocket = vi.fn().mockImplementation(() => ({
  addEventListener: vi.fn(),
  removeEventListener: vi.fn(),
  send: vi.fn(),
  close: vi.fn(),
  readyState: 1,
})) as any

vi.mock('@/lib/config', () => ({
  config: {
    apiUrl: 'http://localhost:8080',
    wsUrl: 'ws://localhost:8080',
  },
}))

describe('CollaborationContext', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
  })

  it('should render children', () => {
    render(
      <CollaborationProvider>
        <div>Test Child</div>
      </CollaborationProvider>
    )

    expect(screen.getByText('Test Child')).toBeInTheDocument()
  })

  it('should provide collaboration context', () => {
    function TestComponent() {
      const { isConnected } = useCollaboration()
      return <div>Connected: {isConnected ? 'yes' : 'no'}</div>
    }

    render(
      <CollaborationProvider>
        <TestComponent />
      </CollaborationProvider>
    )

    expect(screen.getByText(/Connected:/)).toBeInTheDocument()
  })

  it('should throw error when used outside provider', () => {
    expect(() => {
      function TestComponent() {
        useCollaboration()
        return <div>Test</div>
      }
      render(<TestComponent />)
    }).toThrow('useCollaboration must be used within a CollaborationProvider')
  })

  it('should handle connection when token exists', async () => {
    localStorage.setItem('token', 'test-token')

    function TestComponent() {
      const { isConnected } = useCollaboration()
      return <div>Connected: {isConnected ? 'yes' : 'no'}</div>
    }

    render(
      <CollaborationProvider>
        <TestComponent />
      </CollaborationProvider>
    )

    await waitFor(() => {
      expect(screen.getByText(/Connected/)).toBeInTheDocument()
    })
  })

  it('should not connect without token', () => {
    function TestComponent() {
      const { isConnected } = useCollaboration()
      return <div>Connected: {isConnected ? 'yes' : 'no'}</div>
    }

    render(
      <CollaborationProvider>
        <TestComponent />
      </CollaborationProvider>
    )

    expect(screen.getByText('Connected: no')).toBeInTheDocument()
  })
})
