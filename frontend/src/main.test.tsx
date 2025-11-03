import { describe, it, expect, vi, beforeEach } from 'vitest'

// Mock ReactDOM
vi.mock('react-dom/client', () => ({
  createRoot: vi.fn(() => ({
    render: vi.fn(),
  })),
}))

// Mock App
vi.mock('./App', () => ({
  default: () => <div>App</div>,
}))

// Mock libsodium
vi.mock('libsodium-wrappers-sumo', () => ({
  default: {},
  ready: Promise.resolve(),
}))

// Mock QueryClientProvider
vi.mock('@tanstack/react-query', () => ({
  QueryClient: vi.fn(() => ({})),
  QueryClientProvider: ({ children }: any) => children,
}))

describe('main', () => {
  beforeEach(() => {
    // Create root element for main.tsx
    const root = document.createElement('div')
    root.id = 'root'
    document.body.appendChild(root)
  })

  it('should import main module', async () => {
    const mainModule = await import('./main')
    expect(mainModule).toBeDefined()
  })
})
