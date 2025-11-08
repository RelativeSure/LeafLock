import { describe, it, expect, vi, beforeEach } from 'vitest'

// Mock ReactDOM - needs both default export and named export
const mockCreateRoot = vi.fn(() => ({
  render: vi.fn(),
}))

vi.mock('react-dom/client', () => ({
  default: {
    createRoot: mockCreateRoot,
  },
  createRoot: mockCreateRoot,
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
  QueryClient: vi.fn().mockImplementation(function (this: any) {
    return {}
  }),
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
