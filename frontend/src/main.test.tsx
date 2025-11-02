import { describe, it, expect, vi } from 'vitest'

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

describe('main', () => {
  it('should import main module', async () => {
    const mainModule = await import('./main')
    expect(mainModule).toBeDefined()
  })
})
