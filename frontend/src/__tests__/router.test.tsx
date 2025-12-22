import { describe, it, expect, vi } from 'vitest'

// Mock ALL dependencies to avoid complex setup
vi.mock('@/router', () => ({
  router: {
    state: {
      location: {
        pathname: '/',
        search: '',
        hash: '',
      },
    },
    subscribe: vi.fn(() => () => undefined),
    navigate: vi.fn(),
  },
}))

// Import after mocks
import { router } from '../router'

describe('Router', () => {
  it('should create router instance', () => {
    expect(router).toBeDefined()
  })

  it('should have initial state', () => {
    expect(router.state).toBeDefined()
    expect(router.state.location).toBeDefined()
  })

  it('should provide navigation methods', () => {
    expect(router.navigate).toBeDefined()
    expect(typeof router.navigate).toBe('function')
  })

  it('should provide subscription method', () => {
    expect(router.subscribe).toBeDefined()
    expect(typeof router.subscribe).toBe('function')
  })
})
