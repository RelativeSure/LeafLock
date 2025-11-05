import { describe, it, expect, vi } from 'vitest'

// Mock all dependencies
vi.mock('@tanstack/react-router', () => ({
  createRouter: vi.fn(() => ({
    update: vi.fn(),
    navigate: vi.fn(),
    invalidate: vi.fn(),
  })),
  createRoute: vi.fn(() => ({
    useParams: vi.fn(),
    useSearch: vi.fn(),
  })),
  createRootRoute: vi.fn(() => ({
    addChildren: vi.fn(),
  })),
  Outlet: () => <div>Outlet</div>,
  Navigate: ({ to }: any) => <div>Navigate to {to}</div>,
}))

vi.mock('./stores/authStore', () => ({
  useAuthStore: vi.fn(() => ({
    user: null,
    isAuthenticated: false,
  })),
}))

vi.mock('./components/common/AppErrorBoundary', () => ({
  AppErrorBoundary: ({ children }: any) => <div>{children}</div>,
}))

describe('router', () => {
  it(
    'should define router module',
    async () => {
      const routerModule = await import('./router')
      expect(routerModule).toBeDefined()
    },
    10000
  )

  it('should export router instance', async () => {
    const { router } = await import('./router')
    expect(router).toBeDefined()
  })

  it('should have router methods', async () => {
    const { router } = await import('./router')
    expect(router.navigate).toBeDefined()
    expect(router.invalidate).toBeDefined()
  })

  it('should have update method on router', async () => {
    const { router } = await import('./router')
    expect(router.update).toBeDefined()
    expect(typeof router.update).toBe('function')
  })

  it('should have router as object type', async () => {
    const { router } = await import('./router')
    expect(typeof router).toBe('object')
    expect(router).not.toBeNull()
  })

  it('should have all required methods', async () => {
    const { router } = await import('./router')
    const methods = ['navigate', 'invalidate', 'update']
    methods.forEach((method) => {
      expect(router).toHaveProperty(method)
      expect(typeof router[method]).toBe('function')
    })
  })

  it('should maintain router singleton across imports', async () => {
    const { router: router1 } = await import('./router')
    const { router: router2 } = await import('./router')
    expect(router1).toBe(router2)
  })

  it('should not throw error when importing router', async () => {
    await expect(import('./router')).resolves.toBeDefined()
  })
})
