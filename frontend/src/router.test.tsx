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
  it('should define router module', async () => {
    const routerModule = await import('./router')
    expect(routerModule).toBeDefined()
  })

  it('should export router instance', async () => {
    const { router } = await import('./router')
    expect(router).toBeDefined()
  })

  it('should have router methods', async () => {
    const { router } = await import('./router')
    expect(router.navigate).toBeDefined()
    expect(router.invalidate).toBeDefined()
  })
})
