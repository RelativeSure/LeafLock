import '@testing-library/jest-dom'
import { server } from './mocks/server'
import { beforeAll, afterEach, afterAll, vi } from 'vitest'
import React from 'react'

// Setup MSW server
beforeAll(() => server.listen({ onUnhandledRequest: 'bypass' }))
afterEach(() => server.resetHandlers())
afterAll(() => server.close())

// Mock Clerk for all tests
vi.mock('@clerk/clerk-react', () => {
  const mockClerk = {
    signOut: vi.fn().mockResolvedValue(undefined),
    openSignIn: vi.fn(),
    openSignUp: vi.fn(),
    openUserProfile: vi.fn(),
    session: {
      id: 'sess_test',
      user: {
        id: 'user_test',
        fullName: 'Test User',
        email: 'test@example.com',
        imageUrl: 'https://example.com/avatar.jpg',
      },
      getToken: vi.fn().mockResolvedValue('mock-token'),
    },
    user: {
      id: 'user_test',
      fullName: 'Test User',
      email: 'test@example.com',
      imageUrl: 'https://example.com/avatar.jpg',
    },
  }

  return {
    ClerkProvider: ({ children }: { children: React.ReactNode }) =>
      React.createElement(React.Fragment, {}, children),
    SignIn: () => React.createElement('div', { 'data-testid': 'sign-in' }, 'Sign In'),
    SignUp: () => React.createElement('div', { 'data-testid': 'sign-up' }, 'Sign Up'),
    useClerk: () => mockClerk,
    useAuth: () => ({
      isSignedIn: true,
      isLoaded: true,
      userId: 'user_test',
    }),
    useUser: () => ({
      user: mockClerk.user,
      isLoaded: true,
    }),
    useSession: () => ({
      session: mockClerk.session,
      isLoaded: true,
      getToken: mockClerk.session.getToken,
    }),
  }
})

const prototype = Element.prototype as Element & {
  setPointerCapture?: (pointerId: number) => void
  releasePointerCapture?: (pointerId: number) => void
  hasPointerCapture?: (pointerId: number) => boolean
  scrollIntoView?: (arg?: boolean | ScrollIntoViewOptions) => void
}

const noop = () => undefined

if (!prototype.setPointerCapture) {
  prototype.setPointerCapture = () => {
    /* no-op polyfill for jsdom */
    return undefined
  }
}

if (!prototype.releasePointerCapture) {
  prototype.releasePointerCapture = () => {
    /* no-op polyfill for jsdom */
    return undefined
  }
}

if (!prototype.hasPointerCapture) {
  prototype.hasPointerCapture = () => false
}

if (!prototype.scrollIntoView) {
  prototype.scrollIntoView = () => {
    /* jsdom does not implement scrollIntoView */
    return undefined
  }
}

if (typeof File !== 'undefined' && typeof File.prototype.text !== 'function') {
  ;(File.prototype as any).text = function (this: File): Promise<string> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      reader.onload = () => resolve(reader.result as string)
      reader.onerror = () => reject(reader.error)
      reader.readAsText(this)
    })
  }
}

// Polyfill for ResizeObserver (used by slider, tooltip components)
global.ResizeObserver = class ResizeObserver {
  observe(): void {
    return undefined
  }
  unobserve(): void {
    return undefined
  }
  disconnect(): void {
    return undefined
  }
}

// Polyfill for IntersectionObserver (used by rolling-text component)
global.IntersectionObserver = class IntersectionObserver {
  constructor() {
    this.root = null
    this.rootMargin = ''
    this.thresholds = []
  }
  observe(): void {
    return undefined
  }
  unobserve(): void {
    return undefined
  }
  disconnect(): void {
    return undefined
  }
  takeRecords() {
    return []
  }
  root: Element | null
  rootMargin: string
  thresholds: ReadonlyArray<number>
}

// Polyfill for window.matchMedia (used by sonner/toaster component)
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: noop,
    removeListener: noop,
    addEventListener: noop,
    removeEventListener: noop,
    dispatchEvent: () => false,
  }),
})
