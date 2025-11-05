import '@testing-library/jest-dom'
import { server } from './mocks/server'
import { beforeAll, afterEach, afterAll } from 'vitest'

// Setup MSW server
beforeAll(() => server.listen({ onUnhandledRequest: 'bypass' }))
afterEach(() => server.resetHandlers())
afterAll(() => server.close())

const prototype = Element.prototype as Element & {
  setPointerCapture?: (pointerId: number) => void
  releasePointerCapture?: (pointerId: number) => void
  hasPointerCapture?: (pointerId: number) => boolean
  scrollIntoView?: (arg?: boolean | ScrollIntoViewOptions) => void
}

if (!prototype.setPointerCapture) {
  prototype.setPointerCapture = () => {
    /* no-op polyfill for jsdom */
  }
}

if (!prototype.releasePointerCapture) {
  prototype.releasePointerCapture = () => {
    /* no-op polyfill for jsdom */
  }
}

if (!prototype.hasPointerCapture) {
  prototype.hasPointerCapture = () => false
}

if (!prototype.scrollIntoView) {
  prototype.scrollIntoView = () => {
    /* jsdom does not implement scrollIntoView */
  }
}

// Polyfill for ResizeObserver (used by slider, tooltip components)
global.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

// Polyfill for IntersectionObserver (used by rolling-text component)
global.IntersectionObserver = class IntersectionObserver {
  constructor() {
    this.root = null
    this.rootMargin = ''
    this.thresholds = []
  }
  observe() {}
  unobserve() {}
  disconnect() {}
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
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  }),
})
