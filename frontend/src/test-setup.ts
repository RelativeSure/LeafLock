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
