import '@testing-library/jest-dom'

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
