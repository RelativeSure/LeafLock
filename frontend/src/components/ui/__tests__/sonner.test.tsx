import { describe, it, expect } from 'vitest'
import { render } from '@testing-library/react'
import { Toaster } from '../sonner'

describe('Toaster', () => {
  it('should render toaster component', () => {
    const { container } = render(<Toaster />)

    expect(container).toBeTruthy()
  })

  it('should render with custom className', () => {
    const { container } = render(<Toaster className="custom-toaster" />)

    expect(container.firstChild).toHaveClass('custom-toaster')
  })

  it('should render in light theme', () => {
    const { container } = render(<Toaster theme="light" />)

    expect(container).toBeTruthy()
  })

  it('should render in dark theme', () => {
    const { container } = render(<Toaster theme="dark" />)

    expect(container).toBeTruthy()
  })
})
