import { describe, it, expect } from 'vitest'
import { render } from '@testing-library/react'
import { InteractiveGridPattern } from '../interactive-grid-pattern'

describe('InteractiveGridPattern', () => {
  it('should render grid pattern', () => {
    const { container } = render(<InteractiveGridPattern />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('should render with custom className', () => {
    const { container } = render(<InteractiveGridPattern className="custom-grid" />)
    expect(container.querySelector('.custom-grid')).toBeInTheDocument()
  })

  it('should render with custom width', () => {
    const { container } = render(<InteractiveGridPattern width={100} />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('should render with custom height', () => {
    const { container } = render(<InteractiveGridPattern height={100} />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('should render with custom square size', () => {
    const { container } = render(<InteractiveGridPattern squareSize={10} />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('should render with custom square gap', () => {
    const { container } = render(<InteractiveGridPattern squareGap={5} />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('should render with all custom props', () => {
    const { container } = render(
      <InteractiveGridPattern
        width={200}
        height={200}
        squareSize={15}
        squareGap={3}
        className="full-custom"
      />
    )
    expect(container.firstChild).toBeInTheDocument()
  })
})
