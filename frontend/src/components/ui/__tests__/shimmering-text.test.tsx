import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ShimmeringText } from '../shimmering-text'

describe('ShimmeringText', () => {
  it('should render text', () => {
    render(<ShimmeringText>Hello World</ShimmeringText>)
    expect(screen.getByText('Hello World')).toBeInTheDocument()
  })

  it('should render with custom className', () => {
    const { container } = render(
      <ShimmeringText className="custom-class">Test</ShimmeringText>
    )
    expect(container.querySelector('.custom-class')).toBeInTheDocument()
  })

  it('should render as different element', () => {
    render(<ShimmeringText as="h1">Heading</ShimmeringText>)
    expect(screen.getByText('Heading').tagName).toBe('H1')
  })

  it('should render with custom duration', () => {
    render(<ShimmeringText duration={2}>Test</ShimmeringText>)
    expect(screen.getByText('Test')).toBeInTheDocument()
  })

  it('should render with spread prop', () => {
    render(<ShimmeringText spread={5}>Test</ShimmeringText>)
    expect(screen.getByText('Test')).toBeInTheDocument()
  })

  it('should render empty children', () => {
    const { container} = render(<ShimmeringText></ShimmeringText>)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('should render with numbers', () => {
    render(<ShimmeringText>12345</ShimmeringText>)
    expect(screen.getByText('12345')).toBeInTheDocument()
  })
})
