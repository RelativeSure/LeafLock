import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ShimmeringText } from '../shimmering-text'

describe('ShimmeringText', () => {
  it('should render text', () => {
    render(<ShimmeringText text="Hello World" />)
    expect(screen.getByText('H')).toBeInTheDocument()
    expect(screen.getByText('e')).toBeInTheDocument()
  })

  it('should render with custom className', () => {
    const { container } = render(<ShimmeringText text="Test" className="custom-class" />)
    expect(container.querySelector('.custom-class')).toBeInTheDocument()
  })

  it('should render with custom duration', () => {
    render(<ShimmeringText text="Test" duration={2} />)
    expect(screen.getByText('T')).toBeInTheDocument()
  })

  it('should render with wave prop', () => {
    render(<ShimmeringText text="Test" wave={true} />)
    expect(screen.getByText('T')).toBeInTheDocument()
  })

  it('should render empty text', () => {
    const { container } = render(<ShimmeringText text="" />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('should render with numbers', () => {
    render(<ShimmeringText text="12345" />)
    expect(screen.getByText('1')).toBeInTheDocument()
    expect(screen.getByText('2')).toBeInTheDocument()
  })

  it('should render with custom colors', () => {
    render(<ShimmeringText text="Test" color="#000000" shimmeringColor="#FFFFFF" />)
    expect(screen.getByText('T')).toBeInTheDocument()
  })
})
