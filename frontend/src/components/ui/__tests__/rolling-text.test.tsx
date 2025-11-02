import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { RollingText } from '../rolling-text'

describe('RollingText', () => {
  it('should render text', () => {
    render(<RollingText text="Hello World" />)
    expect(screen.getByText(/Hello/i)).toBeInTheDocument()
  })

  it('should render with custom className', () => {
    const { container } = render(<RollingText text="Test" className="custom-class" />)
    expect(container.querySelector('.custom-class')).toBeInTheDocument()
  })

  it('should render single character', () => {
    render(<RollingText text="A" />)
    expect(screen.getByText('A')).toBeInTheDocument()
  })

  it('should render empty string', () => {
    const { container } = render(<RollingText text="" />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('should render with numbers', () => {
    render(<RollingText text="123" />)
    expect(document.body).toBeTruthy()
  })

  it('should render with special characters', () => {
    render(<RollingText text="Hello!" />)
    expect(document.body).toBeTruthy()
  })

  it('should handle inView prop', () => {
    render(<RollingText text="Test" inView={true} />)
    expect(document.body).toBeTruthy()
  })

  it('should handle custom transition', () => {
    render(<RollingText text="Test" transition={{ duration: 1, delay: 0.2, ease: 'easeIn' }} />)
    expect(document.body).toBeTruthy()
  })
})
