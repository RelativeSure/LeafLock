import { describe, it, expect } from 'vitest'
import { render } from '@testing-library/react'
import { Skeleton } from '../skeleton'

describe('Skeleton', () => {
  it('should render skeleton', () => {
    const { container } = render(<Skeleton />)
    
    const skeleton = container.firstChild
    expect(skeleton).toBeInTheDocument()
  })

  it('should apply custom className', () => {
    const { container } = render(<Skeleton className="custom-skeleton" />)
    
    const skeleton = container.firstChild
    expect(skeleton).toHaveClass('custom-skeleton')
  })

  it('should render with default animation', () => {
    const { container } = render(<Skeleton />)
    
    const skeleton = container.firstChild
    expect(skeleton).toHaveClass('animate-pulse')
  })

  it('should support different sizes', () => {
    const { container } = render(<Skeleton className="h-10 w-10" />)
    
    const skeleton = container.firstChild
    expect(skeleton).toHaveClass('h-10', 'w-10')
  })
})
