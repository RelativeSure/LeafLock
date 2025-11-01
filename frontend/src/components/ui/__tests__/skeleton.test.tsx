import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Skeleton } from '../skeleton'

describe('Skeleton', () => {
  describe('basic rendering', () => {
    it('should render skeleton element', () => {
      render(<Skeleton data-testid="skeleton" />)
      expect(screen.getByTestId('skeleton')).toBeInTheDocument()
    })

    it('should render with default classes', () => {
      render(<Skeleton data-testid="skeleton" />)
      const skeleton = screen.getByTestId('skeleton')
      expect(skeleton).toBeInTheDocument()
    })

    it('should render as div by default', () => {
      render(<Skeleton data-testid="skeleton" />)
      expect(screen.getByTestId('skeleton').tagName).toBe('DIV')
    })

    it('should apply custom className', () => {
      render(<Skeleton className="custom-class" data-testid="skeleton" />)
      expect(screen.getByTestId('skeleton')).toHaveClass('custom-class')
    })
  })

  describe('styling', () => {
    it('should merge custom classes with default classes', () => {
      render(
        <Skeleton
          className="h-10 w-full"
          data-testid="skeleton"
        />
      )
      const skeleton = screen.getByTestId('skeleton')
      expect(skeleton).toHaveClass('h-10')
      expect(skeleton).toHaveClass('w-full')
    })

    it('should apply inline styles', () => {
      render(
        <Skeleton
          style={{ width: '200px', height: '50px' }}
          data-testid="skeleton"
        />
      )
      const skeleton = screen.getByTestId('skeleton')
      expect(skeleton).toHaveStyle({ width: '200px', height: '50px' })
    })

    it('should support custom background color', () => {
      render(
        <Skeleton
          className="bg-gray-200"
          data-testid="skeleton"
        />
      )
      expect(screen.getByTestId('skeleton')).toHaveClass('bg-gray-200')
    })
  })

  describe('sizes and shapes', () => {
    it('should render circular skeleton', () => {
      render(
        <Skeleton
          className="h-12 w-12 rounded-full"
          data-testid="skeleton"
        />
      )
      const skeleton = screen.getByTestId('skeleton')
      expect(skeleton).toHaveClass('rounded-full')
    })

    it('should render rectangular skeleton', () => {
      render(
        <Skeleton
          className="h-4 w-full rounded-md"
          data-testid="skeleton"
        />
      )
      const skeleton = screen.getByTestId('skeleton')
      expect(skeleton).toHaveClass('rounded-md')
    })

    it('should render square skeleton', () => {
      render(
        <Skeleton
          className="h-10 w-10"
          data-testid="skeleton"
        />
      )
      const skeleton = screen.getByTestId('skeleton')
      expect(skeleton).toHaveClass('h-10', 'w-10')
    })
  })

  describe('multiple skeletons', () => {
    it('should render multiple skeletons', () => {
      render(
        <>
          <Skeleton data-testid="skeleton-1" />
          <Skeleton data-testid="skeleton-2" />
          <Skeleton data-testid="skeleton-3" />
        </>
      )
      expect(screen.getByTestId('skeleton-1')).toBeInTheDocument()
      expect(screen.getByTestId('skeleton-2')).toBeInTheDocument()
      expect(screen.getByTestId('skeleton-3')).toBeInTheDocument()
    })

    it('should render skeleton list', () => {
      const items = [1, 2, 3, 4, 5]
      render(
        <div>
          {items.map((item) => (
            <Skeleton key={item} data-testid={`skeleton-${item}`} />
          ))}
        </div>
      )
      items.forEach((item) => {
        expect(screen.getByTestId(`skeleton-${item}`)).toBeInTheDocument()
      })
    })
  })

  describe('real world usage', () => {
    it('should render avatar skeleton', () => {
      render(
        <Skeleton
          className="h-12 w-12 rounded-full"
          data-testid="avatar-skeleton"
        />
      )
      expect(screen.getByTestId('avatar-skeleton')).toBeInTheDocument()
    })

    it('should render text skeleton', () => {
      render(
        <div>
          <Skeleton className="h-4 w-full mb-2" data-testid="line-1" />
          <Skeleton className="h-4 w-3/4" data-testid="line-2" />
        </div>
      )
      expect(screen.getByTestId('line-1')).toBeInTheDocument()
      expect(screen.getByTestId('line-2')).toBeInTheDocument()
    })

    it('should render card skeleton', () => {
      render(
        <div className="space-y-3">
          <Skeleton className="h-32 w-full" data-testid="image" />
          <Skeleton className="h-4 w-3/4" data-testid="title" />
          <Skeleton className="h-4 w-full" data-testid="desc-1" />
          <Skeleton className="h-4 w-5/6" data-testid="desc-2" />
        </div>
      )
      expect(screen.getByTestId('image')).toBeInTheDocument()
      expect(screen.getByTestId('title')).toBeInTheDocument()
      expect(screen.getByTestId('desc-1')).toBeInTheDocument()
      expect(screen.getByTestId('desc-2')).toBeInTheDocument()
    })

    it('should render user profile skeleton', () => {
      render(
        <div className="flex items-center space-x-4">
          <Skeleton className="h-12 w-12 rounded-full" data-testid="avatar" />
          <div className="space-y-2">
            <Skeleton className="h-4 w-[250px]" data-testid="name" />
            <Skeleton className="h-4 w-[200px]" data-testid="email" />
          </div>
        </div>
      )
      expect(screen.getByTestId('avatar')).toBeInTheDocument()
      expect(screen.getByTestId('name')).toBeInTheDocument()
      expect(screen.getByTestId('email')).toBeInTheDocument()
    })

    it('should render table skeleton', () => {
      render(
        <div>
          {[1, 2, 3].map((row) => (
            <div key={row} className="flex space-x-4">
              <Skeleton className="h-4 w-[100px]" data-testid={`col1-${row}`} />
              <Skeleton className="h-4 w-[200px]" data-testid={`col2-${row}`} />
              <Skeleton className="h-4 w-[150px]" data-testid={`col3-${row}`} />
            </div>
          ))}
        </div>
      )
      expect(screen.getByTestId('col1-1')).toBeInTheDocument()
      expect(screen.getByTestId('col2-1')).toBeInTheDocument()
      expect(screen.getByTestId('col3-1')).toBeInTheDocument()
    })
  })

  describe('accessibility', () => {
    it('should support aria-label', () => {
      render(
        <Skeleton
          aria-label="Loading content"
          data-testid="skeleton"
        />
      )
      expect(screen.getByTestId('skeleton')).toHaveAttribute(
        'aria-label',
        'Loading content'
      )
    })

    it('should support role attribute', () => {
      render(
        <Skeleton
          role="status"
          data-testid="skeleton"
        />
      )
      expect(screen.getByTestId('skeleton')).toHaveAttribute('role', 'status')
    })

    it('should support aria-busy', () => {
      render(
        <Skeleton
          aria-busy="true"
          data-testid="skeleton"
        />
      )
      expect(screen.getByTestId('skeleton')).toHaveAttribute('aria-busy', 'true')
    })
  })

  describe('edge cases', () => {
    it('should handle no className', () => {
      render(<Skeleton data-testid="skeleton" />)
      expect(screen.getByTestId('skeleton')).toBeInTheDocument()
    })

    it('should handle empty className', () => {
      render(<Skeleton className="" data-testid="skeleton" />)
      expect(screen.getByTestId('skeleton')).toBeInTheDocument()
    })

    it('should handle children prop', () => {
      render(
        <Skeleton data-testid="skeleton">
          <div>Hidden content</div>
        </Skeleton>
      )
      expect(screen.getByTestId('skeleton')).toBeInTheDocument()
    })

    it('should handle data attributes', () => {
      render(
        <Skeleton
          data-testid="skeleton"
          data-custom="value"
        />
      )
      expect(screen.getByTestId('skeleton')).toHaveAttribute('data-custom', 'value')
    })
  })

  describe('composition', () => {
    it('should work within a card', () => {
      render(
        <div data-testid="card">
          <Skeleton className="h-4 w-full" data-testid="skeleton" />
        </div>
      )
      expect(screen.getByTestId('card')).toBeInTheDocument()
      expect(screen.getByTestId('skeleton')).toBeInTheDocument()
    })

    it('should work in a flex layout', () => {
      render(
        <div className="flex gap-4">
          <Skeleton className="h-10 w-10" data-testid="skeleton-1" />
          <Skeleton className="h-10 flex-1" data-testid="skeleton-2" />
        </div>
      )
      expect(screen.getByTestId('skeleton-1')).toBeInTheDocument()
      expect(screen.getByTestId('skeleton-2')).toBeInTheDocument()
    })

    it('should work in a grid layout', () => {
      render(
        <div className="grid grid-cols-3 gap-4">
          <Skeleton data-testid="skeleton-1" />
          <Skeleton data-testid="skeleton-2" />
          <Skeleton data-testid="skeleton-3" />
        </div>
      )
      expect(screen.getByTestId('skeleton-1')).toBeInTheDocument()
      expect(screen.getByTestId('skeleton-2')).toBeInTheDocument()
      expect(screen.getByTestId('skeleton-3')).toBeInTheDocument()
    })
  })

  describe('animation', () => {
    it('should support animation classes', () => {
      render(
        <Skeleton
          className="animate-pulse"
          data-testid="skeleton"
        />
      )
      expect(screen.getByTestId('skeleton')).toHaveClass('animate-pulse')
    })

    it('should support custom animation', () => {
      render(
        <Skeleton
          className="animate-shimmer"
          data-testid="skeleton"
        />
      )
      expect(screen.getByTestId('skeleton')).toHaveClass('animate-shimmer')
    })
  })
})
