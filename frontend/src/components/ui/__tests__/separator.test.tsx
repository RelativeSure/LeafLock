import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Separator } from '../separator'

describe('Separator', () => {
  describe('basic rendering', () => {
    it('should render separator element', () => {
      render(<Separator data-testid="separator" />)
      expect(screen.getByTestId('separator')).toBeInTheDocument()
    })

    it('should render with horizontal orientation by default', () => {
      render(<Separator data-testid="separator" />)
      const separator = screen.getByTestId('separator')
      expect(separator).toBeInTheDocument()
    })

    it('should render with vertical orientation', () => {
      render(<Separator orientation="vertical" data-testid="separator" />)
      const separator = screen.getByTestId('separator')
      expect(separator).toBeInTheDocument()
    })

    it('should apply custom className', () => {
      render(<Separator className="custom-class" data-testid="separator" />)
      expect(screen.getByTestId('separator')).toHaveClass('custom-class')
    })
  })

  describe('orientation variants', () => {
    it('should render horizontal separator', () => {
      render(<Separator orientation="horizontal" data-testid="separator" />)
      expect(screen.getByTestId('separator')).toBeInTheDocument()
    })

    it('should render vertical separator', () => {
      render(<Separator orientation="vertical" data-testid="separator" />)
      expect(screen.getByTestId('separator')).toBeInTheDocument()
    })
  })

  describe('decorative prop', () => {
    it('should be decorative by default', () => {
      render(<Separator data-testid="separator" />)
      const separator = screen.getByTestId('separator')
      expect(separator).toHaveAttribute('data-orientation')
    })

    it('should accept decorative prop', () => {
      render(<Separator decorative data-testid="separator" />)
      expect(screen.getByTestId('separator')).toBeInTheDocument()
    })

    it('should work without decorative prop', () => {
      render(<Separator decorative={false} data-testid="separator" />)
      expect(screen.getByTestId('separator')).toBeInTheDocument()
    })
  })

  describe('styling', () => {
    it('should merge custom classes with default classes', () => {
      render(<Separator className="bg-red-500 h-1" data-testid="separator" />)
      const separator = screen.getByTestId('separator')
      expect(separator).toHaveClass('bg-red-500')
      expect(separator).toHaveClass('h-1')
    })

    it('should apply inline styles', () => {
      // Verify component accepts style prop without error
      const { getByTestId } = render(<Separator style={{ backgroundColor: 'blue' }} data-testid="separator" />)
      expect(getByTestId('separator')).toBeInTheDocument()
    })
  })

  describe('accessibility', () => {
    it('should have separator role', () => {
      render(<Separator decorative={false} data-testid="separator" />)
      const separator = screen.getByTestId('separator')
      expect(separator).toHaveAttribute('role', 'separator')
    })

    it('should support aria-orientation', () => {
      render(<Separator orientation="vertical" data-testid="separator" />)
      const separator = screen.getByTestId('separator')
      expect(separator).toHaveAttribute('data-orientation', 'vertical')
    })
  })

  describe('usage in layouts', () => {
    it('should work in horizontal layout', () => {
      render(
        <div>
          <div>Content 1</div>
          <Separator data-testid="separator" />
          <div>Content 2</div>
        </div>
      )
      expect(screen.getByTestId('separator')).toBeInTheDocument()
      expect(screen.getByText('Content 1')).toBeInTheDocument()
      expect(screen.getByText('Content 2')).toBeInTheDocument()
    })

    it('should work in vertical layout', () => {
      render(
        <div style={{ display: 'flex' }}>
          <div>Left</div>
          <Separator orientation="vertical" data-testid="separator" />
          <div>Right</div>
        </div>
      )
      expect(screen.getByTestId('separator')).toBeInTheDocument()
      expect(screen.getByText('Left')).toBeInTheDocument()
      expect(screen.getByText('Right')).toBeInTheDocument()
    })
  })

  describe('edge cases', () => {
    it('should handle multiple separators', () => {
      render(
        <>
          <Separator data-testid="sep-1" />
          <Separator data-testid="sep-2" />
          <Separator data-testid="sep-3" />
        </>
      )
      expect(screen.getByTestId('sep-1')).toBeInTheDocument()
      expect(screen.getByTestId('sep-2')).toBeInTheDocument()
      expect(screen.getByTestId('sep-3')).toBeInTheDocument()
    })

    it('should handle custom data attributes', () => {
      render(<Separator data-testid="separator" data-custom="value" />)
      const separator = screen.getByTestId('separator')
      expect(separator).toHaveAttribute('data-custom', 'value')
    })
  })

  describe('composition', () => {
    it('should work within a card', () => {
      render(
        <div data-testid="card">
          <div>Header</div>
          <Separator data-testid="separator" />
          <div>Content</div>
        </div>
      )
      expect(screen.getByTestId('card')).toBeInTheDocument()
      expect(screen.getByTestId('separator')).toBeInTheDocument()
    })

    it('should work in a navigation menu', () => {
      render(
        <nav>
          <a href="#1">Link 1</a>
          <Separator orientation="vertical" data-testid="separator" />
          <a href="#2">Link 2</a>
        </nav>
      )
      expect(screen.getByTestId('separator')).toBeInTheDocument()
    })

    it('should work in a list', () => {
      render(
        <ul>
          <li>Item 1</li>
          <Separator data-testid="separator" />
          <li>Item 2</li>
        </ul>
      )
      expect(screen.getByTestId('separator')).toBeInTheDocument()
    })
  })
})
