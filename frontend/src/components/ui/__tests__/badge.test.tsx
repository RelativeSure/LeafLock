import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Badge } from '../badge'

describe('Badge', () => {
  describe('basic rendering', () => {
    it('should render badge element', () => {
      render(<Badge data-testid="badge">Test Badge</Badge>)
      expect(screen.getByTestId('badge')).toBeInTheDocument()
    })

    it('should render with text content', () => {
      render(<Badge>Badge Text</Badge>)
      expect(screen.getByText('Badge Text')).toBeInTheDocument()
    })

    it('should render with children', () => {
      render(
        <Badge>
          <span>Child Element</span>
        </Badge>
      )
      expect(screen.getByText('Child Element')).toBeInTheDocument()
    })

    it('should render as div by default', () => {
      render(<Badge data-testid="badge">Badge</Badge>)
      expect(screen.getByTestId('badge').tagName).toBe('DIV')
    })
  })

  describe('variants', () => {
    it('should render default variant', () => {
      render(<Badge data-testid="badge">Default</Badge>)
      expect(screen.getByTestId('badge')).toBeInTheDocument()
    })

    it('should render secondary variant', () => {
      render(
        <Badge variant="secondary" data-testid="badge">
          Secondary
        </Badge>
      )
      expect(screen.getByTestId('badge')).toBeInTheDocument()
    })

    it('should render destructive variant', () => {
      render(
        <Badge variant="destructive" data-testid="badge">
          Destructive
        </Badge>
      )
      expect(screen.getByTestId('badge')).toBeInTheDocument()
    })

    it('should render outline variant', () => {
      render(
        <Badge variant="outline" data-testid="badge">
          Outline
        </Badge>
      )
      expect(screen.getByTestId('badge')).toBeInTheDocument()
    })
  })

  describe('styling', () => {
    it('should apply custom className', () => {
      render(
        <Badge className="custom-class" data-testid="badge">
          Badge
        </Badge>
      )
      expect(screen.getByTestId('badge')).toHaveClass('custom-class')
    })

    it('should merge custom classes with default classes', () => {
      render(
        <Badge className="bg-red-500 text-white" data-testid="badge">
          Badge
        </Badge>
      )
      const badge = screen.getByTestId('badge')
      expect(badge).toHaveClass('bg-red-500')
      expect(badge).toHaveClass('text-white')
    })

    it('should apply inline styles', () => {
      render(
        <Badge style={{ fontSize: '20px' }} data-testid="badge">
          Badge
        </Badge>
      )
      const badge = screen.getByTestId('badge')
      expect(badge).toHaveStyle({ fontSize: '20px' })
    })
  })

  describe('content types', () => {
    it('should render with number content', () => {
      render(<Badge>42</Badge>)
      expect(screen.getByText('42')).toBeInTheDocument()
    })

    it('should render with icon', () => {
      render(
        <Badge>
          <svg data-testid="icon" />
        </Badge>
      )
      expect(screen.getByTestId('icon')).toBeInTheDocument()
    })

    it('should render with mixed content', () => {
      render(
        <Badge>
          <svg data-testid="icon" />
          <span>Text</span>
        </Badge>
      )
      expect(screen.getByTestId('icon')).toBeInTheDocument()
      expect(screen.getByText('Text')).toBeInTheDocument()
    })

    it('should render with empty content', () => {
      render(<Badge data-testid="badge" />)
      expect(screen.getByTestId('badge')).toBeInTheDocument()
    })
  })

  describe('accessibility', () => {
    it('should support aria-label', () => {
      render(
        <Badge aria-label="notification count" data-testid="badge">
          5
        </Badge>
      )
      expect(screen.getByTestId('badge')).toHaveAttribute(
        'aria-label',
        'notification count'
      )
    })

    it('should support role attribute', () => {
      render(
        <Badge role="status" data-testid="badge">
          New
        </Badge>
      )
      expect(screen.getByTestId('badge')).toHaveAttribute('role', 'status')
    })

    it('should support aria-live for dynamic content', () => {
      render(
        <Badge aria-live="polite" data-testid="badge">
          3
        </Badge>
      )
      expect(screen.getByTestId('badge')).toHaveAttribute(
        'aria-live',
        'polite'
      )
    })
  })

  describe('edge cases', () => {
    it('should handle null children', () => {
      render(<Badge data-testid="badge">{null}</Badge>)
      expect(screen.getByTestId('badge')).toBeInTheDocument()
    })

    it('should handle undefined children', () => {
      render(<Badge data-testid="badge">{undefined}</Badge>)
      expect(screen.getByTestId('badge')).toBeInTheDocument()
    })

    it('should handle empty string', () => {
      render(<Badge data-testid="badge"></Badge>)
      expect(screen.getByTestId('badge')).toBeInTheDocument()
    })

    it('should handle zero as content', () => {
      render(<Badge>0</Badge>)
      expect(screen.getByText('0')).toBeInTheDocument()
    })

    it('should handle boolean false', () => {
      render(<Badge data-testid="badge">{false}</Badge>)
      expect(screen.getByTestId('badge')).toBeInTheDocument()
    })
  })

  describe('data attributes', () => {
    it('should apply data-testid attribute', () => {
      render(<Badge data-testid="custom-badge">Badge</Badge>)
      expect(screen.getByTestId('custom-badge')).toBeInTheDocument()
    })

    it('should apply custom data attributes', () => {
      render(
        <Badge data-custom="value" data-testid="badge">
          Badge
        </Badge>
      )
      expect(screen.getByTestId('badge')).toHaveAttribute(
        'data-custom',
        'value'
      )
    })
  })

  describe('combinations', () => {
    it('should render secondary variant with custom class', () => {
      render(
        <Badge
          variant="secondary"
          className="custom"
          data-testid="badge"
        >
          Badge
        </Badge>
      )
      expect(screen.getByTestId('badge')).toHaveClass('custom')
    })

    it('should render destructive variant with icon', () => {
      render(
        <Badge variant="destructive" data-testid="badge">
          <svg data-testid="warning-icon" />
          Error
        </Badge>
      )
      expect(screen.getByTestId('badge')).toBeInTheDocument()
      expect(screen.getByTestId('warning-icon')).toBeInTheDocument()
      expect(screen.getByText('Error')).toBeInTheDocument()
    })

    it('should render outline variant with aria attributes', () => {
      render(
        <Badge
          variant="outline"
          aria-label="status"
          role="status"
          data-testid="badge"
        >
          Active
        </Badge>
      )
      const badge = screen.getByTestId('badge')
      expect(badge).toHaveAttribute('aria-label', 'status')
      expect(badge).toHaveAttribute('role', 'status')
    })
  })

  describe('complex children', () => {
    it('should render nested components', () => {
      render(
        <Badge>
          <div data-testid="parent">
            <span data-testid="child">Nested</span>
          </div>
        </Badge>
      )
      expect(screen.getByTestId('parent')).toBeInTheDocument()
      expect(screen.getByTestId('child')).toBeInTheDocument()
    })

    it('should render multiple text nodes', () => {
      render(
        <Badge>
          First
          <span> Middle </span>
          Last
        </Badge>
      )
      expect(screen.getByText(/First/)).toBeInTheDocument()
      expect(screen.getByText(/Middle/)).toBeInTheDocument()
      expect(screen.getByText(/Last/)).toBeInTheDocument()
    })
  })
})
