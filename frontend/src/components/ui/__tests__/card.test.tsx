import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Card, CardHeader, CardFooter, CardTitle, CardDescription, CardContent } from '../card'

describe('Card Components', () => {
  describe('Card', () => {
    it('should render card element', () => {
      render(<Card data-testid="card">Card Content</Card>)
      expect(screen.getByTestId('card')).toBeInTheDocument()
    })

    it('should render with children', () => {
      render(<Card>Test Card</Card>)
      expect(screen.getByText('Test Card')).toBeInTheDocument()
    })

    it('should apply custom className', () => {
      render(<Card className="custom-class" data-testid="card" />)
      expect(screen.getByTestId('card')).toHaveClass('custom-class')
    })

    it('should render as div by default', () => {
      render(<Card data-testid="card" />)
      expect(screen.getByTestId('card').tagName).toBe('DIV')
    })

    it('should apply default card styles', () => {
      render(<Card data-testid="card" />)
      const card = screen.getByTestId('card')
      expect(card).toHaveClass('rounded-lg')
    })
  })

  describe('CardHeader', () => {
    it('should render card header', () => {
      render(<CardHeader data-testid="card-header">Header</CardHeader>)
      expect(screen.getByTestId('card-header')).toBeInTheDocument()
    })

    it('should render with children', () => {
      render(<CardHeader>Test Header</CardHeader>)
      expect(screen.getByText('Test Header')).toBeInTheDocument()
    })

    it('should apply custom className', () => {
      render(<CardHeader className="custom-header" data-testid="card-header" />)
      expect(screen.getByTestId('card-header')).toHaveClass('custom-header')
    })

    it('should render multiple children', () => {
      render(
        <CardHeader>
          <CardTitle>Title</CardTitle>
          <CardDescription>Description</CardDescription>
        </CardHeader>
      )
      expect(screen.getByText('Title')).toBeInTheDocument()
      expect(screen.getByText('Description')).toBeInTheDocument()
    })
  })

  describe('CardTitle', () => {
    it('should render card title', () => {
      render(<CardTitle data-testid="card-title">Title</CardTitle>)
      expect(screen.getByTestId('card-title')).toBeInTheDocument()
    })

    it('should render with text content', () => {
      render(<CardTitle>Test Title</CardTitle>)
      expect(screen.getByText('Test Title')).toBeInTheDocument()
    })

    it('should apply custom className', () => {
      render(<CardTitle className="custom-title" data-testid="card-title" />)
      expect(screen.getByTestId('card-title')).toHaveClass('custom-title')
    })

    it('should render as h3 by default', () => {
      render(<CardTitle data-testid="card-title">Title</CardTitle>)
      expect(screen.getByTestId('card-title').tagName).toBe('H3')
    })
  })

  describe('CardDescription', () => {
    it('should render card description', () => {
      render(<CardDescription data-testid="card-description">Description</CardDescription>)
      expect(screen.getByTestId('card-description')).toBeInTheDocument()
    })

    it('should render with text content', () => {
      render(<CardDescription>Test Description</CardDescription>)
      expect(screen.getByText('Test Description')).toBeInTheDocument()
    })

    it('should apply custom className', () => {
      render(<CardDescription className="custom-desc" data-testid="card-description" />)
      expect(screen.getByTestId('card-description')).toHaveClass('custom-desc')
    })

    it('should render as p by default', () => {
      render(<CardDescription data-testid="card-description">Description</CardDescription>)
      expect(screen.getByTestId('card-description').tagName).toBe('P')
    })
  })

  describe('CardContent', () => {
    it('should render card content', () => {
      render(<CardContent data-testid="card-content">Content</CardContent>)
      expect(screen.getByTestId('card-content')).toBeInTheDocument()
    })

    it('should render with children', () => {
      render(<CardContent>Test Content</CardContent>)
      expect(screen.getByText('Test Content')).toBeInTheDocument()
    })

    it('should apply custom className', () => {
      render(<CardContent className="custom-content" data-testid="card-content" />)
      expect(screen.getByTestId('card-content')).toHaveClass('custom-content')
    })

    it('should render complex children', () => {
      render(
        <CardContent>
          <p>Paragraph 1</p>
          <p>Paragraph 2</p>
        </CardContent>
      )
      expect(screen.getByText('Paragraph 1')).toBeInTheDocument()
      expect(screen.getByText('Paragraph 2')).toBeInTheDocument()
    })
  })

  describe('CardFooter', () => {
    it('should render card footer', () => {
      render(<CardFooter data-testid="card-footer">Footer</CardFooter>)
      expect(screen.getByTestId('card-footer')).toBeInTheDocument()
    })

    it('should render with children', () => {
      render(<CardFooter>Test Footer</CardFooter>)
      expect(screen.getByText('Test Footer')).toBeInTheDocument()
    })

    it('should apply custom className', () => {
      render(<CardFooter className="custom-footer" data-testid="card-footer" />)
      expect(screen.getByTestId('card-footer')).toHaveClass('custom-footer')
    })

    it('should render buttons in footer', () => {
      render(
        <CardFooter>
          <button>Cancel</button>
          <button>Confirm</button>
        </CardFooter>
      )
      expect(screen.getByText('Cancel')).toBeInTheDocument()
      expect(screen.getByText('Confirm')).toBeInTheDocument()
    })
  })

  describe('Complete Card Structure', () => {
    it('should render complete card with all components', () => {
      render(
        <Card data-testid="complete-card">
          <CardHeader>
            <CardTitle>Card Title</CardTitle>
            <CardDescription>Card Description</CardDescription>
          </CardHeader>
          <CardContent>Card Content</CardContent>
          <CardFooter>Card Footer</CardFooter>
        </Card>
      )

      expect(screen.getByTestId('complete-card')).toBeInTheDocument()
      expect(screen.getByText('Card Title')).toBeInTheDocument()
      expect(screen.getByText('Card Description')).toBeInTheDocument()
      expect(screen.getByText('Card Content')).toBeInTheDocument()
      expect(screen.getByText('Card Footer')).toBeInTheDocument()
    })

    it('should render card without header', () => {
      render(
        <Card>
          <CardContent>Content Only</CardContent>
          <CardFooter>Footer</CardFooter>
        </Card>
      )

      expect(screen.getByText('Content Only')).toBeInTheDocument()
      expect(screen.getByText('Footer')).toBeInTheDocument()
    })

    it('should render card without footer', () => {
      render(
        <Card>
          <CardHeader>
            <CardTitle>Title</CardTitle>
          </CardHeader>
          <CardContent>Content</CardContent>
        </Card>
      )

      expect(screen.getByText('Title')).toBeInTheDocument()
      expect(screen.getByText('Content')).toBeInTheDocument()
    })

    it('should render card with only content', () => {
      render(
        <Card>
          <CardContent>Standalone Content</CardContent>
        </Card>
      )

      expect(screen.getByText('Standalone Content')).toBeInTheDocument()
    })
  })

  describe('Styling and Classes', () => {
    it('should merge custom classes with default classes', () => {
      render(<Card className="bg-red-500 p-10" data-testid="styled-card" />)
      const card = screen.getByTestId('styled-card')
      expect(card).toHaveClass('bg-red-500')
      expect(card).toHaveClass('p-10')
    })

    it('should apply different styles to different card parts', () => {
      render(
        <Card data-testid="card">
          <CardHeader className="header-class" data-testid="header" />
          <CardContent className="content-class" data-testid="content" />
          <CardFooter className="footer-class" data-testid="footer" />
        </Card>
      )

      expect(screen.getByTestId('header')).toHaveClass('header-class')
      expect(screen.getByTestId('content')).toHaveClass('content-class')
      expect(screen.getByTestId('footer')).toHaveClass('footer-class')
    })
  })

  describe('Accessibility', () => {
    it('should support aria attributes on card', () => {
      render(<Card aria-label="Information card" data-testid="card" />)
      expect(screen.getByTestId('card')).toHaveAttribute('aria-label', 'Information card')
    })

    it('should support role attribute', () => {
      render(<Card role="article" data-testid="card" />)
      expect(screen.getByTestId('card')).toHaveAttribute('role', 'article')
    })

    it('should have proper semantic structure', () => {
      render(
        <Card>
          <CardHeader>
            <CardTitle>Semantic Title</CardTitle>
            <CardDescription>Semantic Description</CardDescription>
          </CardHeader>
          <CardContent>Semantic Content</CardContent>
        </Card>
      )

      const title = screen.getByText('Semantic Title')
      const description = screen.getByText('Semantic Description')

      expect(title.tagName).toBe('H3')
      expect(description.tagName).toBe('P')
    })
  })

  describe('Edge Cases', () => {
    it('should handle empty card', () => {
      render(<Card data-testid="empty-card" />)
      expect(screen.getByTestId('empty-card')).toBeInTheDocument()
    })

    it('should handle null children', () => {
      render(<Card>{null}</Card>)
      expect(document.querySelector('div')).toBeInTheDocument()
    })

    it('should handle undefined children', () => {
      render(<Card>{undefined}</Card>)
      expect(document.querySelector('div')).toBeInTheDocument()
    })

    it('should handle mixed content types', () => {
      render(
        <Card>
          Text node
          <CardContent>Component</CardContent>
          {null}
          {undefined}
          <span>Span element</span>
        </Card>
      )

      expect(screen.getByText('Text node')).toBeInTheDocument()
      expect(screen.getByText('Component')).toBeInTheDocument()
      expect(screen.getByText('Span element')).toBeInTheDocument()
    })
  })
})
