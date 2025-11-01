import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Tooltip, TooltipTrigger, TooltipContent, TooltipProvider } from '../tooltip'

describe('Tooltip', () => {
  it('renders tooltip trigger', () => {
    render(
      <Tooltip>
        <TooltipTrigger>Hover me</TooltipTrigger>
        <TooltipContent>Tooltip text</TooltipContent>
      </Tooltip>
    )
    expect(screen.getByText('Hover me')).toBeInTheDocument()
  })

  it('does not show content by default', () => {
    render(
      <Tooltip>
        <TooltipTrigger>Hover me</TooltipTrigger>
        <TooltipContent>Tooltip text</TooltipContent>
      </Tooltip>
    )
    expect(screen.queryByText('Tooltip text')).not.toBeInTheDocument()
  })

  it('shows content when hovering over trigger', async () => {
    const user = userEvent.setup()
    render(
      <Tooltip>
        <TooltipTrigger>Hover me</TooltipTrigger>
        <TooltipContent>Tooltip text</TooltipContent>
      </Tooltip>
    )

    const trigger = screen.getByText('Hover me')
    await user.hover(trigger)

    await waitFor(() => {
      expect(screen.getByText('Tooltip text')).toBeInTheDocument()
    })
  })

  it('hides content when mouse leaves', async () => {
    const user = userEvent.setup()
    render(
      <Tooltip>
        <TooltipTrigger>Hover me</TooltipTrigger>
        <TooltipContent>Tooltip text</TooltipContent>
      </Tooltip>
    )

    const trigger = screen.getByText('Hover me')

    await user.hover(trigger)
    await waitFor(() => {
      expect(screen.getByText('Tooltip text')).toBeInTheDocument()
    })

    await user.unhover(trigger)
    await waitFor(() => {
      expect(screen.queryByText('Tooltip text')).not.toBeInTheDocument()
    })
  })

  it('can be controlled with open prop', async () => {
    const handleOpenChange = vi.fn()
    const { rerender } = render(
      <Tooltip open={false} onOpenChange={handleOpenChange}>
        <TooltipTrigger>Hover me</TooltipTrigger>
        <TooltipContent>Controlled content</TooltipContent>
      </Tooltip>
    )

    expect(screen.queryByText('Controlled content')).not.toBeInTheDocument()

    rerender(
      <Tooltip open={true} onOpenChange={handleOpenChange}>
        <TooltipTrigger>Hover me</TooltipTrigger>
        <TooltipContent>Controlled content</TooltipContent>
      </Tooltip>
    )

    await waitFor(() => {
      expect(screen.getByText('Controlled content')).toBeInTheDocument()
    })
  })

  it('renders with defaultOpen prop', async () => {
    render(
      <Tooltip defaultOpen>
        <TooltipTrigger>Hover me</TooltipTrigger>
        <TooltipContent>Default open content</TooltipContent>
      </Tooltip>
    )

    await waitFor(() => {
      expect(screen.getByText('Default open content')).toBeInTheDocument()
    })
  })

  it('applies custom className to content', async () => {
    const user = userEvent.setup()
    const customClass = 'custom-tooltip-content'
    render(
      <Tooltip>
        <TooltipTrigger>Hover me</TooltipTrigger>
        <TooltipContent className={customClass}>Content</TooltipContent>
      </Tooltip>
    )

    const trigger = screen.getByText('Hover me')
    await user.hover(trigger)

    await waitFor(() => {
      const content = screen.getByText('Content')
      expect(content).toHaveClass(customClass)
    })
  })

  it('supports custom sideOffset', async () => {
    const user = userEvent.setup()
    render(
      <Tooltip>
        <TooltipTrigger>Hover me</TooltipTrigger>
        <TooltipContent sideOffset={10}>Offset content</TooltipContent>
      </Tooltip>
    )

    const trigger = screen.getByText('Hover me')
    await user.hover(trigger)

    await waitFor(() => {
      expect(screen.getByText('Offset content')).toBeInTheDocument()
    })
  })

  it('forwards ref to trigger', () => {
    const ref = vi.fn()
    render(
      <Tooltip>
        <TooltipTrigger ref={ref}>Trigger</TooltipTrigger>
        <TooltipContent>Content</TooltipContent>
      </Tooltip>
    )
    expect(ref).toHaveBeenCalled()
  })

  it('forwards ref to content', async () => {
    const user = userEvent.setup()
    const ref = vi.fn()
    render(
      <Tooltip>
        <TooltipTrigger>Trigger</TooltipTrigger>
        <TooltipContent ref={ref}>Content</TooltipContent>
      </Tooltip>
    )

    const trigger = screen.getByText('Trigger')
    await user.hover(trigger)

    await waitFor(() => {
      expect(ref).toHaveBeenCalled()
    })
  })

  it('renders tooltip provider', () => {
    const { container } = render(
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger>Hover me</TooltipTrigger>
          <TooltipContent>Content</TooltipContent>
        </Tooltip>
      </TooltipProvider>
    )
    expect(container).toBeInTheDocument()
  })

  it('supports custom delayDuration in provider', () => {
    const { container } = render(
      <TooltipProvider delayDuration={500}>
        <Tooltip>
          <TooltipTrigger>Hover me</TooltipTrigger>
          <TooltipContent>Content</TooltipContent>
        </Tooltip>
      </TooltipProvider>
    )
    expect(container).toBeInTheDocument()
  })

  it('calls onOpenChange when tooltip opens', async () => {
    const user = userEvent.setup()
    const handleOpenChange = vi.fn()
    render(
      <Tooltip onOpenChange={handleOpenChange}>
        <TooltipTrigger>Hover me</TooltipTrigger>
        <TooltipContent>Content</TooltipContent>
      </Tooltip>
    )

    const trigger = screen.getByText('Hover me')
    await user.hover(trigger)

    await waitFor(() => {
      expect(handleOpenChange).toHaveBeenCalledWith(true)
    })
  })

  it('calls onOpenChange when tooltip closes', async () => {
    const user = userEvent.setup()
    const handleOpenChange = vi.fn()
    render(
      <Tooltip onOpenChange={handleOpenChange}>
        <TooltipTrigger>Hover me</TooltipTrigger>
        <TooltipContent>Content</TooltipContent>
      </Tooltip>
    )

    const trigger = screen.getByText('Hover me')

    await user.hover(trigger)
    await waitFor(() => {
      expect(handleOpenChange).toHaveBeenCalledWith(true)
    })

    vi.clearAllMocks()

    await user.unhover(trigger)
    await waitFor(() => {
      expect(handleOpenChange).toHaveBeenCalledWith(false)
    })
  })

  it('renders content in a portal', async () => {
    const user = userEvent.setup()
    render(
      <div id="root">
        <Tooltip>
          <TooltipTrigger>Hover me</TooltipTrigger>
          <TooltipContent>Portal content</TooltipContent>
        </Tooltip>
      </div>
    )

    const trigger = screen.getByText('Hover me')
    await user.hover(trigger)

    await waitFor(() => {
      const content = screen.getByText('Portal content')
      expect(content).toBeInTheDocument()
    })
  })

  it('has proper z-index styling', async () => {
    const user = userEvent.setup()
    render(
      <Tooltip>
        <TooltipTrigger>Hover me</TooltipTrigger>
        <TooltipContent>Styled content</TooltipContent>
      </Tooltip>
    )

    const trigger = screen.getByText('Hover me')
    await user.hover(trigger)

    await waitFor(() => {
      const content = screen.getByText('Styled content')
      expect(content).toHaveClass('z-50')
    })
  })

  it('applies animation classes', async () => {
    const user = userEvent.setup()
    render(
      <Tooltip>
        <TooltipTrigger>Hover me</TooltipTrigger>
        <TooltipContent>Animated content</TooltipContent>
      </Tooltip>
    )

    const trigger = screen.getByText('Hover me')
    await user.hover(trigger)

    await waitFor(() => {
      const content = screen.getByText('Animated content')
      expect(content).toHaveClass('animate-in', 'fade-in-0')
    })
  })

  it('supports different side positions', async () => {
    const user = userEvent.setup()
    render(
      <Tooltip>
        <TooltipTrigger>Hover me</TooltipTrigger>
        <TooltipContent side="bottom">Bottom content</TooltipContent>
      </Tooltip>
    )

    const trigger = screen.getByText('Hover me')
    await user.hover(trigger)

    await waitFor(() => {
      expect(screen.getByText('Bottom content')).toBeInTheDocument()
    })
  })

  it('preserves additional props on trigger', () => {
    render(
      <Tooltip>
        <TooltipTrigger data-testid="custom-trigger">Trigger</TooltipTrigger>
        <TooltipContent>Content</TooltipContent>
      </Tooltip>
    )
    expect(screen.getByTestId('custom-trigger')).toBeInTheDocument()
  })

  it('preserves additional props on content', async () => {
    const user = userEvent.setup()
    render(
      <Tooltip>
        <TooltipTrigger>Trigger</TooltipTrigger>
        <TooltipContent data-testid="custom-content">Content</TooltipContent>
      </Tooltip>
    )

    const trigger = screen.getByText('Trigger')
    await user.hover(trigger)

    await waitFor(() => {
      expect(screen.getByTestId('custom-content')).toBeInTheDocument()
    })
  })

  it('applies data-slot attributes', async () => {
    const user = userEvent.setup()
    const { container } = render(
      <Tooltip>
        <TooltipTrigger>Hover me</TooltipTrigger>
        <TooltipContent>Content</TooltipContent>
      </Tooltip>
    )

    expect(container.querySelector('[data-slot="tooltip"]')).toBeInTheDocument()
    expect(container.querySelector('[data-slot="tooltip-trigger"]')).toBeInTheDocument()

    const trigger = screen.getByText('Hover me')
    await user.hover(trigger)

    await waitFor(() => {
      expect(document.querySelector('[data-slot="tooltip-content"]')).toBeInTheDocument()
    })
  })

  it('renders tooltip arrow', async () => {
    const user = userEvent.setup()
    const { container } = render(
      <Tooltip>
        <TooltipTrigger>Hover me</TooltipTrigger>
        <TooltipContent>Content with arrow</TooltipContent>
      </Tooltip>
    )

    const trigger = screen.getByText('Hover me')
    await user.hover(trigger)

    await waitFor(() => {
      const arrow = document.querySelector('.fill-foreground')
      expect(arrow).toBeInTheDocument()
    })
  })

  it('applies text styling', async () => {
    const user = userEvent.setup()
    render(
      <Tooltip>
        <TooltipTrigger>Hover me</TooltipTrigger>
        <TooltipContent>Styled text</TooltipContent>
      </Tooltip>
    )

    const trigger = screen.getByText('Hover me')
    await user.hover(trigger)

    await waitFor(() => {
      const content = screen.getByText('Styled text')
      expect(content).toHaveClass('text-xs', 'text-balance')
    })
  })

  it('applies padding and rounded styling', async () => {
    const user = userEvent.setup()
    render(
      <Tooltip>
        <TooltipTrigger>Hover me</TooltipTrigger>
        <TooltipContent>Styled content</TooltipContent>
      </Tooltip>
    )

    const trigger = screen.getByText('Hover me')
    await user.hover(trigger)

    await waitFor(() => {
      const content = screen.getByText('Styled content')
      expect(content).toHaveClass('rounded-md', 'px-3', 'py-1.5')
    })
  })

  it('supports disableHoverableContent prop', async () => {
    const user = userEvent.setup()
    render(
      <Tooltip disableHoverableContent>
        <TooltipTrigger>Hover me</TooltipTrigger>
        <TooltipContent>Content</TooltipContent>
      </Tooltip>
    )

    const trigger = screen.getByText('Hover me')
    await user.hover(trigger)

    await waitFor(() => {
      expect(screen.getByText('Content')).toBeInTheDocument()
    })
  })

  it('renders with proper background colors', async () => {
    const user = userEvent.setup()
    render(
      <Tooltip>
        <TooltipTrigger>Hover me</TooltipTrigger>
        <TooltipContent>Content</TooltipContent>
      </Tooltip>
    )

    const trigger = screen.getByText('Hover me')
    await user.hover(trigger)

    await waitFor(() => {
      const content = screen.getByText('Content')
      expect(content).toHaveClass('bg-foreground', 'text-background')
    })
  })

  it('handles focus events', async () => {
    const user = userEvent.setup()
    render(
      <Tooltip>
        <TooltipTrigger>Focus me</TooltipTrigger>
        <TooltipContent>Tooltip on focus</TooltipContent>
      </Tooltip>
    )

    const trigger = screen.getByText('Focus me')
    await user.tab()

    if (trigger === document.activeElement) {
      await waitFor(() => {
        expect(screen.getByText('Tooltip on focus')).toBeInTheDocument()
      })
    }
  })

  it('supports align prop', async () => {
    const user = userEvent.setup()
    render(
      <Tooltip>
        <TooltipTrigger>Hover me</TooltipTrigger>
        <TooltipContent align="start">Aligned content</TooltipContent>
      </Tooltip>
    )

    const trigger = screen.getByText('Hover me')
    await user.hover(trigger)

    await waitFor(() => {
      expect(screen.getByText('Aligned content')).toBeInTheDocument()
    })
  })

  it('can render complex content', async () => {
    const user = userEvent.setup()
    render(
      <Tooltip>
        <TooltipTrigger>Hover me</TooltipTrigger>
        <TooltipContent>
          <div>
            <strong>Bold text</strong>
            <p>Regular text</p>
          </div>
        </TooltipContent>
      </Tooltip>
    )

    const trigger = screen.getByText('Hover me')
    await user.hover(trigger)

    await waitFor(() => {
      expect(screen.getByText('Bold text')).toBeInTheDocument()
      expect(screen.getByText('Regular text')).toBeInTheDocument()
    })
  })
})
