import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { HoverCard, HoverCardTrigger, HoverCardContent } from '../hover-card'

describe('HoverCard', () => {
  it('renders hover card trigger', () => {
    render(
      <HoverCard>
        <HoverCardTrigger>Hover over me</HoverCardTrigger>
        <HoverCardContent>Card Content</HoverCardContent>
      </HoverCard>
    )
    expect(screen.getByText('Hover over me')).toBeInTheDocument()
  })

  it('does not show content by default', () => {
    render(
      <HoverCard>
        <HoverCardTrigger>Hover over me</HoverCardTrigger>
        <HoverCardContent>Card Content</HoverCardContent>
      </HoverCard>
    )
    expect(screen.queryByText('Card Content')).not.toBeInTheDocument()
  })

  it('shows content when hovering over trigger', async () => {
    const user = userEvent.setup()
    render(
      <HoverCard>
        <HoverCardTrigger>Hover over me</HoverCardTrigger>
        <HoverCardContent>Card Content</HoverCardContent>
      </HoverCard>
    )

    const trigger = screen.getByText('Hover over me')
    await user.hover(trigger)

    await waitFor(() => {
      expect(screen.getByText('Card Content')).toBeInTheDocument()
    })
  })

  it('hides content when mouse leaves', async () => {
    const user = userEvent.setup()
    render(
      <HoverCard>
        <HoverCardTrigger>Hover over me</HoverCardTrigger>
        <HoverCardContent>Card Content</HoverCardContent>
      </HoverCard>
    )

    const trigger = screen.getByText('Hover over me')

    // Hover over trigger
    await user.hover(trigger)
    await waitFor(() => {
      expect(screen.getByText('Card Content')).toBeInTheDocument()
    })

    // Unhover
    await user.unhover(trigger)
    await waitFor(() => {
      expect(screen.queryByText('Card Content')).not.toBeInTheDocument()
    })
  })

  it('can be controlled with open prop', async () => {
    const handleOpenChange = vi.fn()
    const { rerender } = render(
      <HoverCard open={false} onOpenChange={handleOpenChange}>
        <HoverCardTrigger>Hover over me</HoverCardTrigger>
        <HoverCardContent>Controlled Content</HoverCardContent>
      </HoverCard>
    )

    expect(screen.queryByText('Controlled Content')).not.toBeInTheDocument()

    rerender(
      <HoverCard open={true} onOpenChange={handleOpenChange}>
        <HoverCardTrigger>Hover over me</HoverCardTrigger>
        <HoverCardContent>Controlled Content</HoverCardContent>
      </HoverCard>
    )

    await waitFor(() => {
      expect(screen.getByText('Controlled Content')).toBeInTheDocument()
    })
  })

  it('renders with defaultOpen prop', async () => {
    render(
      <HoverCard defaultOpen>
        <HoverCardTrigger>Hover over me</HoverCardTrigger>
        <HoverCardContent>Default Open Content</HoverCardContent>
      </HoverCard>
    )

    await waitFor(() => {
      expect(screen.getByText('Default Open Content')).toBeInTheDocument()
    })
  })

  it('applies custom className to content', async () => {
    const user = userEvent.setup()
    const customClass = 'custom-hover-card-content'
    render(
      <HoverCard>
        <HoverCardTrigger>Hover over me</HoverCardTrigger>
        <HoverCardContent className={customClass}>Content</HoverCardContent>
      </HoverCard>
    )

    const trigger = screen.getByText('Hover over me')
    await user.hover(trigger)

    await waitFor(() => {
      const content = screen.getByText('Content')
      expect(content).toHaveClass(customClass)
    })
  })

  it('supports different align positions', async () => {
    const user = userEvent.setup()
    render(
      <HoverCard>
        <HoverCardTrigger>Hover over me</HoverCardTrigger>
        <HoverCardContent align="start">Aligned Content</HoverCardContent>
      </HoverCard>
    )

    const trigger = screen.getByText('Hover over me')
    await user.hover(trigger)

    await waitFor(() => {
      expect(screen.getByText('Aligned Content')).toBeInTheDocument()
    })
  })

  it('supports custom sideOffset', async () => {
    const user = userEvent.setup()
    render(
      <HoverCard>
        <HoverCardTrigger>Hover over me</HoverCardTrigger>
        <HoverCardContent sideOffset={10}>Offset Content</HoverCardContent>
      </HoverCard>
    )

    const trigger = screen.getByText('Hover over me')
    await user.hover(trigger)

    await waitFor(() => {
      expect(screen.getByText('Offset Content')).toBeInTheDocument()
    })
  })

  it('forwards ref to trigger', () => {
    const ref = vi.fn()
    render(
      <HoverCard>
        <HoverCardTrigger ref={ref}>Trigger</HoverCardTrigger>
        <HoverCardContent>Content</HoverCardContent>
      </HoverCard>
    )
    expect(ref).toHaveBeenCalled()
  })

  it('forwards ref to content', async () => {
    const user = userEvent.setup()
    const ref = vi.fn()
    render(
      <HoverCard>
        <HoverCardTrigger>Trigger</HoverCardTrigger>
        <HoverCardContent ref={ref}>Content</HoverCardContent>
      </HoverCard>
    )

    const trigger = screen.getByText('Trigger')
    await user.hover(trigger)

    await waitFor(() => {
      expect(ref).toHaveBeenCalled()
    })
  })

  it('supports custom openDelay', async () => {
    const user = userEvent.setup()
    render(
      <HoverCard openDelay={0}>
        <HoverCardTrigger>Hover over me</HoverCardTrigger>
        <HoverCardContent>Fast Content</HoverCardContent>
      </HoverCard>
    )

    const trigger = screen.getByText('Hover over me')
    await user.hover(trigger)

    await waitFor(() => {
      expect(screen.getByText('Fast Content')).toBeInTheDocument()
    })
  })

  it('supports custom closeDelay', async () => {
    const user = userEvent.setup()
    render(
      <HoverCard closeDelay={0}>
        <HoverCardTrigger>Hover over me</HoverCardTrigger>
        <HoverCardContent>Fast Close Content</HoverCardContent>
      </HoverCard>
    )

    const trigger = screen.getByText('Hover over me')
    await user.hover(trigger)

    await waitFor(() => {
      expect(screen.getByText('Fast Close Content')).toBeInTheDocument()
    })

    await user.unhover(trigger)

    await waitFor(() => {
      expect(screen.queryByText('Fast Close Content')).not.toBeInTheDocument()
    })
  })

  it('calls onOpenChange when hover card opens', async () => {
    const user = userEvent.setup()
    const handleOpenChange = vi.fn()
    render(
      <HoverCard onOpenChange={handleOpenChange}>
        <HoverCardTrigger>Hover over me</HoverCardTrigger>
        <HoverCardContent>Content</HoverCardContent>
      </HoverCard>
    )

    const trigger = screen.getByText('Hover over me')
    await user.hover(trigger)

    await waitFor(() => {
      expect(handleOpenChange).toHaveBeenCalledWith(true)
    })
  })

  it('calls onOpenChange when hover card closes', async () => {
    const user = userEvent.setup()
    const handleOpenChange = vi.fn()
    render(
      <HoverCard onOpenChange={handleOpenChange}>
        <HoverCardTrigger>Hover over me</HoverCardTrigger>
        <HoverCardContent>Content</HoverCardContent>
      </HoverCard>
    )

    const trigger = screen.getByText('Hover over me')

    // Hover
    await user.hover(trigger)
    await waitFor(() => {
      expect(handleOpenChange).toHaveBeenCalledWith(true)
    })

    vi.clearAllMocks()

    // Unhover
    await user.unhover(trigger)
    await waitFor(() => {
      expect(handleOpenChange).toHaveBeenCalledWith(false)
    })
  })

  it('has proper z-index styling', async () => {
    const user = userEvent.setup()
    render(
      <HoverCard>
        <HoverCardTrigger>Hover over me</HoverCardTrigger>
        <HoverCardContent>Styled Content</HoverCardContent>
      </HoverCard>
    )

    const trigger = screen.getByText('Hover over me')
    await user.hover(trigger)

    await waitFor(() => {
      const content = screen.getByText('Styled Content')
      expect(content).toHaveClass('z-50')
    })
  })

  it('applies animation classes', async () => {
    const user = userEvent.setup()
    render(
      <HoverCard>
        <HoverCardTrigger>Hover over me</HoverCardTrigger>
        <HoverCardContent>Animated Content</HoverCardContent>
      </HoverCard>
    )

    const trigger = screen.getByText('Hover over me')
    await user.hover(trigger)

    await waitFor(() => {
      const content = screen.getByText('Animated Content')
      expect(content).toHaveClass('data-[state=open]:animate-in')
    })
  })

  it('applies default width styling', async () => {
    const user = userEvent.setup()
    render(
      <HoverCard>
        <HoverCardTrigger>Hover over me</HoverCardTrigger>
        <HoverCardContent>Width Content</HoverCardContent>
      </HoverCard>
    )

    const trigger = screen.getByText('Hover over me')
    await user.hover(trigger)

    await waitFor(() => {
      const content = screen.getByText('Width Content')
      expect(content).toHaveClass('w-64')
    })
  })

  it('supports different side positions', async () => {
    const user = userEvent.setup()
    render(
      <HoverCard>
        <HoverCardTrigger>Hover over me</HoverCardTrigger>
        <HoverCardContent side="bottom">Bottom Content</HoverCardContent>
      </HoverCard>
    )

    const trigger = screen.getByText('Hover over me')
    await user.hover(trigger)

    await waitFor(() => {
      expect(screen.getByText('Bottom Content')).toBeInTheDocument()
    })
  })

  it('preserves additional props on trigger', () => {
    render(
      <HoverCard>
        <HoverCardTrigger data-testid="custom-trigger">Trigger</HoverCardTrigger>
        <HoverCardContent>Content</HoverCardContent>
      </HoverCard>
    )
    expect(screen.getByTestId('custom-trigger')).toBeInTheDocument()
  })

  it('preserves additional props on content', async () => {
    const user = userEvent.setup()
    render(
      <HoverCard>
        <HoverCardTrigger>Trigger</HoverCardTrigger>
        <HoverCardContent data-testid="custom-content">Content</HoverCardContent>
      </HoverCard>
    )

    const trigger = screen.getByText('Trigger')
    await user.hover(trigger)

    await waitFor(() => {
      expect(screen.getByTestId('custom-content')).toBeInTheDocument()
    })
  })

  it('applies rounded border styling', async () => {
    const user = userEvent.setup()
    render(
      <HoverCard>
        <HoverCardTrigger>Hover over me</HoverCardTrigger>
        <HoverCardContent>Styled Content</HoverCardContent>
      </HoverCard>
    )

    const trigger = screen.getByText('Hover over me')
    await user.hover(trigger)

    await waitFor(() => {
      const content = screen.getByText('Styled Content')
      expect(content).toHaveClass('rounded-md', 'border')
    })
  })

  it('applies popover background styling', async () => {
    const user = userEvent.setup()
    render(
      <HoverCard>
        <HoverCardTrigger>Hover over me</HoverCardTrigger>
        <HoverCardContent>Styled Content</HoverCardContent>
      </HoverCard>
    )

    const trigger = screen.getByText('Hover over me')
    await user.hover(trigger)

    await waitFor(() => {
      const content = screen.getByText('Styled Content')
      expect(content).toHaveClass('bg-popover', 'text-popover-foreground')
    })
  })

  it('applies padding styling', async () => {
    const user = userEvent.setup()
    render(
      <HoverCard>
        <HoverCardTrigger>Hover over me</HoverCardTrigger>
        <HoverCardContent>Styled Content</HoverCardContent>
      </HoverCard>
    )

    const trigger = screen.getByText('Hover over me')
    await user.hover(trigger)

    await waitFor(() => {
      const content = screen.getByText('Styled Content')
      expect(content).toHaveClass('p-4')
    })
  })
})
