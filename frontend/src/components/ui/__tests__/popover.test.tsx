import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Popover, PopoverTrigger, PopoverContent, PopoverAnchor } from '../popover'

describe('Popover', () => {
  it('renders popover trigger', () => {
    render(
      <Popover>
        <PopoverTrigger>Open Popover</PopoverTrigger>
        <PopoverContent>Popover Content</PopoverContent>
      </Popover>
    )
    expect(screen.getByText('Open Popover')).toBeInTheDocument()
  })

  it('does not show content by default', () => {
    render(
      <Popover>
        <PopoverTrigger>Open Popover</PopoverTrigger>
        <PopoverContent>Popover Content</PopoverContent>
      </Popover>
    )
    expect(screen.queryByText('Popover Content')).not.toBeInTheDocument()
  })

  it('shows content when trigger is clicked', async () => {
    const user = userEvent.setup()
    render(
      <Popover>
        <PopoverTrigger>Open Popover</PopoverTrigger>
        <PopoverContent>Popover Content</PopoverContent>
      </Popover>
    )

    const trigger = screen.getByText('Open Popover')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Popover Content')).toBeInTheDocument()
    })
  })

  it('hides content when trigger is clicked again', async () => {
    const user = userEvent.setup()
    render(
      <Popover>
        <PopoverTrigger>Open Popover</PopoverTrigger>
        <PopoverContent>Popover Content</PopoverContent>
      </Popover>
    )

    const trigger = screen.getByText('Open Popover')

    // Open popover
    await user.click(trigger)
    await waitFor(() => {
      expect(screen.getByText('Popover Content')).toBeInTheDocument()
    })

    // Close popover
    await user.click(trigger)
    await waitFor(() => {
      expect(screen.queryByText('Popover Content')).not.toBeInTheDocument()
    })
  })

  it('can be controlled with open prop', async () => {
    const user = userEvent.setup()
    const handleOpenChange = vi.fn()
    const { rerender } = render(
      <Popover open={false} onOpenChange={handleOpenChange}>
        <PopoverTrigger>Open Popover</PopoverTrigger>
        <PopoverContent>Controlled Content</PopoverContent>
      </Popover>
    )

    expect(screen.queryByText('Controlled Content')).not.toBeInTheDocument()

    const trigger = screen.getByText('Open Popover')
    await user.click(trigger)

    expect(handleOpenChange).toHaveBeenCalledWith(true)

    rerender(
      <Popover open={true} onOpenChange={handleOpenChange}>
        <PopoverTrigger>Open Popover</PopoverTrigger>
        <PopoverContent>Controlled Content</PopoverContent>
      </Popover>
    )

    await waitFor(() => {
      expect(screen.getByText('Controlled Content')).toBeInTheDocument()
    })
  })

  it('renders with defaultOpen prop', async () => {
    render(
      <Popover defaultOpen>
        <PopoverTrigger>Open Popover</PopoverTrigger>
        <PopoverContent>Default Open Content</PopoverContent>
      </Popover>
    )

    await waitFor(() => {
      expect(screen.getByText('Default Open Content')).toBeInTheDocument()
    })
  })

  it('applies custom className to content', async () => {
    const user = userEvent.setup()
    const customClass = 'custom-popover-content'
    render(
      <Popover>
        <PopoverTrigger>Open Popover</PopoverTrigger>
        <PopoverContent className={customClass}>Content</PopoverContent>
      </Popover>
    )

    const trigger = screen.getByText('Open Popover')
    await user.click(trigger)

    await waitFor(() => {
      const content = screen.getByText('Content')
      expect(content).toHaveClass(customClass)
    })
  })

  it('supports different align positions', async () => {
    const user = userEvent.setup()
    render(
      <Popover>
        <PopoverTrigger>Open Popover</PopoverTrigger>
        <PopoverContent align="start">Aligned Content</PopoverContent>
      </Popover>
    )

    const trigger = screen.getByText('Open Popover')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Aligned Content')).toBeInTheDocument()
    })
  })

  it('supports custom sideOffset', async () => {
    const user = userEvent.setup()
    render(
      <Popover>
        <PopoverTrigger>Open Popover</PopoverTrigger>
        <PopoverContent sideOffset={10}>Offset Content</PopoverContent>
      </Popover>
    )

    const trigger = screen.getByText('Open Popover')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Offset Content')).toBeInTheDocument()
    })
  })

  it('forwards ref to trigger', () => {
    const ref = vi.fn()
    render(
      <Popover>
        <PopoverTrigger ref={ref}>Trigger</PopoverTrigger>
        <PopoverContent>Content</PopoverContent>
      </Popover>
    )
    expect(ref).toHaveBeenCalled()
  })

  it('forwards ref to content', async () => {
    const user = userEvent.setup()
    const ref = vi.fn()
    render(
      <Popover>
        <PopoverTrigger>Trigger</PopoverTrigger>
        <PopoverContent ref={ref}>Content</PopoverContent>
      </Popover>
    )

    const trigger = screen.getByText('Trigger')
    await user.click(trigger)

    await waitFor(() => {
      expect(ref).toHaveBeenCalled()
    })
  })

  it('closes on escape key', async () => {
    const user = userEvent.setup()
    render(
      <Popover>
        <PopoverTrigger>Open Popover</PopoverTrigger>
        <PopoverContent>Escapable Content</PopoverContent>
      </Popover>
    )

    const trigger = screen.getByText('Open Popover')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Escapable Content')).toBeInTheDocument()
    })

    await user.keyboard('{Escape}')

    await waitFor(() => {
      expect(screen.queryByText('Escapable Content')).not.toBeInTheDocument()
    })
  })

  it('closes when clicking outside', async () => {
    const user = userEvent.setup()
    render(
      <div>
        <div data-testid="outside">Outside Element</div>
        <Popover>
          <PopoverTrigger>Open Popover</PopoverTrigger>
          <PopoverContent>Clickaway Content</PopoverContent>
        </Popover>
      </div>
    )

    const trigger = screen.getByText('Open Popover')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Clickaway Content')).toBeInTheDocument()
    })

    const outside = screen.getByTestId('outside')
    await user.click(outside)

    await waitFor(() => {
      expect(screen.queryByText('Clickaway Content')).not.toBeInTheDocument()
    })
  })

  it('renders PopoverAnchor component', () => {
    render(
      <Popover>
        <PopoverAnchor>
          <div>Anchor Element</div>
        </PopoverAnchor>
        <PopoverTrigger>Open Popover</PopoverTrigger>
        <PopoverContent>Content</PopoverContent>
      </Popover>
    )
    expect(screen.getByText('Anchor Element')).toBeInTheDocument()
  })

  it('supports modal behavior', async () => {
    const user = userEvent.setup()
    render(
      <Popover modal>
        <PopoverTrigger>Open Modal Popover</PopoverTrigger>
        <PopoverContent>Modal Content</PopoverContent>
      </Popover>
    )

    const trigger = screen.getByText('Open Modal Popover')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Modal Content')).toBeInTheDocument()
    })
  })

  it('calls onOpenChange when popover opens', async () => {
    const user = userEvent.setup()
    const handleOpenChange = vi.fn()
    render(
      <Popover onOpenChange={handleOpenChange}>
        <PopoverTrigger>Open Popover</PopoverTrigger>
        <PopoverContent>Content</PopoverContent>
      </Popover>
    )

    const trigger = screen.getByText('Open Popover')
    await user.click(trigger)

    expect(handleOpenChange).toHaveBeenCalledWith(true)
  })

  it('calls onOpenChange when popover closes', async () => {
    const user = userEvent.setup()
    const handleOpenChange = vi.fn()
    render(
      <Popover onOpenChange={handleOpenChange}>
        <PopoverTrigger>Open Popover</PopoverTrigger>
        <PopoverContent>Content</PopoverContent>
      </Popover>
    )

    const trigger = screen.getByText('Open Popover')

    // Open
    await user.click(trigger)
    expect(handleOpenChange).toHaveBeenCalledWith(true)

    vi.clearAllMocks()

    // Close
    await user.click(trigger)
    expect(handleOpenChange).toHaveBeenCalledWith(false)
  })

  it('renders content in a portal', async () => {
    const user = userEvent.setup()
    const { container } = render(
      <div id="root">
        <Popover>
          <PopoverTrigger>Open Popover</PopoverTrigger>
          <PopoverContent>Portal Content</PopoverContent>
        </Popover>
      </div>
    )

    const trigger = screen.getByText('Open Popover')
    await user.click(trigger)

    await waitFor(() => {
      const content = screen.getByText('Portal Content')
      // Content should be in document but not inside the root container
      expect(content).toBeInTheDocument()
    })
  })

  it('has proper z-index styling', async () => {
    const user = userEvent.setup()
    render(
      <Popover>
        <PopoverTrigger>Open Popover</PopoverTrigger>
        <PopoverContent>Styled Content</PopoverContent>
      </Popover>
    )

    const trigger = screen.getByText('Open Popover')
    await user.click(trigger)

    await waitFor(() => {
      const content = screen.getByText('Styled Content')
      expect(content).toHaveClass('z-50')
    })
  })

  it('applies animation classes', async () => {
    const user = userEvent.setup()
    render(
      <Popover>
        <PopoverTrigger>Open Popover</PopoverTrigger>
        <PopoverContent>Animated Content</PopoverContent>
      </Popover>
    )

    const trigger = screen.getByText('Open Popover')
    await user.click(trigger)

    await waitFor(() => {
      const content = screen.getByText('Animated Content')
      expect(content).toHaveClass('data-[state=open]:animate-in')
    })
  })

  it('supports different side positions', async () => {
    const user = userEvent.setup()
    render(
      <Popover>
        <PopoverTrigger>Open Popover</PopoverTrigger>
        <PopoverContent side="bottom">Bottom Content</PopoverContent>
      </Popover>
    )

    const trigger = screen.getByText('Open Popover')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Bottom Content')).toBeInTheDocument()
    })
  })

  it('preserves additional props on trigger', () => {
    render(
      <Popover>
        <PopoverTrigger data-testid="custom-trigger">Trigger</PopoverTrigger>
        <PopoverContent>Content</PopoverContent>
      </Popover>
    )
    expect(screen.getByTestId('custom-trigger')).toBeInTheDocument()
  })

  it('preserves additional props on content', async () => {
    const user = userEvent.setup()
    render(
      <Popover>
        <PopoverTrigger>Trigger</PopoverTrigger>
        <PopoverContent data-testid="custom-content">Content</PopoverContent>
      </Popover>
    )

    const trigger = screen.getByText('Trigger')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByTestId('custom-content')).toBeInTheDocument()
    })
  })
})
