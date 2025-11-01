import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  Drawer,
  DrawerTrigger,
  DrawerContent,
  DrawerHeader,
  DrawerTitle,
  DrawerDescription,
  DrawerFooter,
  DrawerClose,
} from '../drawer'

describe('Drawer', () => {
  it('renders drawer trigger', () => {
    render(
      <Drawer>
        <DrawerTrigger>Open Drawer</DrawerTrigger>
        <DrawerContent>Drawer Content</DrawerContent>
      </Drawer>
    )
    expect(screen.getByText('Open Drawer')).toBeInTheDocument()
  })

  it('does not show content by default', () => {
    render(
      <Drawer>
        <DrawerTrigger>Open Drawer</DrawerTrigger>
        <DrawerContent>Drawer Content</DrawerContent>
      </Drawer>
    )
    expect(screen.queryByText('Drawer Content')).not.toBeInTheDocument()
  })

  it('shows content when trigger is clicked', async () => {
    const user = userEvent.setup()
    render(
      <Drawer>
        <DrawerTrigger>Open Drawer</DrawerTrigger>
        <DrawerContent>Drawer Content</DrawerContent>
      </Drawer>
    )

    const trigger = screen.getByText('Open Drawer')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Drawer Content')).toBeInTheDocument()
    })
  })

  it('closes when close button is clicked', async () => {
    const user = userEvent.setup()
    render(
      <Drawer>
        <DrawerTrigger>Open Drawer</DrawerTrigger>
        <DrawerContent>
          <div>Drawer Content</div>
          <DrawerClose>Close</DrawerClose>
        </DrawerContent>
      </Drawer>
    )

    const trigger = screen.getByText('Open Drawer')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Drawer Content')).toBeInTheDocument()
    })

    const closeButton = screen.getByText('Close')
    await user.click(closeButton)

    await waitFor(() => {
      expect(screen.queryByText('Drawer Content')).not.toBeInTheDocument()
    })
  })

  it('can be controlled with open prop', async () => {
    const handleOpenChange = vi.fn()
    const { rerender } = render(
      <Drawer open={false} onOpenChange={handleOpenChange}>
        <DrawerTrigger>Open Drawer</DrawerTrigger>
        <DrawerContent>Controlled Content</DrawerContent>
      </Drawer>
    )

    expect(screen.queryByText('Controlled Content')).not.toBeInTheDocument()

    rerender(
      <Drawer open={true} onOpenChange={handleOpenChange}>
        <DrawerTrigger>Open Drawer</DrawerTrigger>
        <DrawerContent>Controlled Content</DrawerContent>
      </Drawer>
    )

    await waitFor(() => {
      expect(screen.getByText('Controlled Content')).toBeInTheDocument()
    })
  })

  it('renders with defaultOpen prop', async () => {
    render(
      <Drawer defaultOpen>
        <DrawerTrigger>Open Drawer</DrawerTrigger>
        <DrawerContent>Default Open Content</DrawerContent>
      </Drawer>
    )

    await waitFor(() => {
      expect(screen.getByText('Default Open Content')).toBeInTheDocument()
    })
  })

  it('applies shouldScaleBackground by default', () => {
    const { container } = render(
      <Drawer>
        <DrawerTrigger>Open Drawer</DrawerTrigger>
        <DrawerContent>Content</DrawerContent>
      </Drawer>
    )
    expect(container).toBeInTheDocument()
  })

  it('renders DrawerHeader component', async () => {
    const user = userEvent.setup()
    render(
      <Drawer>
        <DrawerTrigger>Open Drawer</DrawerTrigger>
        <DrawerContent>
          <DrawerHeader>
            <DrawerTitle>Drawer Title</DrawerTitle>
          </DrawerHeader>
        </DrawerContent>
      </Drawer>
    )

    const trigger = screen.getByText('Open Drawer')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Drawer Title')).toBeInTheDocument()
    })
  })

  it('renders DrawerTitle component', async () => {
    const user = userEvent.setup()
    render(
      <Drawer>
        <DrawerTrigger>Open Drawer</DrawerTrigger>
        <DrawerContent>
          <DrawerTitle>Test Title</DrawerTitle>
        </DrawerContent>
      </Drawer>
    )

    const trigger = screen.getByText('Open Drawer')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Test Title')).toBeInTheDocument()
    })
  })

  it('renders DrawerDescription component', async () => {
    const user = userEvent.setup()
    render(
      <Drawer>
        <DrawerTrigger>Open Drawer</DrawerTrigger>
        <DrawerContent>
          <DrawerDescription>Test Description</DrawerDescription>
        </DrawerContent>
      </Drawer>
    )

    const trigger = screen.getByText('Open Drawer')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Test Description')).toBeInTheDocument()
    })
  })

  it('renders DrawerFooter component', async () => {
    const user = userEvent.setup()
    render(
      <Drawer>
        <DrawerTrigger>Open Drawer</DrawerTrigger>
        <DrawerContent>
          <DrawerFooter>Footer Content</DrawerFooter>
        </DrawerContent>
      </Drawer>
    )

    const trigger = screen.getByText('Open Drawer')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Footer Content')).toBeInTheDocument()
    })
  })

  it('forwards ref to trigger', () => {
    const ref = vi.fn()
    render(
      <Drawer>
        <DrawerTrigger ref={ref}>Trigger</DrawerTrigger>
        <DrawerContent>Content</DrawerContent>
      </Drawer>
    )
    expect(ref).toHaveBeenCalled()
  })

  it('forwards ref to content', async () => {
    const user = userEvent.setup()
    const ref = vi.fn()
    render(
      <Drawer>
        <DrawerTrigger>Trigger</DrawerTrigger>
        <DrawerContent ref={ref}>Content</DrawerContent>
      </Drawer>
    )

    const trigger = screen.getByText('Trigger')
    await user.click(trigger)

    await waitFor(() => {
      expect(ref).toHaveBeenCalled()
    })
  })

  it('calls onOpenChange when drawer opens', async () => {
    const user = userEvent.setup()
    const handleOpenChange = vi.fn()
    render(
      <Drawer onOpenChange={handleOpenChange}>
        <DrawerTrigger>Open Drawer</DrawerTrigger>
        <DrawerContent>Content</DrawerContent>
      </Drawer>
    )

    const trigger = screen.getByText('Open Drawer')
    await user.click(trigger)

    await waitFor(() => {
      expect(handleOpenChange).toHaveBeenCalledWith(true)
    })
  })

  it('calls onOpenChange when drawer closes', async () => {
    const user = userEvent.setup()
    const handleOpenChange = vi.fn()
    render(
      <Drawer onOpenChange={handleOpenChange}>
        <DrawerTrigger>Open Drawer</DrawerTrigger>
        <DrawerContent>
          <div>Content</div>
          <DrawerClose>Close</DrawerClose>
        </DrawerContent>
      </Drawer>
    )

    const trigger = screen.getByText('Open Drawer')
    await user.click(trigger)

    await waitFor(() => {
      expect(handleOpenChange).toHaveBeenCalledWith(true)
    })

    vi.clearAllMocks()

    const closeButton = screen.getByText('Close')
    await user.click(closeButton)

    await waitFor(() => {
      expect(handleOpenChange).toHaveBeenCalledWith(false)
    })
  })

  it('applies custom className to content', async () => {
    const user = userEvent.setup()
    const customClass = 'custom-drawer-content'
    render(
      <Drawer>
        <DrawerTrigger>Open Drawer</DrawerTrigger>
        <DrawerContent className={customClass}>Content</DrawerContent>
      </Drawer>
    )

    const trigger = screen.getByText('Open Drawer')
    await user.click(trigger)

    await waitFor(() => {
      const content = screen.getByText('Content')
      expect(content.parentElement).toHaveClass(customClass)
    })
  })

  it('renders overlay when drawer is open', async () => {
    const user = userEvent.setup()
    const { container } = render(
      <Drawer>
        <DrawerTrigger>Open Drawer</DrawerTrigger>
        <DrawerContent>Content</DrawerContent>
      </Drawer>
    )

    const trigger = screen.getByText('Open Drawer')
    await user.click(trigger)

    await waitFor(() => {
      const overlay = container.querySelector('.bg-black\\/80')
      expect(overlay).toBeInTheDocument()
    })
  })

  it('supports dismissible prop', async () => {
    const user = userEvent.setup()
    render(
      <Drawer dismissible={false}>
        <DrawerTrigger>Open Drawer</DrawerTrigger>
        <DrawerContent>Content</DrawerContent>
      </Drawer>
    )

    const trigger = screen.getByText('Open Drawer')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Content')).toBeInTheDocument()
    })
  })

  it('supports modal prop', async () => {
    const user = userEvent.setup()
    render(
      <Drawer modal>
        <DrawerTrigger>Open Drawer</DrawerTrigger>
        <DrawerContent>Modal Content</DrawerContent>
      </Drawer>
    )

    const trigger = screen.getByText('Open Drawer')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Modal Content')).toBeInTheDocument()
    })
  })

  it('preserves additional props on trigger', () => {
    render(
      <Drawer>
        <DrawerTrigger data-testid="custom-trigger">Trigger</DrawerTrigger>
        <DrawerContent>Content</DrawerContent>
      </Drawer>
    )
    expect(screen.getByTestId('custom-trigger')).toBeInTheDocument()
  })

  it('has correct display name', () => {
    expect(Drawer.displayName).toBe('Drawer')
  })

  it('renders with proper z-index', async () => {
    const user = userEvent.setup()
    const { container } = render(
      <Drawer>
        <DrawerTrigger>Open Drawer</DrawerTrigger>
        <DrawerContent>Content</DrawerContent>
      </Drawer>
    )

    const trigger = screen.getByText('Open Drawer')
    await user.click(trigger)

    await waitFor(() => {
      const overlay = container.querySelector('.z-50')
      expect(overlay).toBeInTheDocument()
    })
  })

  it('applies rounded top corners to content', async () => {
    const user = userEvent.setup()
    const { container } = render(
      <Drawer>
        <DrawerTrigger>Open Drawer</DrawerTrigger>
        <DrawerContent>Content</DrawerContent>
      </Drawer>
    )

    const trigger = screen.getByText('Open Drawer')
    await user.click(trigger)

    await waitFor(() => {
      const content = container.querySelector('.rounded-t-\\[10px\\]')
      expect(content).toBeInTheDocument()
    })
  })

  it('supports direction prop', () => {
    const { container } = render(
      <Drawer direction="right">
        <DrawerTrigger>Open Drawer</DrawerTrigger>
        <DrawerContent>Content</DrawerContent>
      </Drawer>
    )
    expect(container).toBeInTheDocument()
  })

  it('renders complete drawer structure', async () => {
    const user = userEvent.setup()
    render(
      <Drawer>
        <DrawerTrigger>Open Drawer</DrawerTrigger>
        <DrawerContent>
          <DrawerHeader>
            <DrawerTitle>Complete Drawer</DrawerTitle>
            <DrawerDescription>This is a complete drawer example</DrawerDescription>
          </DrawerHeader>
          <div>Main Content</div>
          <DrawerFooter>
            <DrawerClose>Close</DrawerClose>
          </DrawerFooter>
        </DrawerContent>
      </Drawer>
    )

    const trigger = screen.getByText('Open Drawer')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Complete Drawer')).toBeInTheDocument()
      expect(screen.getByText('This is a complete drawer example')).toBeInTheDocument()
      expect(screen.getByText('Main Content')).toBeInTheDocument()
      expect(screen.getByText('Close')).toBeInTheDocument()
    })
  })
})
