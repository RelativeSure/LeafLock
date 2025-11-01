import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  Sheet,
  SheetTrigger,
  SheetContent,
  SheetHeader,
  SheetFooter,
  SheetTitle,
  SheetDescription,
  SheetClose,
} from '../sheet'

describe('Sheet', () => {
  it('renders sheet trigger', () => {
    render(
      <Sheet>
        <SheetTrigger>Open Sheet</SheetTrigger>
        <SheetContent>
          <SheetTitle>Sheet Title</SheetTitle>
        </SheetContent>
      </Sheet>
    )
    expect(screen.getByText('Open Sheet')).toBeInTheDocument()
  })

  it('does not show content by default', () => {
    render(
      <Sheet>
        <SheetTrigger>Open Sheet</SheetTrigger>
        <SheetContent>
          <SheetTitle>Sheet Title</SheetTitle>
        </SheetContent>
      </Sheet>
    )
    expect(screen.queryByText('Sheet Title')).not.toBeInTheDocument()
  })

  it('shows content when trigger is clicked', async () => {
    const user = userEvent.setup()
    render(
      <Sheet>
        <SheetTrigger>Open Sheet</SheetTrigger>
        <SheetContent>
          <SheetTitle>Sheet Title</SheetTitle>
        </SheetContent>
      </Sheet>
    )

    const trigger = screen.getByText('Open Sheet')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Sheet Title')).toBeInTheDocument()
    })
  })

  it('closes when close button is clicked', async () => {
    const user = userEvent.setup()
    render(
      <Sheet>
        <SheetTrigger>Open Sheet</SheetTrigger>
        <SheetContent>
          <SheetTitle>Sheet Title</SheetTitle>
          <SheetClose>Close</SheetClose>
        </SheetContent>
      </Sheet>
    )

    const trigger = screen.getByText('Open Sheet')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Sheet Title')).toBeInTheDocument()
    })

    const closeButton = screen.getByText('Close')
    await user.click(closeButton)

    await waitFor(() => {
      expect(screen.queryByText('Sheet Title')).not.toBeInTheDocument()
    })
  })

  it('can be controlled with open prop', async () => {
    const handleOpenChange = vi.fn()
    const { rerender } = render(
      <Sheet open={false} onOpenChange={handleOpenChange}>
        <SheetTrigger>Open Sheet</SheetTrigger>
        <SheetContent>
          <SheetTitle>Controlled Sheet</SheetTitle>
        </SheetContent>
      </Sheet>
    )

    expect(screen.queryByText('Controlled Sheet')).not.toBeInTheDocument()

    rerender(
      <Sheet open={true} onOpenChange={handleOpenChange}>
        <SheetTrigger>Open Sheet</SheetTrigger>
        <SheetContent>
          <SheetTitle>Controlled Sheet</SheetTitle>
        </SheetContent>
      </Sheet>
    )

    await waitFor(() => {
      expect(screen.getByText('Controlled Sheet')).toBeInTheDocument()
    })
  })

  it('renders with defaultOpen prop', async () => {
    render(
      <Sheet defaultOpen>
        <SheetTrigger>Open Sheet</SheetTrigger>
        <SheetContent>
          <SheetTitle>Default Open Sheet</SheetTitle>
        </SheetContent>
      </Sheet>
    )

    await waitFor(() => {
      expect(screen.getByText('Default Open Sheet')).toBeInTheDocument()
    })
  })

  it('renders complete sheet structure', async () => {
    const user = userEvent.setup()
    render(
      <Sheet>
        <SheetTrigger>Open Sheet</SheetTrigger>
        <SheetContent>
          <SheetHeader>
            <SheetTitle>Complete Sheet</SheetTitle>
            <SheetDescription>This is a complete sheet example</SheetDescription>
          </SheetHeader>
          <div>Main Content</div>
          <SheetFooter>
            <SheetClose>Close</SheetClose>
          </SheetFooter>
        </SheetContent>
      </Sheet>
    )

    const trigger = screen.getByText('Open Sheet')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Complete Sheet')).toBeInTheDocument()
      expect(screen.getByText('This is a complete sheet example')).toBeInTheDocument()
      expect(screen.getByText('Main Content')).toBeInTheDocument()
      expect(screen.getByText('Close')).toBeInTheDocument()
    })
  })

  it('supports different side positions - right', async () => {
    const user = userEvent.setup()
    render(
      <Sheet>
        <SheetTrigger>Open Sheet</SheetTrigger>
        <SheetContent side="right">
          <SheetTitle>Right Sheet</SheetTitle>
        </SheetContent>
      </Sheet>
    )

    const trigger = screen.getByText('Open Sheet')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Right Sheet')).toBeInTheDocument()
    })
  })

  it('supports different side positions - left', async () => {
    const user = userEvent.setup()
    render(
      <Sheet>
        <SheetTrigger>Open Sheet</SheetTrigger>
        <SheetContent side="left">
          <SheetTitle>Left Sheet</SheetTitle>
        </SheetContent>
      </Sheet>
    )

    const trigger = screen.getByText('Open Sheet')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Left Sheet')).toBeInTheDocument()
    })
  })

  it('supports different side positions - top', async () => {
    const user = userEvent.setup()
    render(
      <Sheet>
        <SheetTrigger>Open Sheet</SheetTrigger>
        <SheetContent side="top">
          <SheetTitle>Top Sheet</SheetTitle>
        </SheetContent>
      </Sheet>
    )

    const trigger = screen.getByText('Open Sheet')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Top Sheet')).toBeInTheDocument()
    })
  })

  it('supports different side positions - bottom', async () => {
    const user = userEvent.setup()
    render(
      <Sheet>
        <SheetTrigger>Open Sheet</SheetTrigger>
        <SheetContent side="bottom">
          <SheetTitle>Bottom Sheet</SheetTitle>
        </SheetContent>
      </Sheet>
    )

    const trigger = screen.getByText('Open Sheet')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Bottom Sheet')).toBeInTheDocument()
    })
  })

  it('applies custom className to content', async () => {
    const user = userEvent.setup()
    const customClass = 'custom-sheet-content'
    render(
      <Sheet>
        <SheetTrigger>Open Sheet</SheetTrigger>
        <SheetContent className={customClass}>
          <SheetTitle>Sheet</SheetTitle>
        </SheetContent>
      </Sheet>
    )

    const trigger = screen.getByText('Open Sheet')
    await user.click(trigger)

    await waitFor(() => {
      const content = screen.getByText('Sheet').closest('[role="dialog"]')
      expect(content).toHaveClass(customClass)
    })
  })

  it('forwards ref to trigger', () => {
    const ref = vi.fn()
    render(
      <Sheet>
        <SheetTrigger ref={ref}>Trigger</SheetTrigger>
        <SheetContent>
          <SheetTitle>Title</SheetTitle>
        </SheetContent>
      </Sheet>
    )
    expect(ref).toHaveBeenCalled()
  })

  it('forwards ref to content', async () => {
    const user = userEvent.setup()
    const ref = vi.fn()
    render(
      <Sheet>
        <SheetTrigger>Trigger</SheetTrigger>
        <SheetContent ref={ref}>
          <SheetTitle>Title</SheetTitle>
        </SheetContent>
      </Sheet>
    )

    const trigger = screen.getByText('Trigger')
    await user.click(trigger)

    await waitFor(() => {
      expect(ref).toHaveBeenCalled()
    })
  })

  it('renders overlay when sheet is open', async () => {
    const user = userEvent.setup()
    const { container } = render(
      <Sheet>
        <SheetTrigger>Open Sheet</SheetTrigger>
        <SheetContent>
          <SheetTitle>Sheet</SheetTitle>
        </SheetContent>
      </Sheet>
    )

    const trigger = screen.getByText('Open Sheet')
    await user.click(trigger)

    await waitFor(() => {
      const overlay = container.querySelector('.bg-black\\/80')
      expect(overlay).toBeInTheDocument()
    })
  })

  it('calls onOpenChange when sheet opens', async () => {
    const user = userEvent.setup()
    const handleOpenChange = vi.fn()
    render(
      <Sheet onOpenChange={handleOpenChange}>
        <SheetTrigger>Open Sheet</SheetTrigger>
        <SheetContent>
          <SheetTitle>Sheet</SheetTitle>
        </SheetContent>
      </Sheet>
    )

    const trigger = screen.getByText('Open Sheet')
    await user.click(trigger)

    await waitFor(() => {
      expect(handleOpenChange).toHaveBeenCalledWith(true)
    })
  })

  it('calls onOpenChange when sheet closes', async () => {
    const user = userEvent.setup()
    const handleOpenChange = vi.fn()
    render(
      <Sheet onOpenChange={handleOpenChange}>
        <SheetTrigger>Open Sheet</SheetTrigger>
        <SheetContent>
          <SheetTitle>Sheet</SheetTitle>
          <SheetClose>Close</SheetClose>
        </SheetContent>
      </Sheet>
    )

    const trigger = screen.getByText('Open Sheet')
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

  it('closes on escape key', async () => {
    const user = userEvent.setup()
    render(
      <Sheet>
        <SheetTrigger>Open Sheet</SheetTrigger>
        <SheetContent>
          <SheetTitle>Escapable Sheet</SheetTitle>
        </SheetContent>
      </Sheet>
    )

    const trigger = screen.getByText('Open Sheet')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Escapable Sheet')).toBeInTheDocument()
    })

    await user.keyboard('{Escape}')

    await waitFor(() => {
      expect(screen.queryByText('Escapable Sheet')).not.toBeInTheDocument()
    })
  })

  it('renders sheet header', async () => {
    const user = userEvent.setup()
    render(
      <Sheet>
        <SheetTrigger>Open Sheet</SheetTrigger>
        <SheetContent>
          <SheetHeader>
            <SheetTitle>Header Title</SheetTitle>
            <SheetDescription>Header Description</SheetDescription>
          </SheetHeader>
        </SheetContent>
      </Sheet>
    )

    const trigger = screen.getByText('Open Sheet')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Header Title')).toBeInTheDocument()
      expect(screen.getByText('Header Description')).toBeInTheDocument()
    })
  })

  it('renders sheet footer', async () => {
    const user = userEvent.setup()
    render(
      <Sheet>
        <SheetTrigger>Open Sheet</SheetTrigger>
        <SheetContent>
          <SheetTitle>Sheet with Footer</SheetTitle>
          <SheetFooter>
            <button>Action Button</button>
          </SheetFooter>
        </SheetContent>
      </Sheet>
    )

    const trigger = screen.getByText('Open Sheet')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Action Button')).toBeInTheDocument()
    })
  })

  it('has proper z-index', async () => {
    const user = userEvent.setup()
    const { container } = render(
      <Sheet>
        <SheetTrigger>Open Sheet</SheetTrigger>
        <SheetContent>
          <SheetTitle>Sheet</SheetTitle>
        </SheetContent>
      </Sheet>
    )

    const trigger = screen.getByText('Open Sheet')
    await user.click(trigger)

    await waitFor(() => {
      const overlay = container.querySelector('.z-50')
      expect(overlay).toBeInTheDocument()
    })
  })

  it('applies animation classes', async () => {
    const user = userEvent.setup()
    render(
      <Sheet>
        <SheetTrigger>Open Sheet</SheetTrigger>
        <SheetContent>
          <SheetTitle>Animated Sheet</SheetTitle>
        </SheetContent>
      </Sheet>
    )

    const trigger = screen.getByText('Open Sheet')
    await user.click(trigger)

    await waitFor(() => {
      const content = screen.getByText('Animated Sheet').closest('[role="dialog"]')
      expect(content).toHaveClass('data-[state=open]:animate-in')
    })
  })

  it('preserves additional props on trigger', () => {
    render(
      <Sheet>
        <SheetTrigger data-testid="custom-trigger">Trigger</SheetTrigger>
        <SheetContent>
          <SheetTitle>Title</SheetTitle>
        </SheetContent>
      </Sheet>
    )
    expect(screen.getByTestId('custom-trigger')).toBeInTheDocument()
  })

  it('renders content in portal', async () => {
    const user = userEvent.setup()
    render(
      <div id="root">
        <Sheet>
          <SheetTrigger>Open Sheet</SheetTrigger>
          <SheetContent>
            <SheetTitle>Portal Content</SheetTitle>
          </SheetContent>
        </Sheet>
      </div>
    )

    const trigger = screen.getByText('Open Sheet')
    await user.click(trigger)

    await waitFor(() => {
      const content = screen.getByText('Portal Content')
      expect(content).toBeInTheDocument()
    })
  })

  it('has proper ARIA role', async () => {
    const user = userEvent.setup()
    render(
      <Sheet>
        <SheetTrigger>Open Sheet</SheetTrigger>
        <SheetContent>
          <SheetTitle>Sheet</SheetTitle>
        </SheetContent>
      </Sheet>
    )

    const trigger = screen.getByText('Open Sheet')
    await user.click(trigger)

    await waitFor(() => {
      const dialog = screen.getByRole('dialog')
      expect(dialog).toBeInTheDocument()
    })
  })

  it('renders X close button by default', async () => {
    const user = userEvent.setup()
    const { container } = render(
      <Sheet>
        <SheetTrigger>Open Sheet</SheetTrigger>
        <SheetContent>
          <SheetTitle>Sheet</SheetTitle>
        </SheetContent>
      </Sheet>
    )

    const trigger = screen.getByText('Open Sheet')
    await user.click(trigger)

    await waitFor(() => {
      const xButton = container.querySelector('.lucide-x')
      expect(xButton).toBeInTheDocument()
    })
  })

  it('closes when clicking overlay', async () => {
    const user = userEvent.setup()
    const { container } = render(
      <Sheet>
        <SheetTrigger>Open Sheet</SheetTrigger>
        <SheetContent>
          <SheetTitle>Clickaway Sheet</SheetTitle>
        </SheetContent>
      </Sheet>
    )

    const trigger = screen.getByText('Open Sheet')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Clickaway Sheet')).toBeInTheDocument()
    })

    const overlay = container.querySelector('.bg-black\\/80')
    if (overlay) {
      await user.click(overlay)

      await waitFor(() => {
        expect(screen.queryByText('Clickaway Sheet')).not.toBeInTheDocument()
      })
    }
  })

  it('supports modal prop', async () => {
    const user = userEvent.setup()
    render(
      <Sheet modal>
        <SheetTrigger>Open Modal Sheet</SheetTrigger>
        <SheetContent>
          <SheetTitle>Modal Content</SheetTitle>
        </SheetContent>
      </Sheet>
    )

    const trigger = screen.getByText('Open Modal Sheet')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Modal Content')).toBeInTheDocument()
    })
  })
})
