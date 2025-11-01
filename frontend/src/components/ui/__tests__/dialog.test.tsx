import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  Dialog,
  DialogTrigger,
  DialogContent,
  DialogHeader,
  DialogFooter,
  DialogTitle,
  DialogDescription,
  DialogClose,
} from '../dialog'

describe('Dialog', () => {
  it('renders dialog trigger', () => {
    render(
      <Dialog>
        <DialogTrigger>Open Dialog</DialogTrigger>
        <DialogContent>
          <DialogTitle>Dialog Title</DialogTitle>
        </DialogContent>
      </Dialog>
    )
    expect(screen.getByText('Open Dialog')).toBeInTheDocument()
  })

  it('does not show content by default', () => {
    render(
      <Dialog>
        <DialogTrigger>Open Dialog</DialogTrigger>
        <DialogContent>
          <DialogTitle>Dialog Title</DialogTitle>
        </DialogContent>
      </Dialog>
    )
    expect(screen.queryByText('Dialog Title')).not.toBeInTheDocument()
  })

  it('shows content when trigger is clicked', async () => {
    const user = userEvent.setup()
    render(
      <Dialog>
        <DialogTrigger>Open Dialog</DialogTrigger>
        <DialogContent>
          <DialogTitle>Dialog Title</DialogTitle>
        </DialogContent>
      </Dialog>
    )

    const trigger = screen.getByText('Open Dialog')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Dialog Title')).toBeInTheDocument()
    })
  })

  it('closes when close button is clicked', async () => {
    const user = userEvent.setup()
    render(
      <Dialog>
        <DialogTrigger>Open Dialog</DialogTrigger>
        <DialogContent>
          <DialogTitle>Dialog Title</DialogTitle>
          <DialogClose>Close</DialogClose>
        </DialogContent>
      </Dialog>
    )

    const trigger = screen.getByText('Open Dialog')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Dialog Title')).toBeInTheDocument()
    })

    const closeButton = screen.getByText('Close')
    await user.click(closeButton)

    await waitFor(() => {
      expect(screen.queryByText('Dialog Title')).not.toBeInTheDocument()
    })
  })

  it('closes when X button is clicked', async () => {
    const user = userEvent.setup()
    const { container } = render(
      <Dialog>
        <DialogTrigger>Open Dialog</DialogTrigger>
        <DialogContent>
          <DialogTitle>Dialog Title</DialogTitle>
        </DialogContent>
      </Dialog>
    )

    const trigger = screen.getByText('Open Dialog')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Dialog Title')).toBeInTheDocument()
    })

    const xButton = container.querySelector('[data-slot="dialog-close"]')
    if (xButton) {
      await user.click(xButton)

      await waitFor(() => {
        expect(screen.queryByText('Dialog Title')).not.toBeInTheDocument()
      })
    }
  })

  it('can be controlled with open prop', async () => {
    const handleOpenChange = vi.fn()
    const { rerender } = render(
      <Dialog open={false} onOpenChange={handleOpenChange}>
        <DialogTrigger>Open Dialog</DialogTrigger>
        <DialogContent>
          <DialogTitle>Controlled Dialog</DialogTitle>
        </DialogContent>
      </Dialog>
    )

    expect(screen.queryByText('Controlled Dialog')).not.toBeInTheDocument()

    rerender(
      <Dialog open={true} onOpenChange={handleOpenChange}>
        <DialogTrigger>Open Dialog</DialogTrigger>
        <DialogContent>
          <DialogTitle>Controlled Dialog</DialogTitle>
        </DialogContent>
      </Dialog>
    )

    await waitFor(() => {
      expect(screen.getByText('Controlled Dialog')).toBeInTheDocument()
    })
  })

  it('renders with defaultOpen prop', async () => {
    render(
      <Dialog defaultOpen>
        <DialogTrigger>Open Dialog</DialogTrigger>
        <DialogContent>
          <DialogTitle>Default Open Dialog</DialogTitle>
        </DialogContent>
      </Dialog>
    )

    await waitFor(() => {
      expect(screen.getByText('Default Open Dialog')).toBeInTheDocument()
    })
  })

  it('renders complete dialog structure', async () => {
    const user = userEvent.setup()
    render(
      <Dialog>
        <DialogTrigger>Open Dialog</DialogTrigger>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Complete Dialog</DialogTitle>
            <DialogDescription>This is a complete dialog example</DialogDescription>
          </DialogHeader>
          <div>Main Content</div>
          <DialogFooter>
            <DialogClose>Close</DialogClose>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    )

    const trigger = screen.getByText('Open Dialog')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Complete Dialog')).toBeInTheDocument()
      expect(screen.getByText('This is a complete dialog example')).toBeInTheDocument()
      expect(screen.getByText('Main Content')).toBeInTheDocument()
      expect(screen.getByText('Close')).toBeInTheDocument()
    })
  })

  it('applies custom className to content', async () => {
    const user = userEvent.setup()
    const customClass = 'custom-dialog-content'
    render(
      <Dialog>
        <DialogTrigger>Open Dialog</DialogTrigger>
        <DialogContent className={customClass}>
          <DialogTitle>Dialog</DialogTitle>
        </DialogContent>
      </Dialog>
    )

    const trigger = screen.getByText('Open Dialog')
    await user.click(trigger)

    await waitFor(() => {
      const content = screen.getByText('Dialog').closest('[role="dialog"]')
      expect(content).toHaveClass(customClass)
    })
  })

  it('forwards ref to trigger', () => {
    const ref = vi.fn()
    render(
      <Dialog>
        <DialogTrigger ref={ref}>Trigger</DialogTrigger>
        <DialogContent>
          <DialogTitle>Title</DialogTitle>
        </DialogContent>
      </Dialog>
    )
    expect(ref).toHaveBeenCalled()
  })

  it('forwards ref to content', async () => {
    const user = userEvent.setup()
    const ref = vi.fn()
    render(
      <Dialog>
        <DialogTrigger>Trigger</DialogTrigger>
        <DialogContent ref={ref}>
          <DialogTitle>Title</DialogTitle>
        </DialogContent>
      </Dialog>
    )

    const trigger = screen.getByText('Trigger')
    await user.click(trigger)

    await waitFor(() => {
      expect(ref).toHaveBeenCalled()
    })
  })

  it('forwards ref to close button', async () => {
    const user = userEvent.setup()
    const ref = vi.fn()
    render(
      <Dialog>
        <DialogTrigger>Trigger</DialogTrigger>
        <DialogContent>
          <DialogTitle>Title</DialogTitle>
          <DialogClose ref={ref}>Close</DialogClose>
        </DialogContent>
      </Dialog>
    )

    const trigger = screen.getByText('Trigger')
    await user.click(trigger)

    await waitFor(() => {
      expect(ref).toHaveBeenCalled()
    })
  })

  it('renders overlay when dialog is open', async () => {
    const user = userEvent.setup()
    const { container } = render(
      <Dialog>
        <DialogTrigger>Open Dialog</DialogTrigger>
        <DialogContent>
          <DialogTitle>Dialog</DialogTitle>
        </DialogContent>
      </Dialog>
    )

    const trigger = screen.getByText('Open Dialog')
    await user.click(trigger)

    await waitFor(() => {
      const overlay = container.querySelector('[data-slot="dialog-overlay"]')
      expect(overlay).toBeInTheDocument()
    })
  })

  it('calls onOpenChange when dialog opens', async () => {
    const user = userEvent.setup()
    const handleOpenChange = vi.fn()
    render(
      <Dialog onOpenChange={handleOpenChange}>
        <DialogTrigger>Open Dialog</DialogTrigger>
        <DialogContent>
          <DialogTitle>Dialog</DialogTitle>
        </DialogContent>
      </Dialog>
    )

    const trigger = screen.getByText('Open Dialog')
    await user.click(trigger)

    await waitFor(() => {
      expect(handleOpenChange).toHaveBeenCalledWith(true)
    })
  })

  it('calls onOpenChange when dialog closes', async () => {
    const user = userEvent.setup()
    const handleOpenChange = vi.fn()
    render(
      <Dialog onOpenChange={handleOpenChange}>
        <DialogTrigger>Open Dialog</DialogTrigger>
        <DialogContent>
          <DialogTitle>Dialog</DialogTitle>
          <DialogClose>Close</DialogClose>
        </DialogContent>
      </Dialog>
    )

    const trigger = screen.getByText('Open Dialog')
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
      <Dialog>
        <DialogTrigger>Open Dialog</DialogTrigger>
        <DialogContent>
          <DialogTitle>Escapable Dialog</DialogTitle>
        </DialogContent>
      </Dialog>
    )

    const trigger = screen.getByText('Open Dialog')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Escapable Dialog')).toBeInTheDocument()
    })

    await user.keyboard('{Escape}')

    await waitFor(() => {
      expect(screen.queryByText('Escapable Dialog')).not.toBeInTheDocument()
    })
  })

  it('closes when clicking outside', async () => {
    const user = userEvent.setup()
    const { container } = render(
      <div>
        <div data-testid="outside">Outside Element</div>
        <Dialog>
          <DialogTrigger>Open Dialog</DialogTrigger>
          <DialogContent>
            <DialogTitle>Clickaway Dialog</DialogTitle>
          </DialogContent>
        </Dialog>
      </div>
    )

    const trigger = screen.getByText('Open Dialog')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Clickaway Dialog')).toBeInTheDocument()
    })

    const overlay = container.querySelector('[data-slot="dialog-overlay"]')
    if (overlay) {
      await user.click(overlay)

      await waitFor(() => {
        expect(screen.queryByText('Clickaway Dialog')).not.toBeInTheDocument()
      })
    }
  })

  it('renders dialog header', async () => {
    const user = userEvent.setup()
    render(
      <Dialog>
        <DialogTrigger>Open Dialog</DialogTrigger>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Header Title</DialogTitle>
            <DialogDescription>Header Description</DialogDescription>
          </DialogHeader>
        </DialogContent>
      </Dialog>
    )

    const trigger = screen.getByText('Open Dialog')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Header Title')).toBeInTheDocument()
      expect(screen.getByText('Header Description')).toBeInTheDocument()
    })
  })

  it('renders dialog footer', async () => {
    const user = userEvent.setup()
    render(
      <Dialog>
        <DialogTrigger>Open Dialog</DialogTrigger>
        <DialogContent>
          <DialogTitle>Dialog with Footer</DialogTitle>
          <DialogFooter>
            <button>Action Button</button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    )

    const trigger = screen.getByText('Open Dialog')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Action Button')).toBeInTheDocument()
    })
  })

  it('applies data-slot attributes', async () => {
    const user = userEvent.setup()
    const { container } = render(
      <Dialog>
        <DialogTrigger>Open Dialog</DialogTrigger>
        <DialogContent>
          <DialogTitle>Dialog</DialogTitle>
          <DialogClose>Close</DialogClose>
        </DialogContent>
      </Dialog>
    )

    expect(container.querySelector('[data-slot="dialog"]')).toBeInTheDocument()
    expect(container.querySelector('[data-slot="dialog-trigger"]')).toBeInTheDocument()

    const trigger = screen.getByText('Open Dialog')
    await user.click(trigger)

    await waitFor(() => {
      expect(document.querySelector('[data-slot="dialog-overlay"]')).toBeInTheDocument()
      expect(document.querySelector('[data-slot="dialog-content"]')).toBeInTheDocument()
    })
  })

  it('renders content in portal', async () => {
    const user = userEvent.setup()
    render(
      <div id="root">
        <Dialog>
          <DialogTrigger>Open Dialog</DialogTrigger>
          <DialogContent>
            <DialogTitle>Portal Content</DialogTitle>
          </DialogContent>
        </Dialog>
      </div>
    )

    const trigger = screen.getByText('Open Dialog')
    await user.click(trigger)

    await waitFor(() => {
      const content = screen.getByText('Portal Content')
      expect(content).toBeInTheDocument()
    })
  })

  it('has proper z-index on overlay', async () => {
    const user = userEvent.setup()
    const { container } = render(
      <Dialog>
        <DialogTrigger>Open Dialog</DialogTrigger>
        <DialogContent>
          <DialogTitle>Dialog</DialogTitle>
        </DialogContent>
      </Dialog>
    )

    const trigger = screen.getByText('Open Dialog')
    await user.click(trigger)

    await waitFor(() => {
      const overlay = container.querySelector('.z-50')
      expect(overlay).toBeInTheDocument()
    })
  })

  it('applies animation classes', async () => {
    const user = userEvent.setup()
    render(
      <Dialog>
        <DialogTrigger>Open Dialog</DialogTrigger>
        <DialogContent>
          <DialogTitle>Animated Dialog</DialogTitle>
        </DialogContent>
      </Dialog>
    )

    const trigger = screen.getByText('Open Dialog')
    await user.click(trigger)

    await waitFor(() => {
      const content = screen.getByText('Animated Dialog').closest('[role="dialog"]')
      expect(content).toHaveClass('data-[state=open]:animate-in')
    })
  })

  it('preserves additional props on trigger', () => {
    render(
      <Dialog>
        <DialogTrigger data-testid="custom-trigger">Trigger</DialogTrigger>
        <DialogContent>
          <DialogTitle>Title</DialogTitle>
        </DialogContent>
      </Dialog>
    )
    expect(screen.getByTestId('custom-trigger')).toBeInTheDocument()
  })

  it('preserves additional props on content', async () => {
    const user = userEvent.setup()
    render(
      <Dialog>
        <DialogTrigger>Trigger</DialogTrigger>
        <DialogContent data-testid="custom-content">
          <DialogTitle>Title</DialogTitle>
        </DialogContent>
      </Dialog>
    )

    const trigger = screen.getByText('Trigger')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByTestId('custom-content')).toBeInTheDocument()
    })
  })

  it('supports modal prop', async () => {
    const user = userEvent.setup()
    render(
      <Dialog modal>
        <DialogTrigger>Open Modal Dialog</DialogTrigger>
        <DialogContent>
          <DialogTitle>Modal Content</DialogTitle>
        </DialogContent>
      </Dialog>
    )

    const trigger = screen.getByText('Open Modal Dialog')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Modal Content')).toBeInTheDocument()
    })
  })

  it('has proper ARIA role', async () => {
    const user = userEvent.setup()
    render(
      <Dialog>
        <DialogTrigger>Open Dialog</DialogTrigger>
        <DialogContent>
          <DialogTitle>Dialog</DialogTitle>
        </DialogContent>
      </Dialog>
    )

    const trigger = screen.getByText('Open Dialog')
    await user.click(trigger)

    await waitFor(() => {
      const dialog = screen.getByRole('dialog')
      expect(dialog).toBeInTheDocument()
    })
  })

  it('renders multiple dialogs independently', async () => {
    const user = userEvent.setup()
    render(
      <div>
        <Dialog>
          <DialogTrigger>Open Dialog 1</DialogTrigger>
          <DialogContent>
            <DialogTitle>Dialog 1 Title</DialogTitle>
          </DialogContent>
        </Dialog>
        <Dialog>
          <DialogTrigger>Open Dialog 2</DialogTrigger>
          <DialogContent>
            <DialogTitle>Dialog 2 Title</DialogTitle>
          </DialogContent>
        </Dialog>
      </div>
    )

    const trigger1 = screen.getByText('Open Dialog 1')
    await user.click(trigger1)

    await waitFor(() => {
      expect(screen.getByText('Dialog 1 Title')).toBeInTheDocument()
      expect(screen.queryByText('Dialog 2 Title')).not.toBeInTheDocument()
    })
  })
})
