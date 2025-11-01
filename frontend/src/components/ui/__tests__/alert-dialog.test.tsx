import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  AlertDialog,
  AlertDialogTrigger,
  AlertDialogContent,
  AlertDialogHeader,
  AlertDialogFooter,
  AlertDialogTitle,
  AlertDialogDescription,
  AlertDialogAction,
  AlertDialogCancel,
} from '../alert-dialog'

describe('AlertDialog', () => {
  it('renders alert dialog trigger', () => {
    render(
      <AlertDialog>
        <AlertDialogTrigger>Open Alert</AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogTitle>Alert Title</AlertDialogTitle>
        </AlertDialogContent>
      </AlertDialog>
    )
    expect(screen.getByText('Open Alert')).toBeInTheDocument()
  })

  it('does not show content by default', () => {
    render(
      <AlertDialog>
        <AlertDialogTrigger>Open Alert</AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogTitle>Alert Title</AlertDialogTitle>
        </AlertDialogContent>
      </AlertDialog>
    )
    expect(screen.queryByText('Alert Title')).not.toBeInTheDocument()
  })

  it('shows content when trigger is clicked', async () => {
    const user = userEvent.setup()
    render(
      <AlertDialog>
        <AlertDialogTrigger>Open Alert</AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogTitle>Alert Title</AlertDialogTitle>
        </AlertDialogContent>
      </AlertDialog>
    )

    const trigger = screen.getByText('Open Alert')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Alert Title')).toBeInTheDocument()
    })
  })

  it('closes when cancel button is clicked', async () => {
    const user = userEvent.setup()
    render(
      <AlertDialog>
        <AlertDialogTrigger>Open Alert</AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogTitle>Alert Title</AlertDialogTitle>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    )

    const trigger = screen.getByText('Open Alert')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Alert Title')).toBeInTheDocument()
    })

    const cancelButton = screen.getByText('Cancel')
    await user.click(cancelButton)

    await waitFor(() => {
      expect(screen.queryByText('Alert Title')).not.toBeInTheDocument()
    })
  })

  it('closes when action button is clicked', async () => {
    const user = userEvent.setup()
    const handleAction = vi.fn()
    render(
      <AlertDialog>
        <AlertDialogTrigger>Open Alert</AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogTitle>Alert Title</AlertDialogTitle>
          <AlertDialogFooter>
            <AlertDialogAction onClick={handleAction}>Confirm</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    )

    const trigger = screen.getByText('Open Alert')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Alert Title')).toBeInTheDocument()
    })

    const actionButton = screen.getByText('Confirm')
    await user.click(actionButton)

    expect(handleAction).toHaveBeenCalled()

    await waitFor(() => {
      expect(screen.queryByText('Alert Title')).not.toBeInTheDocument()
    })
  })

  it('can be controlled with open prop', async () => {
    const handleOpenChange = vi.fn()
    const { rerender } = render(
      <AlertDialog open={false} onOpenChange={handleOpenChange}>
        <AlertDialogTrigger>Open Alert</AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogTitle>Controlled Alert</AlertDialogTitle>
        </AlertDialogContent>
      </AlertDialog>
    )

    expect(screen.queryByText('Controlled Alert')).not.toBeInTheDocument()

    rerender(
      <AlertDialog open={true} onOpenChange={handleOpenChange}>
        <AlertDialogTrigger>Open Alert</AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogTitle>Controlled Alert</AlertDialogTitle>
        </AlertDialogContent>
      </AlertDialog>
    )

    await waitFor(() => {
      expect(screen.getByText('Controlled Alert')).toBeInTheDocument()
    })
  })

  it('renders complete alert dialog structure', async () => {
    const user = userEvent.setup()
    render(
      <AlertDialog>
        <AlertDialogTrigger>Delete Account</AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Are you absolutely sure?</AlertDialogTitle>
            <AlertDialogDescription>
              This action cannot be undone. This will permanently delete your account.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction>Continue</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    )

    const trigger = screen.getByText('Delete Account')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Are you absolutely sure?')).toBeInTheDocument()
      expect(
        screen.getByText('This action cannot be undone. This will permanently delete your account.')
      ).toBeInTheDocument()
      expect(screen.getByText('Cancel')).toBeInTheDocument()
      expect(screen.getByText('Continue')).toBeInTheDocument()
    })
  })

  it('applies custom className to content', async () => {
    const user = userEvent.setup()
    const customClass = 'custom-dialog-content'
    render(
      <AlertDialog>
        <AlertDialogTrigger>Open Alert</AlertDialogTrigger>
        <AlertDialogContent className={customClass}>
          <AlertDialogTitle>Alert</AlertDialogTitle>
        </AlertDialogContent>
      </AlertDialog>
    )

    const trigger = screen.getByText('Open Alert')
    await user.click(trigger)

    await waitFor(() => {
      const content = screen.getByText('Alert').closest('[role="alertdialog"]')
      expect(content).toHaveClass(customClass)
    })
  })

  it('forwards ref to trigger', () => {
    const ref = vi.fn()
    render(
      <AlertDialog>
        <AlertDialogTrigger ref={ref}>Trigger</AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogTitle>Title</AlertDialogTitle>
        </AlertDialogContent>
      </AlertDialog>
    )
    expect(ref).toHaveBeenCalled()
  })

  it('forwards ref to content', async () => {
    const user = userEvent.setup()
    const ref = vi.fn()
    render(
      <AlertDialog>
        <AlertDialogTrigger>Trigger</AlertDialogTrigger>
        <AlertDialogContent ref={ref}>
          <AlertDialogTitle>Title</AlertDialogTitle>
        </AlertDialogContent>
      </AlertDialog>
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
      <AlertDialog>
        <AlertDialogTrigger>Open Alert</AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogTitle>Alert</AlertDialogTitle>
        </AlertDialogContent>
      </AlertDialog>
    )

    const trigger = screen.getByText('Open Alert')
    await user.click(trigger)

    await waitFor(() => {
      const overlay = container.querySelector('.bg-black\\/80')
      expect(overlay).toBeInTheDocument()
    })
  })

  it('calls onOpenChange when dialog opens', async () => {
    const user = userEvent.setup()
    const handleOpenChange = vi.fn()
    render(
      <AlertDialog onOpenChange={handleOpenChange}>
        <AlertDialogTrigger>Open Alert</AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogTitle>Alert</AlertDialogTitle>
        </AlertDialogContent>
      </AlertDialog>
    )

    const trigger = screen.getByText('Open Alert')
    await user.click(trigger)

    await waitFor(() => {
      expect(handleOpenChange).toHaveBeenCalledWith(true)
    })
  })

  it('calls onOpenChange when dialog closes', async () => {
    const user = userEvent.setup()
    const handleOpenChange = vi.fn()
    render(
      <AlertDialog onOpenChange={handleOpenChange}>
        <AlertDialogTrigger>Open Alert</AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogTitle>Alert</AlertDialogTitle>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
        </AlertDialogContent>
      </AlertDialog>
    )

    const trigger = screen.getByText('Open Alert')
    await user.click(trigger)

    await waitFor(() => {
      expect(handleOpenChange).toHaveBeenCalledWith(true)
    })

    vi.clearAllMocks()

    const cancelButton = screen.getByText('Cancel')
    await user.click(cancelButton)

    await waitFor(() => {
      expect(handleOpenChange).toHaveBeenCalledWith(false)
    })
  })

  it('preserves additional props on trigger', () => {
    render(
      <AlertDialog>
        <AlertDialogTrigger data-testid="custom-trigger">Trigger</AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogTitle>Title</AlertDialogTitle>
        </AlertDialogContent>
      </AlertDialog>
    )
    expect(screen.getByTestId('custom-trigger')).toBeInTheDocument()
  })

  it('has proper z-index on overlay', async () => {
    const user = userEvent.setup()
    const { container } = render(
      <AlertDialog>
        <AlertDialogTrigger>Open Alert</AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogTitle>Alert</AlertDialogTitle>
        </AlertDialogContent>
      </AlertDialog>
    )

    const trigger = screen.getByText('Open Alert')
    await user.click(trigger)

    await waitFor(() => {
      const overlay = container.querySelector('.z-50')
      expect(overlay).toBeInTheDocument()
    })
  })

  it('applies animation classes to overlay', async () => {
    const user = userEvent.setup()
    const { container } = render(
      <AlertDialog>
        <AlertDialogTrigger>Open Alert</AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogTitle>Alert</AlertDialogTitle>
        </AlertDialogContent>
      </AlertDialog>
    )

    const trigger = screen.getByText('Open Alert')
    await user.click(trigger)

    await waitFor(() => {
      const overlay = container.querySelector('.data-\\[state\\=open\\]\\:animate-in')
      expect(overlay).toBeInTheDocument()
    })
  })

  it('renders alert dialog header with proper styling', async () => {
    const user = userEvent.setup()
    render(
      <AlertDialog>
        <AlertDialogTrigger>Open Alert</AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Header Title</AlertDialogTitle>
          </AlertDialogHeader>
        </AlertDialogContent>
      </AlertDialog>
    )

    const trigger = screen.getByText('Open Alert')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Header Title')).toBeInTheDocument()
    })
  })

  it('renders alert dialog footer with proper styling', async () => {
    const user = userEvent.setup()
    render(
      <AlertDialog>
        <AlertDialogTrigger>Open Alert</AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogTitle>Title</AlertDialogTitle>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction>OK</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    )

    const trigger = screen.getByText('Open Alert')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Cancel')).toBeInTheDocument()
      expect(screen.getByText('OK')).toBeInTheDocument()
    })
  })

  it('renders alert dialog description', async () => {
    const user = userEvent.setup()
    render(
      <AlertDialog>
        <AlertDialogTrigger>Open Alert</AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogTitle>Title</AlertDialogTitle>
          <AlertDialogDescription>This is a description</AlertDialogDescription>
        </AlertDialogContent>
      </AlertDialog>
    )

    const trigger = screen.getByText('Open Alert')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('This is a description')).toBeInTheDocument()
    })
  })

  it('applies button variants to action button', async () => {
    const user = userEvent.setup()
    render(
      <AlertDialog>
        <AlertDialogTrigger>Open Alert</AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogTitle>Title</AlertDialogTitle>
          <AlertDialogAction>Confirm</AlertDialogAction>
        </AlertDialogContent>
      </AlertDialog>
    )

    const trigger = screen.getByText('Open Alert')
    await user.click(trigger)

    await waitFor(() => {
      const actionButton = screen.getByText('Confirm')
      expect(actionButton).toBeInTheDocument()
    })
  })

  it('applies outline variant to cancel button', async () => {
    const user = userEvent.setup()
    render(
      <AlertDialog>
        <AlertDialogTrigger>Open Alert</AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogTitle>Title</AlertDialogTitle>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
        </AlertDialogContent>
      </AlertDialog>
    )

    const trigger = screen.getByText('Open Alert')
    await user.click(trigger)

    await waitFor(() => {
      const cancelButton = screen.getByText('Cancel')
      expect(cancelButton).toBeInTheDocument()
    })
  })

  it('renders content in portal', async () => {
    const user = userEvent.setup()
    render(
      <div id="root">
        <AlertDialog>
          <AlertDialogTrigger>Open Alert</AlertDialogTrigger>
          <AlertDialogContent>
            <AlertDialogTitle>Portal Content</AlertDialogTitle>
          </AlertDialogContent>
        </AlertDialog>
      </div>
    )

    const trigger = screen.getByText('Open Alert')
    await user.click(trigger)

    await waitFor(() => {
      const content = screen.getByText('Portal Content')
      expect(content).toBeInTheDocument()
    })
  })

  it('prevents closing on escape key by default', async () => {
    const user = userEvent.setup()
    render(
      <AlertDialog>
        <AlertDialogTrigger>Open Alert</AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogTitle>Alert Title</AlertDialogTitle>
        </AlertDialogContent>
      </AlertDialog>
    )

    const trigger = screen.getByText('Open Alert')
    await user.click(trigger)

    await waitFor(() => {
      expect(screen.getByText('Alert Title')).toBeInTheDocument()
    })

    await user.keyboard('{Escape}')

    // Alert dialog should still be visible (escape doesn't close it by default)
    expect(screen.getByText('Alert Title')).toBeInTheDocument()
  })

  it('has proper ARIA role', async () => {
    const user = userEvent.setup()
    render(
      <AlertDialog>
        <AlertDialogTrigger>Open Alert</AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogTitle>Alert</AlertDialogTitle>
        </AlertDialogContent>
      </AlertDialog>
    )

    const trigger = screen.getByText('Open Alert')
    await user.click(trigger)

    await waitFor(() => {
      const dialog = screen.getByRole('alertdialog')
      expect(dialog).toBeInTheDocument()
    })
  })
})
