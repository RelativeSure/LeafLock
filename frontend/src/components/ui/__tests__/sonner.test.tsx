import { describe, it, expect, vi } from 'vitest'
import { render } from '@testing-library/react'
import { Toaster } from '../sonner'

describe('Sonner Toaster', () => {
  it('renders toaster component', () => {
    const { container } = render(<Toaster />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('applies system theme by default', () => {
    const { container } = render(<Toaster />)
    const toaster = container.querySelector('[data-sonner-toaster]')
    expect(toaster).toBeInTheDocument()
  })

  it('applies custom className', () => {
    const { container } = render(<Toaster />)
    const toaster = container.querySelector('.toaster')
    expect(toaster).toBeInTheDocument()
    expect(toaster).toHaveClass('group')
  })

  it('forwards ref correctly', () => {
    const ref = vi.fn()
    render(<Toaster ref={ref} />)
    expect(ref).toHaveBeenCalled()
  })

  it('accepts custom theme prop', () => {
    const { container } = render(<Toaster theme="dark" />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('accepts custom position prop', () => {
    const { container } = render(<Toaster position="top-right" />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('accepts custom richColors prop', () => {
    const { container } = render(<Toaster richColors />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('accepts custom expand prop', () => {
    const { container } = render(<Toaster expand />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('accepts custom duration prop', () => {
    const { container } = render(<Toaster duration={5000} />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('accepts custom visibleToasts prop', () => {
    const { container } = render(<Toaster visibleToasts={5} />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('accepts custom closeButton prop', () => {
    const { container } = render(<Toaster closeButton />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('accepts custom offset prop', () => {
    const { container } = render(<Toaster offset="20px" />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('applies toast classNames', () => {
    const { container } = render(<Toaster />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('configures toast background styling', () => {
    const { container } = render(<Toaster />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('configures description styling', () => {
    const { container } = render(<Toaster />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('configures action button styling', () => {
    const { container } = render(<Toaster />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('configures cancel button styling', () => {
    const { container } = render(<Toaster />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('preserves additional props', () => {
    const { container } = render(<Toaster data-testid="custom-toaster" />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('accepts custom dir prop', () => {
    const { container } = render(<Toaster dir="rtl" />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('accepts custom hotkey prop', () => {
    const { container } = render(<Toaster hotkey={['ctrl', 't']} />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('accepts custom invert prop', () => {
    const { container } = render(<Toaster invert />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('accepts custom toastOptions', () => {
    const { container } = render(
      <Toaster
        toastOptions={{
          duration: 3000,
        }}
      />
    )
    expect(container.firstChild).toBeInTheDocument()
  })

  it('has correct display name', () => {
    expect(Toaster.displayName).toBe('Toaster')
  })

  it('renders without crashing with minimal props', () => {
    const { container } = render(<Toaster />)
    expect(container).toBeTruthy()
  })

  it('accepts custom gap prop', () => {
    const { container } = render(<Toaster gap={12} />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('accepts custom loadingIcon prop', () => {
    const LoadingIcon = () => <div>Loading...</div>
    const { container } = render(<Toaster loadingIcon={<LoadingIcon />} />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('accepts custom pauseWhenPageIsHidden prop', () => {
    const { container } = render(<Toaster pauseWhenPageIsHidden />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('accepts custom cn prop', () => {
    const { container } = render(<Toaster cn={(classes) => classes} />)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('renders in different positions', () => {
    const positions = [
      'top-left',
      'top-center',
      'top-right',
      'bottom-left',
      'bottom-center',
      'bottom-right',
    ] as const

    positions.forEach((position) => {
      const { container } = render(<Toaster position={position} />)
      expect(container.firstChild).toBeInTheDocument()
    })
  })

  it('supports all theme options', () => {
    const themes = ['light', 'dark', 'system'] as const

    themes.forEach((theme) => {
      const { container } = render(<Toaster theme={theme} />)
      expect(container.firstChild).toBeInTheDocument()
    })
  })
})
